import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { triageConfigs, triageRuns } from '../db/schema';
import type { TriageRunStatus } from '../types';
import { compareCandidates, countsTowardRetryCap, MAX_ATTEMPTS_PER_HASH, selectTriageCandidates, type SelectOptions } from './select';
import { findingInputHash } from './state';
import { seedConfig, seedFinding, seedLabel, seedProject, seedRun, setAdvisoryModified } from './test-support';

let db: Db;
let scanId: number;
let config: typeof triageConfigs.$inferSelect;

beforeEach(() => {
  db = openDb(':memory:');
  ({ scanId } = seedProject(db));
  config = seedConfig(db);
});

function select(opts: Partial<SelectOptions> = {}) {
  const r = selectTriageCandidates(db, config, { minPriority: 'P2', limit: 25, ...opts });
  return {
    ids: r.candidates.map((c) => c.finding.id),
    remaining: r.remaining,
    backlog: r.backlog.map((c) => c.finding.id),
    candidates: r.candidates,
    excluded: r.excluded,
  };
}

/** A stored run with the fields the retry cap looks at. */
function addRun(
  findingId: number,
  hash: string,
  status: TriageRunStatus,
  extra: { attempts?: number; error?: string; raw?: Record<string, unknown> | null } = {},
) {
  db.insert(triageRuns)
    .values({
      findingId,
      configName: config.name,
      inputHash: hash,
      status,
      prompt: 'p',
      attempts: extra.attempts ?? 1,
      error: extra.error ?? null,
      raw: extra.raw ?? null,
    })
    .run();
}

const cliResult = (subtype: string, result: string) => ({ type: 'result', subtype, is_error: true, result });

describe('selectTriageCandidates', () => {
  it('orders by priority, then EPSS, then CVSS, then id', () => {
    const p2 = seedFinding(db, { scanId, priority: 'P2', epss: 0.9, cvss: 9.9 });
    const p0 = seedFinding(db, { scanId, priority: 'P0' });
    const p1LowEpss = seedFinding(db, { scanId, priority: 'P1', epss: 0.01, cvss: 9 });
    const p1HighEpss = seedFinding(db, { scanId, priority: 'P1', epss: 0.5, cvss: 5 });
    const p1NoEpssHighCvss = seedFinding(db, { scanId, priority: 'P1', epss: null, cvss: 9.8 });
    const p1NoEpssLowCvss = seedFinding(db, { scanId, priority: 'P1', epss: null, cvss: 7 });
    const p1NoEpssLowCvssLater = seedFinding(db, { scanId, priority: 'P1', epss: null, cvss: 7 });
    expect(select().ids).toEqual([
      p0.id,
      p1HighEpss.id,
      p1LowEpss.id,
      p1NoEpssHighCvss.id,
      p1NoEpssLowCvss.id,
      p1NoEpssLowCvssLater.id,
      p2.id,
    ]);
  });

  it('puts unprioritised findings last when they are requested explicitly', () => {
    const none = seedFinding(db, { scanId, priority: null });
    const p2 = seedFinding(db, { scanId, priority: 'P2' });
    expect(select().ids).toEqual([p2.id]);
    expect(select({ findingIds: [none.id, p2.id] }).ids).toEqual([p2.id, none.id]);
    expect(compareCandidates(none, p2)).toBeGreaterThan(0);
  });

  it('applies the limit and reports how many remain, in order', () => {
    const ids = Array.from({ length: 5 }, () => seedFinding(db, { scanId }).id);
    const r = select({ limit: 2 });
    expect(r.ids).toEqual(ids.slice(0, 2));
    expect(r.remaining).toBe(3);
    expect(r.backlog).toEqual(ids.slice(2));
    expect(select({ limit: 10 })).toMatchObject({ remaining: 0, backlog: [] });
  });

  it('never selects skipped findings; explicit ids lift min priority but not the malicious skip', () => {
    const p3 = seedFinding(db, { scanId, priority: 'P3' });
    const mal = seedFinding(db, { scanId, priority: 'P0', malicious: true, osvId: 'MAL-2026-1' });
    expect(select().ids).toEqual([]);
    expect(select({ force: true }).ids).toEqual([]);
    expect(select({ findingIds: [p3.id, mal.id] }).ids).toEqual([p3.id]);
  });

  it('does not pull a below-min-priority finding with an old ok run into forced or sampled runs', () => {
    const p3 = seedFinding(db, { scanId, priority: 'P3' });
    const p2 = seedFinding(db, { scanId, priority: 'P2' });
    for (const f of [p3, p2]) {
      seedRun(db, f.id, config.name, findingInputHash(db, f, config), 'ok'); // e.g. p3 was triaged on request once
      seedLabel(db, f.id);
    }
    expect(select({ force: true }).ids).toEqual([p2.id]);
    expect(select({ sample: 5, force: true }).ids).toEqual([p2.id]);
    // An explicit request still reaches it.
    expect(select({ findingIds: [p3.id], force: true }).ids).toEqual([p3.id]);
    expect(select({ findingIds: [p3.id] }).ids).toEqual([]);
  });

  it('only considers open findings; open-ended runs skip disabled projects, explicit requests do not', () => {
    const open = seedFinding(db, { scanId });
    seedFinding(db, { scanId, status: 'fixed' });
    const other = seedProject(db, { id: 'other' });
    const otherFinding = seedFinding(db, { scanId: other.scanId, projectId: 'other' });
    const off = seedProject(db, { id: 'off', enabled: false });
    const offFinding = seedFinding(db, { scanId: off.scanId, projectId: 'off' });
    expect(select().ids).toEqual([open.id, otherFinding.id]);
    expect(select({ projectId: 'other' }).ids).toEqual([otherFinding.id]);
    expect(select({ findingIds: [] })).toMatchObject({ ids: [], excluded: [] });
    // Naming the project or the finding triages a disabled project anyway (as scan --project does).
    expect(select({ projectId: 'off' }).ids).toEqual([offFinding.id]);
    expect(select({ findingIds: [offFinding.id] })).toMatchObject({ ids: [offFinding.id], excluded: [] });
  });

  it('reports every explicitly requested finding it filters out, with the reason', () => {
    const ok = seedFinding(db, { scanId });
    seedRun(db, ok.id, config.name, findingInputHash(db, ok, config), 'ok');
    const capped = seedFinding(db, { scanId });
    const cappedHash = findingInputHash(db, capped, config);
    addRun(capped.id, cappedHash, 'invalid');
    addRun(capped.id, cappedHash, 'timeout');
    const fixed = seedFinding(db, { scanId, status: 'fixed' });
    const mal = seedFinding(db, { scanId, malicious: true, osvId: 'MAL-2026-9' });
    const other = seedProject(db, { id: 'other' });
    const elsewhere = seedFinding(db, { scanId: other.scanId, projectId: 'other' });
    const pending = seedFinding(db, { scanId, priority: 'P3' });

    const r = select({ findingIds: [999, ok.id, capped.id, fixed.id, mal.id, elsewhere.id, pending.id], projectId: 'demo' });

    expect(r.ids).toEqual([pending.id]);
    expect(r.excluded.map((e) => e.findingId)).toEqual([999, ok.id, capped.id, fixed.id, mal.id, elsewhere.id]);
    const reasons = Object.fromEntries(r.excluded.map((e) => [e.findingId, e.reason]));
    expect(reasons[999]).toBe('no such finding');
    expect(reasons[ok.id]).toMatch(/already has an ok run under cfg .*force re-runs it/);
    expect(reasons[capped.id]).toMatch(/^2 runs under cfg already failed .*retries stop at 2; force re-runs it/);
    expect(reasons[fixed.id]).toBe('the finding is fixed, not open');
    expect(reasons[mal.id]).toMatch(/malicious/);
    expect(reasons[elsewhere.id]).toBe('it belongs to project "other", not "demo"');

    // With force the ok and capped findings are run; open-ended runs never report exclusions.
    const forced = select({ findingIds: [ok.id, capped.id], force: true });
    expect(forced).toMatchObject({ ids: [ok.id, capped.id], excluded: [] });
    expect(select().excluded).toEqual([]);
  });

  it('reports requested findings that are unlabeled or not drawn when sampling', () => {
    const labeled = Array.from({ length: 3 }, () => seedFinding(db, { scanId }));
    for (const f of labeled) seedLabel(db, f.id);
    const unlabeled = seedFinding(db, { scanId });
    const r = select({ findingIds: [...labeled.map((f) => f.id), unlabeled.id], sample: 2 });
    expect(r.ids).toHaveLength(2);
    expect(r.excluded).toHaveLength(2);
    expect(r.excluded.find((e) => e.findingId === unlabeled.id)?.reason).toMatch(/not labeled/);
    expect(r.excluded.find((e) => e.findingId !== unlabeled.id)?.reason).toBe('it was not drawn in the sample of 2');
  });

  it('re-triages ok findings only with force, or when the input hash changes', () => {
    const f = seedFinding(db, { scanId });
    seedRun(db, f.id, config.name, findingInputHash(db, f, config), 'ok');
    expect(select().ids).toEqual([]);
    expect(select({ force: true }).ids).toEqual([f.id]);
    expect(select({ force: true }).candidates[0]!.state.status).toBe('ok');

    setAdvisoryModified(db, f.osvId, '2026-11-01T00:00:00Z');
    const r = select();
    expect(r.ids).toEqual([f.id]);
    expect(r.candidates[0]!.state.status).toBe('pending');
  });

  it(`retries failed findings until ${MAX_ATTEMPTS_PER_HASH} counted runs exist for the current hash`, () => {
    const f = seedFinding(db, { scanId });
    const hash = findingInputHash(db, f, config);
    addRun(f.id, hash, 'failed', { raw: cliResult('error_max_turns', ''), error: 'claude error_max_turns (exit 1)' });
    expect(select().ids).toEqual([f.id]);
    seedRun(db, f.id, config.name, hash, 'cancelled'); // cancelled runs don't count
    expect(select().ids).toEqual([f.id]);
    seedRun(db, f.id, config.name, hash, 'invalid');
    expect(select().ids).toEqual([]);
    expect(select({ force: true }).ids).toEqual([f.id]);
    // runs under another config or hash don't count
    seedRun(db, f.id, 'other-config', hash, 'failed');
    expect(selectTriageCandidates(db, { ...config, name: 'other-config' }, { minPriority: 'P2', limit: 5 }).candidates).toHaveLength(1);
  });

  it('does not let infrastructure failures (outage, usage limit, setup) use up the retries', () => {
    const f = seedFinding(db, { scanId, priority: 'P0' });
    const hash = findingInputHash(db, f, config);
    addRun(f.id, hash, 'failed', { attempts: 0, error: 'setup failed: git exited 128' });
    addRun(f.id, hash, 'failed', { attempts: 1, error: 'could not start claude: spawn claude ENOENT' });
    addRun(f.id, hash, 'failed', { attempts: 2, error: 'claude exited 1: fetch failed' });
    addRun(f.id, hash, 'failed', {
      attempts: 2,
      raw: cliResult('success', 'API Error: 529 overloaded'),
      error: 'claude success: API Error: 529 overloaded',
    });
    addRun(f.id, hash, 'failed', {
      attempts: 1,
      raw: cliResult('success', 'Claude AI usage limit reached|1762790400'),
      error: 'claude success (exit 1): Claude AI usage limit reached|1762790400',
    });
    addRun(f.id, hash, 'failed', {
      attempts: 1,
      raw: cliResult('success', 'Invalid API key · Please run /login'),
      error: 'claude success: Invalid API key · Please run /login',
    });
    expect(select().ids).toEqual([f.id]);
    // One failure that does say something about the finding, and one invalid output: capped.
    addRun(f.id, hash, 'failed', {
      attempts: 1,
      raw: cliResult('error_max_budget_usd', ''),
      error: 'claude error_max_budget_usd (exit 1)',
    });
    expect(select().ids).toEqual([f.id]);
    addRun(f.id, hash, 'invalid', { error: 'invalid structured output: verdict: Invalid option' });
    expect(select().ids).toEqual([]);
  });

  it('samples labeled findings deterministically, with or without force', () => {
    const labeled = Array.from({ length: 6 }, () => seedFinding(db, { scanId }));
    seedFinding(db, { scanId }); // unlabeled
    for (const f of labeled) seedLabel(db, f.id);
    seedRun(db, labeled[0]!.id, config.name, findingInputHash(db, labeled[0]!, config), 'ok');

    const forced = select({ sample: 3, force: true });
    expect(forced.ids).toHaveLength(3);
    expect(forced.ids.every((id) => labeled.some((f) => f.id === id))).toBe(true);
    expect(select({ sample: 3, force: true }).ids).toEqual(forced.ids);

    // Without force the same sample is drawn, minus the finding that already has an ok run.
    const plain = select({ sample: 3 });
    expect(plain.ids).toEqual(forced.ids.filter((id) => id !== labeled[0]!.id));

    expect(select({ sample: 50, force: true }).ids).toHaveLength(6);
  });
});

describe('countsTowardRetryCap', () => {
  const run = (status: TriageRunStatus, attempts: number, raw: Record<string, unknown> | null, error: string | null = null) => ({
    status,
    attempts,
    raw,
    error,
  });

  it('counts invalid output and timeouts', () => {
    expect(countsTowardRetryCap(run('invalid', 2, { type: 'result' }))).toBe(true);
    expect(countsTowardRetryCap(run('timeout', 1, null, 'timed out after 600000 ms'))).toBe(true);
  });

  it('never counts ok or cancelled runs', () => {
    expect(countsTowardRetryCap(run('ok', 1, { type: 'result' }))).toBe(false);
    expect(countsTowardRetryCap(run('cancelled', 1, null, 'cancelled'))).toBe(false);
  });

  it('does not count failures where claude never ran or produced no JSON result', () => {
    expect(countsTowardRetryCap(run('failed', 0, null, 'setup failed: no snapshot'))).toBe(false);
    expect(countsTowardRetryCap(run('failed', 1, null, 'could not start claude: spawn claude ENOENT'))).toBe(false);
    expect(countsTowardRetryCap(run('failed', 2, null, 'claude stdout is not a JSON object: hello'))).toBe(false);
    expect(countsTowardRetryCap(run('failed', 2, null, 'claude exited 2: something broke'))).toBe(false);
  });

  it.each([
    'API Error: 500 {"type":"error","error":{"type":"api_error","message":"Internal server error"}}',
    'API Error: Request timed out.',
    'Claude AI usage limit reached|1762790400',
    '5-hour limit reached ∙ resets 3pm',
    'Invalid API key · Please run /login',
    'OAuth token has expired. Please obtain a new token or refresh your existing token.',
    'Credit balance is too low',
    'API Error: Connection error.',
    'Rate limited: 429',
  ])('does not count an is_error result about availability: %s', (result) => {
    expect(countsTowardRetryCap(run('failed', 1, cliResult('success', result), `claude success: ${result}`))).toBe(false);
  });

  it('does not count a run whose last attempt printed no result, even when an earlier attempt did', () => {
    // Attempt 1 returned invalid output (raw kept), attempt 2 crashed mid-outage: the stored error is attempt 2's.
    const earlier = { type: 'result', subtype: 'success', is_error: false, result: '{"verdict":"maybe"}' };
    expect(countsTowardRetryCap(run('failed', 2, earlier, 'claude exited 1: something went wrong'))).toBe(false);
    expect(countsTowardRetryCap(run('failed', 2, earlier, 'claude stdout is not a JSON object: Update available'))).toBe(false);
  });

  it("reads only the CLI's own message, never the model's answer, for availability words", () => {
    // Exit 1 although the result is not is_error: the result is the model's text, which may talk about networks.
    const answer = { type: 'result', subtype: 'success', is_error: false, result: 'Not reachable: no network timeout path is used' };
    expect(countsTowardRetryCap(run('failed', 1, answer, `claude success (exit 1): ${answer.result}`))).toBe(true);
    // No result text: the stderr line in the error is the CLI's message.
    const bare = { type: 'result', subtype: 'error_during_execution', is_error: true };
    expect(countsTowardRetryCap(run('failed', 1, bare, 'claude error_during_execution (exit 1): API Error: 529 overloaded'))).toBe(false);
    expect(countsTowardRetryCap(run('failed', 1, bare, 'claude error_during_execution (exit 1): Tool Read crashed'))).toBe(true);
  });

  it('counts a CLI failure about the run itself', () => {
    expect(countsTowardRetryCap(run('failed', 1, cliResult('error_max_budget_usd', ''), 'claude error_max_budget_usd (exit 1)'))).toBe(
      true,
    );
    // Own limits count even when the message reads like a limit.
    expect(countsTowardRetryCap(run('failed', 1, cliResult('error_max_turns', 'turn limit reached'), 'claude error_max_turns'))).toBe(true);
    expect(
      countsTowardRetryCap(
        run('failed', 2, cliResult('error_during_execution', 'Tool Read crashed'), 'claude error_during_execution: Tool Read crashed'),
      ),
    ).toBe(true);
  });
});
