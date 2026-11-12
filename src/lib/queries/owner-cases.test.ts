import { and, eq } from 'drizzle-orm';
import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../db/client';
import { findings, labels, ownerCases, projects } from '../db/schema';
import type { OwnerBrief, ProjectProfile } from '../types';
import {
  answerOwnerCase,
  BRIEF_SOFT_LIMITS,
  briefLengthWarnings,
  countOpenOwnerCases,
  getDecideView,
  getOwnerCase,
  importOwnerCases,
  listOwnerCases,
  mergeDecideNote,
  nextOpenCaseId,
  parseAnswerInput,
  validateCaseImport,
  withdrawOwnerCases,
} from './owner-cases';

const profile = { id: 'held-api', name: 'Held API' } as unknown as ProjectProfile;

const brief: OwnerBrief = {
  title: 'Image optimizer: server crash (not reachable today)',
  whatItIs: 'A bug in the image resizer.',
  attackerCouldDo: 'Crash the server for everyone.',
  whatItTakes: 'The image endpoint must be public.',
  yourApp: 'The endpoint is turned off.',
  exploitableToday: 'no',
  fix: 'Minor version bump.',
  similarTo: null,
};

let db: Db;

function seed() {
  db = openDb(':memory:');
  db.insert(projects).values({ id: 'held-api', name: 'Held API', repoPath: '/x', ref: 'origin/main', profile, profileHash: 'h' }).run();
  for (const id of [1, 2, 3]) {
    db.insert(findings)
      .values({
        id,
        projectId: 'held-api',
        lockfile: 'package-lock.json',
        ecosystem: 'npm',
        packageName: `pkg-${id}`,
        osvId: `GHSA-${id}`,
        origin: 'baseline',
        firstSeenScanId: 1,
        lastSeenScanId: 1,
        currentAction: 'log',
      })
      .run();
  }
}

function addCase(findingId: number, extra: Partial<typeof ownerCases.$inferInsert> = {}): number {
  return db
    .insert(ownerCases)
    .values({ findingId, brief: { ...brief, title: `Case for ${findingId}` }, reason: 'why', ...extra })
    .returning({ id: ownerCases.id })
    .get().id;
}

function label(findingId: number, labeler = 'me') {
  return db
    .select()
    .from(labels)
    .where(and(eq(labels.findingId, findingId), eq(labels.labeler, labeler)))
    .get();
}

beforeEach(seed);

describe('reads', () => {
  it('joins the project and finding, and falls back to the finding current action', () => {
    const id = addCase(1, { agentAction: 'digest' });
    const v = getOwnerCase(db, id)!;
    expect(v).toMatchObject({
      title: 'Case for 1',
      projectName: 'Held API',
      packageName: 'pkg-1',
      systemAction: 'log',
      agentAction: 'digest',
      status: 'open',
    });
    expect(v.brief?.exploitableToday).toBe('no');
    addCase(2, { systemAction: 'ping' });
    expect(listOwnerCases(db)[1]!.systemAction).toBe('ping');
  });

  it('keeps a case with an unreadable brief visible with a fallback title', () => {
    const id = addCase(1, { brief: { title: 'x' } as unknown as OwnerBrief });
    const v = getOwnerCase(db, id)!;
    expect(v.brief).toBeNull();
    expect(v.title).toBe('pkg-1 (GHSA-1)');
  });

  it('builds the decide view: open first in asking order, answered newest first, withdrawn hidden', () => {
    const a = addCase(1);
    const b = addCase(2, { status: 'answered', answer: 'ping', answeredAt: '2026-11-10T10:00:00.000Z' });
    const c = addCase(3, { status: 'answered', answer: 'log', answeredAt: '2026-11-11T10:00:00.000Z' });
    const w = addCase(1, { status: 'withdrawn' });
    const d = addCase(2);

    const v = getDecideView(db, null);
    expect(v.open.map((x) => x.id)).toEqual([a, d]);
    expect(v.answered.map((x) => x.id)).toEqual([c, b]);
    expect(v).toMatchObject({ total: 4, decided: 2, nextId: d, requestedMissing: false });
    expect(v.current?.id).toBe(a);

    // An answered case can be requested (its reveal); Next goes to the next open case after it.
    const r = getDecideView(db, b);
    expect(r.current?.id).toBe(b);
    expect(r.nextId).toBe(d);

    const missing = getDecideView(db, w);
    expect(missing.requestedMissing).toBe(true);
    expect(missing.current?.id).toBe(a);
    expect(countOpenOwnerCases(db)).toBe(2);
  });

  it('is empty without cases', () => {
    expect(getDecideView(db, null)).toMatchObject({ total: 0, decided: 0, current: null, nextId: null });
    expect(countOpenOwnerCases(db)).toBe(0);
  });

  it('picks the next open case, wrapping and never the same one', () => {
    const open = [{ id: 2 }, { id: 5 }, { id: 9 }];
    expect(nextOpenCaseId(open, 2)).toBe(5);
    expect(nextOpenCaseId(open, 9)).toBe(2);
    expect(nextOpenCaseId(open, 6)).toBe(9);
    expect(nextOpenCaseId([{ id: 4 }], 4)).toBeNull();
    expect(nextOpenCaseId([], 1)).toBeNull();
  });
});

describe('answering', () => {
  it('validates the form', () => {
    expect(parseAnswerInput({ caseId: '3', answer: 'digest', note: '  fine \n by me ' })).toEqual({
      ok: true,
      value: { caseId: 3, answer: 'digest', note: 'fine by me' },
    });
    expect(parseAnswerInput({ caseId: '3', answer: 'digest', note: '   ' })).toMatchObject({ ok: true, value: { note: null } });
    expect(parseAnswerInput({ caseId: '3', answer: 'loud' })).toEqual({ ok: false, error: 'Choose Ping, Digest or Log.' });
    expect(parseAnswerInput({ answer: 'ping' })).toEqual({ ok: false, error: 'This case could not be found. Reload the page.' });
    expect(parseAnswerInput({ caseId: '3', answer: 'ping', note: 'x'.repeat(501) })).toMatchObject({ ok: false });
    const fd = new FormData();
    fd.set('caseId', '7');
    fd.set('answer', 'log');
    expect(parseAnswerInput(fd)).toEqual({ ok: true, value: { caseId: 7, answer: 'log', note: null } });
  });

  it('merges label notes', () => {
    expect(mergeDecideNote(null, null)).toBe('[decide]');
    expect(mergeDecideNote(null, 'too noisy')).toBe('[decide] too noisy');
    expect(mergeDecideNote('from review', 'ok')).toBe('[decide] ok\nfrom review');
    expect(mergeDecideNote('[decide] old\nfrom review', 'new')).toBe('[decide] new\nfrom review');
    expect(mergeDecideNote('[decide] old', null)).toBe('[decide]');
  });

  it('answers a case and upserts the label, keeping "actually affected"; changing updates both', () => {
    const id = addCase(1);
    db.insert(labels).values({ findingId: 1, labeler: 'me', expectedAction: 'log', affectedTruth: 'no', note: 'review note' }).run();

    const row = answerOwnerCase(db, { caseId: id, answer: 'digest', note: 'monday is fine' }, 'me', new Date('2026-11-11T09:00:00Z'));
    expect(row).toMatchObject({
      status: 'answered',
      answer: 'digest',
      answeredBy: 'me',
      answeredAt: '2026-11-11T09:00:00.000Z',
      note: 'monday is fine',
    });
    expect(label(1)).toMatchObject({ expectedAction: 'digest', affectedTruth: 'no', note: '[decide] monday is fine\nreview note' });

    answerOwnerCase(db, { caseId: id, answer: 'ping', note: null }, 'me');
    expect(getOwnerCase(db, id)).toMatchObject({ answer: 'ping', note: null });
    expect(label(1)).toMatchObject({ expectedAction: 'ping', affectedTruth: 'no', note: '[decide]\nreview note' });
    expect(db.select().from(labels).all()).toHaveLength(1);
  });

  it('writes the label under the current labeler', () => {
    const id = addCase(2);
    answerOwnerCase(db, { caseId: id, answer: 'log', note: null }, 'ana');
    expect(label(2, 'ana')).toMatchObject({ expectedAction: 'log', affectedTruth: null, note: '[decide]' });
    expect(label(2, 'me')).toBeUndefined();
    expect(getOwnerCase(db, id)?.answeredBy).toBe('ana');
  });

  it('refuses withdrawn or unknown cases and leaves no label behind', () => {
    const w = addCase(1, { status: 'withdrawn' });
    expect(() => answerOwnerCase(db, { caseId: w, answer: 'ping', note: null }, 'me')).toThrow(/withdrawn/);
    expect(() => answerOwnerCase(db, { caseId: 999, answer: 'ping', note: null }, 'me')).toThrow(/could not be found/);
    const orphan = addCase(42);
    expect(() => answerOwnerCase(db, { caseId: orphan, answer: 'ping', note: null }, 'me')).toThrow(/finding 42 not found/);
    expect(getOwnerCase(db, orphan)?.status).toBe('open');
    expect(db.select().from(labels).all()).toHaveLength(0);
  });
});

describe('import and withdraw', () => {
  const item = (findingId: number, extra: Record<string, unknown> = {}) => ({ findingId, brief, reason: 'Borderline', ...extra });

  it('validates every item and reports all problems', () => {
    expect(validateCaseImport({})).toEqual({ ok: false, errors: ['expected a JSON array of cases'] });
    const res = validateCaseImport([
      item(1, { systemAction: 'digest', agentAction: null }),
      item(2, { brief: { ...brief, fix: '  ' } }),
      item(1),
      { findingId: 3, brief: { ...brief, exploitableToday: 'maybe' }, reason: '' },
    ]);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errors).toEqual([
      'item 2 (finding 2): brief.fix is empty',
      'item 3 (finding 1): finding 1 is also in item 1',
      expect.stringMatching(/^item 4 \(finding 3\): brief\.exploitableToday: /),
      'item 4 (finding 3): reason: reason is empty',
    ]);
  });

  it('normalises optional fields', () => {
    const res = validateCaseImport([item(1, { batch: ' b1 ', brief: { ...brief, similarTo: ' ' } })]);
    expect(res).toEqual({
      ok: true,
      items: [
        { findingId: 1, brief: { ...brief, similarTo: null }, reason: 'Borderline', systemAction: null, agentAction: null, batch: 'b1' },
      ],
    });
  });

  it('warns about briefs too long to read in under a minute', () => {
    expect(briefLengthWarnings(brief)).toEqual([]);
    const long = 'word '.repeat(80).trim(); // 399 characters
    expect(briefLengthWarnings({ ...brief, yourApp: long })).toEqual([
      `brief.yourApp is 399 characters; aim for ${BRIEF_SOFT_LIMITS.section} or fewer`,
    ]);
    const sections = 'x'.repeat(300);
    const all = briefLengthWarnings({
      ...brief,
      title: 't'.repeat(120),
      whatItIs: sections,
      attackerCouldDo: sections,
      whatItTakes: sections,
      yourApp: sections,
      fix: sections,
    });
    expect(all).toEqual([
      `title is 120 characters; aim for ${BRIEF_SOFT_LIMITS.title} or fewer`,
      expect.stringMatching(/^the brief is 1620 characters in all; aim for 1300 or fewer/),
    ]);
  });

  it('imports, skips findings with an open case, and replaces them on request', () => {
    const parsed = validateCaseImport([item(1, { systemAction: 'digest' }), item(2)]);
    if (!parsed.ok) throw new Error(parsed.errors.join('\n'));
    const first = importOwnerCases(db, parsed.items, { batch: 'round-1' });
    expect(first.created).toHaveLength(2);
    expect(listOwnerCases(db).map((c) => [c.findingId, c.batch, c.systemAction])).toEqual([
      [1, 'round-1', 'digest'],
      [2, 'round-1', 'log'],
    ]);

    const again = importOwnerCases(db, parsed.items);
    expect(again.created).toHaveLength(0);
    expect(again.skipped.map((s) => s.findingId)).toEqual([1, 2]);

    const old = first.created[0]!.caseId;
    const replaced = importOwnerCases(db, [parsed.items[0]!], { replace: true });
    expect(replaced.replaced).toEqual([{ oldCaseId: old, caseId: replaced.created[0]!.caseId, findingId: 1 }]);
    expect(getOwnerCase(db, old)?.status).toBe('withdrawn');
    expect(countOpenOwnerCases(db)).toBe(2);
  });

  it('does not skip a finding whose earlier case was answered', () => {
    addCase(1, { status: 'answered', answer: 'log' });
    const parsed = validateCaseImport([item(1)]);
    if (!parsed.ok) throw new Error('invalid');
    expect(importOwnerCases(db, parsed.items).created).toHaveLength(1);
  });

  it('imports nothing when a finding is unknown', () => {
    const parsed = validateCaseImport([item(1), item(77)]);
    if (!parsed.ok) throw new Error('invalid');
    expect(() => importOwnerCases(db, parsed.items)).toThrow('unknown finding: 77; nothing imported');
    expect(listOwnerCases(db)).toHaveLength(0);
  });

  it('withdraws open cases by id or batch, keeping answered ones', () => {
    const a = addCase(1, { batch: 'b' });
    const b = addCase(2, { batch: 'b', status: 'answered', answer: 'ping' });
    const c = addCase(3, { batch: 'other' });
    expect(withdrawOwnerCases(db, { batch: 'b' })).toEqual({ withdrawn: [a], skipped: [{ id: b, status: 'answered' }] });
    expect(withdrawOwnerCases(db, { id: c })).toEqual({ withdrawn: [c], skipped: [] });
    expect(withdrawOwnerCases(db, { id: c })).toEqual({ withdrawn: [], skipped: [{ id: c, status: 'withdrawn' }] });
    expect(() => withdrawOwnerCases(db, { id: 999 })).toThrow('case 999 not found');
    expect(withdrawOwnerCases(db, { batch: 'none' })).toEqual({ withdrawn: [], skipped: [] });
  });
});
