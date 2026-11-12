import { beforeEach, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../lib/db/client';
import { findings, ownerCases, projects } from '../lib/db/schema';
import { getOwnerCase } from '../lib/queries/owner-cases';
import type { OwnerBrief, ProjectProfile } from '../lib/types';
import { formatCaseList, parseCasesArgs, runCasesCommand, type CasesIo } from './cases';

const brief: OwnerBrief = {
  title: 'Login library: account takeover (not reachable today)',
  whatItIs: 'A flaw in token checks.',
  attackerCouldDo: 'Log in as another user.',
  whatItTakes: 'A forged token and the legacy login route.',
  yourApp: 'The legacy route is not deployed.',
  exploitableToday: 'no',
  fix: 'Patch bump.',
  similarTo: null,
};

describe('parseCasesArgs', () => {
  it('parses the commands', () => {
    expect(parseCasesArgs([])).toEqual({ ok: true, command: { cmd: 'help' } });
    expect(parseCasesArgs(['import', 'cases.json'])).toEqual({
      ok: true,
      command: { cmd: 'import', file: 'cases.json', replace: false, batch: null },
    });
    expect(parseCasesArgs(['import', '--replace', 'c.json', '--batch', 'round-2'])).toEqual({
      ok: true,
      command: { cmd: 'import', file: 'c.json', replace: true, batch: 'round-2' },
    });
    expect(parseCasesArgs(['list'])).toEqual({ ok: true, command: { cmd: 'list', all: false } });
    expect(parseCasesArgs(['list', '--all'])).toEqual({ ok: true, command: { cmd: 'list', all: true } });
    expect(parseCasesArgs(['withdraw', '4'])).toEqual({ ok: true, command: { cmd: 'withdraw', target: { id: 4 } } });
    expect(parseCasesArgs(['withdraw', '--batch', 'round-1'])).toEqual({
      ok: true,
      command: { cmd: 'withdraw', target: { batch: 'round-1' } },
    });
  });

  it('rejects bad input with a readable error', () => {
    const err = (argv: string[]) => {
      const r = parseCasesArgs(argv);
      return r.ok ? null : r.error;
    };
    expect(err(['nuke'])).toBe('unknown command "nuke"');
    expect(err(['import'])).toBe('import takes exactly one file');
    expect(err(['import', 'a.json', 'b.json'])).toBe('import takes exactly one file');
    expect(err(['import', 'a.json', '--batch'])).toBe('--batch needs a value');
    expect(err(['import', 'a.json', '--all'])).toBe('unknown option --all for import');
    expect(err(['list', 'x'])).toBe('list takes no arguments');
    expect(err(['withdraw'])).toBe('withdraw needs one case id or --batch <name>');
    expect(err(['withdraw', 'abc'])).toBe('withdraw needs one case id or --batch <name>');
    expect(err(['withdraw', '3', '--batch', 'b'])).toBe('withdraw takes a case id or --batch, not both');
    expect(err(['withdraw', '--replace'])).toBe('unknown option --replace for withdraw');
  });
});

describe('runCasesCommand', () => {
  let db: Db;
  let out: string[];
  let errs: string[];
  let files: Record<string, string>;
  const io: CasesIo = {
    log: (l) => void out.push(l),
    error: (l) => void errs.push(l),
    readFile: (f) => {
      if (!(f in files)) throw new Error('ENOENT: no such file');
      return files[f]!;
    },
  };

  beforeEach(() => {
    db = openDb(':memory:');
    out = [];
    errs = [];
    files = {};
    const profile = { id: 'held-ios', name: 'Held iOS' } as unknown as ProjectProfile;
    db.insert(projects).values({ id: 'held-ios', name: 'Held iOS', repoPath: '/x', ref: 'origin/main', profile, profileHash: 'h' }).run();
    for (const id of [1, 2]) {
      db.insert(findings)
        .values({
          id,
          projectId: 'held-ios',
          lockfile: 'Package.resolved',
          ecosystem: 'SwiftURL',
          packageName: `p${id}`,
          osvId: `GHSA-${id}`,
          origin: 'baseline',
          firstSeenScanId: 1,
          lastSeenScanId: 1,
        })
        .run();
    }
  });

  it('imports a valid file, skips repeats, and replaces on request', () => {
    files['c.json'] = JSON.stringify([
      { findingId: 1, brief, reason: 'Close call between digest and log', systemAction: 'log', agentAction: 'digest' },
      { findingId: 2, brief, reason: 'Agents split', batch: 'own' },
    ]);
    expect(runCasesCommand(db, { cmd: 'import', file: 'c.json', replace: false, batch: 'round-1' }, io)).toBe(0);
    expect(out).toEqual(['created 2 cases', '  #1 finding 1', '  #2 finding 2']);
    expect(getOwnerCase(db, 1)?.batch).toBe('round-1');
    expect(getOwnerCase(db, 2)?.batch).toBe('own');

    out = [];
    expect(runCasesCommand(db, { cmd: 'import', file: 'c.json', replace: false, batch: null }, io)).toBe(0);
    expect(out).toEqual([
      'created 0 cases',
      'skipped 2 findings that already have an open case (use --replace to ask again):',
      '  finding 1: open case #1',
      '  finding 2: open case #2',
    ]);

    out = [];
    expect(runCasesCommand(db, { cmd: 'import', file: 'c.json', replace: true, batch: null }, io)).toBe(0);
    expect(out).toEqual(['created 2 cases', '  #3 finding 1 (replaces #1)', '  #4 finding 2 (replaces #2)']);
    expect(getOwnerCase(db, 1)?.status).toBe('withdrawn');
  });

  it('reports invalid files and unknown findings without importing anything', () => {
    files['bad.json'] = JSON.stringify([{ findingId: 1, brief: { ...brief, whatItIs: '' }, reason: 'x' }]);
    expect(runCasesCommand(db, { cmd: 'import', file: 'bad.json', replace: false, batch: null }, io)).toBe(1);
    expect(errs).toEqual(['bad.json is invalid; nothing imported:', '  item 1 (finding 1): brief.whatItIs is empty']);

    errs = [];
    files['broken.json'] = '[{';
    expect(runCasesCommand(db, { cmd: 'import', file: 'broken.json', replace: false, batch: null }, io)).toBe(1);
    expect(errs[0]).toMatch(/^cannot read broken\.json: /);

    errs = [];
    expect(runCasesCommand(db, { cmd: 'import', file: 'missing.json', replace: false, batch: null }, io)).toBe(1);
    expect(errs[0]).toBe('cannot read missing.json: ENOENT: no such file');

    errs = [];
    files['unknown.json'] = JSON.stringify([{ findingId: 9, brief, reason: 'x' }]);
    expect(runCasesCommand(db, { cmd: 'import', file: 'unknown.json', replace: false, batch: null }, io)).toBe(1);
    expect(errs).toEqual(['unknown finding: 9; nothing imported']);
    expect(db.select().from(ownerCases).all()).toHaveLength(0);
  });

  it('imports a long brief but warns which parts to tighten', () => {
    files['long.json'] = JSON.stringify([{ findingId: 1, brief: { ...brief, yourApp: 'y'.repeat(400) }, reason: 'r' }]);
    expect(runCasesCommand(db, { cmd: 'import', file: 'long.json', replace: false, batch: null }, io)).toBe(0);
    expect(errs).toEqual(['warning: item 1 (finding 1): brief.yourApp is 400 characters; aim for 350 or fewer']);
    expect(out[0]).toBe('created 1 case');
  });

  it('lists open and answered cases with answers', () => {
    db.insert(ownerCases)
      .values([
        { findingId: 1, brief, reason: 'r', systemAction: 'log', agentAction: 'digest' },
        {
          findingId: 2,
          brief,
          reason: 'r',
          status: 'answered',
          answer: 'ping',
          answeredBy: 'me',
          answeredAt: '2026-11-11T08:00:00.000Z',
          note: 'scary',
        },
        { findingId: 2, brief, reason: 'r', status: 'withdrawn' },
      ])
      .run();
    expect(runCasesCommand(db, { cmd: 'list', all: false }, io)).toBe(0);
    const text = out.join('\n');
    expect(text).toContain('Open (1)\n  #1  Login library');
    expect(text).toContain('held-ios · finding 1 · system log, agents digest');
    expect(text).toMatch(/Answered \(1\)\n {2}#2 {2}Login library.*\n.*\n {6}answer: ping \(me, 2026-11-11 \d\d:\d\d/);
    expect(text).toContain('note: scary');
    expect(text).not.toContain('Withdrawn');
    expect(formatCaseList([], true)).toEqual(['Open (0)', 'Answered (0)', 'Withdrawn (0)']);
  });

  it('withdraws by id or batch', () => {
    db.insert(ownerCases)
      .values([
        { findingId: 1, brief, reason: 'r', batch: 'b' },
        { findingId: 2, brief, reason: 'r', batch: 'b', status: 'answered', answer: 'log' },
      ])
      .run();
    expect(runCasesCommand(db, { cmd: 'withdraw', target: { batch: 'b' } }, io)).toBe(0);
    expect(out).toEqual(['withdrew #1', '  #2 left as is (answered)']);

    out = [];
    expect(runCasesCommand(db, { cmd: 'withdraw', target: { id: 2 } }, io)).toBe(1);
    expect(out).toEqual(['nothing withdrawn', '  #2 left as is (answered)']);
    expect(runCasesCommand(db, { cmd: 'withdraw', target: { id: 99 } }, io)).toBe(1);
    expect(errs).toEqual(['case 99 not found']);
  });
});
