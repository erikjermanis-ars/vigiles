import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseOsvOutput } from '../lib/osv/output';
import type { OsvScanRun, RunOsvScannerOptions } from '../lib/osv/scanner';
import { EPSS_API_URL } from '../lib/signals/epss';
import { KEV_FEED_URL } from '../lib/signals/kev-feed';
import { epssApiStub, jsonResponse, kevFeed, stubFetch } from '../lib/signals/test-support';
import type { ClaudeTriageRequest, ClaudeTriageResult } from '../lib/triage/claude';
import { EXIT, main, type CliDeps } from './cli';
import { createTestRepo, tempDir, type TestRepo } from './git-test-support';
import { makeOutput } from './report-fixtures';

const ROOT = process.cwd();
const fixture = (f: string) => readFileSync(path.join(ROOT, 'test/fixtures/scan', f), 'utf8');
const OSV_FIXTURE = parseOsvOutput(JSON.parse(fixture('osv-output.json')));
const OSV_BASE = 'https://osv.test';
const ZIP = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(32, 7)]);

const PROFILE_YAML = `
id: demo-app
name: Demo App
ref: origin/main
exclude: []
criticality: high
exposure: internet-facing
data_classes: [pii]
runtime: { language: typescript }
deployments: [{ env: production, hosting: Linux container }]
mitigations: none known
notes: fixture
`;

const epssStub = epssApiStub({ 'CVE-2026-1000': 0.62, 'CVE-2026-2000': 0.02 });
const fetchFn = stubFetch((url, init) => {
  if (url.startsWith(OSV_BASE)) {
    return new Response(new Uint8Array(ZIP), { status: 200, headers: { 'last-modified': 'Tue, 10 Nov 2026 08:00:00 GMT', etag: '"z"' } });
  }
  if (url === KEV_FEED_URL) return jsonResponse(kevFeed([{ cveID: 'CVE-2026-1000', dateAdded: '2026-10-02' }]));
  if (url.startsWith(EPSS_API_URL)) return epssStub(url, init);
  throw new Error(`unexpected request ${url}`);
});

async function fakeOsvScanner(opts: RunOsvScannerOptions): Promise<OsvScanRun> {
  const results = opts.lockfiles.flatMap((abs) => {
    const hit = OSV_FIXTURE.find((r) => abs.endsWith(r.path.replace(/^\/snapshot/, '')));
    return hit ? [{ ...hit, path: abs }] : [];
  });
  return { results, durationMs: 1, exitCode: 1, warnings: '', unsupported: [] };
}

function claudeResult(o: Partial<ClaudeTriageResult>): ClaudeTriageResult {
  return {
    status: 'ok',
    output: makeOutput({ suggested_action: 'digest', verdict: 'affected', suggested_action_reason: 'Reachable from the API. Upgrade.' }),
    raw: null,
    modelResolved: 'claude-opus-5-5',
    costUsd: 0.1,
    inputTokens: null,
    outputTokens: null,
    cacheReadTokens: null,
    numTurns: 3,
    durationMs: 1000,
    attempts: 1,
    error: null,
    retriedErrors: [],
    permissionDenials: 0,
    ...o,
  };
}

let base: string;
let bin: string;
let cache: string;
let env: NodeJS.ProcessEnv;
const claudeCalls: ClaudeTriageRequest[] = [];

function script(name: string, body: string): string {
  const file = path.join(bin, name);
  writeFileSync(file, `#!/bin/sh\n${body}\n`);
  chmodSync(file, 0o755);
  return file;
}

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

async function run(argv: string[], deps: Partial<CliDeps> = {}): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, {
    cwd: ROOT,
    env,
    assetRoot: ROOT,
    stdout: (l) => out.push(l),
    stderr: (l) => err.push(l),
    scan: { fetchFn, runOsvScanner: fakeOsvScanner, osvBaseUrl: OSV_BASE, clock: () => new Date('2026-11-12T10:00:00Z') },
    runClaude: async (req) => {
      claudeCalls.push(req);
      return claudeResult({});
    },
    signal: new AbortController().signal,
    now: () => new Date('2026-11-12T10:05:00Z'),
    ...deps,
  });
  return { code, stdout: out.join('\n'), stderr: err.join('\n') };
}

function demoRepo(prefix: string, profile: string | null = PROFILE_YAML): TestRepo {
  const repo = createTestRepo(prefix);
  repo.write('package.json', JSON.stringify({ name: 'fixture-app', dependencies: { 'web-framework': '^2.0.0' } }));
  repo.write('package-lock.json', fixture('package-lock.json'));
  repo.write('src/server.ts', "import { serve } from 'web-framework/server';\nserve();\n");
  repo.write('tools/deno.json', '{}\n');
  if (profile !== null) repo.write('.vigiles/profile.yaml', profile);
  repo.commit('init');
  return repo;
}

beforeAll(() => {
  base = tempDir('vigiles-cli-');
  bin = path.join(base, 'bin');
  cache = path.join(base, 'cache');
  mkdirSync(bin);
  env = {
    ...process.env,
    VIGILES_CACHE_DIR: cache,
    VIGILES_GIT_BIN: 'git',
    VIGILES_OSV_SCANNER_BIN: script('osv-scanner', 'echo "osv-scanner version: 2.7.1"'),
    VIGILES_CLAUDE_BIN: script(
      'claude',
      'if [ "$1" = "--version" ]; then echo "2.1.318 (Claude Code)"; exit 0; fi\n' +
        'if [ "$1" = "auth" ]; then echo \'{"loggedIn": true, "authMethod": "claude.ai", "email": "someone@example.com"}\'; exit 0; fi\nexit 1',
    ),
  };
  delete env.VIGILES_ASSET_ROOT;
});
afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('arguments', () => {
  it('prints the version and the help', async () => {
    const version = await run(['--version']);
    expect(version.code).toBe(EXIT.ok);
    const manifest = JSON.parse(readFileSync(path.join(ROOT, 'plugin/.claude-plugin/plugin.json'), 'utf8')) as { version: string };
    expect(version.stdout).toBe(`vigiles ${manifest.version}`);

    const help = await run(['--help']);
    expect(help.code).toBe(EXIT.ok);
    for (const c of ['doctor', 'init', 'profile', 'scan', 'triage', 'report', 'audit']) expect(help.stdout).toContain(`  ${c} `);
    expect(help.stdout).toContain('Exit codes');

    expect((await run(['help', 'triage'])).stdout).toContain('Usage: vigiles triage [--limit <n>]');
    const scanHelp = await run(['scan', '--help']);
    expect(scanHelp.code).toBe(EXIT.ok);
    expect(scanHelp.stdout).toContain('--refresh-db');
  });

  it('exits 2 on usage errors, before doing any work', async () => {
    const cases: [string[], RegExp][] = [
      [[], /Usage: vigiles <command>/],
      [['bogus'], /unknown command bogus/],
      [['--bogus'], /unknown option --bogus/],
      [['scan', '--limit', '3'], /unknown option --limit for scan/],
      [['scan', '--ref'], /--ref needs a value/],
      [['scan', '--fetch=yes'], /--fetch takes no value/],
      [['report', 'extra'], /unexpected argument extra for report/],
      [['triage', '--limit', 'x'], /--limit must be a whole number/],
      [['triage', '--limit', '-1'], /--limit needs a value \(for a value starting with -, write --limit=<value>\)/],
      [['triage', '--limit', '--force'], /--limit needs a value/],
      [['triage', '--limit=-1'], /--limit must be a whole number of at least 0/],
      [['scan', '--ref', 'origin/--upload-pack=x'], /--ref "origin\/--upload-pack=x" is not a branch, tag, remote-tracking ref or commit/],
      [['triage', '--concurrency', '0'], /--concurrency must be a whole number from 1 to 10/],
      [['audit', '--concurrency', '11'], /--concurrency/],
      [['triage', '--only', ' , '], /--only needs at least one id/],
    ];
    for (const [argv, pattern] of cases) {
      const r = await run(argv, { cwd: base });
      expect(r.code, argv.join(' ')).toBe(EXIT.input);
      expect(r.stderr, argv.join(' ')).toMatch(pattern);
    }
  });

  it('exits 2 outside a git repository', async () => {
    const r = await run(['profile'], { cwd: base });
    expect(r.code).toBe(EXIT.input);
    expect(r.stderr).toMatch(/not inside a git repository/);
    expect((await run(['profile', '--repo', path.join(base, 'nope')])).stderr).toMatch(/does not exist/);
  });
});

describe('doctor', () => {
  let repo: TestRepo;
  beforeAll(() => {
    repo = demoRepo('vigiles-cli-doctor-', null);
  });
  afterAll(() => repo.cleanup());

  it('reports every check, and a missing profile without failing', async () => {
    const r = await run(['doctor'], { cwd: repo.root });
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toMatch(/^ok node: \d+/m);
    expect(r.stdout).toMatch(/^ok vigiles: .*triage v3-opus-high-code, prompt v3@[0-9a-f]+/m);
    expect(r.stdout).toMatch(/^ok git: \d+\.\d+/m);
    expect(r.stdout).toContain('ok osv-scanner: 2.7.1');
    expect(r.stdout).toContain('ok claude: 2.1.318');
    expect(r.stdout).toContain('ok claude login: logged in (claude.ai)');
    expect(r.stdout).not.toContain('someone@example.com');
    expect(r.stdout).toContain(`ok cache: ${cache} (writable)`);
    expect(r.stdout).toContain(`ok repository: ${repo.root} (main @ `);
    expect(r.stdout).toContain('missing profile: no .vigiles/profile.yaml yet; run `vigiles init`');
  });

  it('exits 3 when a prerequisite is missing or too old', async () => {
    const missing = await run(['doctor'], { cwd: repo.root, env: { ...env, VIGILES_OSV_SCANNER_BIN: path.join(bin, 'nope') } });
    expect(missing.code).toBe(EXIT.prerequisite);
    expect(missing.stdout).toMatch(/^missing osv-scanner: not found .*brew install osv-scanner/m);

    const old = script('osv-scanner-1', 'echo "osv-scanner version: 1.9.2"');
    const tooOld = await run(['doctor'], { cwd: repo.root, env: { ...env, VIGILES_OSV_SCANNER_BIN: old } });
    expect(tooOld.code).toBe(EXIT.prerequisite);
    expect(tooOld.stdout).toContain('missing osv-scanner: 1.9.2; Vigiles needs osv-scanner 2 or newer');

    const loggedOut = script(
      'claude-out',
      'if [ "$1" = "--version" ]; then echo "2.1.318 (Claude Code)"; exit 0; fi\necho \'{"loggedIn": false}\'; exit 1',
    );
    const login = await run(['doctor'], { cwd: repo.root, env: { ...env, VIGILES_CLAUDE_BIN: loggedOut } });
    expect(login.code).toBe(EXIT.prerequisite);
    expect(login.stdout).toMatch(/^missing claude login: not logged in/m);
  });

  it('exits 2 outside a git repository', async () => {
    const r = await run(['doctor'], { cwd: base });
    expect(r.code).toBe(EXIT.input);
    expect(r.stdout).toMatch(/^missing repository: .*not inside a git repository/m);
  });
});

describe('init and profile', () => {
  let repo: TestRepo;
  beforeAll(() => {
    repo = demoRepo('vigiles-cli-init-', null);
  });
  afterAll(() => repo.cleanup());

  it('creates .vigiles/ with its .gitignore and prints facts and a template, writing no profile', async () => {
    const r = await run(['init'], { cwd: repo.root });
    expect(r.code).toBe(EXIT.ok);
    expect(readFileSync(path.join(repo.root, '.vigiles/.gitignore'), 'utf8')).toMatch(/^report\.md$/m);
    expect(existsSync(path.join(repo.root, '.vigiles/profile.yaml'))).toBe(false);
    expect(r.stdout).toContain('Created .vigiles/ and .vigiles/.gitignore');
    expect(r.stdout).toContain('lockfiles: package-lock.json (npm)');
    expect(r.stdout).toContain('## Profile template');
    expect(r.stdout).toContain('criticality: TODO');
  });

  it('checks the profile: missing, invalid, valid', async () => {
    const missing = await run(['profile'], { cwd: repo.root });
    expect(missing.code).toBe(EXIT.input);
    expect(missing.stderr).toContain('run `vigiles init`');

    const template = (await run(['init'], { cwd: repo.root })).stdout.split('## Profile template\n\n')[1]!;
    writeFileSync(path.join(repo.root, '.vigiles/profile.yaml'), template);
    const invalid = await run(['profile'], { cwd: repo.root });
    expect(invalid.code).toBe(EXIT.input);
    expect(invalid.stderr).toMatch(/criticality/);
    expect((await run(['doctor'], { cwd: repo.root })).stdout).toMatch(
      /^warn profile: invalid \(criticality: .*\); run `vigiles profile`/m,
    );

    writeFileSync(path.join(repo.root, '.vigiles/profile.yaml'), `${PROFILE_YAML}owners: [TODO]\n`);
    const valid = await run(['profile'], { cwd: repo.root });
    expect(valid.code).toBe(EXIT.ok);
    expect(valid.stdout).toContain('.vigiles/profile.yaml is valid.');
    expect(valid.stdout).toContain('exposure: internet-facing · criticality: high · data classes: pii');
    expect(valid.stdout).toMatch(/triage profile hash: [0-9a-f]{12}/);
    expect(valid.stdout).toMatch(/^warn: owners\[0\] still hold a placeholder/m);
  });

  it('refuses a symlinked .vigiles/ and never writes into its target', async () => {
    const other = demoRepo('vigiles-cli-symlink-', null);
    const target = path.join(base, 'symlink-target');
    mkdirSync(target, { recursive: true });
    try {
      symlinkSync(target, path.join(other.root, '.vigiles'));
      const r = await run(['init'], { cwd: other.root });
      expect(r.code).toBe(EXIT.input);
      expect(r.stderr).toMatch(/\.vigiles is a symlink; Vigiles only uses a real directory there/);
      expect(readdirSync(target)).toEqual([]);
    } finally {
      other.cleanup();
    }
  });

  it('never overwrites an existing profile', async () => {
    const file = path.join(repo.root, '.vigiles/profile.yaml');
    const before = readFileSync(file, 'utf8');
    const r = await run(['init', '--repo', repo.root], { cwd: base });
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toContain('already exists and was not changed');
    expect(r.stdout).toContain('## Profile template (for reference)');
    expect(readFileSync(file, 'utf8')).toBe(before);
  });
});

describe('scan, triage, report', () => {
  let repo: TestRepo;
  const vigiles = (f: string) => path.join(repo.root, '.vigiles', f);
  beforeAll(() => {
    repo = demoRepo('vigiles-cli-flow-');
  });
  afterAll(() => repo.cleanup());

  it('needs a scan before triage and report', async () => {
    for (const cmd of ['triage', 'report']) {
      const r = await run([cmd], { cwd: repo.root });
      expect(r.code, cmd).toBe(EXIT.input);
      expect(r.stderr, cmd).toContain('no scan of this repository yet; run `vigiles scan` first');
    }
  });

  it('scans: what was audited, findings by priority, what needs triage and the estimate', async () => {
    const r = await run(['scan'], { cwd: repo.root });
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toMatch(/^Audited HEAD \(main\) at [0-9a-f]{10} \(committed \d{4}-\d{2}-\d{2}\): 1 lockfile, \d+ packages$/m);
    expect(r.stdout).toContain('  lockfiles: package-lock.json\n  no lockfile (not audited): tools/deno.json\n');
    expect(r.stdout).toMatch(/^Findings: 3 in 3 packages \(P0 1 · P1 \d · P2 \d · P3 \d\)$/m);
    expect(r.stdout).toContain('Verdicts: 0 cached (current) · 3 to triage');
    expect(r.stdout).toMatch(/^Estimate: 3 findings, under a minute \(3 at a time\), about \$0\.36 of Claude usage at API list prices$/m);
    expect(r.stdout).toContain('Next: `vigiles triage`');
    expect(r.stderr).toMatch(/^· auditing HEAD \(main\)/m);
    // Nothing written to the repository by a scan.
    expect(repo.git(['status', '--porcelain', '--untracked-files=all'])).toBe('');

    const json = await run(['scan', '--json'], { cwd: repo.root });
    const summary = JSON.parse(json.stdout) as { findings: number; toTriage: number; estimate: { usd: number } };
    expect(summary).toMatchObject({ findings: 3, toTriage: 3, estimate: { usd: 0.36 } });
  });

  it('reports untriaged findings by their signals', async () => {
    const r = await run(['report'], { cwd: repo.root });
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toMatch(/^Fix now \d · Fix soon \d · Logged \d \(main @ [0-9a-f]{7}\); 3 of these 3 items not triaged yet$/m);
    expect(r.stdout).toContain('Report: .vigiles/report.md');
    expect(readFileSync(vigiles('report.md'), 'utf8')).toContain('# Dependency audit: Demo App');
    expect(readFileSync(vigiles('.gitignore'), 'utf8')).toMatch(/^report\.md$/m);
  });

  it('triages the most urgent first, saving each verdict', async () => {
    claudeCalls.length = 0;
    const r = await run(['triage', '--limit', '1'], { cwd: repo.root });
    expect(r.code).toBe(EXIT.ok);
    expect(claudeCalls).toHaveLength(1);
    expect(claudeCalls[0]!.userPrompt).toContain('GHSA-aaaa-bbbb-cccc');
    expect(r.stdout).toMatch(/^\[1\/1\] ok vuln-pkg@.* GHSA-aaaa-bbbb-cccc → suggests Fix soon \(affected, \d+s\)$/m);
    expect(r.stdout).toContain('2 findings still need triage');
    expect(r.stdout).toContain('Next: `vigiles report`');
    const file = JSON.parse(readFileSync(vigiles('verdicts.json'), 'utf8')) as { verdicts: { osvId: string }[] };
    expect(file.verdicts.map((v) => v.osvId)).toEqual(['GHSA-aaaa-bbbb-cccc']);

    const rescan = await run(['scan'], { cwd: repo.root });
    expect(rescan.stdout).toContain('Verdicts: 1 cached (current) · 2 to triage');
  });

  it('exits 2 when --only matches nothing, and 3 when claude cannot work', async () => {
    const none = await run(['triage', '--only', 'GHSA-nope-nope-nope'], { cwd: repo.root });
    expect(none.code).toBe(EXIT.input);
    expect(none.stdout).toContain('No finding matched: GHSA-nope-nope-nope');

    const loggedOut = await run(['triage'], {
      cwd: repo.root,
      runClaude: async () => claudeResult({ status: 'failed', output: null, error: 'Invalid API key · Please run /login' }),
    });
    expect(loggedOut.code).toBe(EXIT.prerequisite);
    expect(loggedOut.stdout).toContain('Stopped early. Claude Code is not logged in');
  });

  it('reports the triaged and untriaged findings', async () => {
    const r = await run(['report'], { cwd: repo.root });
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toMatch(/^Fix now \d · Fix soon \d · Logged \d \(main @ [0-9a-f]{7}\); 2 of these 3 items not triaged yet$/m);
    const md = readFileSync(vigiles('report.md'), 'utf8');
    expect(md).toContain('Reachable from the API.');
  });

  it('refuses to triage a stale scan, and the report says so', async () => {
    writeFileSync(vigiles('profile.yaml'), PROFILE_YAML.replace('mitigations: none known', 'mitigations: WAF'));
    try {
      const triage = await run(['triage'], { cwd: repo.root });
      expect(triage.code).toBe(EXIT.input);
      expect(triage.stderr).toContain('.vigiles/profile.yaml changed since the last scan; run scan again');
      expect((await run(['profile'], { cwd: repo.root })).stdout).toContain('Changed since the last scan');
      expect((await run(['report'], { cwd: repo.root })).code).toBe(EXIT.ok);
      expect(readFileSync(vigiles('report.md'), 'utf8')).toContain('changed since the last scan; run scan again');
    } finally {
      repo.git(['checkout', '--', '.vigiles/profile.yaml']);
    }
  });

  it('says when the audited ref moved after the scan', async () => {
    repo.write('README.md', 'more\n');
    repo.commit('later');
    const r = await run(['report'], { cwd: repo.root });
    expect(r.code).toBe(EXIT.ok);
    expect(readFileSync(vigiles('report.md'), 'utf8')).toMatch(
      /HEAD is now at [0-9a-f]{7}, but this report is for the scanned commit [0-9a-f]{7}; run `scan` to audit the new commit\./,
    );

    // Another ref: the hint keeps it (a plain `scan` would audit HEAD instead).
    expect((await run(['scan', '--ref', 'main'], { cwd: repo.root })).code).toBe(EXIT.ok);
    repo.write('README.md', 'even more\n');
    repo.commit('later still');
    await run(['report'], { cwd: repo.root });
    expect(readFileSync(vigiles('report.md'), 'utf8')).toMatch(
      /main is now at [0-9a-f]{7}, but this report is for the scanned commit [0-9a-f]{7}; run `scan --ref main` to audit the new commit\./,
    );
  });

  it('audit runs scan, triage and report', async () => {
    claudeCalls.length = 0;
    const r = await run(['audit', '--repo', repo.root], { cwd: base });
    expect(r.code).toBe(EXIT.ok);
    expect(r.stdout).toContain('Verdicts: 1 cached (current) · 2 to triage');
    expect(r.stdout).not.toContain('Next: ');
    expect(claudeCalls).toHaveLength(2);
    expect(r.stdout).toMatch(/^Triage done: 2 ok, 0 failed/m);
    expect(r.stdout).toMatch(/^Fix now \d · Fix soon \d · Logged \d \(/m);
    expect(r.stdout).toContain(`Report: ${path.join(repo.root, '.vigiles/report.md')}`);
  });
});
