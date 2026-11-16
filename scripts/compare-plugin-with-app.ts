/**
 * Compares the plugin's result for a repository with the dashboard's (POC database), finding by finding:
 * finding set, base priority, triage input hash, the latest verdict, and the policy decision.
 *
 *   npm run compare:plugin -- --repo ../how-clutch-web [--project how-clutch-web] [--db ~/.vigiles/vigiles.db]
 *
 * Reads the plugin's last scan (cache), .vigiles/verdicts.json and the plugin's bundled policy, and opens the
 * POC database read-only. Writes nothing. Run `vigiles scan` with the same commit the dashboard last scanned.
 */
import Database from 'better-sqlite3';
import { homedir } from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { loadPolicy } from '../src/lib/config/load';
import { decide } from '../src/plugin/decide';
import { pluginPaths, repoPaths } from '../src/plugin/paths';
import { loadProfile } from '../src/plugin/profile';
import { findingId, readScanResult } from '../src/plugin/scan';
import { loadFailures, loadVerdicts } from '../src/plugin/verdicts';

const { values } = parseArgs({
  options: {
    repo: { type: 'string' },
    project: { type: 'string' },
    db: { type: 'string', default: path.join(process.env.VIGILES_DATA_DIR ?? path.join(homedir(), '.vigiles'), 'vigiles.db') },
    verbose: { type: 'boolean', default: false },
  },
});
if (!values.repo) {
  console.error('usage: compare-plugin-with-app --repo <path> [--project <id>] [--db <file>] [--verbose]');
  process.exit(2);
}

const repoRoot = path.resolve(values.repo);
const assetRoot = path.resolve(import.meta.dirname, '..', 'plugin');
const plugin = pluginPaths({ assetRoot });
const { profile } = loadProfile(path.join(repoRoot, '.vigiles', 'profile.yaml'));
const projectId = values.project ?? profile.id;
const paths = repoPaths(repoRoot, profile.id, plugin);
const scan = readScanResult(paths.scanFile);
if (!scan) throw new Error(`no plugin scan at ${paths.scanFile}`);
const { store } = loadVerdicts(paths.verdictsFile);
const policy = loadPolicy(assetRoot);
const decisions = decide(scan, store, loadFailures(paths.failuresFile), policy, profile);

interface AppRow {
  id: number;
  lockfile: string;
  ecosystem: string;
  package_name: string;
  osv_id: string;
  priority: string | null;
  current_action: string | null;
  current_rule_id: string | null;
  input_hash: string | null;
  output: string | null;
}

const db = new Database(values.db, { readonly: true, fileMustExist: true });
const config = scan.triageConfig.name;
const rows = db
  .prepare(
    `SELECT f.id, f.lockfile, f.ecosystem, f.package_name, f.osv_id, f.priority, f.current_action, f.current_rule_id,
            r.input_hash, r.output
       FROM findings f
       LEFT JOIN triage_runs r ON r.id = (
         SELECT id FROM triage_runs WHERE finding_id = f.id AND config_name = ? AND status = 'ok'
         ORDER BY id DESC LIMIT 1)
      WHERE f.project_id = ? AND f.status = 'open'`,
  )
  .all(config, projectId) as AppRow[];
db.close();

const app = new Map(
  rows.map((r) => [findingId({ osvId: r.osv_id, ecosystem: r.ecosystem, packageName: r.package_name, lockfile: r.lockfile }), r]),
);
const mine = new Map(decisions.findings.map((d) => [d.finding.id, d]));

const onlyApp = [...app.keys()].filter((k) => !mine.has(k));
const onlyPlugin = [...mine.keys()].filter((k) => !app.has(k));
const both = [...mine.keys()].filter((k) => app.has(k));

const diff = {
  priority: [] as string[],
  inputHash: [] as string[],
  verdict: [] as string[],
  suggested: [] as string[],
  action: [] as string[],
};
const confusion = new Map<string, number>();
let sameHashVerdicts = 0;
for (const k of both) {
  const a = app.get(k)!;
  const p = mine.get(k)!;
  if (a.priority !== p.finding.priority) diff.priority.push(`${k}: app ${a.priority} · plugin ${p.finding.priority}`);
  if (a.input_hash !== p.finding.inputHash) diff.inputHash.push(k);
  const appOutput = a.output ? (JSON.parse(a.output) as { verdict: string; suggested_action: string }) : null;
  const myOutput = p.verdict?.output ?? null;
  if (p.verdict && p.verdict.inputHash === a.input_hash) sameHashVerdicts++;
  if (appOutput?.verdict !== myOutput?.verdict) diff.verdict.push(`${k}: app ${appOutput?.verdict} · plugin ${myOutput?.verdict}`);
  if (appOutput?.suggested_action !== myOutput?.suggested_action) {
    diff.suggested.push(`${k}: app ${appOutput?.suggested_action} · plugin ${myOutput?.suggested_action}`);
  }
  const key = `${a.current_action} → ${p.action}`;
  confusion.set(key, (confusion.get(key) ?? 0) + 1);
  if (a.current_action !== p.action) {
    diff.action.push(`${k} (${p.finding.priority}): app ${a.current_action}/${a.current_rule_id} · plugin ${p.action}/${p.ruleId}`);
  }
}

const count = (xs: string[]) => `${both.length - xs.length}/${both.length} match`;
const out: string[] = [
  `Plugin scan: ${scan.ref} @ ${scan.commit.slice(0, 10)} (${scan.scannedAt}) · app: ${rows.length} open findings of ${projectId}`,
  `Finding set: ${both.length} in both · ${onlyApp.length} only in the app · ${onlyPlugin.length} only in the plugin`,
  ...onlyApp.map((k) => `  only app: ${k}`),
  ...onlyPlugin.map((k) => `  only plugin: ${k}`),
  `Priority: ${count(diff.priority)}`,
  `Triage input hash: ${count(diff.inputHash)} (${sameHashVerdicts} plugin verdicts were triaged from the same inputs as the app's latest run)`,
  `Verdict (affected / likely / not): ${count(diff.verdict)}`,
  `Triage's suggested action: ${count(diff.suggested)}`,
  `Action: ${count(diff.action)}`,
  `  app → plugin: ${[...confusion].map(([k, n]) => `${k} ${n}`).join(' · ')}`,
  `Plugin counts: ping ${decisions.counts.ping} · digest ${decisions.counts.digest} · log ${decisions.counts.log} · untriaged ${decisions.counts.untriaged}`,
];
if (diff.priority.length) out.push('Priority differences:', ...diff.priority.map((l) => `  ${l}`));
if (diff.action.length) out.push('Action differences:', ...diff.action.map((l) => `  ${l}`));
if (values.verbose && diff.verdict.length) out.push('Verdict differences:', ...diff.verdict.map((l) => `  ${l}`));
if (values.verbose && diff.suggested.length) out.push('Suggested action differences:', ...diff.suggested.map((l) => `  ${l}`));
if (values.verbose && diff.inputHash.length) out.push('Input hash differences:', ...diff.inputHash.map((l) => `  ${l}`));
console.log(out.join('\n'));
