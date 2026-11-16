#!/usr/bin/env node
/**
 * Builds the Claude Code plugin in plugin/ (docs/plugin.md). Everything it writes is committed:
 *
 *   plugin/bin/vigiles              esbuild CommonJS bundle of src/plugin/main.ts: self-contained (zod, yaml and
 *                                   picomatch inlined), without the DB, Next.js or React
 *   plugin/bin/package.json         {"type": "commonjs"}: Node decides how to load an extensionless file from the
 *                                   nearest package.json, and this repo's says "module" (plugin/ loads in place
 *                                   with `claude --plugin-dir ./plugin` or a local marketplace)
 *   plugin/prompts/triage/<v>.*     the active triage config's prompt files, verbatim (same prompt fingerprint,
 *                                   so the same triage input hashes as the dashboard); other versions are deleted
 *   plugin/config/policy.yaml       verbatim (same policy hash)
 *   plugin/config/osv-scanner.toml  verbatim
 *   plugin/config/vigiles.yaml      generated: only `triage:` with the active config
 *
 * Usage: node scripts/build-plugin.mjs [--assets-only | --check]
 *   --assets-only   copy and generate the assets and check them; skip the bundle
 *   --check         write nothing; exit 1 when plugin/ differs from what a build would write (stale bundle or
 *                   assets after a change to src/plugin, src/lib, a prompt or config/*). `npm test` runs it
 *                   (src/plugin/build.test.ts), so a source change without a rebuild fails the tests.
 *
 * The bundle gets the version from plugin/.claude-plugin/plugin.json as the global `__VIGILES_VERSION__` (esbuild
 * define; undefined when the CLI runs from source with tsx). The plugin root must not hold a package.json or
 * lockfile: Claude Code would run a package install in it.
 */
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { stringify as toYaml } from 'yaml';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PLUGIN = path.join(REPO, 'plugin');
const ENTRY = 'src/plugin/main.ts';
const OUTFILE = path.join(PLUGIN, 'bin', 'vigiles');
const PROMPT_FILES = ['system.md', 'user.md', 'schema.json'];
const CONFIG_FILES = ['policy.yaml', 'osv-scanner.toml', 'vigiles.yaml'];
/** Files at the plugin root that make Claude Code install packages there (it does when it finds a package.json and a lockfile). */
const ROOT_FORBIDDEN = ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'bun.lock', 'bun.lockb', 'yarn.lock', 'pnpm-lock.yaml'];
/** Packages the bundle must not contain: the POC's persistence and UI. */
const FORBIDDEN_PACKAGES = new Set(['drizzle-orm', 'drizzle-kit', 'better-sqlite3', 'next', 'react', 'react-dom', 'react-markdown']);
const FORBIDDEN_SOURCES = ['src/lib/db/'];

const rel = (p) => path.relative(REPO, p) || '.';
const log = (msg = '') => process.stdout.write(`${msg}\n`);

class BuildError extends Error {}
function fail(msg) {
  throw new BuildError(msg);
}

/**
 * Runs `code` as an ES module under tsx (so it can import src/lib/*.ts) and returns the JSON it prints last.
 * `load(p)` imports a repo file; REPO and PLUGIN are the absolute paths.
 */
function tsxJson(code) {
  const prelude = [
    "import path from 'node:path';",
    "import { pathToFileURL } from 'node:url';",
    'const REPO = process.env.VIGILES_BUILD_REPO;',
    'const PLUGIN = process.env.VIGILES_BUILD_PLUGIN;',
    'const load = (p) => import(pathToFileURL(path.join(REPO, p)).href);',
  ].join('\n');
  let stdout;
  try {
    stdout = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `${prelude}\n${code}`], {
      cwd: REPO,
      env: { ...process.env, VIGILES_BUILD_REPO: REPO, VIGILES_BUILD_PLUGIN: PLUGIN },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    fail(`${(err.stderr || err.message).toString().trim()}`);
  }
  const lines = stdout.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
}

function readManifest() {
  const file = path.join(PLUGIN, '.claude-plugin', 'plugin.json');
  if (!existsSync(file)) fail(`${rel(file)} is missing`);
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  if (manifest.name !== 'vigiles') fail(`${rel(file)}: name must be "vigiles" (the skill is /vigiles:audit)`);
  if (typeof manifest.version !== 'string' || !manifest.version) fail(`${rel(file)}: version is missing`);
  return manifest;
}

function checkPluginRoot() {
  const found = ROOT_FORBIDDEN.filter((f) => existsSync(path.join(PLUGIN, f)));
  if (found.length > 0) {
    fail(
      `plugin/ must not contain ${found.join(', ')}: Claude Code installs packages into a plugin root holding a package.json and a lockfile`,
    );
  }
  const warnings = [];
  if (!existsSync(path.join(PLUGIN, 'skills', 'audit', 'SKILL.md'))) warnings.push('plugin/skills/audit/SKILL.md is missing');
  if (existsSync(path.join(PLUGIN, 'CLAUDE.md'))) {
    warnings.push('plugin/CLAUDE.md is not loaded by Claude Code; put instructions in the skill');
  }
  return warnings;
}

/** The repo's resolved triage settings (config/vigiles.yaml through its zod schema, defaults applied). */
function sourceTriageConfig() {
  return tsxJson(`
    const { loadVigilesConfig } = await load('src/lib/config/load.ts');
    const t = loadVigilesConfig(REPO).triage;
    const active = t.configs.find((c) => c.name === t.active_config);
    console.log(JSON.stringify({ ...t, active }));
  `);
}

const PROMPT_DIR = path.join(PLUGIN, 'prompts', 'triage');
const CONFIG_DIR = path.join(PLUGIN, 'config');

/** The prompt file names of the active config (everything else in plugin/prompts/triage is stale). */
function promptNames(triage) {
  return new Set(PROMPT_FILES.map((f) => `${triage.active.prompt_version}.${f}`));
}

/** Every asset file the build writes, as [absolute path, content]. */
function assetFiles(triage) {
  const files = [];
  for (const name of promptNames(triage)) {
    const src = path.join(REPO, 'prompts', 'triage', name);
    if (!existsSync(src)) fail(`${rel(src)} is missing (prompt ${triage.active.prompt_version} of triage config ${triage.active.name})`);
    files.push([path.join(PROMPT_DIR, name), readFileSync(src)]);
  }
  for (const name of ['policy.yaml', 'osv-scanner.toml']) {
    files.push([path.join(CONFIG_DIR, name), readFileSync(path.join(REPO, 'config', name))]);
  }
  files.push([path.join(CONFIG_DIR, 'vigiles.yaml'), Buffer.from(renderVigilesYaml(triage))]);
  const binPackageJson = {
    '//': 'Written by scripts/build-plugin.mjs. Makes Node load bin/vigiles (a CommonJS bundle without an extension) as CommonJS, also inside a "type": "module" package.',
    type: 'commonjs',
  };
  files.push([path.join(PLUGIN, 'bin', 'package.json'), Buffer.from(`${JSON.stringify(binPackageJson, null, 2)}\n`)]);
  return files;
}

/** Prompt files in plugin/ that are not the active config's. */
function stalePrompts(triage) {
  if (!existsSync(PROMPT_DIR)) return [];
  const keep = promptNames(triage);
  return readdirSync(PROMPT_DIR).filter((name) => !keep.has(name));
}

function copyAssets(triage) {
  const files = assetFiles(triage);
  for (const name of stalePrompts(triage)) {
    rmSync(path.join(PROMPT_DIR, name), { recursive: true, force: true });
    log(`  removed  ${rel(path.join(PROMPT_DIR, name))}`);
  }
  for (const [file, content] of files) {
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, content);
  }
  for (const name of readdirSync(CONFIG_DIR)) {
    if (!CONFIG_FILES.includes(name)) log(`  warning  ${rel(path.join(CONFIG_DIR, name))} is not a plugin asset; remove it`);
  }
  return files.map(([file]) => file);
}

function renderVigilesYaml(triage) {
  const { name, prompt_version, model, effort, code_access } = triage.active;
  const doc = {
    triage: {
      active_config: name,
      // The plugin triages every finding; priority only orders the queue.
      min_priority: 'P3',
      concurrency: triage.concurrency,
      timeout_minutes: triage.timeout_minutes,
      max_budget_usd_per_run: triage.max_budget_usd_per_run,
      configs: [{ name, prompt_version, model, effort, code_access }],
    },
  };
  return [
    '# GENERATED by scripts/build-plugin.mjs from config/vigiles.yaml. Do not edit: change config/vigiles.yaml and run',
    '# `npm run build:plugin`. The plugin reads only `triage:` and always uses the active config below.',
    toYaml(doc),
  ].join('\n');
}

/** Loads the plugin's assets with the same src/lib code the CLI uses and compares them with the repo's. */
function checkAssets(source) {
  const r = tsxJson(`
    const { loadVigilesConfig, loadPolicy } = await load('src/lib/config/load.ts');
    const { promptFingerprint } = await load('src/lib/triage/input-hash.ts');
    const { loadTriagePrompt } = await load('src/lib/triage/prompt.ts');
    const t = loadVigilesConfig(PLUGIN).triage;
    const active = t.configs.find((c) => c.name === t.active_config);
    loadTriagePrompt(PLUGIN, active.prompt_version);
    console.log(JSON.stringify({
      triage: { ...t, active },
      pluginFingerprint: promptFingerprint(active.prompt_version, PLUGIN),
      repoFingerprint: promptFingerprint(active.prompt_version, REPO),
      pluginPolicyHash: loadPolicy(PLUGIN).hash,
      repoPolicyHash: loadPolicy(REPO).hash,
    }));
  `);
  const problems = [];
  if (r.triage.configs.length !== 1) problems.push(`plugin/config/vigiles.yaml has ${r.triage.configs.length} triage configs, expected 1`);
  if (JSON.stringify(r.triage.active) !== JSON.stringify(source.active)) {
    problems.push('the active triage config differs from config/vigiles.yaml');
  }
  for (const key of ['concurrency', 'timeout_minutes', 'max_budget_usd_per_run']) {
    if (r.triage[key] !== source[key]) problems.push(`triage.${key} is ${r.triage[key]}, config/vigiles.yaml has ${source[key]}`);
  }
  if (r.triage.min_priority !== 'P3') problems.push(`triage.min_priority is ${r.triage.min_priority}, expected P3`);
  // Same prompt fingerprint and policy hash as the dashboard: same triage input hashes, same decisions.
  if (r.pluginFingerprint !== r.repoFingerprint) {
    problems.push(`prompt fingerprint ${r.pluginFingerprint} differs from the repo's ${r.repoFingerprint}`);
  }
  if (r.pluginPolicyHash !== r.repoPolicyHash) {
    problems.push(`policy hash ${r.pluginPolicyHash} differs from the repo's ${r.repoPolicyHash}`);
  }
  if (problems.length > 0) fail(`plugin assets check failed:\n  ${problems.join('\n  ')}`);
  return r;
}

/** `node_modules/@scope/name/...` → '@scope/name' (null for repo sources). */
function packageOf(input) {
  return /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(input)?.[1] ?? null;
}

/** Package name, or the top directory of a repo source (src/lib/triage). */
function inputOwner(input) {
  return packageOf(input) ?? input.split('/').slice(0, 3).join('/');
}

/** What is forbidden in the bundle: a package name, or a repo source file. */
function forbiddenName(input) {
  const pkg = packageOf(input);
  if (pkg) return FORBIDDEN_PACKAGES.has(pkg) || pkg.startsWith('@next/') ? pkg : null;
  return FORBIDDEN_SOURCES.some((s) => input.startsWith(s)) ? input : null;
}

/** Forbidden packages/files in the bundle, and the imports that pull them in from allowed code. */
function forbiddenInputs(metafile) {
  const names = new Set();
  const edges = new Set();
  for (const [file, info] of Object.entries(metafile.inputs)) {
    const name = forbiddenName(file);
    if (name) {
      names.add(name);
      continue;
    }
    for (const imp of info.imports) {
      const target = imp.path && forbiddenName(imp.path);
      if (target) edges.add(`${file} imports ${target}`);
    }
  }
  return { names: [...names].sort(), edges: [...edges].sort() };
}

/** Builds the bundle in memory (with the forbidden-input and import.meta checks): its text and metafile. */
async function buildBundle(version) {
  if (!existsSync(path.resolve(REPO, ENTRY))) fail(`${ENTRY} does not exist yet; run with --assets-only to build only the assets`);
  const esbuild = await import('esbuild');
  const result = await esbuild.build({
    absWorkingDir: REPO,
    entryPoints: [ENTRY],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node20',
    outfile: rel(OUTFILE),
    banner: { js: '#!/usr/bin/env node' },
    define: { __VIGILES_VERSION__: JSON.stringify(version) },
    metafile: true,
    write: false,
    logLevel: 'silent',
    charset: 'utf8',
  });
  for (const w of result.warnings) {
    log(`  esbuild warning [${w.id || 'warning'}] ${w.location ? `${w.location.file}:${w.location.line}: ` : ''}${w.text}`);
  }
  // import.meta is empty in CommonJS output: code relying on it would break only in the bundle.
  const importMeta = result.warnings.filter((w) => w.id === 'empty-import-meta');
  if (importMeta.length > 0) {
    fail(`the bundle uses import.meta, which is empty in CommonJS (${importMeta.map((w) => w.location?.file).join(', ')})`);
  }

  const bad = forbiddenInputs(result.metafile);
  if (bad.names.length > 0) {
    fail(`the bundle must not include the DB, Next.js or React, but includes ${bad.names.join(', ')}:\n  ${bad.edges.join('\n  ')}`);
  }

  const out = result.outputFiles.find((f) => path.resolve(f.path) === OUTFILE);
  if (!out) fail('esbuild produced no bundle');
  let text = out.text;
  // An entry file with its own shebang would leave a second one under the banner's.
  const lines = text.split('\n');
  if (lines[0].startsWith('#!') && lines[1]?.startsWith('#!')) text = [lines[0], ...lines.slice(2)].join('\n');
  return { text, metafile: result.metafile };
}

async function bundle(version) {
  const { text, metafile } = await buildBundle(version);
  mkdirSync(path.dirname(OUTFILE), { recursive: true });
  writeFileSync(OUTFILE, text);
  chmodSync(OUTFILE, 0o755);

  const bytes = Buffer.byteLength(text);
  const byOwner = new Map();
  const outputInfo = metafile.outputs[rel(OUTFILE)];
  for (const [input, info] of Object.entries(outputInfo?.inputs ?? {})) {
    const owner = inputOwner(input);
    byOwner.set(owner, (byOwner.get(owner) ?? 0) + info.bytesInOutput);
  }
  const top = [...byOwner.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  log(`  bundle   ${rel(OUTFILE)}: ${kb(bytes)} (${Object.keys(metafile.inputs).length} inputs)`);
  log(`           largest: ${top.map(([owner, n]) => `${owner} ${kb(n)}`).join(', ')}`);
}

function kb(bytes) {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(2)} MB` : `${Math.round(bytes / 1024)} KB`;
}

/** The bundle must run from any directory, without the repo (no VIGILES_ASSET_ROOT, cwd outside the repo). */
function checkBundleRuns(version) {
  const env = { ...process.env };
  delete env.VIGILES_ASSET_ROOT;
  const cwd = tmpdir();
  let out;
  try {
    out = execFileSync(process.execPath, [OUTFILE, '--version'], { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    fail(`node ${rel(OUTFILE)} --version failed (cwd ${cwd}):\n${(err.stderr || err.message).toString().trim()}`);
  }
  if (!out.includes(version)) fail(`node ${rel(OUTFILE)} --version printed "${out.trim()}", expected it to contain ${version}`);
  log(`  check    node ${rel(OUTFILE)} --version (cwd ${cwd}): ${out.trim()}`);
  // Through the shebang, as the bare `vigiles` command on the Bash tool's PATH runs it (needs a `node` on PATH).
  try {
    const direct = execFileSync(OUTFILE, ['--version'], { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    log(`  check    ${rel(OUTFILE)} --version: ${direct.trim()}`);
  } catch (err) {
    log(`  warning  running ${rel(OUTFILE)} through its shebang failed: ${(err.stderr || err.message).toString().trim().split('\n')[0]}`);
  }
}

/** --check: compares plugin/ with what a build would write, writing nothing. */
async function check(manifest) {
  const stale = [];
  const triage = sourceTriageConfig();
  for (const [file, content] of assetFiles(triage)) {
    if (!existsSync(file) || !readFileSync(file).equals(content)) stale.push(rel(file));
  }
  for (const name of stalePrompts(triage)) stale.push(`${rel(path.join(PROMPT_DIR, name))} (not a file of prompt ${triage.active.prompt_version})`);
  const { text } = await buildBundle(manifest.version);
  if (!existsSync(OUTFILE) || readFileSync(OUTFILE, 'utf8') !== text) stale.push(rel(OUTFILE));
  else if ((statSync(OUTFILE).mode & 0o111) === 0) stale.push(`${rel(OUTFILE)} (not executable)`);
  if (stale.length > 0) fail(`plugin/ is stale; run \`npm run build:plugin\` and commit plugin/:\n  ${stale.join('\n  ')}`);
  log(`plugin/ is up to date (vigiles ${manifest.version}).`);
}

async function main() {
  const { values } = parseArgs({
    options: {
      'assets-only': { type: 'boolean', default: false },
      check: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) {
    log(
      'Usage: node scripts/build-plugin.mjs [--assets-only | --check]\n' +
        '  --assets-only  copy and generate the plugin assets and check them; skip the bundle\n' +
        '  --check        write nothing; exit 1 when plugin/ is out of date with the source',
    );
    return;
  }
  const manifest = readManifest();
  if (values.check) {
    const problems = checkPluginRoot();
    for (const w of problems) log(`  warning  ${w}`);
    await check(manifest);
    return;
  }
  log(`Building the vigiles plugin ${manifest.version} into ${rel(PLUGIN)}/`);
  for (const w of checkPluginRoot()) log(`  warning  ${w}`);

  const source = sourceTriageConfig();
  const written = copyAssets(source);
  for (const f of written) log(`  wrote    ${rel(f)}`);
  const checked = checkAssets(source);
  log(
    `  check    triage ${checked.triage.active.name} (prompt ${checked.pluginFingerprint}, ${checked.triage.active.model}, effort ${checked.triage.active.effort}, ` +
      `code ${checked.triage.active.code_access ? 'on' : 'off'}), concurrency ${checked.triage.concurrency}, timeout ${checked.triage.timeout_minutes} min, ` +
      `budget $${checked.triage.max_budget_usd_per_run}/run; policy ${checked.pluginPolicyHash}: same as the repo`,
  );

  if (values['assets-only']) {
    log('Assets built (--assets-only: bundle skipped).');
    return;
  }
  await bundle(manifest.version);
  checkBundleRuns(manifest.version);
  log('Plugin built. Commit plugin/ (bin/vigiles included).');
}

main().catch((err) => {
  process.stderr.write(`build-plugin: ${err instanceof BuildError ? err.message : (err.stack ?? err)}\n`);
  process.exit(1);
});
