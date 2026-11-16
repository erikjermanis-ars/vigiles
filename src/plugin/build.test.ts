/**
 * plugin/bin/vigiles and the copied assets are committed build output that installs use as they are: a change to
 * src/plugin, src/lib, a prompt or config/* without `npm run build:plugin` would ship the old logic, and the
 * plugin's results would quietly stop matching the dashboard's. This fails until plugin/ is rebuilt.
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { expect, it } from 'vitest';

const ROOT = path.join(import.meta.dirname, '../..');

it('plugin/ is up to date with the source (run `npm run build:plugin` if this fails)', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/build-plugin.mjs'), '--check'], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 120_000,
  });
  expect(`${r.stdout}${r.stderr}`.trim()).toMatch(/^plugin\/ is up to date/m);
  expect(r.status).toBe(0);
}, 120_000);
