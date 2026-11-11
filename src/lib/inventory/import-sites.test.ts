import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  buildImportIndex,
  extractImportSpecifiers,
  findImportSites,
  importSiteKind,
  isScannableSource,
  MAX_IMPORT_SITES,
  owningDir,
  packageNameFromSpecifier,
  searchImportSites,
} from './import-sites';

describe('extractImportSpecifiers', () => {
  it('finds static, side-effect, re-export, require and dynamic imports with statement lines', () => {
    const src = [
      "import React from 'react';", // 1
      'import {', // 2
      '  a,', // 3
      '  b,', // 4
      '} from "@scope/pkg/sub";', // 5
      "import 'side-effect/register';", // 6
      "export * from 'reexported';", // 7
      "export { x } from './local';", // 8
      "const z = require('zod');", // 9
      "const lazy = await import('lazy-lib');", // 10
      "import type { T } from 'types-only';", // 11
      "// import nope from 'commented-out';", // 12
      " * import alsoNope from 'jsdoc';", // 13
      'export const y = 1', // 14
      "import late from 'late-lib'", // 15
    ].join('\n');
    expect(extractImportSpecifiers(src)).toEqual([
      { specifier: 'react', line: 1 },
      { specifier: '@scope/pkg/sub', line: 2 },
      { specifier: 'side-effect/register', line: 6 },
      { specifier: 'reexported', line: 7 },
      { specifier: './local', line: 8 },
      { specifier: 'zod', line: 9 },
      { specifier: 'lazy-lib', line: 10 },
      { specifier: 'types-only', line: 11 },
      { specifier: 'late-lib', line: 15 },
    ]);
  });

  it('ignores look-alikes that are not imports', () => {
    const src = ["const from = 'x';", "Array.from('abc');", "someimport('nope');", "const s = 'import x from y';"].join('\n');
    expect(extractImportSpecifiers(src)).toEqual([]);
  });
});

describe('packageNameFromSpecifier', () => {
  it.each([
    ['next', 'next'],
    ['next/image', 'next'],
    ['@scope/pkg', '@scope/pkg'],
    ['@scope/pkg/deep/path', '@scope/pkg'],
    ['./x', null],
    ['../x', null],
    ['/abs', null],
    ['@/components/ui', null],
    ['~/lib', null],
    ['#internal', null],
    ['node:fs', null],
    ['npm:zod@3', null],
    ['https://esm.sh/zod', null],
    ['@scope', null],
  ])('%s → %s', (spec, name) => {
    expect(packageNameFromSpecifier(spec)).toBe(name);
  });
});

describe('isScannableSource', () => {
  it.each([
    ['src/app/page.tsx', true],
    ['lib/a.mjs', true],
    ['lib/a.cts', true],
    ['src/a.test.ts', false],
    ['src/a.spec.tsx', false],
    ['src/__tests__/a.ts', false],
    ['src/Button.stories.tsx', false],
    ['src/stories/lib/role-visibility.tsx', false],
    ['stories/helpers.ts', false],
    ['src/__mocks__/x.ts', false],
    ['src/app/tests/page.tsx', true],
    ['src/storybook-ish/a.ts', true],
    ['src/latest/a.ts', true],
    ['.storybook/main.ts', false],
    ['node_modules/x/index.js', false],
    ['types/global.d.ts', false],
    ['README.md', false],
    ['styles.css', false],
  ])('%s → %s', (file, ok) => {
    expect(isScannableSource(file)).toBe(ok);
  });
});

describe('importSiteKind', () => {
  it.each([
    ['next.config.ts', '', 'config'],
    ['vitest.config.mts', '', 'config'],
    ['eslint.config.js', '', 'config'],
    ['packages/web/tailwind.config.cjs', 'packages/web', 'config'],
    ['vitest.setup.ts', '', 'config'],
    ['.eslintrc.js', '', 'config'],
    ['backend/.eslintrc.cjs', 'backend', 'config'],
    ['scripts/seed.ts', '', 'script'],
    ['scripts/ingest/bbcity/client.ts', '', 'script'],
    ['backend/scripts/migrate.mjs', 'backend', 'script'],
    ['src/lib/config.ts', '', 'source'],
    ['src/app/api/route.ts', '', 'source'],
    ['src/config/index.ts', '', 'source'],
    // Below the package root these are application code, not tool config or one-off scripts.
    ['src/config/database.config.ts', '', 'source'],
    ['backend/src/config/app.config.ts', 'backend', 'source'],
    ['src/site.config.ts', '', 'source'],
    ['src/app/scripts/page.tsx', '', 'source'],
    ['src/lib/scripts/loader.ts', '', 'source'],
    // Another package's root is not this package's root.
    ['packages/web/next.config.ts', '', 'source'],
  ])('%s (package %j) → %s', (file, packageDir, kind) => {
    expect(importSiteKind(file, packageDir)).toBe(kind);
  });
});

describe('owningDir', () => {
  it('picks the deepest lockfile directory containing the file', () => {
    expect(owningDir('backend/src/a.ts', ['', 'backend', 'dashboard'])).toBe('backend');
    expect(owningDir('scripts/a.ts', ['', 'backend'])).toBe('');
    expect(owningDir('backend-old/a.ts', ['backend'])).toBeNull();
  });
});

describe('buildImportIndex + findImportSites', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'vigiles-import-sites-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const write = (file: string, content: string) => {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), content);
  };
  write('src/a.ts', "import { z } from 'zod';\nimport posthog from 'posthog-js';\n");
  write('src/b.tsx', "import Image from 'next/image';\nconst z = require('zod/v4');\n");
  write('src/a.test.ts', "import { z } from 'zod';\n");
  write('sub/src/c.ts', "import { z } from 'zod';\n");
  const files = ['src/a.ts', 'src/b.tsx', 'src/a.test.ts', 'sub/src/c.ts', 'src/gone.ts'];
  const index = buildImportIndex(dir, files);

  it('indexes scannable files only and skips missing ones', () => {
    expect(index.filesScanned).toBe(3);
  });

  it('does not follow symlinks out of the snapshot', () => {
    const outside = path.join(dir, 'outside.ts');
    writeFileSync(outside, "import secret from 'secret-pkg';\n");
    mkdirSync(path.join(dir, 'snap'), { recursive: true });
    symlinkSync(outside, path.join(dir, 'snap', 'link.ts'));
    const linked = buildImportIndex(path.join(dir, 'snap'), ['link.ts']);
    expect(linked.filesScanned).toBe(0);
    expect(linked.byPackage.size).toBe(0);
  });

  it('finds sites for a package and its subpaths, scoped to the lockfile directory', () => {
    const sites = findImportSites(index, { lockfileDir: '', allLockfileDirs: ['', 'sub'], packages: ['zod'] });
    expect(sites).toEqual([
      { file: 'src/a.ts', line: 1, specifier: 'zod', via: 'zod' },
      { file: 'src/b.tsx', line: 2, specifier: 'zod/v4', via: 'zod' },
    ]);
    const sub = findImportSites(index, { lockfileDir: 'sub', allLockfileDirs: ['', 'sub'], packages: ['zod'] });
    expect(sub.map((s) => s.file)).toEqual(['sub/src/c.ts']);
  });

  it('records which direct dependency was searched for', () => {
    const sites = findImportSites(index, { lockfileDir: '', allLockfileDirs: [''], packages: ['posthog-js', 'next', 'shadcn'] });
    expect(sites.map((s) => `${s.via}@${s.file}:${s.line}`)).toEqual(['posthog-js@src/a.ts:2', 'next@src/b.tsx:1']);
  });

  it('caps the number of sites, keeping every searched package represented, and reports the uncapped total', () => {
    const many = Array.from({ length: 30 }, (_, i) => `f${String(i).padStart(2, '0')}.ts`);
    for (const f of many) write(`cap/${f}`, "import x from 'big';\n");
    write('cap/zz.ts', "import y from 'small';\n");
    const capIndex = buildImportIndex(path.join(dir, 'cap'), [...many, 'zz.ts']);
    const sites = findImportSites(capIndex, { lockfileDir: '', allLockfileDirs: [''], packages: ['big', 'small'], max: 20 });
    expect(sites).toHaveLength(20);
    expect(sites.some((s) => s.via === 'small')).toBe(true);
    const result = searchImportSites(capIndex, { lockfileDir: '', allLockfileDirs: [''], packages: ['big', 'small'] });
    expect(result.sites).toHaveLength(MAX_IMPORT_SITES);
    expect(result.total).toBe(31);
  });
});
