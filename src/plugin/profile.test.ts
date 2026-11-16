import { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parse as parseYaml, stringify as toYaml } from 'yaml';
import { ProjectProfileSchema } from '../lib/types';
import { triageProfileHash, HIDDEN_PROFILE_KEYS } from '../lib/triage/profile';
import { createTestRepo, tempDir, type TestRepo } from './git-test-support';
import { stripCredentials, uncommittedDependencyFiles } from './git-info';
import {
  detectFacts,
  formatFacts,
  infraEntry,
  loadProfile,
  notablePackages,
  ProfileInvalidError,
  ProfileMissingError,
  profileTemplate,
  suggestId,
  toProjectProfile,
  type RepoFacts,
} from './profile';

const dir = tempDir('vigiles-profile-');
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const POC_PROFILE = path.join(process.cwd(), 'projects/how-clutch-web.yaml');

function writeProfile(name: string, value: unknown): string {
  const file = path.join(dir, name);
  writeFileSync(file, typeof value === 'string' ? value : toYaml(value));
  return file;
}

/** The POC's profile without repo_path, as a plugin user would commit it. */
function pocProfileWithoutRepoPath(): Record<string, unknown> {
  const raw = parseYaml(readFileSync(POC_PROFILE, 'utf8')) as Record<string, unknown>;
  delete raw.repo_path;
  return raw;
}

describe('loadProfile', () => {
  it('accepts a profile without repo_path and warns about placeholders left in values', () => {
    const file = writeProfile('ok.yaml', pocProfileWithoutRepoPath());
    const { profile, warnings } = loadProfile(file);
    expect(profile.id).toBe('how-clutch-web');
    expect(profile.repo_path).toBeUndefined();
    // how-clutch-web.yaml still has a "⚠ Fill in" mitigations value
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('mitigations');
    expect(warnings[0]).not.toContain('criticality'); // a ⚠ in a comment is dropped by YAML
  });

  it('names nested placeholder paths', () => {
    const file = writeProfile('nested.yaml', {
      id: 'x',
      name: 'X',
      criticality: 'low',
      exposure: 'internal',
      deployments: [{ env: 'production', hosting: 'TODO: where' }],
      runtime: { frameworks: ['next', 'Fill in'] },
    });
    const [warning] = loadProfile(file).warnings;
    expect(warning).toContain('runtime.frameworks[1]');
    expect(warning).toContain('deployments[0].hosting');
    expect(warning).not.toContain('deployments[0].env');
  });

  it('has no warnings for a complete profile', () => {
    const file = writeProfile('clean.yaml', {
      id: 'x',
      name: 'X',
      criticality: 'low',
      exposure: 'internal',
      notes: 'todo-app is a package name',
    });
    expect(loadProfile(file).warnings).toEqual([]);
  });

  it('throws ProfileMissingError for a missing file', () => {
    expect(() => loadProfile(path.join(dir, 'nope.yaml'))).toThrow(ProfileMissingError);
  });

  it('throws ProfileInvalidError with the failing fields', () => {
    const file = writeProfile('bad.yaml', { id: 'Not Kebab', name: 'X', criticality: 'TODO', exposure: 'internal' });
    let err: unknown;
    try {
      loadProfile(file);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ProfileInvalidError);
    expect((err as Error).message).toContain('id: kebab-case id');
    expect((err as Error).message).toContain('criticality:');
    expect(() => loadProfile(writeProfile('syntax.yaml', 'id: [unclosed\n'))).toThrow(/not valid YAML/);
    expect(() => loadProfile(writeProfile('empty.yaml', ''))).toThrow(/empty/);
  });

  // The error is printed into the Claude session: it names the problem and the position, never the content.
  const SECRET_INI = '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG\n';

  it('reports a YAML syntax error by code and position without quoting the file', () => {
    let message = '';
    try {
      loadProfile(writeProfile('ini.yaml', SECRET_INI));
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/not valid YAML \(UNEXPECTED_TOKEN at line 2, column 1\)$/);
    expect(message).not.toMatch(/AKIA|wJalr|aws_|default/);
  });

  it('refuses a symlinked profile.yaml or .vigiles/ and never reads the target', () => {
    const secret = path.join(dir, 'credentials');
    writeFileSync(secret, SECRET_INI);
    const repo = path.join(dir, 'symlinked-profile');
    mkdirSync(path.join(repo, '.vigiles'), { recursive: true });
    symlinkSync(secret, path.join(repo, '.vigiles/profile.yaml'));
    let message = '';
    try {
      loadProfile(path.join(repo, '.vigiles/profile.yaml'));
    } catch (e) {
      expect(e).toBeInstanceOf(ProfileInvalidError);
      message = (e as Error).message;
    }
    expect(message).toMatch(/profile\.yaml is a symlink; Vigiles only reads a regular file there/);
    expect(message).not.toMatch(/AKIA|wJalr|aws_/);

    const real = path.join(dir, 'elsewhere');
    mkdirSync(real);
    writeFileSync(path.join(real, 'profile.yaml'), 'id: x\nname: X\ncriticality: low\nexposure: internal\n');
    const linkedDir = path.join(dir, 'symlinked-dir');
    mkdirSync(linkedDir);
    symlinkSync(real, path.join(linkedDir, '.vigiles'));
    expect(() => loadProfile(path.join(linkedDir, '.vigiles/profile.yaml'))).toThrow(/\.vigiles is a symlink/);

    // A directory where the file should be is refused too.
    const dirProfile = path.join(dir, 'dir-profile');
    mkdirSync(path.join(dirProfile, '.vigiles/profile.yaml'), { recursive: true });
    expect(() => loadProfile(path.join(dirProfile, '.vigiles/profile.yaml'))).toThrow(/is not a regular file/);
  });
});

describe('toProjectProfile', () => {
  it('gives the same triage profile hash as the POC for the same values', () => {
    const poc = ProjectProfileSchema.parse(parseYaml(readFileSync(POC_PROFILE, 'utf8')));
    const { profile } = loadProfile(writeProfile('hash.yaml', pocProfileWithoutRepoPath()));
    const converted = toProjectProfile(profile, '/somewhere/else');
    expect(converted.repo_path).toBe('/somewhere/else');
    expect(triageProfileHash(converted)).toBe(triageProfileHash(poc));
    // also when the YAML lists the keys in another order
    const reordered = Object.fromEntries(Object.entries(pocProfileWithoutRepoPath()).reverse());
    const { profile: p2 } = loadProfile(writeProfile('hash2.yaml', reordered));
    expect(triageProfileHash(toProjectProfile(p2, '/x'))).toBe(triageProfileHash(poc));
  });
});

describe('helpers', () => {
  it('strips credentials from remote URLs', () => {
    expect(stripCredentials('https://user:ghp_secret@github.com/org/repo.git')).toBe('https://github.com/org/repo.git');
    expect(stripCredentials('https://x-access-token@github.com/org/repo.git')).toBe('https://github.com/org/repo.git');
    expect(stripCredentials('ssh://git:pw@host/repo.git')).toBe('ssh://git@host/repo.git');
    expect(stripCredentials('git@github.com:org/repo.git')).toBe('git@github.com:org/repo.git');
    expect(stripCredentials('https://github.com/org/repo.git')).toBe('https://github.com/org/repo.git');
  });

  it('recognises deployment and infra files', () => {
    expect(infraEntry('Dockerfile')).toBe('Dockerfile');
    expect(infraEntry('backend/aws/Dockerfile.prod')).toBe('backend/aws/Dockerfile.prod');
    expect(infraEntry('amplify.yml')).toBe('amplify.yml');
    expect(infraEntry('.github/workflows/deploy.yml')).toBe('.github/workflows/deploy.yml');
    expect(infraEntry('infra/main.tf')).toBe('infra/*.tf');
    expect(infraEntry('deploy/k8s/app/deployment.yaml')).toBe('deploy/k8s/');
    expect(infraEntry('backend/aws/buildspec.yaml')).toBe('backend/aws/buildspec.yaml');
    expect(infraEntry('node_modules/x/Dockerfile')).toBeNull();
    expect(infraEntry('src/app.ts')).toBeNull();
  });

  it('picks notable packages from a package.json', () => {
    const pkg = JSON.stringify({
      dependencies: { next: '16.0.1', react: '^19.0.0', lodash: '4', '@aws-sdk/client-s3': '3', '@aws-sdk/client-ses': '3' },
      devDependencies: { typescript: '5.9.3', vitest: '4' },
    });
    expect(notablePackages(pkg)).toEqual(['next@16.0.1', 'react@^19.0.0', '@aws-sdk/*', 'typescript@5.9.3']);
    expect(notablePackages('not json')).toEqual([]);
  });

  it('suggests a kebab-case id', () => {
    expect(suggestId('/x/How_Clutch Web')).toBe('how-clutch-web');
    expect(suggestId('/x/___')).toBe('project');
  });
});

describe('detectFacts / profileTemplate', () => {
  let repo: TestRepo;
  let facts: RepoFacts;

  beforeAll(async () => {
    repo = createTestRepo('vigiles-facts-');
    repo.write(
      'package.json',
      JSON.stringify({ name: 'app', engines: { node: '>=22' }, dependencies: { next: '16.0.1', react: '19.0.0' } }),
    );
    repo.write('package-lock.json', '{"lockfileVersion":3,"packages":{}}');
    repo.write('tsconfig.json', '{}');
    repo.write('Dockerfile', 'FROM node:22\n');
    repo.write('.github/workflows/ci.yml', 'on: push\n');
    repo.write('tools/pyproject.toml', '[project]\n');
    repo.write('.nvmrc', '24.18\n');
    repo.write('.env', 'SECRET=never-read\n'); // committed on purpose: facts must never read it
    const sha = repo.commit('init');
    repo.git(['remote', 'add', 'origin', 'https://user:secret-token@example.com/org/app.git']);
    repo.git(['update-ref', 'refs/remotes/origin/main', sha]);
    repo.git(['symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main']);
    facts = await detectFacts(repo.root, 'git');
  });
  afterAll(() => repo.cleanup());

  it('detects lockfiles, branches, remotes, infra and frameworks at HEAD', () => {
    expect(facts.suggestedId).toBe('repo');
    expect(facts.head?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(facts.currentBranch).toBe('main');
    expect(facts.defaultBranch).toBe('origin/main');
    expect(facts.remotes).toEqual([{ name: 'origin', url: 'https://example.com/org/app.git' }]);
    expect(facts.lockfiles).toEqual([{ file: 'package-lock.json', ecosystem: 'npm' }]);
    expect(facts.coverageGaps).toEqual(['tools/pyproject.toml']);
    expect(facts.infraFiles).toEqual(['.github/workflows/ci.yml', 'Dockerfile']);
    expect(facts.frameworks).toEqual([{ manifest: 'package.json', packages: ['next@16.0.1', 'react@19.0.0'] }]);
    expect(facts.nodeVersion).toBe('24.18');
    expect(facts.languages).toEqual(['typescript']);
    const text = formatFacts(facts);
    expect(text).toContain('lockfiles: package-lock.json (npm)');
    expect(text).not.toContain('secret');
  });

  it('renders a template that names every triage-visible field and needs the TODOs filled in', () => {
    const template = profileTemplate(facts);
    expect(template).not.toContain('secret');
    expect(template).toContain('#   lockfiles: package-lock.json (npm)');
    const raw = parseYaml(template) as Record<string, unknown>;
    const visible = Object.keys(ProjectProfileSchema.shape).filter((k) => !(HIDDEN_PROFILE_KEYS as readonly string[]).includes(k));
    for (const key of visible) expect(raw, key).toHaveProperty(key);
    expect(raw).toMatchObject({
      id: 'repo',
      ref: 'origin/main',
      runtime: { language: 'typescript', node: '24.18', frameworks: ['next@16.0.1', 'react@19.0.0'] },
    });

    // As printed it does not validate: criticality and exposure must be chosen.
    expect(() => loadProfile(writeProfile('template.yaml', template))).toThrow(/criticality[\s\S]*exposure/);
    // Once they are, the remaining TODOs are reported as placeholders.
    const filled = template.replace('criticality: TODO', 'criticality: high').replace('exposure: TODO', 'exposure: internet-facing');
    const { warnings } = loadProfile(writeProfile('filled.yaml', filled));
    expect(warnings[0]).toContain('data_classes[0]');
    expect(warnings[0]).toContain('deployments[0].hosting');
    expect(warnings[0]).toContain('mitigations');
    expect(warnings[0]).toContain('notes');
  });

  it('handles a repository without commits', async () => {
    const empty = createTestRepo('vigiles-facts-empty-');
    try {
      const f = await detectFacts(empty.root, 'git');
      expect(f.head).toBeNull();
      expect(f.lockfiles).toEqual([]);
      expect(profileTemplate(f)).toContain('No commit at HEAD yet');
    } finally {
      empty.cleanup();
    }
  });
});

describe('uncommittedDependencyFiles', () => {
  it('lists changed, staged, untracked and renamed lockfiles and manifests only', async () => {
    const repo = createTestRepo('vigiles-status-');
    try {
      repo.write('package.json', '{}');
      repo.write('package-lock.json', '{}');
      repo.write('web/yarn.lock', '');
      repo.write('src/index.ts', '');
      repo.commit();
      repo.write('package-lock.json', '{"changed":true}');
      repo.write('src/index.ts', 'changed');
      repo.write('api/requirements-prod.txt', 'flask==1\n');
      repo.write('vendor/node_modules/x/package.json', '{}');
      repo.write('examples/package.json', '{}');
      repo.git(['mv', 'web/yarn.lock', 'web/old-yarn.lock']);
      const files = await uncommittedDependencyFiles('git', repo.root, (f) => f.startsWith('examples/'));
      expect(files).toEqual(['api/requirements-prod.txt', 'package-lock.json', 'web/yarn.lock']);
    } finally {
      repo.cleanup();
    }
  });
});
