/** Test fixtures for the plugin's verdict, triage, decide and report modules. Not used at runtime. */
import type { TriageOutput } from '../lib/types';
import {
  STATE_FORMAT,
  type PluginProfile,
  type ScanAdvisory,
  type ScanFinding,
  type ScanResult,
  type StoredVerdict,
  type TriageConfig,
} from './types';

export const PROFILE: PluginProfile = {
  id: 'demo-web',
  name: 'Demo Web',
  enabled: true,
  ref: 'origin/main',
  fetch_before_scan: true,
  exclude: [],
  owners: [],
  criticality: 'high',
  exposure: 'internet-facing',
  data_classes: ['customer PII'],
  runtime: { language: 'typescript', framework: 'next' },
  deployments: [{ env: 'production', hosting: 'Vercel' }],
  third_party_services: [],
  mitigations: '',
  notes: '',
};

export const TRIAGE_CONFIG: TriageConfig = {
  name: 'v3-opus-high-code',
  promptVersion: 'v3',
  promptFingerprint: 'v3@1a2b3c4d',
  model: 'opus',
  effort: 'high',
  codeAccess: true,
  concurrency: 3,
  timeoutMinutes: 10,
  maxBudgetUsd: 3,
};

export function findingIdOf(f: Pick<ScanFinding, 'osvId' | 'ecosystem' | 'packageName' | 'lockfile'>): string {
  return `${f.osvId} ${f.ecosystem}:${f.packageName} ${f.lockfile}`;
}

export function makeFinding(o: Partial<ScanFinding> & Pick<ScanFinding, 'osvId' | 'packageName'>): ScanFinding {
  const base: ScanFinding = {
    id: '',
    lockfile: 'package-lock.json',
    ecosystem: 'npm',
    installedVersions: ['1.0.0'],
    fixedVersions: ['1.0.1'],
    direct: true,
    devOnly: false,
    paths: [[o.packageName]],
    instances: [{ version: o.installedVersions?.[0] ?? '1.0.0', direct: true, devOnly: false, paths: [[o.packageName]] }],
    importSites: [],
    importSiteCount: 0,
    advisoryModified: '2026-10-01T00:00:00Z',
    cves: [],
    malicious: false,
    inKev: false,
    kevDateAdded: null,
    kevRansomware: null,
    epss: null,
    epssPercentile: null,
    cvssScore: null,
    priority: 'P3',
    priorityReasons: ['no CVSS/EPSS signal'],
    inputHash: `hash-${o.osvId}-${o.packageName}`,
    ...o,
  };
  return { ...base, id: o.id ?? findingIdOf(base) };
}

export function makeAdvisory(o: Partial<ScanAdvisory> & Pick<ScanAdvisory, 'osvId'>): ScanAdvisory {
  return {
    aliases: [],
    cves: [],
    summary: `Test advisory ${o.osvId}`,
    details: 'Details.',
    cvssVector: null,
    cvssScore: null,
    severityLabel: null,
    cwes: [],
    references: [],
    published: '2026-09-01T00:00:00Z',
    modified: '2026-10-01T00:00:00Z',
    withdrawn: null,
    malicious: false,
    raw: { id: o.osvId },
    ...o,
  };
}

export function makeOutput(o: Partial<TriageOutput> = {}): TriageOutput {
  return {
    verdict: 'likely_not_affected',
    confidence: 'medium',
    runtime_usage: 'server',
    vulnerable_code_used: 'no',
    attacker_reachable: 'no',
    deployment_conditions_met: 'unknown',
    summary: 'A summary.',
    evidence: [],
    exploit_conditions: 'An attacker needs X.',
    remediation: 'Upgrade.',
    workaround: null,
    suggested_action: 'log',
    suggested_action_reason: 'Not reachable here. More detail follows.',
    ...o,
  };
}

export function makeVerdict(f: ScanFinding, output: Partial<TriageOutput> = {}, o: Partial<StoredVerdict> = {}): StoredVerdict {
  return {
    osvId: f.osvId,
    ecosystem: f.ecosystem,
    packageName: f.packageName,
    lockfile: f.lockfile,
    inputHash: f.inputHash,
    config: TRIAGE_CONFIG.name,
    prompt: TRIAGE_CONFIG.promptFingerprint,
    model: 'claude-opus-5-5',
    triagedAt: '2026-11-12T09:00:00.000Z',
    commit: 'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0',
    ref: 'main',
    costUsd: 0.12,
    durationMs: 21_000,
    output: makeOutput(output),
    ...o,
  };
}

export function makeScan(findings: ScanFinding[], advisories: ScanAdvisory[], o: Partial<ScanResult> = {}): ScanResult {
  return {
    format: STATE_FORMAT,
    toolVersion: '0.1.0',
    scannedAt: '2026-11-12T09:00:00.000Z',
    repoRoot: '/repos/demo-web',
    projectId: PROFILE.id,
    projectName: PROFILE.name,
    ref: 'HEAD',
    branch: 'main',
    commit: 'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0',
    commitDate: '2026-11-10T16:20:00+01:00',
    uncommittedDependencyFiles: [],
    snapshotDir: '/cache/snapshots/demo-web-12345678/a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0',
    lockfiles: ['package-lock.json'],
    skippedLockfiles: [],
    coverageGaps: [],
    ecosystems: ['npm'],
    warnings: [],
    data: { osvDbDate: '2026-11-12', kevCatalogDate: '2026-11-11', kevAvailable: true, epssDate: '2026-11-12', epssFailedCves: 0 },
    triageConfig: TRIAGE_CONFIG,
    profileHash: 'profilehash12',
    policyHash: 'policyhash12',
    stats: { packages: 812, vulnerablePackages: findings.length },
    findings: [...findings].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    advisories: Object.fromEntries(advisories.map((a) => [a.osvId, a])),
    ...o,
  };
}
