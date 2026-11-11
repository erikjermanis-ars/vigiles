/**
 * Turns osv-scanner results plus our dependency facts into what one scan observed: inventory rows,
 * findings keyed per §7.5, and advisory rows. Pure apart from the lazily built import index.
 */
import path from 'node:path';
import { advisoryFromRecord, fixedVersionsFor, type AdvisoryInsert, type OsvPackage, type OsvRecord } from '../osv/output';
import type { FindingInstance, ImportSite } from '../types';
import { searchImportSites, type ImportIndex } from './import-sites';
import { isDevOnly, isDirect, shortestPaths, type NpmLockGraph } from './npm-lock';

export interface LockfileScan {
  /** Repo-relative lockfile path */
  lockfile: string;
  /** osv-scanner's packages for this lockfile */
  packages: OsvPackage[];
  /** Dependency graph when the lockfile is a parsed package-lock.json */
  npmGraph?: NpmLockGraph | null;
}

export interface InventoryItem {
  lockfile: string;
  ecosystem: string;
  name: string;
  version: string;
  direct: boolean | null;
  devOnly: boolean;
}

export interface ObservedFinding {
  lockfile: string;
  ecosystem: string;
  packageName: string;
  osvId: string;
  installedVersions: string[];
  fixedVersions: string[];
  /** Merged over instances: any instance is direct (null = unknown) */
  direct: boolean | null;
  /** Merged over instances: every instance is dev-only */
  devOnly: boolean;
  /** Merged over instances: the 3 shortest chains to any instance */
  paths: string[][];
  /** Facts per installed version, sorted like installedVersions */
  instances: FindingInstance[];
  /** At most MAX_IMPORT_SITES */
  importSites: ImportSite[];
  /** Uncapped number of import sites */
  importSiteCount: number;
  advisoryModified: string | null;
}

export interface ScanObservation {
  inventory: InventoryItem[];
  findings: ObservedFinding[];
  advisories: AdvisoryInsert[];
  /** Distinct lockfile+name+version entries */
  packages: number;
  /** Distinct lockfile+name+version entries with at least one advisory */
  vulnerablePackages: number;
}

export interface ObserveOptions {
  /** Called at most once, on first use (only when an npm graph finding needs import sites) */
  importIndex?: () => ImportIndex;
}

export function findingKey(f: Pick<ObservedFinding, 'lockfile' | 'ecosystem' | 'packageName' | 'osvId'>): string {
  return [f.lockfile, f.ecosystem, f.packageName, f.osvId].join('\0');
}

export function lockfileDir(lockfile: string): string {
  const dir = path.posix.dirname(lockfile);
  return dir === '.' ? '' : dir;
}

const byVersion = (a: string, b: string) => a.localeCompare(b, 'en', { numeric: true });

interface FindingAccumulator {
  lockfile: string;
  ecosystem: string;
  name: string;
  osvId: string;
  graph: NpmLockGraph | null;
  versions: Set<string>;
  devByVersion: Map<string, boolean>;
  records: Map<string, OsvRecord>;
}

function buildInventory(scan: LockfileScan): InventoryItem[] {
  const items = new Map<string, InventoryItem>();
  const graph = scan.npmGraph ?? null;
  for (const p of scan.packages) {
    const key = `${p.ecosystem}\0${p.name}\0${p.version}`;
    const existing = items.get(key);
    if (existing) {
      existing.devOnly = existing.devOnly && p.dev;
      continue;
    }
    items.set(key, {
      lockfile: scan.lockfile,
      ecosystem: p.ecosystem,
      name: p.name,
      version: p.version,
      direct: graph ? isDirect(graph, p.name, [p.version]) : null,
      devOnly: graph ? (isDevOnly(graph, p.name, [p.version]) ?? p.dev) : p.dev,
    });
  }
  return [...items.values()];
}

/** Facts for each installed version on its own (spec §7.3), so one instance's facts never stand in for another's. */
function instanceFacts(acc: FindingAccumulator, versions: string[]): FindingInstance[] {
  const graph = acc.graph;
  return versions.map((version): FindingInstance => {
    const osvDev = acc.devByVersion.get(version) === true;
    if (!graph) return { version, direct: null, devOnly: osvDev, paths: [] };
    return {
      version,
      direct: isDirect(graph, acc.name, [version]),
      devOnly: isDevOnly(graph, acc.name, [version]) ?? osvDev,
      paths: shortestPaths(graph, acc.name, [version]),
    };
  });
}

/**
 * Packages whose imports show where the vulnerable code is used: the package itself for instances the
 * root depends on directly, plus the direct dependencies at the head of every transitive instance's paths.
 */
function importSearchFor(name: string, instances: FindingInstance[]): string[] {
  const out = new Set<string>();
  if (instances.some((i) => i.direct)) out.add(name);
  for (const i of instances) {
    if (i.direct) continue;
    for (const p of i.paths) if (p[0]) out.add(p[0]);
  }
  return [...out];
}

function finalizeFinding(acc: FindingAccumulator, opts: ObserveOptions, npmLockfileDirs: string[]): ObservedFinding {
  const versions = [...acc.versions].sort(byVersion);
  const records = [...acc.records.values()];
  const graph = acc.graph;
  const instances = instanceFacts(acc, versions);

  // Merged view for filters and policy inputs (direct = any instance, dev_only = every instance).
  let direct: boolean | null = null;
  const devOnly = instances.every((i) => i.devOnly);
  let paths: string[][] = [];
  let importSites: ImportSite[] = [];
  let importSiteCount = 0;
  if (graph) {
    direct = instances.some((i) => i.direct === true);
    paths = shortestPaths(graph, acc.name, versions);
    const searchFor = importSearchFor(acc.name, instances);
    if (opts.importIndex && searchFor.length) {
      const found = searchImportSites(opts.importIndex(), {
        lockfileDir: lockfileDir(acc.lockfile),
        allLockfileDirs: npmLockfileDirs,
        packages: searchFor,
      });
      importSites = found.sites;
      importSiteCount = found.total;
    }
  }

  return {
    lockfile: acc.lockfile,
    ecosystem: acc.ecosystem,
    packageName: acc.name,
    osvId: acc.osvId,
    installedVersions: versions,
    fixedVersions: fixedVersionsFor(records, acc.name, acc.ecosystem),
    direct,
    devOnly,
    paths,
    instances,
    importSites,
    importSiteCount,
    advisoryModified: acc.records.get(acc.osvId)?.modified ?? null,
  };
}

export function observeScan(scans: LockfileScan[], opts: ObserveOptions = {}): ScanObservation {
  let index: ImportIndex | undefined;
  const build = opts.importIndex;
  const memoized: ObserveOptions = build ? { importIndex: () => (index ??= build()) } : {};
  const inventory: InventoryItem[] = [];
  const advisories = new Map<string, AdvisoryInsert>();
  const accumulators = new Map<string, FindingAccumulator>();
  const vulnerable = new Set<string>();
  const npmLockfileDirs = scans.filter((s) => s.npmGraph).map((s) => lockfileDir(s.lockfile));

  for (const scan of scans) {
    inventory.push(...buildInventory(scan));
    for (const p of scan.packages) {
      for (const group of p.groups) {
        for (const record of group.records) {
          const groupAliases = record.id === group.osvId ? group.aliases : [];
          if (!advisories.has(record.id)) advisories.set(record.id, advisoryFromRecord(record, group.maxSeverity, groupAliases));
        }
        const representative = group.records.find((r) => r.id === group.osvId);
        // A withdrawn advisory no longer matches; its row is still stored above for the record.
        if (!representative || representative.withdrawn) continue;
        vulnerable.add(`${scan.lockfile}\0${p.ecosystem}\0${p.name}\0${p.version}`);

        const key = findingKey({ lockfile: scan.lockfile, ecosystem: p.ecosystem, packageName: p.name, osvId: group.osvId });
        let acc = accumulators.get(key);
        if (!acc) {
          acc = {
            lockfile: scan.lockfile,
            ecosystem: p.ecosystem,
            name: p.name,
            osvId: group.osvId,
            graph: scan.npmGraph ?? null,
            versions: new Set(),
            devByVersion: new Map(),
            records: new Map(),
          };
          accumulators.set(key, acc);
        }
        acc.versions.add(p.version);
        acc.devByVersion.set(p.version, (acc.devByVersion.get(p.version) ?? true) && p.dev);
        for (const r of group.records) if (!acc.records.has(r.id)) acc.records.set(r.id, r);
      }
    }
  }

  const findings = [...accumulators.values()]
    .map((acc) => finalizeFinding(acc, memoized, npmLockfileDirs))
    .sort((a, b) => findingKey(a).localeCompare(findingKey(b)));

  return {
    inventory,
    findings,
    advisories: [...advisories.values()],
    packages: inventory.length,
    vulnerablePackages: vulnerable.size,
  };
}
