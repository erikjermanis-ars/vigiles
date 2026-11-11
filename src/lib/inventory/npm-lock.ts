/**
 * Dependency facts from package-lock.json v2/v3 (spec §7.3): installed instances, direct, dev_only,
 * and the shortest dependency chains from the root, resolved the way Node resolves modules.
 */

interface LockEntry {
  name?: string;
  version?: string;
  resolved?: string;
  link?: boolean;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  workspaces?: unknown;
}

export interface NpmInstance {
  /** Key in the lockfile's `packages` map, e.g. `node_modules/a/node_modules/b` */
  key: string;
  name: string;
  version: string;
  dev: boolean;
  optional: boolean;
  devOptional: boolean;
}

export interface NpmLockGraph {
  /** Instances by package name (link entries excluded; their targets are instances) */
  instances: Map<string, NpmInstance[]>;
  /** Names the root declares in dependencies, devDependencies or optionalDependencies */
  directNames: Set<string>;
  /** Keys those root declarations resolve to (the directly installed instances) */
  directKeys: Set<string>;
  /** Keys the root depends on (its declared deps plus workspace members) */
  rootEdges: string[];
  /** Resolved dependency keys per package key (links followed) */
  edges(key: string): string[];
  nameOf(key: string): string;
}

export class NpmLockfileError extends Error {}

const NODE_MODULES = 'node_modules/';

function nameFromKey(key: string): string {
  const i = key.lastIndexOf(NODE_MODULES);
  if (i >= 0) return key.slice(i + NODE_MODULES.length);
  return key.split('/').pop() ?? key;
}

/** True for the root and for workspace/link targets, whose devDependencies get installed too. */
function isProjectDir(key: string): boolean {
  return key === '' || !(key.startsWith(NODE_MODULES) || key.includes(`/${NODE_MODULES}`));
}

function declaredDeps(entry: LockEntry, includeDev: boolean): string[] {
  const names = [
    ...Object.keys(entry.dependencies ?? {}),
    ...Object.keys(entry.optionalDependencies ?? {}),
    ...Object.keys(entry.peerDependencies ?? {}),
    ...(includeDev ? Object.keys(entry.devDependencies ?? {}) : []),
  ];
  return [...new Set(names)];
}

export function parsePackageLock(text: string, file = 'package-lock.json'): NpmLockGraph {
  let json: { lockfileVersion?: number; packages?: Record<string, LockEntry> };
  try {
    json = JSON.parse(text) as typeof json;
  } catch (err) {
    throw new NpmLockfileError(`${file}: invalid JSON (${(err as Error).message})`);
  }
  if (!json.packages || typeof json.packages !== 'object') {
    const v = json.lockfileVersion ?? 'unknown';
    throw new NpmLockfileError(
      `${file}: lockfileVersion ${v} has no "packages" map; only lockfile v2/v3 (npm 7+) are supported. Regenerate it with a current npm.`,
    );
  }
  return buildGraph(new Map(Object.entries(json.packages)));
}

function buildGraph(packages: Map<string, LockEntry>): NpmLockGraph {
  const root = packages.get('') ?? {};

  const nameOf = (key: string): string => packages.get(key)?.name ?? nameFromKey(key);

  /** Follows `link: true` entries (workspaces, file: deps) to their target key. */
  const followLink = (key: string): string | undefined => {
    const entry = packages.get(key);
    if (!entry) return undefined;
    if (!entry.link) return key;
    return entry.resolved !== undefined && packages.has(entry.resolved) ? entry.resolved : undefined;
  };

  /** Node resolution: <dir>/node_modules/<dep> for the package dir and each ancestor (never inside a node_modules dir). */
  const resolve = (fromKey: string, dep: string): string | undefined => {
    const segments = fromKey ? fromKey.split('/') : [];
    for (let i = segments.length; i >= 0; i--) {
      if (i > 0 && segments[i - 1] === 'node_modules') continue;
      const dir = segments.slice(0, i).join('/');
      const candidate = dir ? `${dir}/${NODE_MODULES}${dep}` : `${NODE_MODULES}${dep}`;
      if (packages.has(candidate)) return followLink(candidate);
    }
    return undefined;
  };

  const edgeCache = new Map<string, string[]>();
  const edges = (key: string): string[] => {
    let out = edgeCache.get(key);
    if (out) return out;
    const entry = packages.get(key);
    out = [];
    if (entry) {
      for (const dep of declaredDeps(entry, isProjectDir(key))) {
        const target = resolve(key, dep);
        if (target !== undefined && target !== key && !out.includes(target)) out.push(target);
      }
    }
    edgeCache.set(key, out);
    return out;
  };

  const instances = new Map<string, NpmInstance[]>();
  for (const [key, entry] of packages) {
    if (key === '' || entry.link || !entry.version) continue;
    const inst: NpmInstance = {
      key,
      name: nameOf(key),
      version: entry.version,
      dev: entry.dev === true,
      optional: entry.optional === true,
      devOptional: entry.devOptional === true,
    };
    const list = instances.get(inst.name);
    if (list) list.push(inst);
    else instances.set(inst.name, [inst]);
  }

  const rootEdges = [...edges('')];
  if (root.workspaces !== undefined) {
    for (const [key, entry] of packages) {
      const topLevel = key.startsWith(NODE_MODULES) && !key.slice(NODE_MODULES.length).includes(`/${NODE_MODULES}`);
      const target = entry.link && topLevel ? followLink(key) : undefined;
      if (target !== undefined && !rootEdges.includes(target)) rootEdges.push(target);
    }
  }

  // Resolved names cover npm aliases ("string-width-cjs": "npm:string-width@4"); raw keys cover unresolved deps.
  const directNames = new Set<string>();
  const directKeys = new Set<string>();
  const rootDirect = [root.dependencies, root.devDependencies, root.optionalDependencies];
  for (const deps of rootDirect) {
    for (const dep of Object.keys(deps ?? {})) {
      directNames.add(dep);
      const target = resolve('', dep);
      if (target === undefined) continue;
      directNames.add(nameOf(target));
      directKeys.add(target);
    }
  }

  return { instances, directNames, directKeys, rootEdges, edges, nameOf };
}

export function instancesOf(graph: NpmLockGraph, name: string, versions?: Iterable<string>): NpmInstance[] {
  const all = graph.instances.get(name) ?? [];
  if (!versions) return all;
  const wanted = new Set(versions);
  return all.filter((i) => wanted.has(i.version));
}

/**
 * Whether the root declares the package. With `versions`, only when one of those versions is the
 * instance the root resolves to: next's nested postcss@8.4.31 is transitive even though the root
 * also depends on postcss@8.5.
 */
export function isDirect(graph: NpmLockGraph, name: string, versions?: Iterable<string>): boolean {
  if (!versions) return graph.directNames.has(name);
  const list = instancesOf(graph, name, versions);
  if (list.length === 0) return graph.directNames.has(name);
  return list.some((i) => graph.directKeys.has(i.key));
}

/** True when every matching instance is dev-only; null when no instance matches (caller decides). */
export function isDevOnly(graph: NpmLockGraph, name: string, versions?: Iterable<string>): boolean | null {
  const list = instancesOf(graph, name, versions);
  if (list.length === 0) return null;
  return list.every((i) => i.dev || i.devOptional);
}

/**
 * Up to `max` shortest dependency chains from the root to an instance of `name` (restricted to
 * `versions` when given), each as package names from the direct dependency down to the package,
 * e.g. ['shadcn', '@modelcontextprotocol/sdk', 'express', 'proxy-addr'].
 *
 * Breadth-first over paths where each package key is expanded at most `max` times, which yields
 * the k shortest chains without enumerating every path in the graph.
 */
export function shortestPaths(graph: NpmLockGraph, name: string, versions?: Iterable<string>, max = 3): string[][] {
  const targets = new Set(instancesOf(graph, name, versions).map((i) => i.key));
  if (targets.size === 0) return [];

  const expansions = new Map<string, number>();
  const found: string[][] = [];
  const seen = new Set<string>();
  const queue: string[][] = graph.rootEdges.map((k) => [k]);

  for (let head = 0; head < queue.length && found.length < max; head++) {
    const chain = queue[head]!;
    const key = chain[chain.length - 1]!;
    const count = expansions.get(key) ?? 0;
    if (count >= max) continue;
    expansions.set(key, count + 1);

    if (targets.has(key)) {
      const names = chain.map((k) => graph.nameOf(k));
      const signature = names.join('\0');
      if (!seen.has(signature)) {
        seen.add(signature);
        found.push(names);
      }
      continue;
    }
    for (const next of graph.edges(key)) {
      if (!chain.includes(next)) queue.push([...chain, next]);
    }
  }
  return found;
}
