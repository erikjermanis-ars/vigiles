/**
 * Version ordering for display only (the Inbox's "upgrade to X"). Matching never uses this:
 * osv-scanner owns range matching (spec §3.3).
 */

interface ParsedVersion {
  main: string[];
  prerelease: string[] | null;
}

function parseVersion(v: string): ParsedVersion {
  const m = /^v?([^-+]*)(?:-([^+]*))?(?:\+.*)?$/i.exec(v.trim());
  const main = (m?.[1] ?? v).split('.');
  const pre = m?.[2];
  return { main, prerelease: pre ? pre.split('.') : null };
}

const isNumeric = (s: string) => /^\d+$/.test(s);

function compareIdentifier(a: string, b: string): number {
  if (isNumeric(a) && isNumeric(b)) return Math.sign(Number(a) - Number(b));
  // semver: numeric identifiers sort before alphanumeric ones
  if (isNumeric(a)) return -1;
  if (isNumeric(b)) return 1;
  return Math.sign(a.localeCompare(b, 'en', { numeric: true }));
}

/** Compares dot segments numerically ("1.10" > "1.9"); missing segments count as 0; "1.0.0-rc.1" < "1.0.0". */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.main.length, pb.main.length);
  for (let i = 0; i < len; i++) {
    const c = compareIdentifier(pa.main[i] || '0', pb.main[i] || '0');
    if (c !== 0) return c;
  }
  if (!pa.prerelease && !pb.prerelease) return 0;
  if (!pa.prerelease) return 1;
  if (!pb.prerelease) return -1;
  const plen = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < plen; i++) {
    const x = pa.prerelease[i];
    const y = pb.prerelease[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const c = compareIdentifier(x, y);
    if (c !== 0) return c;
  }
  return 0;
}

/**
 * A release version ("16.2.13", "v2.0.0-rc.1", "2.0.0a1"), as opposed to the commit SHAs that OSV GIT
 * ranges put in `fixed` events. A SHA is no upgrade target, and the compare above would rank it highest.
 */
export function isReleaseVersion(v: string): boolean {
  return /^v?\d+(\.[0-9A-Za-z]+)*([-+].*)?$/i.test(v.trim());
}

/** Highest release version in the list, or null when it has none. */
export function highestVersion(versions: readonly string[]): string | null {
  let best: string | null = null;
  for (const v of versions) {
    if (!isReleaseVersion(v)) continue;
    if (best === null || compareVersions(v, best) > 0) best = v;
  }
  return best;
}

const isPrerelease = (v: string) => parseVersion(v).prerelease !== null;

function lowestVersion(versions: readonly string[]): string | null {
  let best: string | null = null;
  for (const v of versions) if (best === null || compareVersions(v, best) < 0) best = v;
  return best;
}

/**
 * The version one advisory asks you to upgrade to. OSV lists one `fixed` per release line
 * (storybook: 8.6.19, 9.1.21, 10.6.2, 11.0.0-alpha.6), so the highest entry is usually the wrong advice:
 * from 10.5.5 the fix is 10.6.2, not a pre-release of the next major. Picks the lowest stable fix above the
 * highest installed version, else the lowest pre-release above it, else the highest fix overall. Display only.
 */
export function upgradeTarget(installed: readonly string[], fixed: readonly string[]): string | null {
  const releases = fixed.filter(isReleaseVersion);
  const current = highestVersion(installed);
  if (current === null) return highestVersion(releases);
  const ahead = releases.filter((v) => compareVersions(v, current) > 0);
  return lowestVersion(ahead.filter((v) => !isPrerelease(v))) ?? lowestVersion(ahead) ?? highestVersion(releases);
}
