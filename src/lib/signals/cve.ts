export const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;

/** Sorted, de-duplicated, upper-cased CVE IDs; anything that isn't a CVE ID is dropped (EPSS puts them in a URL). */
export function normalizeCves(cves: Iterable<string>): string[] {
  const set = new Set<string>();
  for (const c of cves) {
    const id = c.trim().toUpperCase();
    if (CVE_ID_RE.test(id)) set.add(id);
  }
  return [...set].sort();
}
