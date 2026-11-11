import { describe, expect, it } from 'vitest';
import { openDb } from '../db/client';
import { kev } from '../db/schema';
import { getFeedState } from './feed-state';
import { HttpError, USER_AGENT } from './http';
import { fetchKevFeed, KEV_FEED_URL, kevRowsFromFeed, loadKevIndex, matchKev, parseKevFeed, replaceKevCatalog } from './kev';
import { jsonResponse, kevFeed, stubFetch } from './test-support';

describe('parseKevFeed', () => {
  it('accepts the CISA shape and ignores unknown fields', () => {
    const feed = parseKevFeed(kevFeed([{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }]));
    expect(feed.catalogVersion).toBe('2026.11.10');
    expect(feed.vulnerabilities[0]).toMatchObject({ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10', knownRansomwareCampaignUse: 'Unknown' });
    expect(feed.vulnerabilities[0]).not.toHaveProperty('cwes');
  });

  it('normalizes CVE IDs', () => {
    const feed = parseKevFeed(kevFeed([{ cveID: ' cve-2021-44228 ', dateAdded: '2021-12-10' }]));
    expect(feed.vulnerabilities[0]!.cveID).toBe('CVE-2021-44228');
  });

  it('accepts null optional text fields', () => {
    const json = kevFeed([{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }]);
    const v = json.vulnerabilities[0] as Record<string, unknown>;
    v.dueDate = null;
    v.knownRansomwareCampaignUse = undefined;
    expect(parseKevFeed(json).vulnerabilities[0]!.dueDate).toBeNull();
  });

  it.each([
    ['an empty catalog', kevFeed([])],
    ['a malformed CVE ID', kevFeed([{ cveID: 'GHSA-xxxx-yyyy-zzzz', dateAdded: '2021-12-10' }])],
    ['a missing dateAdded', { ...kevFeed([]), vulnerabilities: [{ cveID: 'CVE-2021-44228' }] }],
    ['a missing catalogVersion', { dateReleased: 'x', count: 1, vulnerabilities: kevFeed([{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }]).vulnerabilities }],
    ['an HTML error page', '<html>Access denied</html>'],
  ])('rejects %s', (_name, json) => {
    expect(() => parseKevFeed(json)).toThrow(/KEV feed failed validation/);
  });
});

describe('kevRowsFromFeed', () => {
  it('maps fields and keeps one row per CVE with the earliest dateAdded', () => {
    const rows = kevRowsFromFeed(
      parseKevFeed(
        kevFeed([
          { cveID: 'CVE-2024-0001', dateAdded: '2024-05-01' },
          { cveID: 'CVE-2024-0001', dateAdded: '2024-03-01' },
          { cveID: 'CVE-2024-0002', dateAdded: '2024-06-01' },
        ]),
      ),
    );
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.cve === 'CVE-2024-0001')).toEqual({
      cve: 'CVE-2024-0001',
      dateAdded: '2024-03-01',
      dueDate: '2027-01-01',
      ransomware: 'Unknown',
      vendor: 'Vendor',
      product: 'Product',
      name: 'Vuln CVE-2024-0001',
      shortDescription: 'A synthetic entry.',
    });
  });
});

describe('replaceKevCatalog', () => {
  it('replaces the table and records feed_state', () => {
    const db = openDb(':memory:');
    replaceKevCatalog(db, parseKevFeed(kevFeed([{ cveID: 'CVE-2020-0001', dateAdded: '2020-01-01' }])), '2026-11-01T00:00:00.000Z');
    const { count } = replaceKevCatalog(
      db,
      parseKevFeed(
        kevFeed([
          { cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' },
          { cveID: 'CVE-2023-4966', dateAdded: '2023-10-18' },
        ]),
      ),
      '2026-11-10T00:00:00.000Z',
    );
    expect(count).toBe(2);
    expect(db.select({ cve: kev.cve }).from(kev).all().map((r) => r.cve).sort()).toEqual(['CVE-2021-44228', 'CVE-2023-4966']);
    expect(getFeedState(db, 'kev')).toEqual({
      feed: 'kev',
      lastAttemptAt: '2026-11-10T00:00:00.000Z',
      lastSuccessAt: '2026-11-10T00:00:00.000Z',
      lastError: null,
      meta: { catalogVersion: '2026.11.10', dateReleased: '2026-11-10T15:00:00.000Z', count: 2 },
    });
  });

  it('inserts large catalogs in chunks', () => {
    const db = openDb(':memory:');
    const entries = Array.from({ length: 1234 }, (_, i) => ({ cveID: `CVE-2024-${String(i + 1).padStart(5, '0')}`, dateAdded: '2024-01-01' }));
    expect(replaceKevCatalog(db, parseKevFeed(kevFeed(entries))).count).toBe(1234);
    expect(loadKevIndex(db).size).toBe(1234);
  });
});

describe('matchKev', () => {
  const index = new Map<string, string | null>([
    ['CVE-2021-44228', '2021-12-10'],
    ['CVE-2021-45046', '2023-05-01'],
    ['CVE-2099-0001', null],
  ]);

  it('returns the earliest dateAdded among matching CVEs', () => {
    expect(matchKev(['CVE-2021-45046', 'CVE-2021-44228', 'CVE-2000-1234'], index)).toEqual({ inKev: true, dateAdded: '2021-12-10' });
  });
  it('matches a CVE without a date', () => {
    expect(matchKev(['CVE-2099-0001'], index)).toEqual({ inKev: true, dateAdded: null });
  });
  it('is false for no or unknown CVEs', () => {
    expect(matchKev([], index)).toEqual({ inKev: false, dateAdded: null });
    expect(matchKev(['CVE-2000-1234'], index)).toEqual({ inKev: false, dateAdded: null });
  });
});

describe('fetchKevFeed', () => {
  it('GETs the CISA feed with the vigiles User-Agent and an abort signal', async () => {
    const fetchFn = stubFetch(() => jsonResponse(kevFeed([{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }])));
    const feed = await fetchKevFeed({ fetchFn, signal: new AbortController().signal });
    expect(feed.vulnerabilities).toHaveLength(1);
    expect(fetchFn.calls[0]!.url).toBe(KEV_FEED_URL);
    expect(new Headers(fetchFn.calls[0]!.init?.headers).get('user-agent')).toBe(USER_AGENT);
    expect(fetchFn.calls[0]!.init?.signal).toBeInstanceOf(AbortSignal);
  });

  it('throws HttpError on a non-2xx response and releases its body', async () => {
    const res = new Response('nope', { status: 503, statusText: 'Service Unavailable' });
    const fetchFn = stubFetch(() => res);
    await expect(fetchKevFeed({ fetchFn })).rejects.toBeInstanceOf(HttpError);
    await expect(res.text()).rejects.toThrow(); // the body was cancelled, not left open
  });

  it('aborts when the job is cancelled', async () => {
    const controller = new AbortController();
    const fetchFn = stubFetch(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init!.signal!;
          signal.addEventListener('abort', () => reject(signal.reason));
        }),
    );
    const pending = fetchKevFeed({ fetchFn, signal: controller.signal });
    controller.abort(new Error('cancelled by user'));
    await expect(pending).rejects.toThrow('cancelled by user');
  });
});
