import { describe, expect, it } from 'vitest';
import { normalizeCves } from './cve';
import { chunk, EPSS_API_URL, epssUrl, fetchEpssScores, maxEpss, parseEpssResponse } from './epss';
import { USER_AGENT } from './http';
import { epssApiStub, jsonResponse, stubFetch } from './test-support';

const cveList = (n: number, year = 2025) => Array.from({ length: n }, (_, i) => `CVE-${year}-${String(i + 1).padStart(5, '0')}`);

describe('parseEpssResponse', () => {
  it('parses the decimal strings the API returns', () => {
    const scores = parseEpssResponse({
      status: 'OK',
      data: [
        { cve: 'CVE-2021-44228', epss: '0.944240000', percentile: '0.999950000', date: '2026-11-09' },
        { cve: 'cve-2025-29927', epss: 0.5, percentile: 0.98, date: '2026-11-09' },
      ],
    });
    expect(scores.get('CVE-2021-44228')).toEqual({ epss: 0.94424, percentile: 0.99995, date: '2026-11-09' });
    expect(scores.get('CVE-2025-29927')).toEqual({ epss: 0.5, percentile: 0.98, date: '2026-11-09' });
  });

  it('accepts an empty result (CVEs without a score are simply absent)', () => {
    expect(parseEpssResponse({ data: [] }).size).toBe(0);
  });

  it.each([
    ['a non-numeric score', { data: [{ cve: 'CVE-2021-44228', epss: 'n/a', percentile: '0.5' }] }],
    ['an empty score', { data: [{ cve: 'CVE-2021-44228', epss: ' ', percentile: '0.5' }] }],
    ['a score above 1', { data: [{ cve: 'CVE-2021-44228', epss: '1.5', percentile: '0.5' }] }],
    ['a missing data array', { status: 'error', message: 'rate limited' }],
  ])('rejects %s', (_name, json) => {
    expect(() => parseEpssResponse(json)).toThrow(/EPSS response failed validation/);
  });
});

describe('CVE helpers', () => {
  it('normalizeCves dedupes, upper-cases, sorts and drops non-CVE IDs', () => {
    expect(normalizeCves(['cve-2025-29927', 'CVE-2021-44228', 'CVE-2025-29927 ', 'GHSA-f82v-jwr5-mffw', 'CVE-2021-44228&x=1'])).toEqual([
      'CVE-2021-44228',
      'CVE-2025-29927',
    ]);
  });

  it('chunk splits into fixed-size batches', () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 100)).toEqual([]);
  });

  it('epssUrl builds a comma list', () => {
    expect(epssUrl(['CVE-2021-44228', 'CVE-2025-29927'])).toBe(`${EPSS_API_URL}?cve=CVE-2021-44228,CVE-2025-29927`);
  });
});

describe('fetchEpssScores', () => {
  it('queries in batches of 100 with deduplicated CVEs', async () => {
    const cves = cveList(250);
    const fetchFn = epssApiStub(Object.fromEntries(cves.map((c, i) => [c, i / 1000])));
    const batches: string[] = [];
    const result = await fetchEpssScores([...cves, ...cves.slice(0, 10)], { fetchFn, onBatch: (i, n) => batches.push(`${i + 1}/${n}`) });

    expect(fetchFn.calls.map((c) => new URL(c.url).searchParams.get('cve')!.split(',').length)).toEqual([100, 100, 50]);
    expect(new Set(fetchFn.calls.flatMap((c) => new URL(c.url).searchParams.get('cve')!.split(','))).size).toBe(250);
    expect(new Headers(fetchFn.calls[0]!.init?.headers).get('user-agent')).toBe(USER_AGENT);
    expect(fetchFn.calls[0]!.init?.signal).toBeInstanceOf(AbortSignal);
    expect(batches).toEqual(['1/3', '2/3', '3/3']);
    expect(result.scores.size).toBe(250);
    expect(result.failedCves.size).toBe(0);
    expect(result.errors).toEqual([]);
    expect(result.date).toBe('2026-11-09');
  });

  it('makes no request when there are no CVEs', async () => {
    const fetchFn = epssApiStub({});
    const result = await fetchEpssScores([], { fetchFn });
    expect(fetchFn.calls).toHaveLength(0);
    expect(result).toEqual({ scores: new Map(), failedCves: new Set(), errors: [], date: null });
  });

  it('is fail-soft per batch on HTTP and network errors', async () => {
    const cves = cveList(300);
    let call = 0;
    const fetchFn = stubFetch(async (url) => {
      call++;
      if (call === 2) return new Response('busy', { status: 503, statusText: 'Service Unavailable' });
      if (call === 3) throw new TypeError('fetch failed', { cause: new Error('ECONNRESET') });
      return epssApiStub({ [cves[0]!]: 0.3 })(url);
    });
    const result = await fetchEpssScores(cves, { fetchFn });

    expect(result.scores.size).toBe(1);
    expect(result.failedCves.size).toBe(200);
    expect(result.failedCves.has(cves[100]!)).toBe(true);
    expect(result.failedCves.has(cves[0]!)).toBe(false);
    expect(result.errors).toEqual([expect.stringContaining('batch 2/3: GET'), 'batch 3/3: fetch failed (ECONNRESET)']);
    expect(result.errors[0]).toContain('HTTP 503');
  });

  it('treats an invalid response body as a failed batch', async () => {
    const fetchFn = stubFetch(() => jsonResponse({ status: 'error' }));
    const result = await fetchEpssScores(['CVE-2021-44228'], { fetchFn });
    expect([...result.failedCves]).toEqual(['CVE-2021-44228']);
    expect(result.errors[0]).toMatch(/failed validation/);
  });

  it('treats a timeout as a failed batch, not as a cancel', async () => {
    const controller = new AbortController();
    const hang = stubFetch(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init!.signal!.addEventListener('abort', () => reject(init!.signal!.reason));
        }),
    );
    const result = await fetchEpssScores(['CVE-2021-44228'], { fetchFn: hang, signal: controller.signal, timeoutMs: 20 });
    expect([...result.failedCves]).toEqual(['CVE-2021-44228']);
    expect(result.errors).toEqual([expect.stringMatching(/^batch 1\/1: timed out/)]);
    expect(controller.signal.aborted).toBe(false);
  });

  it('rethrows when the job is cancelled instead of swallowing it', async () => {
    const controller = new AbortController();
    const fetchFn = stubFetch(async () => {
      controller.abort();
      throw new DOMException('aborted', 'AbortError');
    });
    await expect(fetchEpssScores(['CVE-2021-44228'], { fetchFn, signal: controller.signal })).rejects.toThrow('aborted');
  });
});

describe('maxEpss', () => {
  const scores = new Map([
    ['CVE-2025-0001', { epss: 0.2, percentile: 0.9, date: null }],
    ['CVE-2025-0002', { epss: 0.7, percentile: 0.99, date: null }],
  ]);

  it('returns the highest score with its own percentile', () => {
    expect(maxEpss(['CVE-2025-0001', 'CVE-2025-0002', 'CVE-2025-0003'], scores)).toEqual({ epss: 0.7, percentile: 0.99 });
  });
  it('is null when no CVE is scored', () => {
    expect(maxEpss(['CVE-2025-0003'], scores)).toBeNull();
    expect(maxEpss([], scores)).toBeNull();
  });
});
