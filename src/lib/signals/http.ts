/** Minimal JSON-over-HTTPS helper for the KEV and EPSS feeds (spec §15: the only outbound calls besides git/osv/claude). */

export const USER_AGENT = 'vigiles-poc';

/** The subset of `fetch` the feeds use; tests pass a stub. */
export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

export class HttpError extends Error {
  constructor(
    public url: string,
    public status: number,
    statusText: string,
  ) {
    super(`GET ${url} → HTTP ${status} ${statusText}`.trim());
  }
}

export interface FetchJsonOptions {
  fetchFn?: FetchFn;
  /** Cancellation from the job; combined with the timeout. */
  signal?: AbortSignal;
  timeoutMs: number;
}

export async function fetchJson(url: string, opts: FetchJsonOptions): Promise<unknown> {
  const fetchFn = opts.fetchFn ?? fetch;
  const timeout = AbortSignal.timeout(opts.timeoutMs);
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
  const res = await fetchFn(url, { headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' }, signal });
  if (!res.ok) {
    // Release the unread error body so the connection is not held until GC.
    await res.body?.cancel().catch(() => {});
    throw new HttpError(url, res.status, res.statusText);
  }
  return res.json();
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    // AbortSignal.timeout rejects with a DOMException named TimeoutError, whose message is vague.
    if (err.name === 'TimeoutError') return `timed out: ${err.message}`;
    const cause = (err as { cause?: unknown }).cause;
    return cause instanceof Error ? `${err.message} (${cause.message})` : err.message;
  }
  return String(err);
}
