/**
 * DNS-rebinding guard (review #6). Binding to 127.0.0.1 is not enough: a page on an attacker's
 * domain that re-resolves to 127.0.0.1 is same-origin with that name, so the browser lets it read
 * the dashboard and post server actions (their Origin check compares Origin with Host, which then
 * match). The browser always sends the attacker's name as Host, and scripts cannot set Host, so
 * refusing every Host that is not a loopback name closes it.
 *
 * Next 16 runs this proxy (formerly middleware) before every request when no `config.matcher` is
 * exported: pages, RSC fetches, server-action POSTs, route handlers and `/_next` assets. Do not add
 * a matcher, or the excluded paths (and the server actions on them) lose the check.
 */
import { NextResponse, type NextRequest } from 'next/server';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

/**
 * True when a Host header addresses the local dashboard: the hostname is exactly `127.0.0.1`,
 * `localhost` or `[::1]` (case-insensitive), optionally with `:<port>`, any port. Everything else is
 * refused, including a missing header and other names that also reach loopback (`127.1`,
 * `localhost.`, `x.localhost`, `[0:0:0:0:0:0:0:1]`): only these three are what you type.
 */
export function isAllowedHost(host: string | null | undefined): boolean {
  if (!host) return false;
  const m = /^(\[[^\]]*\]|[^:[\]]+)(?::(\d{1,5}))?$/.exec(host);
  if (!m) return false;
  if (m[2] !== undefined && Number(m[2]) > 65_535) return false;
  return LOOPBACK_HOSTS.has(m[1]!.toLowerCase());
}

export function proxy(request: NextRequest): NextResponse {
  if (isAllowedHost(request.headers.get('host'))) return NextResponse.next();
  return new NextResponse('Forbidden: Vigiles only answers requests addressed to 127.0.0.1, localhost or [::1].\n', {
    status: 403,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
  });
}
