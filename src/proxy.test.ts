import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';
import * as proxyModule from './proxy';
import { isAllowedHost, proxy } from './proxy';

describe('isAllowedHost', () => {
  it('accepts the three loopback names with or without any port', () => {
    for (const host of [
      '127.0.0.1:3900',
      '127.0.0.1',
      'localhost:3900',
      'localhost',
      'LocalHost:3900',
      '[::1]:3900',
      '[::1]',
      '127.0.0.1:1',
      'localhost:65535',
    ]) {
      expect(isAllowedHost(host), host).toBe(true);
    }
  });

  it('refuses everything else', () => {
    for (const host of [
      null,
      undefined,
      '',
      'evil.example:3900',
      'evil.example',
      'rebind.127.0.0.1.nip.io:3900',
      '127.0.0.1.evil.example:3900',
      'localhost.:3900',
      'x.localhost:3900',
      'localhost.evil.example',
      '127.1:3900',
      '2130706433:3900',
      '0.0.0.0:3900',
      '[0:0:0:0:0:0:0:1]:3900',
      '[::ffff:127.0.0.1]:3900',
      '::1',
      '[::1',
      'user@localhost:3900',
      'localhost:3900@evil.example',
      'localhost:',
      'localhost:abc',
      'localhost:3900:1',
      'localhost:99999',
      'localhost:3900, evil.example',
      ' localhost:3900',
      'localhost:3900 ',
      'localhost/x',
    ]) {
      expect(isAllowedHost(host), String(host)).toBe(false);
    }
  });
});

const req = (url: string, host: string | null, init: { method?: string; headers?: Record<string, string> } = {}) => {
  const headers = new Headers(init.headers);
  if (host !== null) headers.set('host', host);
  return new NextRequest(url, { method: init.method ?? 'GET', headers });
};

describe('proxy', () => {
  it('passes requests addressed to the dashboard through', () => {
    const r = proxy(req('http://127.0.0.1:3900/', '127.0.0.1:3900'));
    expect(r.status).toBe(200);
    expect(r.headers.get('x-middleware-next')).toBe('1');
    expect(proxy(req('http://localhost:3900/findings/1', 'localhost:3900')).headers.get('x-middleware-next')).toBe('1');
  });

  it('answers 403 to a rebound name on every kind of request', async () => {
    const cases = [
      req('http://127.0.0.1:3900/', 'evil.example:3900'),
      req('http://127.0.0.1:3900/_next/static/chunks/app.js', 'evil.example:3900'),
      req('http://127.0.0.1:3900/findings/1?_rsc=abc', 'evil.example:3900', { headers: { rsc: '1' } }),
      // a server action: POST to the page, Origin matching the (rebound) Host, X-Forwarded-Host forged
      req('http://127.0.0.1:3900/findings/1', 'evil.example:3900', {
        method: 'POST',
        headers: { 'next-action': 'abc123', origin: 'http://evil.example:3900', 'x-forwarded-host': '127.0.0.1:3900' },
      }),
      req('http://127.0.0.1:3900/', null),
    ];
    for (const r of cases) {
      const res = proxy(r);
      expect(res.status, r.url).toBe(403);
      expect(res.headers.get('x-middleware-next')).toBeNull();
      expect(await res.text()).toMatch(/^Forbidden/);
    }
  });

  it('exports no matcher, so Next runs it on every path', () => {
    expect('config' in proxyModule).toBe(false);
  });
});
