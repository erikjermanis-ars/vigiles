#!/usr/bin/env bash
# Builds the synthetic "canary" project: a tiny Next.js app with two known ping-worthy problems, so the whole
# pipeline (scan → enrich → triage → decide → Inbox) can be checked end to end on a case that MUST ping.
#   1. next 15.2.2 with an admin area protected only by middleware.ts → CVE-2025-29927 (middleware auth bypass).
#   2. flatmap-stream 0.1.1 (the 2018 event-stream malware) in the lockfile → a malicious-package advisory.
# The repo lives outside Vigiles (default ~/.vigiles/canary/repo); projects/canary.yaml points at it.
set -euo pipefail
DIR="${1:-$HOME/.vigiles/canary/repo}"
rm -rf "$DIR"
mkdir -p "$DIR/app/admin" "$DIR/app/api/admin/users"
cd "$DIR"
git init -q -b main

cat > package.json <<'JSON'
{
  "name": "canary-shop",
  "private": true,
  "version": "1.0.0",
  "scripts": { "build": "next build", "start": "next start" },
  "dependencies": {
    "next": "15.2.2",
    "react": "19.0.0",
    "react-dom": "19.0.0",
    "event-stream": "3.3.4"
  }
}
JSON

cat > middleware.ts <<'TS'
import { NextResponse, type NextRequest } from 'next/server';

// The ONLY access control for /admin and /api/admin: a session cookie check in middleware.
export function middleware(req: NextRequest) {
  const session = req.cookies.get('session')?.value;
  if (!session || session !== process.env.ADMIN_SESSION) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ['/admin/:path*', '/api/admin/:path*'] };
TS

cat > app/layout.tsx <<'TSX'
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (<html lang="en"><body>{children}</body></html>);
}
TSX

cat > app/page.tsx <<'TSX'
export default function Home() {
  return <main>Canary Shop</main>;
}
TSX

cat > app/admin/page.tsx <<'TSX'
import { db } from '../../lib/db';

// Admin dashboard: lists every customer with email, address and order history. No auth check here;
// it relies entirely on middleware.ts.
export default async function AdminPage() {
  const customers = await db.customers.findMany();
  return <pre>{JSON.stringify(customers, null, 2)}</pre>;
}
TSX

cat > app/api/admin/users/route.ts <<'TS'
import { db } from '../../../../lib/db';

// Exports all customers (PII) as JSON. Protected only by middleware.ts.
export async function GET() {
  return Response.json(await db.customers.findMany());
}
TS

mkdir -p lib
cat > lib/db.ts <<'TS'
// Stand-in for a real database client holding customer PII (names, emails, addresses, orders).
export const db = { customers: { findMany: async () => [] as unknown[] } };
TS

cat > lib/stream-utils.ts <<'TS'
// Used by the order-export job on the server.
import es from 'event-stream';
export const toLines = () => es.split();
TS

# Lockfile from the real registry with event-stream 3.3.4, then rewritten to the compromised 3.3.6 that pulled in
# the malicious flatmap-stream 0.1.1. Both were unpublished from npm in 2018, so they are injected by hand exactly as
# they appeared in affected lockfiles.
npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null
node -e '
const fs=require("fs");
const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));pkg.dependencies["event-stream"]="3.3.6";
fs.writeFileSync("package.json",JSON.stringify(pkg,null,2)+"\n");
const l=JSON.parse(fs.readFileSync("package-lock.json","utf8"));
l.packages[""].dependencies["event-stream"]="3.3.6";
const es=l.packages["node_modules/event-stream"];
es.version="3.3.6";es.resolved="https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz";delete es.integrity;
es.dependencies={...(es.dependencies||{}),"flatmap-stream":"^0.1.0"};
l.packages["node_modules/flatmap-stream"]={version:"0.1.1",resolved:"https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz",license:"MIT"};
fs.writeFileSync("package-lock.json",JSON.stringify(l,null,2)+"\n");'

cat > README.md <<'MD'
# Canary Shop (synthetic)
A deliberately vulnerable app used by Vigiles to verify that ping-worthy problems are pinged. Self-hosted with
`next start` on a Linux VM behind nginx; public internet; stores customer PII. Never deploy this.
MD
git add -A
git -c user.name=vigiles -c user.email=vigiles@localhost commit -qm "Canary Shop: synthetic vulnerable app for Vigiles"
echo "canary repo at $DIR ($(git rev-parse --short HEAD))"
