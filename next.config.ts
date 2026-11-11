import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  serverExternalPackages: ['better-sqlite3'],
  // The dashboard is local-only; keep dev indicators out of the way.
  devIndicators: false,
};

export default nextConfig;
