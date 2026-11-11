'use client';

import { RouteError } from '@/components/finding/route-error';

export default function FindingsError(props: { error: unknown; retry: () => void }) {
  return <RouteError {...props} />;
}
