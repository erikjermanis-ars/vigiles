'use client';

import { RouteError } from '@/components/finding/route-error';

export default function ReviewError(props: { error: unknown; retry: () => void }) {
  return <RouteError {...props} />;
}
