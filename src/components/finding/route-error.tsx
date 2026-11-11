'use client';

/** Fallback for errors in the findings and review routes (error.tsx re-exports it). */
import { Button, Card, CardBody } from '@/components/ui';

export function RouteError({ error, retry }: { error: unknown; retry: () => void }) {
  const message = error instanceof Error ? error.message : String(error);
  const digest = error instanceof Error && 'digest' in error ? String((error as { digest?: unknown }).digest ?? '') : '';
  return (
    <Card>
      <CardBody className="space-y-3">
        <h2 className="font-semibold">Something went wrong</h2>
        <pre className="rounded-md bg-ping-bg px-3 py-2 text-xs whitespace-pre-wrap text-ping">{message}</pre>
        {digest ? <p className="text-xs text-muted">Server log id: {digest}</p> : null}
        <Button onClick={() => retry()}>Try again</Button>
      </CardBody>
    </Card>
  );
}
