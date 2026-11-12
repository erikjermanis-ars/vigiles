'use client';

/** Error fallback of "Your call": plain words first, the technical message folded away. */
export default function DecideError({ error, retry }: { error: unknown; retry: () => void }) {
  const message = error instanceof Error ? error.message : String(error);
  const digest = error instanceof Error && 'digest' in error ? String((error as { digest?: unknown }).digest ?? '') : '';
  return (
    <div className="mx-auto max-w-3xl rounded-xl border border-border bg-panel px-5 py-6 sm:px-8">
      <h1 className="text-lg font-semibold">This page could not load</h1>
      <p className="mt-1.5 max-w-[68ch] text-base text-muted">Try again. If it keeps failing, the details below help fix it.</p>
      <button
        type="button"
        onClick={() => retry()}
        className="mt-4 rounded-md border border-border bg-panel px-4 py-2 text-sm font-medium hover:bg-panel-2"
      >
        Try again
      </button>
      <details className="mt-5 text-sm">
        <summary className="cursor-pointer text-muted">Technical details</summary>
        <pre className="mt-2 rounded-md bg-panel-2 px-3 py-2 text-xs whitespace-pre-wrap">{message}</pre>
        {digest ? <p className="mt-1 text-xs text-muted">Server log id: {digest}</p> : null}
      </details>
    </div>
  );
}
