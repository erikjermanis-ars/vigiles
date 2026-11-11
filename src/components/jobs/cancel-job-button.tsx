'use client';

import { useRouter } from 'next/navigation';
import { useTransition } from 'react';
import { cancelJobAction } from '@/app/actions';
import { Button } from '@/components/ui';

export function CancelJobButton({ id }: { id: number }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <Button
      type="button"
      variant="danger"
      className="px-2 py-0.5 text-xs"
      disabled={pending}
      onClick={() =>
        startTransition(async () => {
          await cancelJobAction(id);
          router.refresh();
        })
      }
    >
      {pending ? 'Cancelling…' : 'Cancel'}
    </Button>
  );
}
