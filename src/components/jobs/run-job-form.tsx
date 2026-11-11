'use client';

/** A run button for one job type, with the optional inputs that type takes (scan: project; triage: config, limit, force). */
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useActionState } from 'react';
import { enqueueJobAction } from '@/app/actions';
import { Button } from '@/components/ui';
import type { JobType } from '@/lib/types';

export interface RunJobFormProps {
  type: JobType;
  label: string;
  primary?: boolean;
  /** scan: project choices ("" = all enabled projects) */
  projects?: { id: string; name: string; enabled: boolean }[];
  /** triage: config choices */
  configs?: { name: string; active: boolean }[];
  defaultLimit?: number;
  /** Extra fixed params, e.g. decide's { policy, config } from the Eval page */
  fixedParams?: Record<string, unknown>;
}

type State = { ok: true; id: number } | { ok: false; error: string } | null;

function paramsFromForm(fd: FormData): Record<string, unknown> {
  const params: Record<string, unknown> = {};
  const project = fd.get('project');
  if (typeof project === 'string' && project) params.project = project;
  const config = fd.get('config');
  if (typeof config === 'string' && config) params.config = config;
  const limit = Number(fd.get('limit'));
  if (fd.get('limit') !== null && fd.get('limit') !== '' && Number.isInteger(limit) && limit > 0) params.limit = limit;
  if (fd.get('force') === 'on') params.force = true;
  return params;
}

const inputClass = 'rounded-md border border-border bg-panel px-2 py-1 text-sm';

export function RunJobForm({ type, label, primary, projects, configs, defaultLimit, fixedParams }: RunJobFormProps) {
  const router = useRouter();
  const [state, formAction, pending] = useActionState(async (_prev: State, fd: FormData): Promise<State> => {
    try {
      const id = await enqueueJobAction(type, { ...paramsFromForm(fd), ...fixedParams });
      // enqueueJobAction only revalidates /jobs; refresh so other pages (Eval) see the queued job too.
      router.refresh();
      return { ok: true, id };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }, null);

  return (
    <form action={formAction} className="flex flex-wrap items-center gap-2">
      {projects ? (
        <select name="project" defaultValue="" className={inputClass} aria-label="Project">
          <option value="">All enabled projects</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
              {p.enabled ? '' : ' (disabled)'}
            </option>
          ))}
        </select>
      ) : null}
      {configs ? (
        <>
          <select name="config" defaultValue={configs.find((c) => c.active)?.name ?? ''} className={inputClass} aria-label="Triage config">
            {configs.length === 0 ? <option value="">active config</option> : null}
            {configs.map((c) => (
              <option key={c.name} value={c.name}>
                {c.name}
                {c.active ? ' (active)' : ''}
              </option>
            ))}
          </select>
          <input
            name="limit"
            type="number"
            min={1}
            placeholder={defaultLimit ? `limit ${defaultLimit}` : 'limit'}
            className={`${inputClass} w-24`}
            aria-label="Limit"
          />
          <label className="flex items-center gap-1 text-sm text-muted">
            <input name="force" type="checkbox" /> force
          </label>
        </>
      ) : null}
      <Button type="submit" variant={primary ? 'primary' : 'secondary'} disabled={pending}>
        {pending ? 'Queueing…' : label}
      </Button>
      {state?.ok ? (
        <span className="text-xs text-muted">
          Queued <Link href={`/jobs/${state.id}`}>#{state.id}</Link>
        </span>
      ) : null}
      {state && !state.ok ? <span className="text-xs text-ping">{state.error}</span> : null}
    </form>
  );
}
