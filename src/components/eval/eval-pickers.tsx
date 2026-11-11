/** GET form for the Eval page's triage config, policy version and labeler. */
import Form from 'next/form';
import { Button } from '@/components/ui';
import { shortDate } from '@/lib/format';
import type { EvalOptions, EvalSelection } from '@/lib/queries/eval';

const selectClass = 'rounded-md border border-border bg-panel px-2 py-1 text-sm';

/** Keeps a value selectable even when it is not in the list (e.g. a hand-edited URL). */
function withSelected<T extends { value: string; label: string }>(options: T[], selected: string): { value: string; label: string }[] {
  return !selected || options.some((o) => o.value === selected)
    ? options
    : [{ value: selected, label: `${selected} (unknown)` }, ...options];
}

export function EvalPickers({ options, selection }: { options: EvalOptions; selection: EvalSelection }) {
  const configs = withSelected(
    options.configs.map((c) => ({ value: c.name, label: `${c.name}${c.active ? ' (active)' : ''}` })),
    selection.configName,
  );
  const policies = withSelected(
    options.policies.map((p) => ({ value: p.hash, label: `${p.hash} · ${shortDate(p.firstSeenAt)}${p.current ? ' (current file)' : ''}` })),
    selection.policyHash,
  );
  const labelers = withSelected(
    options.labelers.map((l) => ({ value: l, label: l })),
    selection.labeler,
  );
  return (
    <Form action="/eval" className="flex flex-wrap items-end gap-3">
      <label className="flex flex-col gap-1 text-xs text-muted">
        Triage config
        <select name="config" defaultValue={selection.configName} className={selectClass}>
          {configs.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Policy version
        <select name="policy" defaultValue={selection.policyHash} className={selectClass}>
          {policies.length === 0 ? <option value="">no policy versions yet</option> : null}
          {policies.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Labeler
        <select name="labeler" defaultValue={selection.labeler} className={selectClass}>
          {labelers.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <Button type="submit">Apply</Button>
    </Form>
  );
}
