/** Label form for the Finding page: a plain server-rendered form posting to a server action. */
import { Button } from '@/components/ui';
import { relativeTime } from '@/lib/format';
import type { LabelRow } from '@/lib/queries/findings';
import { AFFECTED_CHOICES, ChoiceGroup, EXPECTED_ACTION_CHOICES } from './choice-group';

const withoutShortcuts = (choices: typeof EXPECTED_ACTION_CHOICES) => choices.map(({ shortcut: _shortcut, ...c }) => c);
// A checked radio cannot be unchecked, so the optional answer needs an explicit "not set" (posts '', saved as null).
const AFFECTED_WITH_UNSET = [...withoutShortcuts(AFFECTED_CHOICES), { value: '', label: 'Not set' }];

export function LabelForm({
  findingId,
  label,
  action,
}: {
  findingId: number;
  label: LabelRow | null;
  action: (formData: FormData) => Promise<void>;
}) {
  return (
    <form action={action} className="space-y-3">
      <input type="hidden" name="findingId" value={findingId} />
      <ChoiceGroup
        name="expectedAction"
        legend="Expected action"
        choices={withoutShortcuts(EXPECTED_ACTION_CHOICES)}
        defaultValue={label?.expectedAction ?? null}
        required
      />
      <ChoiceGroup
        name="affectedTruth"
        legend="Actually affected? (optional)"
        choices={AFFECTED_WITH_UNSET}
        defaultValue={label?.affectedTruth ?? ''}
      />
      <div>
        <label htmlFor="label-note" className="mb-1.5 block text-xs font-medium tracking-wide text-muted uppercase">
          Note
        </label>
        <textarea
          id="label-note"
          name="note"
          rows={3}
          maxLength={5000}
          defaultValue={label?.note ?? ''}
          className="w-full rounded-md border border-border bg-panel px-2.5 py-1.5 text-sm"
        />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" variant="primary">
          {label ? 'Update label' : 'Save label'}
        </Button>
        {label ? <span className="text-sm text-muted">Labeled {relativeTime(label.labeledAt)}</span> : null}
      </div>
    </form>
  );
}
