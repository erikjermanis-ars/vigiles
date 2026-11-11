/**
 * A row of radio "pills". Presentational only (no hooks), so it works in server forms and inside the
 * client review form. Pass `value` + `onChange` for a controlled group, else `defaultValue`.
 */
import { cx } from '@/components/ui';

export interface Choice {
  value: string;
  label: string;
  /** Keyboard shortcut shown next to the label */
  shortcut?: string;
  /** Tailwind classes applied when checked (e.g. the action's tone) */
  checkedClass?: string;
}

export function ChoiceGroup({
  name,
  legend,
  choices,
  value,
  defaultValue,
  onChange,
  required,
}: {
  name: string;
  legend: string;
  choices: Choice[];
  value?: string | null;
  defaultValue?: string | null;
  onChange?: (value: string) => void;
  required?: boolean;
}) {
  const controlled = value !== undefined;
  return (
    <fieldset>
      <legend className="mb-1.5 text-xs font-medium tracking-wide text-muted uppercase">{legend}</legend>
      <div className="flex flex-wrap gap-1.5">
        {choices.map((c) => (
          <label key={c.value} className="cursor-pointer">
            <input
              type="radio"
              name={name}
              value={c.value}
              required={required}
              className="peer sr-only"
              {...(controlled
                ? { checked: value === c.value, onChange: () => onChange?.(c.value) }
                : { defaultChecked: defaultValue === c.value })}
            />
            <span
              className={cx(
                'inline-flex items-center gap-1.5 rounded-md border border-border bg-panel px-3 py-1.5 text-sm select-none hover:bg-panel-2',
                'peer-checked:border-current peer-checked:font-semibold peer-focus-visible:ring-2 peer-focus-visible:ring-accent',
                c.checkedClass ?? 'peer-checked:bg-panel-2 peer-checked:text-accent',
              )}
            >
              {c.shortcut ? <kbd className="font-mono text-xs text-muted">{c.shortcut}</kbd> : null}
              {c.label}
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

export const EXPECTED_ACTION_CHOICES: Choice[] = [
  { value: 'ping', label: 'Ping', shortcut: '1', checkedClass: 'peer-checked:bg-ping-bg peer-checked:text-ping' },
  { value: 'digest', label: 'Digest', shortcut: '2', checkedClass: 'peer-checked:bg-digest-bg peer-checked:text-digest' },
  { value: 'log', label: 'Log', shortcut: '3', checkedClass: 'peer-checked:bg-log-bg peer-checked:text-log' },
];

export const AFFECTED_CHOICES: Choice[] = [
  { value: 'yes', label: 'Affected', shortcut: 'y' },
  { value: 'no', label: 'Not affected', shortcut: 'n' },
  { value: 'unsure', label: 'Unsure', shortcut: 'u' },
];
