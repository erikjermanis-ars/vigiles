/**
 * Presentational pieces of the owner's decision page (/decide). No hooks, so both the server page and the
 * client answer form use them.
 */
import { cx } from '@/components/ui';
import type { Action, OwnerBrief } from '@/lib/types';

export interface AnswerChoice {
  value: Action;
  label: string;
  /** Keyboard shortcut */
  key: string;
  /** The owner's own one-line definition */
  definition: string;
}

export const ANSWER_CHOICES: readonly AnswerChoice[] = [
  {
    value: 'ping',
    label: 'Ping',
    key: '1',
    definition: 'Real harm can happen quickly (data leak, server takeover); interrupt someone now.',
  },
  { value: 'digest', label: 'Digest', key: '2', definition: 'Real but not serious; goes into Monday’s summary, fix within 1–2 weeks.' },
  { value: 'log', label: 'Log', key: '3', definition: 'Not a real threat to this project; record it only.' },
];

export const ACTION_LABEL: Record<Action, string> = { ping: 'Ping', digest: 'Digest', log: 'Log' };

/** Border + background + text in the action's colour (used only once the owner has answered). */
export const ACTION_TONE: Record<Action, string> = {
  ping: 'border-ping bg-ping-bg text-ping',
  digest: 'border-digest bg-digest-bg text-digest',
  log: 'border-log bg-log-bg text-log',
};

export function AnswerPill({ action, size = 'md' }: { action: Action; size?: 'sm' | 'md' }) {
  return (
    <span
      className={cx(
        'inline-flex shrink-0 items-center justify-center rounded-full border font-semibold',
        size === 'sm' ? 'w-16 py-0.5 text-xs' : 'px-3 py-0.5 text-base',
        ACTION_TONE[action],
      )}
    >
      {ACTION_LABEL[action]}
    </span>
  );
}

/**
 * Neutral on purpose: the ping/digest/log hues appear only once the owner has answered, so a red "Yes" does
 * not read as "press Ping". "Yes" is the strongest (inverted), "No" the quietest, "Unclear" dashed.
 */
const EXPLOITABLE: Record<OwnerBrief['exploitableToday'], { text: string; className: string }> = {
  yes: { text: 'Yes', className: 'border border-text bg-text text-panel' },
  no: { text: 'No', className: 'border border-border bg-panel-2 text-text' },
  unclear: { text: 'Unclear', className: 'border border-dashed border-muted text-text' },
};

/** "Exploitable today: Yes / No / Unclear": the settled technical answer for this app. */
export function ExploitableBadge({ value }: { value: OwnerBrief['exploitableToday'] }) {
  const e = EXPLOITABLE[value];
  return (
    <span className={cx('inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-sm whitespace-nowrap', e.className)}>
      Exploitable today: <strong className="font-semibold">{e.text}</strong>
    </span>
  );
}

/** A calm "Matches" / "Differs" marker comparing another opinion with the owner's answer. */
export function AgreementMarker({ same }: { same: boolean }) {
  return same ? (
    <span className="rounded-full bg-ok-bg px-2 py-0.5 text-xs font-medium text-ok">Matches</span>
  ) : (
    <span className="rounded-full border border-border px-2 py-0.5 text-xs font-medium text-muted">Differs</span>
  );
}
