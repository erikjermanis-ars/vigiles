/**
 * Minimal UI primitives (Tailwind, tokens from globals.css). Server-component safe.
 * Keep pages consistent by using these instead of ad-hoc styles.
 */
import Link from 'next/link';
import type { ComponentProps, ReactNode } from 'react';
import type { Action, Priority } from '@/lib/types';

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ');
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle ? <div className="mt-1 text-sm text-muted">{subtitle}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Card({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cx('rounded-lg border border-border bg-panel', className)} {...props} />;
}

export function CardHeader({ title, actions }: { title: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-2.5">
      <h2 className="text-sm font-semibold">{title}</h2>
      {actions}
    </div>
  );
}

export function CardBody({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cx('px-4 py-3', className)} {...props} />;
}

type BadgeTone = 'ping' | 'digest' | 'log' | 'ok' | 'neutral' | 'accent';
const toneClass: Record<BadgeTone, string> = {
  ping: 'bg-ping-bg text-ping',
  digest: 'bg-digest-bg text-digest',
  log: 'bg-log-bg text-log',
  ok: 'bg-ok-bg text-ok',
  neutral: 'bg-panel-2 text-muted',
  accent: 'bg-panel-2 text-accent',
};

export function Badge({ tone = 'neutral', children, title }: { tone?: BadgeTone; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cx('inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap', toneClass[tone])}>
      {children}
    </span>
  );
}

export function ActionBadge({ action }: { action: Action | null | undefined }) {
  if (!action) return <Badge>undecided</Badge>;
  return <Badge tone={action}>{action}</Badge>;
}

export function PriorityBadge({ priority }: { priority: Priority | null | undefined }) {
  if (!priority) return <Badge>—</Badge>;
  const tone: BadgeTone = priority === 'P0' || priority === 'P1' ? 'ping' : priority === 'P2' ? 'digest' : 'log';
  return <Badge tone={tone}>{priority}</Badge>;
}

const buttonBase =
  'inline-flex items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50';
const buttonVariant = {
  primary: 'border-accent bg-accent text-white hover:opacity-90',
  secondary: 'border-border bg-panel text-text hover:bg-panel-2',
  danger: 'border-ping bg-panel text-ping hover:bg-ping-bg',
};

export function Button({ variant = 'secondary', className, ...props }: ComponentProps<'button'> & { variant?: keyof typeof buttonVariant }) {
  return <button className={cx(buttonBase, buttonVariant[variant], className)} {...props} />;
}

export function ButtonLink({
  variant = 'secondary',
  className,
  ...props
}: ComponentProps<typeof Link> & { variant?: keyof typeof buttonVariant }) {
  return <Link className={cx(buttonBase, buttonVariant[variant], 'no-underline', className)} {...props} />;
}

export function Table({ className, ...props }: ComponentProps<'table'>) {
  return (
    <div className="overflow-x-auto">
      <table className={cx('w-full border-collapse text-sm', className)} {...props} />
    </div>
  );
}
export function Th({ className, ...props }: ComponentProps<'th'>) {
  return <th className={cx('border-b border-border px-3 py-2 text-left text-xs font-medium tracking-wide text-muted uppercase', className)} {...props} />;
}
export function Td({ className, ...props }: ComponentProps<'td'>) {
  return <td className={cx('border-b border-border px-3 py-2 align-top', className)} {...props} />;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-muted">{children}</div>;
}

export function Kv({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="font-mono text-[0.85em]">{children}</code>;
}
