/** One would-be Slack message: every ping (or digest) advisory of one package in one project. */
import Link from 'next/link';
import { VerdictBadge } from '@/components/inbox/verdict-badge';
import { Card, Mono, PriorityBadge } from '@/components/ui';
import { isReleaseVersion, upgradeTarget } from '@/lib/eval/version';
import { MALICIOUS_REMEDIATION, type InboxGroup } from '@/lib/queries/inbox';

/** The advisory's own fix on the installed release line (spec §12); every release line's fix in the tooltip. */
function FixedIn({ installed, fixed }: { installed: string[]; fixed: string[] }) {
  const target = upgradeTarget(installed, fixed);
  if (!target) return <span className="text-xs text-digest">no fix yet</span>;
  return (
    <span className="text-xs text-muted" title={`fixed in ${fixed.filter(isReleaseVersion).join(', ')}`}>
      fixed in <Mono>{target}</Mono>
    </span>
  );
}

/** What to do about the group: the fixed malicious-package remediation (spec §9.1) and/or the upgrade target. */
function Remediation({ group }: { group: InboxGroup }) {
  const others = group.advisoryCount - group.malicious;
  const upgrade = group.upgradeTo ? (
    <>
      upgrade to <Mono>{group.upgradeTo}</Mono>
      {group.withoutFix ? <span className="font-normal text-digest"> ({group.withoutFix} without a fix yet)</span> : null}
    </>
  ) : null;
  if (!group.malicious) return upgrade ?? <span className="text-muted">no fix yet</span>;
  return (
    <>
      <span className="text-ping">malicious package: {MALICIOUS_REMEDIATION}</span>
      {others > 0 ? (
        <span className="font-normal">
          {' '}
          · other {others === 1 ? 'advisory' : 'advisories'}: {upgrade ?? <span className="text-muted">no fix yet</span>}
        </span>
      ) : null}
    </>
  );
}

export function InboxGroupCard({ group }: { group: InboxGroup }) {
  const n = group.advisoryCount;
  // Several lockfiles (e.g. backend/ and dashboard/) can each match the same advisory; say which line is which.
  const showLockfile = group.lockfiles.length > 1;
  return (
    <Card>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 border-b border-border px-4 py-2.5">
        <h3 className="text-sm font-semibold">
          {group.projectName} · <Mono>{group.packageName}</Mono> — {n} {n === 1 ? 'advisory' : 'advisories'} → <Remediation group={group} />
        </h3>
        <span className="text-xs text-muted">installed {group.installedVersions.join(', ') || '—'}</span>
      </div>
      <ul className="divide-y divide-border">
        {group.items.map((item) => (
          <li key={item.findingId} className="px-4 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <Link href={`/findings/${item.findingId}`} className="font-mono text-[0.85em] font-medium">
                {item.vulnId}
              </Link>
              <PriorityBadge priority={item.priority} />
              <VerdictBadge verdict={item.verdict} confidence={item.confidence} />
              {item.malicious ? (
                <span className="text-xs text-ping">malicious: {MALICIOUS_REMEDIATION}</span>
              ) : (
                <FixedIn installed={item.installedVersions} fixed={item.fixedVersions} />
              )}
              {item.devOnly ? <span className="text-xs text-muted">dev only</span> : null}
              {showLockfile ? (
                <span className="text-xs text-muted">
                  in <Mono>{item.lockfile}</Mono>
                </span>
              ) : null}
              <span className="ml-auto text-xs text-muted">
                rule <Mono>{item.ruleId ?? '—'}</Mono>
              </span>
            </div>
            {item.summary ? <p className="mt-1 text-sm">{item.summary}</p> : null}
            {item.priorityReasons.length ? (
              <p className="mt-0.5 text-xs text-muted">
                {item.priority ?? 'No priority'} because {item.priorityReasons.join(' · ')}
              </p>
            ) : null}
          </li>
        ))}
      </ul>
    </Card>
  );
}
