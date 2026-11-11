import Form from 'next/form';
import Link from 'next/link';
import { DependencyBadges, ProjectDisabledBadge, VerdictBadge } from '@/components/finding/badges';
import { formatCvss, formatEpss, truncate } from '@/components/finding/helpers';
import { ActionBadge, Button, ButtonLink, Card, Empty, Mono, PageHeader, PriorityBadge, Table, Td, Th, cx } from '@/components/ui';
import { getDb } from '@/lib/db/client';
import { currentLabeler } from '@/app/review/labeler';
import { displayVulnId, formatDateTime, shortDate } from '@/lib/format';
import {
  findingFiltersToQuery,
  listFindings,
  listProjectOptions,
  parseFindingFilters,
  type FindingFilters,
  type FindingListRow,
  type FindingSort,
  type SearchParams,
} from '@/lib/queries/findings';
import { ACTIONS, FINDING_ORIGINS, PRIORITIES, VERDICTS } from '@/lib/types';

type Option = { value: string; label: string };

const ANY: Option = { value: '', label: 'any' };
const humanOptions = (values: readonly string[]): Option[] => values.map((v) => ({ value: v, label: v.replace(/_/g, ' ') }));
const YES_NO: Option[] = [ANY, { value: 'yes', label: 'yes' }, { value: 'no', label: 'no' }];

const SORT_OPTIONS: { value: FindingSort; label: string }[] = [
  { value: 'priority', label: 'priority' },
  { value: 'epss', label: 'EPSS' },
  { value: 'cvss', label: 'CVSS' },
  { value: 'firstSeen', label: 'first seen' },
  { value: 'package', label: 'package' },
];

/** A GET select; a multi-value filter from a link (e.g. priority=P0,P1) gets its own option so it survives re-submit. */
function FilterSelect({ name, label, options, current }: { name: string; label: string; options: Option[]; current: readonly string[] | string }) {
  const value = typeof current === 'string' ? current : current.join(',');
  const all = value && !options.some((o) => o.value === value) ? [...options, { value, label: value.replace(/,/g, ', ') }] : options;
  return (
    <label className="flex flex-col gap-1 text-xs text-muted">
      {label}
      <select name={name} defaultValue={value} className="rounded-md border border-border bg-panel px-2 py-1.5 text-sm text-text">
        {all.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

const boolValue = (v: boolean | null) => (v === null ? '' : v ? 'yes' : 'no');

function Filters({ filters, projects, labeler }: { filters: FindingFilters; projects: Option[]; labeler: string }) {
  const status = filters.status.length === 0 ? 'all' : filters.status.join(',');
  return (
    // Keyed by the query so "Reset" and header links remount the uncontrolled selects with fresh defaults.
    <Form key={findingFiltersToQuery(filters)} action="/findings" className="mb-4 flex flex-wrap items-end gap-3">
      <FilterSelect name="project" label="Project" options={[ANY, ...projects]} current={filters.project} />
      <FilterSelect
        name="status"
        label="Status"
        options={[...humanOptions(['open', 'fixed', 'no_longer_matches']), { value: 'all', label: 'all' }]}
        current={status}
      />
      <FilterSelect name="priority" label="Priority" options={[ANY, ...humanOptions(PRIORITIES), { value: 'none', label: 'none' }]} current={filters.priority} />
      <FilterSelect name="action" label="Action" options={[ANY, ...humanOptions(ACTIONS), { value: 'none', label: 'undecided' }]} current={filters.action} />
      <FilterSelect name="verdict" label="Verdict" options={[ANY, ...humanOptions(VERDICTS), { value: 'none', label: 'no verdict' }]} current={filters.verdict} />
      <FilterSelect name="devOnly" label="Dev only" options={YES_NO} current={boolValue(filters.devOnly)} />
      <FilterSelect
        name="direct"
        label="Direct"
        options={[ANY, { value: 'yes', label: 'direct' }, { value: 'no', label: 'transitive' }, { value: 'unknown', label: 'unknown' }]}
        current={filters.direct ?? ''}
      />
      <FilterSelect name="origin" label="Origin" options={[ANY, ...humanOptions(FINDING_ORIGINS)]} current={filters.origin} />
      <FilterSelect name="labeled" label={`Labeled by ${labeler}`} options={YES_NO} current={boolValue(filters.labeled)} />
      <label className="flex min-w-48 flex-1 flex-col gap-1 text-xs text-muted">
        Package or vuln id
        <input
          name="q"
          type="search"
          defaultValue={filters.q}
          placeholder="lodash, CVE-2026-…, GHSA-…"
          className="rounded-md border border-border bg-panel px-2 py-1.5 text-sm text-text"
        />
      </label>
      <FilterSelect name="sort" label="Sort" options={SORT_OPTIONS} current={filters.sort} />
      {/* Filters that only arrive through links (Eval drill-downs) are kept on re-submit. */}
      {filters.expected.length ? <input type="hidden" name="expected" value={filters.expected.join(',')} /> : null}
      {filters.ids.length ? <input type="hidden" name="ids" value={filters.ids.join(',')} /> : null}
      <div className="flex gap-2">
        <Button type="submit" variant="primary">
          Apply
        </Button>
        <ButtonLink href="/findings">Reset</ButtonLink>
      </div>
    </Form>
  );
}

function SortHeader({ filters, sort, children, className }: { filters: FindingFilters; sort: FindingSort; children: string; className?: string }) {
  const active = filters.sort === sort;
  return (
    <Th className={className}>
      <Link href={`/findings${findingFiltersToQuery(filters, { sort })}`} className={cx('no-underline', active ? 'text-text' : 'text-muted')}>
        {children}
        {active ? ' ↓' : ''}
      </Link>
    </Th>
  );
}

function Row({ r, labeler }: { r: FindingListRow; labeler: string }) {
  const href = `/findings/${r.id}`;
  return (
    <tr className="hover:bg-panel-2">
      <Td>
        <PriorityBadge priority={r.priority} />
      </Td>
      <Td>
        <span title={r.currentRuleId ? `rule: ${r.currentRuleId}` : undefined}>
          <ActionBadge action={r.currentAction} />
        </span>
      </Td>
      <Td className="max-w-56">
        <Link href={href} className="font-medium break-words">
          {r.packageName}
        </Link>
        <div className="text-xs break-words text-muted">
          <Mono>@{r.installedVersions.join(', ')}</Mono>
          {r.fixedVersions.length ? <Mono> → {r.fixedVersions.join(', ')}</Mono> : null}
        </div>
      </Td>
      <Td className="min-w-64">
        <Link href={href} className="font-mono text-[0.85em] whitespace-nowrap">
          {displayVulnId(r.osvId, r.cves)}
        </Link>
        {r.summary ? (
          <div className="text-xs text-muted" title={r.summary}>
            {truncate(r.summary, 90)}
          </div>
        ) : null}
      </Td>
      <Td className="text-xs">
        <div className="font-medium text-text">{r.projectId}</div>
        <div className="break-all text-muted">{r.lockfile}</div>
        {r.projectEnabled ? null : <ProjectDisabledBadge />}
      </Td>
      <Td>
        <DependencyBadges direct={r.direct} devOnly={r.devOnly} inKev={r.inKev} malicious={r.malicious} />
      </Td>
      <Td className="whitespace-nowrap tabular-nums">{formatEpss(r.epss)}</Td>
      <Td className="tabular-nums">{formatCvss(r.cvssScore)}</Td>
      <Td>
        <VerdictBadge verdict={r.verdict} confidence={r.confidence} />
      </Td>
      <Td className="text-center">
        {r.labelAction ? (
          <span title={`${labeler} labeled it ${r.labelAction}`} className="text-ok">
            ✓
          </span>
        ) : null}
      </Td>
      <Td className="whitespace-nowrap text-muted" title={formatDateTime(r.firstSeenAt)}>
        {shortDate(r.firstSeenAt)}
      </Td>
    </tr>
  );
}

export default async function FindingsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const filters = parseFindingFilters(await searchParams);
  const db = getDb();
  const labeler = await currentLabeler();
  const list = listFindings(db, filters, undefined, labeler);
  const projects = listProjectOptions(db).map((p) => ({ value: p.id, label: p.enabled ? p.name : `${p.name} (disabled)` }));

  const count =
    list.total > list.rows.length
      ? `Showing the first ${list.rows.length} of ${list.total} findings`
      : `${list.total} finding${list.total === 1 ? '' : 's'}`;
  const linkOnly = [
    filters.expected.length ? `${labeler}'s label ${filters.expected.join(', ')}` : null,
    filters.ids.length ? `${filters.ids.length} selected finding${filters.ids.length === 1 ? '' : 's'}` : null,
  ].filter(Boolean);

  return (
    <>
      <PageHeader title="Findings" subtitle={count + (linkOnly.length ? ` · also filtered by ${linkOnly.join(' and ')}` : '')} />
      <Filters filters={filters} projects={projects} labeler={labeler} />
      {list.rows.length === 0 ? (
        <Empty>No findings match these filters. If nothing has been scanned yet, run Refresh all on the Jobs page.</Empty>
      ) : (
        <Card>
          <Table>
            <thead>
              <tr>
                <SortHeader filters={filters} sort="priority">
                  Priority
                </SortHeader>
                <Th>Action</Th>
                <SortHeader filters={filters} sort="package">
                  Package
                </SortHeader>
                <Th>Vulnerability</Th>
                <Th>Project · lockfile</Th>
                <Th>Facts</Th>
                <SortHeader filters={filters} sort="epss">
                  EPSS
                </SortHeader>
                <SortHeader filters={filters} sort="cvss">
                  CVSS
                </SortHeader>
                <Th>Verdict</Th>
                <Th title={`Labeled by ${labeler}`}>Lbl</Th>
                <SortHeader filters={filters} sort="firstSeen">
                  First seen
                </SortHeader>
              </tr>
            </thead>
            <tbody>
              {list.rows.map((r) => (
                <Row key={r.id} r={r} labeler={labeler} />
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </>
  );
}
