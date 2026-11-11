import type { JobType } from '../types';

/** Human descriptions for the Jobs page (kept apart from handlers so the dashboard doesn't import worker code). */
export const JOB_DESCRIPTIONS: Record<JobType, string> = {
  'refresh-all': 'Run the whole pipeline: sync feeds → scan → enrich → triage → decide',
  'sync-osv': 'Refresh the offline OSV databases: ecosystems in use, configured, or synced before',
  'sync-kev': 'Download the CISA Known Exploited Vulnerabilities catalog',
  scan: 'Snapshot each project at its ref, match lockfiles against OSV, diff findings',
  enrich: 'Fetch EPSS, join KEV, score CVSS, compute base priority',
  triage: 'Run Claude triage on findings that need it (capped per run)',
  decide: 'Evaluate the decision policy for every open finding (no LLM calls)',
  noop: 'Test job: sleeps and reports progress',
};
