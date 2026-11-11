import type { JobHandler } from '../lib/jobs/types';
import type { JobType } from '../lib/types';
import { run as decide } from './decide';
import { run as enrich } from './enrich';
import { run as noop } from './noop';
import { run as refreshAll } from './refresh-all';
import { run as scan } from './scan';
import { run as syncKev } from './sync-kev';
import { run as syncOsv } from './sync-osv';
import { run as triage } from './triage';

export const handlers: Record<JobType, JobHandler> = {
  noop,
  'sync-osv': syncOsv,
  'sync-kev': syncKev,
  scan,
  enrich,
  triage,
  decide,
  'refresh-all': refreshAll,
};
