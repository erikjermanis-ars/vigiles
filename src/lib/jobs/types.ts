import type { DataPaths } from '../config/load';
import type { VigilesConfig } from '../config/schema';
import type { Db } from '../db/client';
import type { JobType } from '../types';

export interface JobContext {
  db: Db;
  jobId: number;
  type: JobType;
  params: Record<string, unknown>;
  config: VigilesConfig;
  paths: DataPaths;
  /** Repo root of Vigiles itself (where config/, projects/, prompts/ live) */
  root: string;
  /** Aborted when the user cancels the job (or a parent job). Pass it to runProcess. */
  signal: AbortSignal;
  /** Appends a timestamped line to job_runs.log (and echoes to the worker console). */
  log(message: string): void;
  /** Replaces job_runs.progress, e.g. "triage 7/25". */
  progress(text: string): void;
  /** Throws CancelledError if the job was cancelled. Call between units of work. */
  throwIfCancelled(): void;
  /**
   * Runs another job inline as a child job_run row (shown nested on the Jobs page).
   * Resolves to the child's stats; throws JobFailedError if the child fails.
   */
  runChild(type: JobType, params?: Record<string, unknown>): Promise<Record<string, unknown>>;
}

/** A job returns stats that are stored in job_runs.stats. */
export type JobHandler = (ctx: JobContext) => Promise<Record<string, unknown> | void>;

export class CancelledError extends Error {
  constructor() {
    super('cancelled');
  }
}

export class JobFailedError extends Error {
  constructor(
    public childType: string,
    public childId: number,
    message: string,
  ) {
    super(`${childType} (#${childId}) failed: ${message}`);
  }
}
