/**
 * Owner cases: the few "taste" questions the system asks the owner on the /decide page (ping, digest or
 * log?), plus the writes behind it and behind `npm run cases`. Whether a finding affects the app is already
 * settled by triage; a case carries a plain-language brief so the owner can answer in under a minute.
 * Answering also records the owner's label for the finding (labels table), so evaluation uses it.
 */
import { and, asc, count, eq, inArray } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../db/client';
import { findings, labels, ownerCases, projects } from '../db/schema';
import { ACTIONS, OwnerBriefSchema, type Action, type FindingStatus, type OwnerBrief, type OwnerCaseStatus } from '../types';
import { findingExists, upsertLabel } from './findings';

export type OwnerCaseRow = typeof ownerCases.$inferSelect;

/** A case as the decide page and the CLI show it: the stored row plus the finding's and project's names. */
export interface OwnerCaseView {
  id: number;
  findingId: number;
  status: OwnerCaseStatus;
  /** The parsed brief; null when the stored JSON does not match OwnerBriefSchema */
  brief: OwnerBrief | null;
  /** brief.title, or a fallback built from the finding when the brief is unreadable */
  title: string;
  reason: string;
  /** What the system does for this finding: the case's recorded action, else the finding's current one */
  systemAction: Action | null;
  agentAction: Action | null;
  batch: string | null;
  answer: Action | null;
  answeredBy: string | null;
  note: string | null;
  createdAt: string;
  answeredAt: string | null;
  projectId: string | null;
  projectName: string | null;
  packageName: string | null;
  osvId: string | null;
  /** null when the finding no longer exists */
  findingStatus: FindingStatus | null;
}

// ---------- reads ----------

function caseQuery(db: Db) {
  return db
    .select({
      c: ownerCases,
      projectId: findings.projectId,
      projectName: projects.name,
      packageName: findings.packageName,
      osvId: findings.osvId,
      findingStatus: findings.status,
      currentAction: findings.currentAction,
    })
    .from(ownerCases)
    .leftJoin(findings, eq(findings.id, ownerCases.findingId))
    .leftJoin(projects, eq(projects.id, findings.projectId));
}

type CaseQueryRow = Awaited<ReturnType<ReturnType<typeof caseQuery>['all']>>[number];

function toView(r: CaseQueryRow): OwnerCaseView {
  const c = r.c;
  const parsed = OwnerBriefSchema.safeParse(c.brief);
  const brief = parsed.success ? parsed.data : null;
  const fallbackTitle = r.packageName ? `${r.packageName} (${r.osvId})` : `Finding #${c.findingId}`;
  return {
    id: c.id,
    findingId: c.findingId,
    status: c.status,
    brief,
    title: brief?.title.trim() || fallbackTitle,
    reason: c.reason,
    systemAction: c.systemAction ?? r.currentAction ?? null,
    agentAction: c.agentAction ?? null,
    batch: c.batch,
    answer: c.answer,
    answeredBy: c.answeredBy,
    note: c.note,
    createdAt: c.createdAt,
    answeredAt: c.answeredAt,
    projectId: r.projectId ?? null,
    projectName: r.projectName ?? r.projectId ?? null,
    packageName: r.packageName ?? null,
    osvId: r.osvId ?? null,
    findingStatus: r.findingStatus ?? null,
  };
}

/** Cases in asking order (oldest first). Withdrawn cases only when asked for. */
export function listOwnerCases(db: Db, opts: { includeWithdrawn?: boolean } = {}): OwnerCaseView[] {
  const q = caseQuery(db);
  const rows = opts.includeWithdrawn
    ? q.orderBy(asc(ownerCases.id)).all()
    : q
        .where(inArray(ownerCases.status, ['open', 'answered']))
        .orderBy(asc(ownerCases.id))
        .all();
  return rows.map(toView);
}

export function getOwnerCase(db: Db, id: number): OwnerCaseView | null {
  const row = caseQuery(db).where(eq(ownerCases.id, id)).get();
  return row ? toView(row) : null;
}

/** Open cases, for the nav badge. */
export function countOpenOwnerCases(db: Db): number {
  return db.select({ n: count() }).from(ownerCases).where(eq(ownerCases.status, 'open')).get()?.n ?? 0;
}

export interface DecideView {
  /** Open cases in asking order */
  open: OwnerCaseView[];
  /** Answered cases, most recently answered first */
  answered: OwnerCaseView[];
  /** open + answered (withdrawn cases do not count) */
  total: number;
  decided: number;
  /** The case to show: the requested one, else the first open case; null when nothing is open */
  current: OwnerCaseView | null;
  /** The open case "Next" goes to from `current` (the next one in asking order, wrapping); null when none is left */
  nextId: number | null;
  /** A case was requested but it does not exist or was withdrawn */
  requestedMissing: boolean;
}

export function getDecideView(db: Db, requestedId: number | null): DecideView {
  const all = listOwnerCases(db);
  const open = all.filter((c) => c.status === 'open');
  const answered = all
    .filter((c) => c.status === 'answered')
    .sort((a, b) => (b.answeredAt ?? '').localeCompare(a.answeredAt ?? '') || b.id - a.id);
  const requested = requestedId === null ? null : (all.find((c) => c.id === requestedId) ?? null);
  const current = requested ?? open[0] ?? null;
  return {
    open,
    answered,
    total: all.length,
    decided: answered.length,
    current,
    nextId: current ? nextOpenCaseId(open, current.id) : null,
    requestedMissing: requestedId !== null && requested === null,
  };
}

/** The `?case=` search param as a case id (first value; a positive integer), else null. */
export function parseCaseParam(value: string | string[] | undefined): number | null {
  const n = Number(Array.isArray(value) ? value[0] : value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** The first open case after `fromId` in asking order, wrapping to the start; never `fromId` itself. */
export function nextOpenCaseId(open: Pick<OwnerCaseView, 'id'>[], fromId: number): number | null {
  const others = open.filter((c) => c.id !== fromId);
  return (others.find((c) => c.id > fromId) ?? others[0])?.id ?? null;
}

// ---------- answering ----------

export const OWNER_NOTE_MAX = 500;
/** Marks label notes written by the decide page. */
export const DECIDE_NOTE_PREFIX = '[decide]';

export const AnswerInputSchema = z.object({
  caseId: z.coerce.number({ error: 'This case could not be found. Reload the page.' }).int().positive(),
  answer: z.enum(ACTIONS, { error: 'Choose Ping, Digest or Log.' }),
  note: z
    .string()
    .optional()
    .transform((v) => v?.replace(/\s+/g, ' ').trim() || null)
    .pipe(z.string().max(OWNER_NOTE_MAX, `Keep the note under ${OWNER_NOTE_MAX} characters.`).nullable()),
});
export type AnswerInput = z.output<typeof AnswerInputSchema>;

/** Validates the decide form; returns a plain-language error instead of throwing. */
export function parseAnswerInput(
  fields: FormData | Record<string, unknown>,
): { ok: true; value: AnswerInput } | { ok: false; error: string } {
  const get = (k: string): unknown => (fields instanceof FormData ? fields.get(k) : fields[k]);
  // FormData.get returns null for a missing field; treat it as absent.
  const parsed = AnswerInputSchema.safeParse({
    caseId: get('caseId') ?? undefined,
    answer: get('answer') ?? undefined,
    note: get('note') ?? undefined,
  });
  if (parsed.success) return { ok: true, value: parsed.data };
  const issue = parsed.error.issues[0];
  return {
    ok: false,
    error: issue?.path[0] === 'caseId' ? 'This case could not be found. Reload the page.' : (issue?.message ?? 'Invalid answer.'),
  };
}

/**
 * The label note for an owner answer: "[decide] <note>" first, then whatever note the labeler had written
 * before (on the Review or Finding page). A note from an earlier answer to this question is replaced.
 */
export function mergeDecideNote(previous: string | null, ownerNote: string | null): string {
  const head = ownerNote ? `${DECIDE_NOTE_PREFIX} ${ownerNote}` : DECIDE_NOTE_PREFIX;
  let rest = previous?.trim() ?? '';
  if (rest.startsWith(DECIDE_NOTE_PREFIX)) {
    const nl = rest.indexOf('\n');
    rest = nl === -1 ? '' : rest.slice(nl + 1).trim();
  }
  return rest ? `${head}\n${rest}` : head;
}

/**
 * Records (or changes) the owner's answer to a case and upserts the labeler's label for its finding:
 * expected action = the answer, note prefixed "[decide]". The label's "actually affected" value is kept.
 * Throws a readable error for a missing or withdrawn case or a missing finding.
 */
export function answerOwnerCase(db: Db, input: AnswerInput, labeler: string, now = new Date()): OwnerCaseRow {
  return db.transaction(() => {
    const row = db.select().from(ownerCases).where(eq(ownerCases.id, input.caseId)).get();
    if (!row) throw new Error('This case could not be found. Reload the page.');
    if (row.status === 'withdrawn')
      throw new Error('This case was withdrawn, so there is nothing to decide. Reload the page to see the next one.');
    const existing = db
      .select()
      .from(labels)
      .where(and(eq(labels.findingId, row.findingId), eq(labels.labeler, labeler)))
      .get();
    upsertLabel(
      db,
      {
        findingId: row.findingId,
        expectedAction: input.answer,
        affectedTruth: existing?.affectedTruth ?? null,
        note: mergeDecideNote(existing?.note ?? null, input.note),
      },
      labeler,
    );
    return db
      .update(ownerCases)
      .set({ status: 'answered', answer: input.answer, answeredBy: labeler, answeredAt: now.toISOString(), note: input.note })
      .where(eq(ownerCases.id, row.id))
      .returning()
      .get();
  });
}

// ---------- import / withdraw (the `cases` CLI) ----------

const optionalAction = z
  .enum(ACTIONS)
  .nullish()
  .transform((v) => v ?? null);

export const OwnerCaseImportSchema = z.object({
  findingId: z.number().int().positive(),
  brief: OwnerBriefSchema,
  reason: z.string().trim().min(1, 'reason is empty'),
  systemAction: optionalAction,
  agentAction: optionalAction,
  batch: z
    .string()
    .trim()
    .nullish()
    .transform((v) => v || null),
});
export type OwnerCaseImport = z.output<typeof OwnerCaseImportSchema>;

/** Brief fields the page always shows; an empty one would leave a blank section. */
const REQUIRED_BRIEF_TEXT = ['title', 'whatItIs', 'attackerCouldDo', 'whatItTakes', 'yourApp', 'fix'] as const;

/** Validates an import file's parsed JSON (an array of cases). All problems are reported at once. */
export function validateCaseImport(data: unknown): { ok: true; items: OwnerCaseImport[] } | { ok: false; errors: string[] } {
  if (!Array.isArray(data)) return { ok: false, errors: ['expected a JSON array of cases'] };
  const errors: string[] = [];
  const items: OwnerCaseImport[] = [];
  const seen = new Map<number, number>();
  data.forEach((raw, i) => {
    const where = `item ${i + 1}${raw && typeof raw === 'object' && 'findingId' in raw ? ` (finding ${String(raw.findingId)})` : ''}`;
    const parsed = OwnerCaseImportSchema.safeParse(raw);
    if (!parsed.success) {
      for (const issue of parsed.error.issues) errors.push(`${where}: ${issue.path.join('.') || '(root)'}: ${issue.message}`);
      return;
    }
    const item = parsed.data;
    for (const k of REQUIRED_BRIEF_TEXT) if (!item.brief[k].trim()) errors.push(`${where}: brief.${k} is empty`);
    if (item.brief.similarTo !== null && !item.brief.similarTo.trim()) item.brief.similarTo = null;
    const dup = seen.get(item.findingId);
    if (dup !== undefined) errors.push(`${where}: finding ${item.findingId} is also in item ${dup}`);
    seen.set(item.findingId, i + 1);
    items.push(item);
  });
  return errors.length ? { ok: false, errors } : { ok: true, items };
}

/**
 * Reading budget: the owner should take in a brief in under a minute (about 200 words). Longer briefs still
 * import, but `npm run cases -- import` warns so whoever wrote them can tighten the wording.
 */
export const BRIEF_SOFT_LIMITS = { title: 100, section: 350, total: 1300 } as const;
const BRIEF_SECTIONS = ['whatItIs', 'attackerCouldDo', 'whatItTakes', 'yourApp', 'fix', 'similarTo'] as const;

/** Plain-language warnings for a brief that is too long to read quickly; empty when it fits. */
export function briefLengthWarnings(brief: OwnerBrief): string[] {
  const out: string[] = [];
  const len = (s: string | null) => (s ?? '').trim().length;
  if (len(brief.title) > BRIEF_SOFT_LIMITS.title)
    out.push(`title is ${len(brief.title)} characters; aim for ${BRIEF_SOFT_LIMITS.title} or fewer`);
  for (const k of BRIEF_SECTIONS) {
    const n = len(brief[k]);
    if (n > BRIEF_SOFT_LIMITS.section) out.push(`brief.${k} is ${n} characters; aim for ${BRIEF_SOFT_LIMITS.section} or fewer`);
  }
  const total = len(brief.title) + BRIEF_SECTIONS.reduce((sum, k) => sum + len(brief[k]), 0);
  if (total > BRIEF_SOFT_LIMITS.total)
    out.push(`the brief is ${total} characters in all; aim for ${BRIEF_SOFT_LIMITS.total} or fewer (under a minute to read)`);
  return out;
}

export interface ImportResult {
  created: { caseId: number; findingId: number }[];
  /** Findings skipped because they already have an open case (without `replace`) */
  skipped: { findingId: number; openCaseId: number }[];
  /** Open cases withdrawn and replaced (with `replace`) */
  replaced: { oldCaseId: number; caseId: number; findingId: number }[];
}

/**
 * Creates one open case per item, in one transaction. A finding that already has an open case is skipped,
 * or with `replace` that case is withdrawn and a new one created. Unknown findings fail the whole import.
 */
export function importOwnerCases(db: Db, items: OwnerCaseImport[], opts: { replace?: boolean; batch?: string | null } = {}): ImportResult {
  const missing = items.filter((it) => !findingExists(db, it.findingId)).map((it) => it.findingId);
  if (missing.length) throw new Error(`unknown finding${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}; nothing imported`);
  const result: ImportResult = { created: [], skipped: [], replaced: [] };
  db.transaction(() => {
    for (const it of items) {
      const openCases = db
        .select({ id: ownerCases.id })
        .from(ownerCases)
        .where(and(eq(ownerCases.findingId, it.findingId), eq(ownerCases.status, 'open')))
        .orderBy(asc(ownerCases.id))
        .all();
      if (openCases.length && !opts.replace) {
        result.skipped.push({ findingId: it.findingId, openCaseId: openCases[0]!.id });
        continue;
      }
      if (openCases.length) {
        db.update(ownerCases)
          .set({ status: 'withdrawn' })
          .where(
            inArray(
              ownerCases.id,
              openCases.map((c) => c.id),
            ),
          )
          .run();
      }
      const caseId = db
        .insert(ownerCases)
        .values({
          findingId: it.findingId,
          brief: it.brief,
          reason: it.reason,
          systemAction: it.systemAction,
          agentAction: it.agentAction,
          batch: it.batch ?? opts.batch ?? null,
        })
        .returning({ id: ownerCases.id })
        .get().id;
      result.created.push({ caseId, findingId: it.findingId });
      for (const old of openCases) result.replaced.push({ oldCaseId: old.id, caseId, findingId: it.findingId });
    }
  });
  return result;
}

export type WithdrawTarget = { id: number } | { batch: string };

/**
 * Withdraws open cases: one by id, or every open case of a batch. Answered cases keep their answer and are
 * reported as skipped. Throws when the id does not exist.
 */
export function withdrawOwnerCases(
  db: Db,
  target: WithdrawTarget,
): { withdrawn: number[]; skipped: { id: number; status: OwnerCaseStatus }[] } {
  const rows =
    'id' in target
      ? db.select({ id: ownerCases.id, status: ownerCases.status }).from(ownerCases).where(eq(ownerCases.id, target.id)).all()
      : db
          .select({ id: ownerCases.id, status: ownerCases.status })
          .from(ownerCases)
          .where(eq(ownerCases.batch, target.batch))
          .orderBy(asc(ownerCases.id))
          .all();
  if ('id' in target && rows.length === 0) throw new Error(`case ${target.id} not found`);
  const withdrawn = rows.filter((r) => r.status === 'open').map((r) => r.id);
  if (withdrawn.length) db.update(ownerCases).set({ status: 'withdrawn' }).where(inArray(ownerCases.id, withdrawn)).run();
  return { withdrawn, skipped: rows.filter((r) => r.status !== 'open') };
}
