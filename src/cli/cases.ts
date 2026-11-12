/**
 * Owner cases for the "Your call" page (/decide).
 *
 *   npm run cases -- import <file.json> [--replace] [--batch name]
 *       file: a JSON array of { findingId, brief, reason, systemAction?, agentAction?, batch? }
 *       (brief = OwnerBrief). A finding that already has an open case is skipped; --replace withdraws
 *       that case and asks again. --batch names the batch of items that do not name one.
 *   npm run cases -- list [--all]          open and answered cases (--all adds withdrawn ones)
 *   npm run cases -- withdraw <id>         withdraw one open case
 *   npm run cases -- withdraw --batch <name>   withdraw every open case of a batch
 */
import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDb, type Db } from '../lib/db/client';
import { formatDateTime } from '../lib/format';
import {
  briefLengthWarnings,
  importOwnerCases,
  listOwnerCases,
  validateCaseImport,
  withdrawOwnerCases,
  type OwnerCaseView,
  type WithdrawTarget,
} from '../lib/queries/owner-cases';

export const USAGE = `usage:
  npm run cases -- import <file.json> [--replace] [--batch name]
  npm run cases -- list [--all]
  npm run cases -- withdraw <id> | --batch <name>`;

export type CasesCommand =
  | { cmd: 'import'; file: string; replace: boolean; batch: string | null }
  | { cmd: 'list'; all: boolean }
  | { cmd: 'withdraw'; target: WithdrawTarget }
  | { cmd: 'help' };

type Parsed = { ok: true; command: CasesCommand } | { ok: false; error: string };

const BOOLEAN_FLAGS: Record<string, string[]> = { import: ['replace'], list: ['all'], withdraw: [] };
const VALUE_FLAGS: Record<string, string[]> = { import: ['batch'], list: [], withdraw: ['batch'] };

export function parseCasesArgs(argv: string[]): Parsed {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') return { ok: true, command: { cmd: 'help' } };
  if (!(cmd in BOOLEAN_FLAGS)) return { ok: false, error: `unknown command "${cmd}"` };

  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const key = a.slice(2);
    if (BOOLEAN_FLAGS[cmd]!.includes(key)) flags.set(key, true);
    else if (VALUE_FLAGS[cmd]!.includes(key)) {
      const value = rest[i + 1];
      if (value === undefined || value.startsWith('--') || !value.trim()) return { ok: false, error: `--${key} needs a value` };
      flags.set(key, value.trim());
      i++;
    } else return { ok: false, error: `unknown option --${key} for ${cmd}` };
  }

  switch (cmd) {
    case 'import': {
      if (positional.length !== 1) return { ok: false, error: 'import takes exactly one file' };
      const batch = flags.get('batch');
      return {
        ok: true,
        command: { cmd, file: positional[0]!, replace: flags.has('replace'), batch: typeof batch === 'string' ? batch : null },
      };
    }
    case 'list':
      if (positional.length) return { ok: false, error: 'list takes no arguments' };
      return { ok: true, command: { cmd, all: flags.has('all') } };
    default: {
      const batch = flags.get('batch');
      if (typeof batch === 'string') {
        if (positional.length) return { ok: false, error: 'withdraw takes a case id or --batch, not both' };
        return { ok: true, command: { cmd: 'withdraw', target: { batch } } };
      }
      const id = Number(positional[0]);
      if (positional.length !== 1 || !Number.isInteger(id) || id <= 0)
        return { ok: false, error: 'withdraw needs one case id or --batch <name>' };
      return { ok: true, command: { cmd: 'withdraw', target: { id } } };
    }
  }
}

export interface CasesIo {
  log: (line: string) => void;
  error: (line: string) => void;
  readFile: (file: string) => string;
}

function describeCase(c: OwnerCaseView): string {
  const where = `${c.projectId ?? '?'} · finding ${c.findingId}${c.batch ? ` · batch ${c.batch}` : ''}`;
  const head = `  #${c.id}  ${c.title}\n      ${where}`;
  const others = `system ${c.systemAction ?? '—'}, agents ${c.agentAction ?? '—'}`;
  if (c.status !== 'answered') return `${head} · ${others}`;
  const by = `${c.answeredBy ?? '?'}, ${formatDateTime(c.answeredAt)}`;
  return `${head}\n      answer: ${c.answer} (${by}) · ${others}${c.note ? `\n      note: ${c.note}` : ''}`;
}

/** Lines printed by `list`: open cases first (asking order), then answered (newest first), then withdrawn. */
export function formatCaseList(cases: OwnerCaseView[], all: boolean): string[] {
  const groups: [string, OwnerCaseView[]][] = [
    ['Open', cases.filter((c) => c.status === 'open')],
    [
      'Answered',
      cases.filter((c) => c.status === 'answered').sort((a, b) => (b.answeredAt ?? '').localeCompare(a.answeredAt ?? '') || b.id - a.id),
    ],
  ];
  if (all) groups.push(['Withdrawn', cases.filter((c) => c.status === 'withdrawn')]);
  const lines: string[] = [];
  for (const [title, list] of groups) {
    lines.push(`${title} (${list.length})`);
    for (const c of list) lines.push(describeCase(c));
  }
  return lines;
}

/** Runs one command; returns the process exit code. */
export function runCasesCommand(db: Db, command: CasesCommand, io: CasesIo): number {
  switch (command.cmd) {
    case 'help':
      io.log(USAGE);
      return 0;

    case 'list':
      for (const line of formatCaseList(listOwnerCases(db, { includeWithdrawn: command.all }), command.all)) io.log(line);
      return 0;

    case 'import': {
      let data: unknown;
      try {
        data = JSON.parse(io.readFile(command.file));
      } catch (err) {
        io.error(`cannot read ${command.file}: ${err instanceof Error ? err.message : String(err)}`);
        return 1;
      }
      const v = validateCaseImport(data);
      if (!v.ok) {
        io.error(`${command.file} is invalid; nothing imported:`);
        for (const e of v.errors) io.error(`  ${e}`);
        return 1;
      }
      let res;
      try {
        res = importOwnerCases(db, v.items, { replace: command.replace, batch: command.batch });
      } catch (err) {
        io.error(err instanceof Error ? err.message : String(err));
        return 1;
      }
      // Long briefs still import; the warnings tell the writer which parts to tighten.
      v.items.forEach((it, i) => {
        for (const w of briefLengthWarnings(it.brief)) io.error(`warning: item ${i + 1} (finding ${it.findingId}): ${w}`);
      });
      const replacedBy = new Map(res.replaced.map((r) => [r.caseId, r.oldCaseId]));
      io.log(`created ${res.created.length} case${res.created.length === 1 ? '' : 's'}`);
      for (const c of res.created) {
        const old = replacedBy.get(c.caseId);
        io.log(`  #${c.caseId} finding ${c.findingId}${old !== undefined ? ` (replaces #${old})` : ''}`);
      }
      if (res.skipped.length) {
        io.log(
          `skipped ${res.skipped.length} finding${res.skipped.length === 1 ? '' : 's'} that already have an open case (use --replace to ask again):`,
        );
        for (const s of res.skipped) io.log(`  finding ${s.findingId}: open case #${s.openCaseId}`);
      }
      return 0;
    }

    case 'withdraw': {
      let res;
      try {
        res = withdrawOwnerCases(db, command.target);
      } catch (err) {
        io.error(err instanceof Error ? err.message : String(err));
        return 1;
      }
      io.log(res.withdrawn.length ? `withdrew ${res.withdrawn.map((id) => `#${id}`).join(', ')}` : 'nothing withdrawn');
      for (const s of res.skipped) io.log(`  #${s.id} left as is (${s.status})`);
      // Asking for one case that could not be withdrawn is an error; a batch with nothing open is not.
      return 'id' in command.target && res.withdrawn.length === 0 ? 1 : 0;
    }
  }
}

function main() {
  const parsed = parseCasesArgs(process.argv.slice(2));
  if (!parsed.ok) {
    console.error(`${parsed.error}\n\n${USAGE}`);
    process.exitCode = 1;
    return;
  }
  if (parsed.command.cmd === 'help') {
    console.log(USAGE);
    return;
  }
  const io: CasesIo = {
    log: (l) => console.log(l),
    error: (l) => console.error(l),
    // `npm run` starts in the package root; INIT_CWD is where the command was typed.
    readFile: (f) => readFileSync(path.resolve(process.env.INIT_CWD ?? process.cwd(), f), 'utf8'),
  };
  process.exitCode = runCasesCommand(getDb(), parsed.command, io);
}

/** True when this file is the entry point (`node --import tsx src/cli/cases.ts`), not imported by a test. */
function isEntryPoint(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) main();
