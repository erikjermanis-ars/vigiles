/** Keeps prompts/triage/v1.schema.json (sent to claude) and TriageOutputSchema (zod, used to validate) in lockstep. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { TriageOutputSchema } from '../types';

type JsonSchema = {
  type?: string | string[];
  enum?: unknown[];
  anyOf?: JsonSchema[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: unknown;
  items?: JsonSchema;
};

interface Shape {
  types: string[];
  enum?: unknown[];
  properties?: Record<string, Shape>;
  required?: string[];
  items?: Shape;
}

/** Reduces both flavours of nullability (`type: [x, 'null']` and `anyOf`) and drops annotations. */
function normalize(node: JsonSchema): Shape {
  const variants = node.anyOf ?? [node];
  const types = new Set<string>();
  const out: Shape = { types: [] };
  for (const v of variants) {
    for (const t of Array.isArray(v.type) ? v.type : v.type ? [v.type] : []) types.add(t);
    if (v.enum) out.enum = [...v.enum].sort();
    if (v.properties) {
      out.properties = Object.fromEntries(Object.entries(v.properties).map(([k, p]) => [k, normalize(p)]));
      out.required = [...(v.required ?? [])].sort();
    }
    if (v.items) out.items = normalize(v.items);
  }
  out.types = [...types].sort();
  return out;
}

function objectNodes(node: JsonSchema, at = '$'): { at: string; node: JsonSchema }[] {
  const own = node.properties ? [{ at, node }] : [];
  const children = Object.entries(node.properties ?? {}).flatMap(([k, p]) => objectNodes(p, `${at}.${k}`));
  const items = node.items ? objectNodes(node.items, `${at}[]`) : [];
  return [...own, ...children, ...items];
}

const jsonSchema = JSON.parse(readFileSync(path.join(import.meta.dirname, '../../../prompts/triage/v1.schema.json'), 'utf8')) as JsonSchema;

describe('prompts/triage/v1.schema.json', () => {
  it('matches TriageOutputSchema: same keys, types, enums and nullability', () => {
    const fromZod = z.toJSONSchema(TriageOutputSchema) as JsonSchema;
    expect(normalize(jsonSchema)).toEqual(normalize(fromZod));
  });

  it('notices drift in enums, nullability and keys', () => {
    const fromZod = normalize(z.toJSONSchema(TriageOutputSchema) as JsonSchema);
    const drift = (mutate: (s: JsonSchema) => void) => {
      const copy = structuredClone(jsonSchema);
      mutate(copy);
      return normalize(copy);
    };
    expect(drift((s) => (s.properties!.verdict!.enum = ['affected']))).not.toEqual(fromZod);
    expect(drift((s) => (s.properties!.workaround!.type = 'string'))).not.toEqual(fromZod);
    expect(drift((s) => delete s.properties!.evidence!.items!.properties!.line)).not.toEqual(fromZod);
  });

  it('requires every property and forbids extra ones on every object', () => {
    const nodes = objectNodes(jsonSchema);
    expect(nodes.map((n) => n.at)).toEqual(['$', '$.evidence[]']);
    for (const { at, node } of nodes) {
      expect(node.additionalProperties, at).toBe(false);
      expect([...(node.required ?? [])].sort(), at).toEqual(Object.keys(node.properties ?? {}).sort());
    }
  });

  it('accepts what zod accepts', () => {
    const sample = {
      verdict: 'not_affected',
      confidence: 'high',
      runtime_usage: 'build_or_tooling_only',
      vulnerable_code_used: 'no',
      attacker_reachable: 'no',
      deployment_conditions_met: 'unknown',
      summary: 's',
      evidence: [{ file: '(dependency facts)', line: null, note: 'only via shadcn' }],
      exploit_conditions: 'none',
      remediation: 'upgrade',
      workaround: null,
      suggested_action: 'log',
      suggested_action_reason: 'tooling only',
    };
    expect(TriageOutputSchema.safeParse(sample).success).toBe(true);
    expect(Object.keys(sample).sort()).toEqual(Object.keys(jsonSchema.properties ?? {}).sort());
  });
});
