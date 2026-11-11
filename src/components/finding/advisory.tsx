/**
 * Advisory text is untrusted (spec §15): Markdown renders with raw HTML skipped, links open in a new
 * tab without an opener, and images become plain links so nothing remote loads on page view.
 */
import Markdown, { type Components } from 'react-markdown';
import type { ReactNode } from 'react';
import { Kv, Mono } from '@/components/ui';
import { shortDate } from '@/lib/format';
import { isHttpUrl } from './helpers';

export function ExternalLink({ href, children }: { href: string; children?: ReactNode }) {
  if (!isHttpUrl(href)) return <span className="break-all">{children ?? href}</span>;
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="break-all">
      {children ?? href}
    </a>
  );
}

const markdownComponents: Components = {
  a: ({ href, children }) => (href ? <ExternalLink href={href}>{children}</ExternalLink> : <span>{children}</span>),
  img: ({ src, alt }) =>
    typeof src === 'string' && src ? <ExternalLink href={src}>[image: {alt || src}]</ExternalLink> : null,
};

export function AdvisoryMarkdown({ text }: { text: string }) {
  return (
    <div className="prose-advisory min-w-0 text-sm break-words">
      <Markdown skipHtml components={markdownComponents}>
        {text}
      </Markdown>
    </div>
  );
}

export interface AdvisoryFields {
  summary: string | null;
  details: string | null;
  references: string[];
  cwes: string[];
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
}

/** Summary, details, references and metadata of an advisory. */
export function AdvisoryBody({ advisory, collapseReferences = false }: { advisory: AdvisoryFields; collapseReferences?: boolean }) {
  const refs = advisory.references.length ? (
    <ul className="space-y-0.5 text-sm">
      {advisory.references.map((r, i) => (
        // References can repeat (same URL under two types), so the index is part of the key.
        <li key={`${i}:${r}`}>
          <ExternalLink href={r} />
        </li>
      ))}
    </ul>
  ) : (
    <span className="text-muted">none</span>
  );
  return (
    <div className="space-y-3">
      {advisory.withdrawn ? (
        <div className="rounded-md bg-digest-bg px-3 py-2 text-sm text-digest">Withdrawn on {shortDate(advisory.withdrawn)}.</div>
      ) : null}
      {advisory.summary ? <p className="font-medium">{advisory.summary}</p> : null}
      {advisory.details ? <AdvisoryMarkdown text={advisory.details} /> : <p className="text-sm text-muted">No details.</p>}
      <Kv
        items={[
          ['CWE', advisory.cwes.length ? advisory.cwes.map((c, i) => <Mono key={`${i}:${c}`}>{c} </Mono>) : '—'],
          ['Published', shortDate(advisory.published)],
          ['Modified', shortDate(advisory.modified)],
          [
            'References',
            collapseReferences && advisory.references.length > 3 ? (
              <details>
                <summary className="cursor-pointer text-muted">{advisory.references.length} links</summary>
                {refs}
              </details>
            ) : (
              refs
            ),
          ],
        ]}
      />
    </div>
  );
}
