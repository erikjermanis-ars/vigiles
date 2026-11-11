/** Projects (spec §12): every project with ref → commit, lockfiles, coverage gaps and counts. */
import Link from 'next/link';
import { Card, CardBody, CardHeader, Empty, PageHeader } from '@/components/ui';
import { getDb } from '@/lib/db/client';
import { listProjectsOverview } from '@/lib/queries/projects';
import { ProjectBadges, ProjectSummary } from './_components/project-summary';

export default function ProjectsPage() {
  const projects = listProjectsOverview(getDb());
  return (
    <>
      <PageHeader title="Projects" subtitle="Profiles live in projects/*.yaml and are synced to the database before every job." />
      {projects.length === 0 ? (
        <Empty>
          No projects in the database yet. Add a profile under <code>projects/</code>, then run any job on the{' '}
          <Link href="/jobs">Jobs</Link> page.
        </Empty>
      ) : (
        <div className="space-y-4">
          {projects.map((p) => (
            <Card key={p.project.id} className={p.project.enabled ? undefined : 'opacity-75'}>
              <CardHeader
                title={
                  <span className="inline-flex flex-wrap items-center gap-2">
                    <Link href={`/projects/${encodeURIComponent(p.project.id)}`}>{p.project.name}</Link>
                    <ProjectBadges project={p.project} />
                  </span>
                }
              />
              <CardBody>
                <ProjectSummary overview={p} />
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
