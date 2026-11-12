/** Projects (spec §12): each project's state at a glance (monitored, last scan, coverage gaps) and its open findings. */
import Link from 'next/link';
import { Empty, PageHeader } from '@/components/ui';
import { getDb } from '@/lib/db/client';
import { colorFor, projectColors } from '@/lib/project-scope';
import { listProjectsOverview } from '@/lib/queries/projects';
import { ProjectStateCard } from './_components/project-summary';

export default function ProjectsPage() {
  const projects = listProjectsOverview(getDb());
  const colors = projectColors(projects.map((p) => p.project.id));
  const enabled = projects.filter((p) => p.project.enabled).length;
  return (
    <>
      <PageHeader
        title="Projects"
        subtitle={
          <>
            {enabled} of {projects.length} project{projects.length === 1 ? '' : 's'} monitored. Profiles live in{' '}
            <code>projects/*.yaml</code> and are synced to the database before every job.
          </>
        }
      />
      {projects.length === 0 ? (
        <Empty>
          No projects in the database yet. Add a profile under <code>projects/</code>, then run any job on the{' '}
          <Link href="/jobs">Jobs</Link> page.
        </Empty>
      ) : (
        <div className="space-y-4">
          {projects.map((p) => (
            <ProjectStateCard key={p.project.id} overview={p} color={colorFor(colors, p.project.id)} />
          ))}
        </div>
      )}
    </>
  );
}
