import type { JobHandler } from '../lib/jobs/types';

/** Test job: `npm run job -- noop --steps 5`. */
export const run: JobHandler = async (ctx) => {
  const steps = Number(ctx.params.steps ?? 5);
  for (let i = 1; i <= steps; i++) {
    ctx.throwIfCancelled();
    ctx.progress(`step ${i}/${steps}`);
    ctx.log(`step ${i}`);
    await new Promise((r) => setTimeout(r, 1000));
  }
  return { steps };
};
