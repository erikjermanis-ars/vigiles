/**
 * Process entry of the Vigiles CLI: plugin/bin/vigiles is this file bundled (scripts/build-plugin.mjs), and
 * `npm run vigiles` runs it from source. Everything else is in cli.ts, which tests import without running it.
 */
import { main } from './cli';

// A closed pipe (`vigiles scan | head`) is not an error.
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code !== 'EPIPE') throw err;
  });
}

void main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
  // Exit even if an idle keep-alive socket or a child's kill timer is still around.
  setTimeout(() => process.exit(code), 200).unref();
});
