/**
 * The coverage gate: the module ships with 100 percent branch coverage, and this script proves it.
 *
 * It runs the test suite with the coverage reporter, reads the branch percentage of every file of
 * the module, and exits with code 1 when any of them is below 100. The house rules ask for tests
 * that fail without the change; this gate is the machine check for the coverage part.
 *
 * Usage: node tools/coverage_gate.mjs
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = ['--experimental-strip-types', '--experimental-test-coverage', '--test', 'test/*.test.ts'];

const child = spawn(process.execPath, args, { cwd: root, shell: false });
let out = '';
child.stdout.on('data', (d) => { out += d; process.stdout.write(d); });
child.stderr.on('data', (d) => { out += d; process.stderr.write(d); });

child.on('close', (code) => {
  if (code !== 0) {
    console.error(`the tests failed (exit ${code}), the coverage gate did not run`);
    process.exit(1);
  }
  // Lines look like: "ℹ  chamber1.ts | 100.00 | 100.00 | 100.00 |" once the reporter prefix is removed.
  const rows = out
    .split('\n')
    .map((l) => l.replace(/^[^A-Za-z0-9_./-]*/, '').trim())
    .filter((l) => /^[^\s|]*\.ts\s*\|/.test(l))
    .map((l) => l.split('|').map((c) => c.trim()))
    .filter((c) => c.length >= 4 && c[0].endsWith('.ts'));
  if (!rows.length) {
    console.error('no coverage rows were found in the report, the gate cannot pass');
    process.exit(1);
  }
  let bad = 0;
  for (const [file, , branch] of rows) {
    const pct = Number(branch);
    const label = file === 'all files' ? 'all files' : file;
    if (!Number.isFinite(pct) || pct < 100) {
      console.error(`FAIL branch coverage of ${label} is ${branch}, it must be 100.00`);
      bad += 1;
    } else {
      console.log(`ok   branch coverage of ${label} is ${branch}`);
    }
  }
  process.exit(bad ? 1 : 0);
});
