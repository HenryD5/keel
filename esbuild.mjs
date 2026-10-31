import * as esbuild from 'esbuild';
import { readFile } from 'node:fs/promises';

const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');
const packageJson = JSON.parse(await readFile(new URL('./package.json', import.meta.url), 'utf8'));

const extension = await esbuild.context({
  entryPoints: ['src/extension.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'node',
  target: 'node20',
  mainFields: ['module', 'main'],
  outfile: 'dist/extension.js',
  external: ['vscode'],
  sourcemap: !production,
  minify: production,
  logLevel: 'info',
});

const cli = await esbuild.context({
  entryPoints: ['src/cli/index.ts'], bundle: true, format: 'cjs', platform: 'node', target: 'node20',
  mainFields: ['module', 'main'],
  outfile: 'dist/cli.js', banner: { js: '#!/usr/bin/env node' }, sourcemap: !production,
  minify: production, logLevel: 'info', define: { __KEEL_VERSION__: JSON.stringify(packageJson.version) },
});

if (watch) {
  await Promise.all([extension.watch(), cli.watch()]);
} else {
  await Promise.all([extension.rebuild(), cli.rebuild()]);
  await Promise.all([extension.dispose(), cli.dispose()]);
  await import('node:fs/promises').then(({ chmod }) => chmod('dist/cli.js', 0o755));
}
