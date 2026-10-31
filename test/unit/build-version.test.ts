import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(import.meta.dirname, '../..');

describe('CLI build version', () => {
  it('injects the package.json version through esbuild', () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string };
    const build = readFileSync(join(ROOT, 'esbuild.mjs'), 'utf8');
    const cli = readFileSync(join(ROOT, 'src/cli/index.ts'), 'utf8');

    expect(manifest.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(build).toContain('define: { __KEEL_VERSION__: JSON.stringify(packageJson.version) }');
    expect(cli).toContain("typeof __KEEL_VERSION__ === 'string' ? __KEEL_VERSION__");
    expect(cli).not.toMatch(/const VERSION = ['"]\d+\.\d+\.\d+['"]/);
  });
});
