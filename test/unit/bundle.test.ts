import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const bundlePath = resolve('dist/extension.js');

describe('bundle de la extensión', () => {
  it.skipIf(!existsSync(bundlePath))('no contiene módulos UMD ni require relativos', () => {
    const bundle = readFileSync(bundlePath, 'utf8');

    expect(bundle).not.toContain('jsonc-parser/lib/umd');
    expect(bundle).not.toContain('require("./');
  });
});
