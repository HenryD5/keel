import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(__dirname, '..', '..');

describe('l10n', () => {
  it('traduce cada literal de l10n.t de src', () => {
    const bundle = readJson('l10n/bundle.l10n.es.json');
    const literals = sourceFiles(join(ROOT, 'src')).flatMap((file) => {
      const text = readFileSync(file, 'utf8');
      return [...text.matchAll(/(?:vscode\.)?l10n\.t\(\s*'((?:\\.|[^'\\])*)'/g)].map((match) => unescapeLiteral(match[1]!));
    });
    expect(Object.keys(bundle).sort()).toEqual([...new Set(literals)].sort());
  });

  it('mantiene las mismas claves nls y cubre package.json', () => {
    const english = readJson('package.nls.json');
    const spanish = readJson('package.nls.es.json');
    const packageText = readFileSync(join(ROOT, 'package.json'), 'utf8');
    const referenced = [...packageText.matchAll(/%([^%]+)%/g)].map((match) => match[1]!);
    expect(Object.keys(spanish).sort()).toEqual(Object.keys(english).sort());
    expect([...new Set(referenced)].sort()).toEqual(Object.keys(english).sort());
  });
});

function readJson(relative: string): Record<string, string> {
  return JSON.parse(readFileSync(join(ROOT, relative), 'utf8')) as Record<string, string>;
}

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? sourceFiles(path) : path.endsWith('.ts') ? [path] : [];
  });
}

function unescapeLiteral(value: string): string {
  return value.replace(/\\'/g, "'").replace(/\\\\/g, '\\');
}
