import { describe, expect, it } from 'vitest';
import {
  dependentsOf,
  LockfileError,
  nameFromPath,
  parseLockfile,
  resolveDependency,
  topLevelAncestors,
} from '../../src/core/audit/lockfile';
import { fixtureText } from './helpers';

describe('parseLockfile', () => {
  const v3 = parseLockfile(fixtureText('lockfile/sample-v3.json'));

  it('lee lockfile v3 con versiones instaladas', () => {
    expect(v3.lockfileVersion).toBe(3);
    expect(v3.packages.get('node_modules/axios')!.version).toBe('1.18.0');
    expect(v3.packages.get('node_modules/vite')!.dev).toBe(true);
    expect(v3.packages.get('')!.deps.get('vite')).toEqual({ range: '~5.4.2', type: 'dev' });
  });

  it('lee lockfile v2 desde la sección packages', () => {
    const v2 = parseLockfile(fixtureText('lockfile/sample-v2.json'));
    expect(v2.lockfileVersion).toBe(2);
    expect(v2.packages.get('node_modules/jsonwebtoken')!.version).toBe('8.5.1');
  });

  it('rechaza lockfile v1 y JSON inválido', () => {
    expect(() => parseLockfile(JSON.stringify({ lockfileVersion: 1, dependencies: {} }))).toThrowError(LockfileError);
    expect(() => parseLockfile('{')).toThrowError(LockfileError);
  });
});

describe('resolución de dependencias', () => {
  const lock = parseLockfile(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { a: '^1.0.0', b: '^1.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { '@s/c': '^2.0.0' } },
        'node_modules/a/node_modules/@s/c': { version: '2.1.0' },
        'node_modules/b': { version: '1.0.0', dependencies: { '@s/c': '^1.0.0' } },
        'node_modules/@s/c': { version: '1.5.0' },
      },
    }),
  );

  it('extrae el nombre desde la ruta, también con scope', () => {
    expect(nameFromPath('node_modules/a/node_modules/@s/c')).toBe('@s/c');
  });

  it('busca primero en node_modules anidado y luego sube', () => {
    expect(resolveDependency(lock, 'node_modules/a', '@s/c')).toBe('node_modules/a/node_modules/@s/c');
    expect(resolveDependency(lock, 'node_modules/b', '@s/c')).toBe('node_modules/@s/c');
    expect(resolveDependency(lock, 'node_modules/b', 'nope')).toBeUndefined();
  });

  it('encuentra quién depende de cada copia instalada', () => {
    expect(dependentsOf(lock, 'node_modules/@s/c').map((d) => [d.name, d.range])).toEqual([['b', '^1.0.0']]);
    expect(dependentsOf(lock, 'node_modules/a/node_modules/@s/c').map((d) => d.name)).toEqual(['a']);
  });

  it('en el fixture real, braces llega por chokidar y esbuild por vite', () => {
    const real = parseLockfile(fixtureText('lockfile/sample-v3.json'));
    expect(dependentsOf(real, 'node_modules/braces').map((d) => [d.name, d.range])).toEqual([['chokidar', '~3.0.2']]);
    expect(topLevelAncestors(real, 'node_modules/braces')).toEqual(['chokidar']);
    expect(topLevelAncestors(real, 'node_modules/esbuild')).toEqual(['vite']);
  });
});
