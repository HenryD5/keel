import { describe, expect, it } from 'vitest';
import { parseLockfile } from '../../src/core/audit/lockfile';
import { findPeerConflicts } from '../../src/core/apply/peers';
import type { Packument } from '../../src/core/registry/types';

// El caso real: vitest 3.2.6 → 3.2.7 con @vitest/ui y @vitest/coverage-v8 3.2.6 como dependencias directas.
const lock = parseLockfile(
  JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', devDependencies: { vitest: '3.2.6', '@vitest/ui': '3.2.6', '@vitest/coverage-v8': '3.2.6', 'vitest-sonar-reporter': '^3.0.0' } },
      'node_modules/vitest': { version: '3.2.6', peerDependencies: { '@vitest/ui': '3.2.6' } },
      'node_modules/@vitest/ui': { version: '3.2.6', peerDependencies: { vitest: '3.2.6' } },
      'node_modules/@vitest/coverage-v8': { version: '3.2.6', peerDependencies: { vitest: '3.2.6', '@vitest/browser': '3.2.6' } },
      'node_modules/vitest-sonar-reporter': { version: '3.0.0', peerDependencies: { vitest: '>=3' } },
    },
  }),
);

function family(name: string, peer: (v: string) => Record<string, string>): Packument {
  const versions = Object.fromEntries(['3.2.6', '3.2.7', '4.1.11'].map((v) => [v, { name, version: v, peerDependencies: peer(v) }]));
  return { name, 'dist-tags': { latest: '4.1.11' }, time: {}, versions };
}

const packuments: Record<string, Packument> = {
  vitest: family('vitest', (v) => ({ '@vitest/ui': v, '@vitest/browser': v })),
  '@vitest/ui': family('@vitest/ui', (v) => ({ vitest: v })),
  '@vitest/coverage-v8': family('@vitest/coverage-v8', (v) => ({ vitest: v, '@vitest/browser': v })),
};
const getPackument = async (name: string) => packuments[name]!;

describe('findPeerConflicts', () => {
  it('detecta el ERESOLVE de vitest 3.2.7 y propone mover @vitest/ui y @vitest/coverage-v8 a 3.2.7', async () => {
    const conflicts = await findPeerConflicts({ planned: [{ name: 'vitest', to: '3.2.7' }], lock, getPackument });
    expect(conflicts.map((c) => `${c.requirer}@${c.requirerVersion} → ${c.peer}@${c.range}`).sort()).toEqual([
      '@vitest/coverage-v8@3.2.6 → vitest@3.2.6',
      '@vitest/ui@3.2.6 → vitest@3.2.6',
      'vitest@3.2.7 → @vitest/ui@3.2.7',
    ]);
    const fixes = new Map(conflicts.map((c) => [c.fix?.name, c.fix?.to]));
    expect(fixes.get('@vitest/ui')).toBe('3.2.7');
    expect(fixes.get('@vitest/coverage-v8')).toBe('3.2.7');
  });

  it('con los hermanos en el plan ya no hay conflicto; un rango amplio (>=3) no choca', async () => {
    const planned = [{ name: 'vitest', to: '3.2.7' }, { name: '@vitest/ui', to: '3.2.7' }, { name: '@vitest/coverage-v8', to: '3.2.7' }];
    expect(await findPeerConflicts({ planned, lock, getPackument })).toEqual([]);
  });
});
