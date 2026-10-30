import { describe, expect, it } from 'vitest';
import type { PackageReport } from '../../src/core/scan';
import { scopeToFilter } from '../../webview-ui/src/filter';

function pkg(name: string, bump: 'patch' | 'minor' | 'major'): PackageReport {
  return { name, resolution: { recommended: { bump } } } as unknown as PackageReport;
}

const packages = [pkg('a', 'patch'), pkg('b', 'minor'), pkg('c', 'major'), pkg('d', 'patch')];

describe('scopeToFilter', () => {
  it('con «Todos» conserva toda la selección', () => {
    expect(scopeToFilter(packages, ['a', 'b', 'c'], 'all')).toEqual(['a', 'b', 'c']);
  });

  it('con «Seguros» deja solo los seguros marcados', () => {
    expect(scopeToFilter(packages, ['a', 'b', 'c'], 'safe')).toEqual(['a']);
  });

  it('no añade paquetes del filtro que no estén marcados', () => {
    expect(scopeToFilter(packages, ['b'], 'safe')).toEqual([]);
  });
});
