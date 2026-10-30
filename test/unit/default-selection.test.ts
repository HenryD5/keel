import { describe, expect, it } from 'vitest';
import type { PackageReport } from '../../src/core/scan';
import type { ScanPayload } from '../../src/webview/protocol';
import { defaultSelected } from '../../webview-ui/src/model';

function pkg(name: string, bump: 'patch' | 'minor' | 'major', agrees = true): PackageReport {
  return { name, reference: { agrees }, resolution: { recommended: { version: '1.0.0', bump } } } as unknown as PackageReport;
}

function scan(packages: PackageReport[], keep: ScanPayload['keep'] = {}): ScanPayload {
  return { result: { packages }, keep, choices: {} } as unknown as ScanPayload;
}

describe('defaultSelected', () => {
  it('marca patch y minor, y deja sin marcar los major', () => {
    expect(defaultSelected(scan([pkg('a', 'patch'), pkg('b', 'minor'), pkg('c', 'major')]))).toEqual(['a', 'b']);
  });

  it('deja sin marcar lo que la segunda referencia contradice', () => {
    expect(defaultSelected(scan([pkg('a', 'patch', false)]))).toEqual([]);
  });

  it('deja sin marcar lo que el dev decidió mantener', () => {
    const keep = { a: {} } as unknown as ScanPayload['keep'];
    expect(defaultSelected(scan([pkg('a', 'patch')], keep))).toEqual([]);
  });
});
