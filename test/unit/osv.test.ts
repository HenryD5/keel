import { describe, expect, it, vi } from 'vitest';
import { OsvReference, maliciousVersions, osvAffects, queryOsv, type OsvVuln } from '../../src/core/reference/osv';
import { fixtureText, makePackument, packumentFixture } from './helpers';

const osv = (name: string) => JSON.parse(fixtureText(`osv/${name}.json`)) as { vulns: OsvVuln[] };

describe('OSV', () => {
  it('evalúa rangos SEMVER reales e introduced 0', () => {
    const vuln = osv('braces').vulns.find((v) => v.id === 'GHSA-grv7-fg5c-xmjg')!;
    expect(osvAffects(vuln, 'braces', '3.0.2')).toBe(true);
    expect(osvAffects(vuln, 'braces', '3.0.3')).toBe(false);
    expect(osvAffects(vuln, 'braces', '0.1.0')).toBe(true);
  });

  it('evalúa last_affected y listas de versiones', () => {
    const ranged: OsvVuln = { id: 'X', affected: [{ package: { name: 'pkg' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { last_affected: '1.2.0' }] }] }] };
    const listed: OsvVuln = { id: 'Y', affected: [{ package: { name: 'pkg' }, versions: ['4.2.0'] }] };
    expect(osvAffects(ranged, 'pkg', '1.2.0')).toBe(true);
    expect(osvAffects(ranged, 'pkg', '1.2.1')).toBe(false);
    expect(osvAffects(listed, 'pkg', '4.2.0')).toBe(true);
  });

  it('solo devuelve versiones maliciosas que siguen publicadas', () => {
    const vulns = osv('node-ipc').vulns;
    expect([...maliciousVersions(vulns, 'node-ipc', Object.keys(packumentFixture('node-ipc').versions))]).toEqual([]);
    const synthetic = makePackument({ '9.1.6': {}, '9.2.3': {}, '12.0.1': {}, '12.0.2': {} });
    expect([...maliciousVersions(vulns, 'node-ipc', Object.keys(synthetic.versions))]).toEqual(['9.1.6', '9.2.3', '12.0.1']);
  });

  it('pagina y filtra avisos retirados', async () => {
    const post = vi.fn().mockResolvedValueOnce({ vulns: [{ id: 'A' }, { id: 'OLD', withdrawn: '2025-01-01' }], next_page_token: 'next' }).mockResolvedValueOnce({ vulns: [{ id: 'B' }] });
    expect((await queryOsv('axios', post)).map((v) => v.id)).toEqual(['A', 'B']);
    expect(post.mock.calls[1]![1]).toMatchObject({ page_token: 'next' });
  });

  it('cachea una consulta entre exclusiones e issues', async () => {
    const post = vi.fn(async () => osv('node-ipc'));
    const ref = new OsvReference(post, async () => ['9.1.6']);
    await ref.excludedVersions('node-ipc');
    await ref.issuesFor('node-ipc', '9.1.6');
    expect(post).toHaveBeenCalledTimes(1);
  });
});
