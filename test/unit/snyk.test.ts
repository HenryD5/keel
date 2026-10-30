import { describe, expect, it, vi } from 'vitest';
import { SnykReference, parseSnykIssues, querySnyk, snykIssuesUrl, snykNextUrl } from '../../src/core/reference/snyk';
import { fixtureText } from './helpers';

const ORG = '123e4567-e89b-12d3-a456-426614174000';

describe('Snyk', () => {
  it('construye la URL con el purl entero codificado', () => {
    const url = snykIssuesUrl(ORG, '@scope/name', '1.2.3');
    expect(url).toContain('/packages/pkg%3Anpm%2F%40scope%2Fname%401.2.3/issues');
    expect(url).toContain('version=2024-10-15');
  });

  it.each([['org', 'axios', '1.0.0'], [ORG, '../bad', '1.0.0'], [ORG, 'axios', 'latest']])('rechaza org, paquete o versión inválidos', (org, name, version) => {
    expect(() => snykIssuesUrl(org, name, version)).toThrow();
  });

  it('resuelve links.next relativos', () => {
    expect(snykNextUrl('/orgs/x/next')).toBe('https://api.snyk.io/rest/orgs/x/next');
    expect(snykNextUrl('/rest/orgs/x/next')).toBe('https://api.snyk.io/rest/orgs/x/next');
    expect(snykNextUrl('relative')).toBeUndefined();
  });

  it('mapea severidad y detecta malware por CWE o título', () => {
    const doc = JSON.parse(fixtureText('snyk/axios-1.6.0-issues.json'));
    const issues = parseSnykIssues(doc);
    expect(issues[0]).toMatchObject({ id: 'SNYK-JS-AXIOS-6032459', severity: 'moderate', malicious: false });
    expect(issues[1]).toMatchObject({ severity: 'high', malicious: true });
    expect(parseSnykIssues({ data: [{ id: 'M', attributes: { title: 'Malicious Package' } }] })[0]!.malicious).toBe(true);
  });

  it('la respuesta 401 lanza por documento inesperado', () => {
    expect(() => parseSnykIssues(JSON.parse(fixtureText('snyk/error-401.json')))).toThrow('Unexpected Snyk response');
  });

  it('sigue links.next', async () => {
    const get = vi.fn().mockResolvedValueOnce({ data: [{ id: 'A' }], links: { next: '/orgs/x/packages/p/issues?page=2' } }).mockResolvedValueOnce({ data: [{ id: 'B' }], links: {} });
    expect((await querySnyk(ORG, 'axios', '1.0.0', 'token', get)).map((i) => i.id)).toEqual(['A', 'B']);
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('delega las exclusiones en la referencia de malware', async () => {
    const excludedVersions = vi.fn(async () => new Set(['1.2.3']));
    const ref = new SnykReference(ORG, 'token', async () => ({ data: [] }), { excludedVersions });
    expect(await ref.excludedVersions('pkg')).toEqual(new Set(['1.2.3']));
    expect(excludedVersions).toHaveBeenCalledWith('pkg');
  });
});
