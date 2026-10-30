import { describe, expect, it, vi } from 'vitest';
import { fetchReleases, getChangelog, githubRepoFromRepository, releasesBetween, versionFromTag, type Release } from '../../src/core/impact/changelog';
import { fixtureText, packumentFixture } from './helpers';

const axiosReleases = JSON.parse(fixtureText('github/axios-releases.json'));

describe('changelog', () => {
  it('extrae repositorios GitHub de formas npm', () => {
    expect(githubRepoFromRepository(packumentFixture('axios').repository)).toEqual({ owner: 'axios', repo: 'axios' });
    expect(githubRepoFromRepository(packumentFixture('vite').repository)).toEqual({ owner: 'vitejs', repo: 'vite' });
    expect(githubRepoFromRepository('github:o/r')).toEqual({ owner: 'o', repo: 'r' });
    expect(githubRepoFromRepository('o/r')).toEqual({ owner: 'o', repo: 'r' });
    expect(githubRepoFromRepository('git@github.com:o/r.git')).toEqual({ owner: 'o', repo: 'r' });
    expect(githubRepoFromRepository('gitlab:o/r')).toBeUndefined();
  });

  it('interpreta tags simples, prefijados y scoped', () => {
    expect(versionFromTag('v1.2.3', 'pkg')).toBe('1.2.3');
    expect(versionFromTag('pkg@1.2.3', 'pkg')).toBe('1.2.3');
    expect(versionFromTag('@scope/pkg@1.2.3', '@scope/pkg')).toBe('1.2.3');
    expect(versionFromTag('other@1.2.3', 'pkg')).toBeUndefined();
  });

  it('selecciona releases de axios en el intervalo', async () => {
    const releases = await fetchReleases({ owner: 'axios', repo: 'axios' }, 'axios', '1.18.0', async () => axiosReleases);
    expect(releasesBetween(releases, 'axios', '1.18.0', '1.20.0').map((r) => r.version)).toEqual(['1.20.0', '1.19.0', '1.18.1']);
  });

  it('usa caché en la segunda consulta', async () => {
    const getJson = vi.fn(async () => axiosReleases);
    const values = new Map<string, Release[]>();
    const cache = { get: (key: string) => values.get(key), set: (key: string, releases: Release[]) => values.set(key, releases) };
    await getChangelog({ name: 'axios', repository: packumentFixture('axios').repository, from: '1.18.0', to: '1.20.0', getJson, cache });
    await getChangelog({ name: 'axios', repository: packumentFixture('axios').repository, from: '1.18.0', to: '1.20.0', getJson, cache });
    expect(getJson).toHaveBeenCalledTimes(1);
  });

  it('distingue vacío, sin repository y error HTTP', async () => {
    const empty = await getChangelog({ name: 'jsonwebtoken', repository: packumentFixture('jsonwebtoken').repository, from: '8.5.1', to: '9.0.3', getJson: async () => JSON.parse(fixtureText('github/jsonwebtoken-releases.json')) });
    expect(empty).toMatchObject({ releases: [], empty: true });
    expect(await getChangelog({ name: 'x', repository: undefined, from: '1.0.0', to: '2.0.0', getJson: async () => [] })).toEqual({ releases: [], unavailable: 'no-repository' });
    const failed = await getChangelog({ name: 'axios', repository: 'axios/axios', from: '1.18.0', to: '1.20.0', getJson: async () => { throw new Error('HTTP 403'); } });
    expect(failed.error).toBe('HTTP 403');
  });

  it('pagina hasta alcanzar oldest', async () => {
    const filler = (tag: string) => ({ tag_name: tag, html_url: 'https://github.com/o/r/releases/x', body: '' });
    const page1 = Array.from({ length: 100 }, (_, i) => filler(`v2.0.${100 - i}`));
    const get = vi.fn().mockResolvedValueOnce(page1).mockResolvedValueOnce([filler('v1.0.0')]);
    const releases = await fetchReleases({ owner: 'o', repo: 'r' }, 'pkg', '1.0.0', get);
    expect(get).toHaveBeenCalledTimes(2);
    expect(releases.at(-1)?.tag).toBe('v1.0.0');
  });
});
