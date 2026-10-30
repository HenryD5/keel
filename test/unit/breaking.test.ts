import { describe, expect, it } from 'vitest';
import { cleanMarkdown, extractBreakingLines } from '../../src/core/impact/breaking';
import { fetchReleases, releasesBetween } from '../../src/core/impact/changelog';
import { fixtureText } from './helpers';

describe('breaking', () => {
  it('extrae la sección real de axios 1.20.0', async () => {
    const raw = await fetchReleases({ owner: 'axios', repo: 'axios' }, 'axios', '1.18.0', async () => JSON.parse(fixtureText('github/axios-releases.json')));
    const releases = releasesBetween(raw, 'axios', '1.18.0', '1.21.0');
    const lines = extractBreakingLines(releases);
    expect(lines).toContainEqual({ version: '1.20.0', text: 'HTTP Status Naming: Added ContentTooLarge (413) and UnprocessableContent (422), while retaining PayloadTooLarge and UnprocessableEntity as backward-compatible deprecated aliases. (#11082)' });
  });

  it('detecta BREAKING fuera de sección y secciones en negrita', () => {
    const releases = [{ version: '2.0.0', tag: 'v2', url: '', body: 'BREAKING CHANGE: remove old API\n\n**Breaking changes:**\n- **Rename:** use [new](https://example.test)' }];
    expect(extractBreakingLines(releases)).toEqual([
      { version: '2.0.0', text: 'remove old API' },
      { version: '2.0.0', text: 'Rename: use new' },
    ]);
  });

  it('deduplica y respeta el tope', () => {
    const releases = [{ version: '2.0.0', tag: 'v2', url: '', body: '## Breaking\n- One\n- one\n- Two\n- Three' }];
    expect(extractBreakingLines(releases, 2).map((x) => x.text)).toEqual(['One', 'Two']);
  });

  it('limpia markdown', () => {
    expect(cleanMarkdown('- ⚠️ BREAKING CHANGE: **Use** [new API](https://x) `now`')).toBe('Use new API now');
  });
});
