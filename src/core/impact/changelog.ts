import semver from 'semver';
import type { Packument } from '../registry/types';

export const GITHUB_API_ORIGIN = 'https://api.github.com';

export interface GitHubRepo {
  owner: string;
  repo: string;
}

/** Lo que Keel guarda de cada GitHub Release. */
export interface Release {
  tag: string;
  name?: string;
  url: string;
  publishedAt?: string;
  body: string;
}

/** Release con la versión npm que le corresponde. */
export interface VersionRelease extends Release {
  version: string;
}

export interface ChangelogCache {
  get(key: string): Release[] | undefined;
  set(key: string, releases: Release[]): void;
}

export type GetJson = (url: string) => Promise<unknown>;

const NAME = /^[A-Za-z0-9_.-]+$/;
const PER_PAGE = 100;
const MAX_PAGES = 3;
/** Tope por release para no guardar notas enormes en la caché. */
const MAX_BODY = 20_000;

/**
 * `repository` del registro → dueño y repo de GitHub. Acepta las formas que publica npm:
 * `git+https://github.com/o/r.git`, `git://`, `git@github.com:o/r.git`, `github:o/r` y `o/r`.
 */
export function githubRepoFromRepository(repository: Packument['repository']): GitHubRepo | undefined {
  const raw = (typeof repository === 'string' ? repository : repository?.url)?.trim();
  if (!raw) return undefined;
  let m = raw.match(/^(?:github:)?([^/:@\s]+)\/([^/#\s]+?)(?:\.git)?(?:#.*)?$/);
  if (!m || /^(?:gitlab|bitbucket|gist):/.test(raw)) {
    m = raw.match(/github\.com[/:]([^/\s]+)\/([^/#?\s]+?)(?:\.git)?(?:[/#?].*)?$/i);
  }
  if (!m) return undefined;
  const [owner, repo] = [m[1]!, m[2]!];
  return NAME.test(owner) && NAME.test(repo) ? { owner, repo } : undefined;
}

export function releasesUrl({ owner, repo }: GitHubRepo, page: number): string {
  return `${GITHUB_API_ORIGIN}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/releases?per_page=${PER_PAGE}&page=${page}`;
}

/**
 * Versión npm de un tag. Acepta `1.2.3`, `v1.2.3`, `pkg@1.2.3` y `pkg@v1.2.3`;
 * en monorepos (tags con prefijo de otro paquete) descarta los que no son de `pkg`.
 */
export function versionFromTag(tag: string, pkg: string): string | undefined {
  let rest = tag;
  const at = tag.lastIndexOf('@');
  if (at > 0) {
    const prefix = tag.slice(0, at);
    const unscoped = pkg.replace(/^@[^/]+\//, '');
    if (prefix !== pkg && prefix !== unscoped) return undefined;
    rest = tag.slice(at + 1);
  }
  rest = rest.replace(/^v/, '');
  return semver.valid(rest) ?? undefined;
}

interface RawRelease {
  tag_name?: string;
  name?: string | null;
  html_url?: string;
  draft?: boolean;
  prerelease?: boolean;
  published_at?: string | null;
  body?: string | null;
}

function toRelease(raw: RawRelease): Release | undefined {
  if (!raw.tag_name || raw.draft || raw.prerelease) return undefined;
  return {
    tag: raw.tag_name,
    name: raw.name ?? undefined,
    url: typeof raw.html_url === 'string' && raw.html_url.startsWith('https://github.com/') ? raw.html_url : '',
    publishedAt: raw.published_at ?? undefined,
    body: (raw.body ?? '').slice(0, MAX_BODY),
  };
}

/**
 * Releases publicadas (sin borradores ni prereleases), de la más nueva a la más vieja.
 * Pide páginas hasta llegar a una release anterior o igual a `oldest`, o hasta 3 páginas.
 */
export async function fetchReleases(repo: GitHubRepo, pkg: string, oldest: string, getJson: GetJson): Promise<Release[]> {
  const releases: Release[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const data = await getJson(releasesUrl(repo, page));
    if (!Array.isArray(data)) throw new Error(`Unexpected GitHub response for ${repo.owner}/${repo.repo}.`);
    for (const raw of data as RawRelease[]) {
      const r = toRelease(raw);
      if (r) releases.push(r);
    }
    const reachedOldest = releases.some((r) => {
      const v = versionFromTag(r.tag, pkg);
      return v !== undefined && semver.lte(v, oldest);
    });
    if (data.length < PER_PAGE || reachedOldest) break;
  }
  return releases;
}

/** Releases con versión `from < v ≤ to`, de la más nueva a la más vieja. */
export function releasesBetween(releases: readonly Release[], pkg: string, from: string, to: string): VersionRelease[] {
  const out: VersionRelease[] = [];
  for (const r of releases) {
    const version = versionFromTag(r.tag, pkg);
    if (version && semver.prerelease(version) === null && semver.gt(version, from) && semver.lte(version, to)) {
      out.push({ ...r, version });
    }
  }
  return out.sort((a, b) => semver.rcompare(a.version, b.version));
}

export interface ChangelogResult {
  repo?: GitHubRepo;
  releases: VersionRelease[];
  /** Enlace a la lista de releases (o al repositorio). */
  url?: string;
  /** Repositorio fuera de GitHub o sin campo `repository`. */
  unavailable?: 'no-repository' | 'not-github';
  /** El repo existe pero no publica GitHub Releases en ese tramo. */
  empty?: boolean;
  error?: string;
}

export async function getChangelog(input: {
  name: string;
  repository: Packument['repository'];
  from: string;
  to: string;
  getJson: GetJson;
  cache?: ChangelogCache;
}): Promise<ChangelogResult> {
  const { name, repository, from, to, getJson, cache } = input;
  if (!repository) return { releases: [], unavailable: 'no-repository' };
  const repo = githubRepoFromRepository(repository);
  if (!repo) return { releases: [], unavailable: 'not-github' };
  const url = `https://github.com/${repo.owner}/${repo.repo}/releases`;

  // La clave incluye `from`: una caché pedida desde una versión más nueva podría no llegar hasta esta.
  const key = `${repo.owner}/${repo.repo}#${name}@${from}`;
  try {
    let releases = cache?.get(key);
    if (!releases) {
      releases = await fetchReleases(repo, name, from, getJson);
      cache?.set(key, releases);
    }
    const between = releasesBetween(releases, name, from, to);
    return { repo, url, releases: between, empty: between.length === 0 };
  } catch (err) {
    return { repo, url, releases: [], error: err instanceof Error ? err.message : String(err) };
  }
}
