import semver from 'semver';
import type { Severity } from '../audit/types';
import { assertPackageName } from '../validate';
import type { ReferenceIssue, SecondReference } from './types';

export const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

// Subconjunto del esquema OSV (https://ossf.github.io/osv-schema/) que usa Keel.
export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string; purl?: string };
  ranges?: Array<{ type: string; events: OsvEvent[] }>;
  versions?: string[];
}

export interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  withdrawn?: string;
  database_specific?: { severity?: string };
  affected?: OsvAffected[];
}

export interface OsvQueryResponse {
  vulns?: OsvVuln[];
  next_page_token?: string;
}

export type PostJson = (url: string, body: unknown) => Promise<unknown>;

const MAX_PAGES = 5;

export function isMalicious(vuln: Pick<OsvVuln, 'id'>): boolean {
  return vuln.id.startsWith('MAL-');
}

/** Todos los avisos de un paquete npm (una consulta por paquete, sin versión). */
export async function queryOsv(name: string, postJson: PostJson): Promise<OsvVuln[]> {
  assertPackageName(name);
  const vulns: OsvVuln[] = [];
  let pageToken: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const body = { package: { name, ecosystem: 'npm' }, ...(pageToken ? { page_token: pageToken } : {}) };
    const data = (await postJson(OSV_QUERY_URL, body)) as OsvQueryResponse | null;
    if (!data || typeof data !== 'object') throw new Error(`Unexpected OSV response for ${name}.`);
    vulns.push(...(data.vulns ?? []).filter((v) => typeof v?.id === 'string' && !v.withdrawn));
    pageToken = data.next_page_token;
    if (!pageToken) break;
  }
  return vulns;
}

/**
 * Si un aviso afecta a `version`, siguiendo la evaluación de rangos de OSV:
 * eventos ordenados, `introduced` abre, `fixed` (≤) y `last_affected` (<) cierran.
 * Un rango sin versiones legibles se trata como si afectara a todo, igual que en npm audit.
 */
export function osvAffects(vuln: OsvVuln, name: string, version: string): boolean {
  for (const affected of vuln.affected ?? []) {
    const pkg = affected.package;
    if (pkg && (pkg.name !== name || (pkg.ecosystem ?? 'npm') !== 'npm')) continue;
    if (affected.versions?.includes(version)) return true;
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      if (rangeAffects(range.events, version)) return true;
    }
  }
  return false;
}

function rangeAffects(events: readonly OsvEvent[], version: string): boolean {
  const parsed = events
    .map((e) => {
      const [kind, raw] = (Object.entries(e)[0] ?? []) as [keyof OsvEvent | undefined, string | undefined];
      const ver = raw === '0' ? '0.0.0' : raw;
      return kind && ver && semver.valid(ver) ? { kind, ver } : undefined;
    })
    .filter((e) => e !== undefined);
  if (parsed.length === 0) return true;
  parsed.sort((a, b) => semver.compare(a.ver, b.ver));

  let affected = false;
  for (const { kind, ver } of parsed) {
    if (kind === 'introduced' && semver.lte(ver, version)) affected = true;
    else if (kind === 'fixed' && semver.lte(ver, version)) affected = false;
    else if (kind === 'last_affected' && semver.lt(ver, version)) affected = false;
  }
  return affected;
}

/** Versiones publicadas que algún aviso `MAL-` marca como maliciosas. */
export function maliciousVersions(vulns: readonly OsvVuln[], name: string, versions: Iterable<string>): Set<string> {
  const mal = vulns.filter(isMalicious);
  const out = new Set<string>();
  if (mal.length === 0) return out;
  for (const v of versions) if (mal.some((m) => osvAffects(m, name, v))) out.add(v);
  return out;
}

export function osvIssuesFor(vulns: readonly OsvVuln[], name: string, version: string): ReferenceIssue[] {
  return vulns
    .filter((v) => osvAffects(v, name, version))
    .map((v) => ({ id: v.id, title: v.summary ?? v.id, severity: osvSeverity(v), malicious: isMalicious(v) }));
}

const SEVERITY_MAP: Record<string, Severity> = { LOW: 'low', MODERATE: 'moderate', MEDIUM: 'moderate', HIGH: 'high', CRITICAL: 'critical' };

function osvSeverity(vuln: OsvVuln): Severity | undefined {
  const s = vuln.database_specific?.severity;
  return s ? SEVERITY_MAP[s.toUpperCase()] : undefined;
}

/** Segunda referencia con OSV: una consulta por paquete, cacheada por instancia (una por escaneo). */
export class OsvReference implements SecondReference {
  readonly source = 'osv' as const;
  private readonly cache = new Map<string, Promise<OsvVuln[]>>();

  constructor(
    private readonly postJson: PostJson,
    /** Versiones publicadas del paquete, para expandir los rangos `MAL-`. */
    private readonly publishedVersions: (name: string) => Promise<string[]>,
  ) {}

  vulns(name: string): Promise<OsvVuln[]> {
    let pending = this.cache.get(name);
    if (!pending) {
      pending = queryOsv(name, this.postJson);
      pending.catch(() => this.cache.delete(name));
      this.cache.set(name, pending);
    }
    return pending;
  }

  async excludedVersions(name: string): Promise<Set<string>> {
    return maliciousVersions(await this.vulns(name), name, await this.publishedVersions(name));
  }

  async issuesFor(name: string, version: string): Promise<ReferenceIssue[]> {
    return osvIssuesFor(await this.vulns(name), name, version);
  }
}
