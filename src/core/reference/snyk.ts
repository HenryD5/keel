import type { Severity } from '../audit/types';
import { assertPackageName, assertVersion } from '../validate';
import type { ReferenceIssue, SecondReference } from './types';

export const SNYK_API_ORIGIN = 'https://api.snyk.io';
/** Versión de la API REST de Snyk (parámetro `version`). */
export const SNYK_API_VERSION = '2024-10-15';

const ORG_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_PAGES = 5;

// Subconjunto de la respuesta JSON:API de "List issues for a package" que usa Keel.
export interface SnykIssue {
  id: string;
  attributes?: {
    key?: string;
    title?: string;
    type?: string;
    effective_severity_level?: string;
    problems?: Array<{ id?: string; source?: string }>;
  };
}

export interface SnykIssuesResponse {
  data?: SnykIssue[];
  links?: { next?: string };
}

export type SnykGet = (url: string, token: string) => Promise<unknown>;

export function isValidSnykOrgId(orgId: string): boolean {
  return ORG_ID.test(orgId);
}

/** `pkg:npm/@scope/name@1.2.3`, URL-encoded entero como pide la API. */
export function snykIssuesUrl(orgId: string, name: string, version: string): string {
  if (!isValidSnykOrgId(orgId)) throw new Error(`Invalid Snyk organization ID: ${JSON.stringify(orgId)}`);
  const purl = `pkg:npm/${assertPackageName(name)}@${assertVersion(version)}`;
  return `${SNYK_API_ORIGIN}/rest/orgs/${orgId}/packages/${encodeURIComponent(purl)}/issues?version=${SNYK_API_VERSION}&limit=100`;
}

/** `links.next` llega relativo (`/orgs/...` o `/rest/orgs/...`): se resuelve contra api.snyk.io. */
export function snykNextUrl(next: string | undefined): string | undefined {
  if (!next) return undefined;
  if (next.startsWith('https://')) return next;
  if (next.startsWith('/rest/')) return `${SNYK_API_ORIGIN}${next}`;
  if (next.startsWith('/')) return `${SNYK_API_ORIGIN}/rest${next}`;
  return undefined;
}

const SEVERITY_MAP: Record<string, Severity> = { low: 'low', medium: 'moderate', high: 'high', critical: 'critical' };

export function parseSnykIssues(data: unknown): ReferenceIssue[] {
  const doc = data as SnykIssuesResponse | null;
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.data)) throw new Error('Unexpected Snyk response.');
  return doc.data.map((issue) => {
    const a = issue.attributes ?? {};
    const title = a.title ?? a.key ?? issue.id;
    // Snyk marca el malware con CWE-506 (código malicioso embebido) y títulos tipo "Malicious Package".
    const malicious = /malicious/i.test(title) || (a.problems ?? []).some((p) => p.id === 'CWE-506');
    const severity = a.effective_severity_level ? SEVERITY_MAP[a.effective_severity_level.toLowerCase()] : undefined;
    return { id: a.key ?? issue.id, title, severity, malicious };
  });
}

export async function querySnyk(orgId: string, name: string, version: string, token: string, get: SnykGet): Promise<ReferenceIssue[]> {
  const issues: ReferenceIssue[] = [];
  let url: string | undefined = snykIssuesUrl(orgId, name, version);
  for (let page = 0; url && page < MAX_PAGES; page++) {
    const data = await get(url, token);
    issues.push(...parseSnykIssues(data));
    url = snykNextUrl((data as SnykIssuesResponse).links?.next);
  }
  return issues;
}

/**
 * Segunda referencia con Snyk: consulta la versión candidata.
 * El malware se descarta con OSV (`MAL-`) antes de calcular la versión, como sin token.
 */
export class SnykReference implements SecondReference {
  readonly source = 'snyk' as const;
  private readonly cache = new Map<string, Promise<ReferenceIssue[]>>();

  constructor(
    private readonly orgId: string,
    private readonly token: string,
    private readonly get: SnykGet,
    private readonly malware: Pick<SecondReference, 'excludedVersions' | 'osvVulns'>,
  ) {}

  osvVulns(name: string) {
    return this.malware.osvVulns ? this.malware.osvVulns(name) : Promise.resolve([]);
  }

  excludedVersions(name: string): Promise<Set<string>> {
    return this.malware.excludedVersions(name);
  }

  issuesFor(name: string, version: string): Promise<ReferenceIssue[]> {
    const key = `${name}@${version}`;
    let pending = this.cache.get(key);
    if (!pending) {
      pending = querySnyk(this.orgId, name, version, this.token, this.get);
      pending.catch(() => this.cache.delete(key));
      this.cache.set(key, pending);
    }
    return pending;
  }
}
