import semver from 'semver';
import type { AuditResult } from '../audit/types';
import type { Lockfile } from '../audit/lockfile';
import { osvAffects, type OsvVuln } from '../reference/osv';
import { categoryOf, fitsCategory, type Category } from './categories';

// Comprueba una lista externa de vulnerabilidades (códigos CVE/GHSA, títulos o ambos)
// contra el estado actual del proyecto: npm audit, el lockfile y los avisos de OSV.

const CVE = /\bCVE-\d{4}-\d{4,}\b/gi;
const GHSA = /\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b/gi;
const MAX_ITEMS = 500;

export interface ListItem {
  /** Líneas (1-based) del texto original en las que aparece. */
  lines: number[];
  ids: string[];
  title?: string;
}

/** Una línea por vulnerabilidad. Las líneas repetidas se agrupan; `,`/`;`/tabulador separan columnas. */
export function parseVulnerabilityList(text: string): ListItem[] {
  const byKey = new Map<string, ListItem>();
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const ids = [...new Set([...(line.match(CVE) ?? []), ...(line.match(GHSA) ?? [])].map(normalizeId))];
    const rest = line.replace(CVE, ' ').replace(GHSA, ' ').replace(/[\t,;|"]+/g, ' ').replace(/\s+/g, ' ').replace(/^[\s:–—-]+|[\s:–—-]+$/g, '').trim();
    const title = /[a-z]{3}/i.test(rest) ? rest : undefined;
    if (ids.length === 0 && !title) return;
    const key = `${ids.join(' ')}|${title?.toLowerCase() ?? ''}`;
    const item = byKey.get(key);
    if (item) item.lines.push(index + 1);
    else byKey.set(key, { lines: [index + 1], ids, title });
  });
  const items = [...byKey.values()];
  if (items.length > MAX_ITEMS) throw new Error(`The list has more than ${MAX_ITEMS} distinct entries.`);
  return items;
}

function normalizeId(id: string): string {
  return id.toUpperCase().startsWith('GHSA') ? `GHSA${id.slice(4).toLowerCase()}` : id.toUpperCase();
}

export type VerifyStatus =
  /** El paquete está instalado en una versión fuera del rango vulnerable. */
  | 'fixed'
  /** Ningún paquete afectado está en el lockfile. */
  | 'not-installed'
  /** Solo título: npm audit ya no reporta nada de ese tipo. */
  | 'no-remaining'
  | 'vulnerable'
  /** Solo título: quedan avisos de ese tipo (candidatos, no confirmados). */
  | 'remaining'
  | 'unknown-id'
  | 'not-npm'
  | 'unmapped'
  | 'error';

export type Outcome = 'resolved' | 'pending' | 'unverified';

export function outcomeOf(status: VerifyStatus): Outcome {
  if (status === 'fixed' || status === 'not-installed' || status === 'no-remaining') return 'resolved';
  if (status === 'vulnerable' || status === 'remaining') return 'pending';
  return 'unverified';
}

export interface InstalledMatch {
  package: string;
  version: string;
  path: string;
  /** Primera versión corregida mayor que la instalada, según OSV. */
  fixedIn?: string;
}

export interface Candidate {
  package: string;
  id: string;
  title: string;
  severity: string;
  cwe: string[];
}

export interface IdCheck {
  id: string;
  status: VerifyStatus;
  /** Otros códigos del mismo aviso (CVE ↔ GHSA). */
  aliases: string[];
  summary?: string;
  cwe: string[];
  packages: string[];
  vulnerable: InstalledMatch[];
  safe: InstalledMatch[];
  /** El aviso sigue en `npm audit`. */
  inAudit: boolean;
  error?: string;
}

export interface VerifyItem extends ListItem {
  status: VerifyStatus;
  outcome: Outcome;
  category?: string;
  checks: IdCheck[];
  /** Solo título: avisos de npm audit que encajan con el tipo. */
  candidates: Candidate[];
  /** Con código y título: si el aviso encaja con el tipo indicado (`undefined` si el tipo no se reconoce). */
  titleMatches?: boolean;
}

export interface VerifyResult {
  items: VerifyItem[];
  totals: Record<Outcome, number> & { lines: number; distinct: number };
  allResolved: boolean;
}

export interface VerifyDeps {
  audit: AuditResult;
  lock: Lockfile;
  /** Aviso de OSV por ID; `undefined` si no existe. */
  getVuln(id: string): Promise<OsvVuln | undefined>;
}

const CONCURRENCY = 6;

export async function verifyList(items: readonly ListItem[], deps: VerifyDeps): Promise<VerifyResult> {
  const auditIds = auditAdvisoryIds(deps.audit);
  const cache = new Map<string, Promise<IdCheck>>();
  const check = (id: string) => {
    let pending = cache.get(id);
    if (!pending) cache.set(id, (pending = checkId(id, deps, auditIds)));
    return pending;
  };
  const allIds = [...new Set(items.flatMap((i) => i.ids))];
  await mapLimit(allIds, CONCURRENCY, check);

  const advisories = [...deps.audit.entries.values()].flatMap((entry) =>
    entry.advisories.map((a) => ({ package: entry.name, id: ghsaFromUrl(a.url) ?? String(a.id), title: a.title, severity: a.severity, cwe: a.cwe })),
  );

  const out: VerifyItem[] = [];
  for (const item of items) {
    const category = item.title ? categoryOf(item.title) : undefined;
    if (item.ids.length > 0) {
      const checks = await Promise.all(item.ids.map(check));
      const status = combine(checks.map((c) => c.status));
      const titleMatches = category ? checks.some((c) => fitsCategory(category, c.cwe, c.summary)) : undefined;
      out.push({ ...item, status, outcome: outcomeOf(status), category: category?.key, checks, candidates: [], titleMatches });
    } else {
      out.push(byTitle(item, category, advisories));
    }
  }

  const totals = { resolved: 0, pending: 0, unverified: 0, lines: 0, distinct: out.length };
  for (const item of out) {
    totals[item.outcome] += item.lines.length;
    totals.lines += item.lines.length;
  }
  return { items: out, totals, allResolved: totals.lines > 0 && totals.pending === 0 && totals.unverified === 0 };
}

function byTitle(item: ListItem, category: Category | undefined, advisories: Candidate[]): VerifyItem {
  if (!category) return { ...item, status: 'unmapped', outcome: 'unverified', checks: [], candidates: [] };
  const candidates = advisories.filter((a) => fitsCategory(category, a.cwe, a.title));
  const status: VerifyStatus = candidates.length > 0 ? 'remaining' : 'no-remaining';
  return { ...item, status, outcome: outcomeOf(status), category: category.key, checks: [], candidates };
}

/** El peor estado manda: basta un código vulnerable para que la línea siga pendiente. */
function combine(statuses: VerifyStatus[]): VerifyStatus {
  const order: VerifyStatus[] = ['vulnerable', 'error', 'unknown-id', 'not-npm', 'fixed', 'not-installed'];
  for (const s of order) if (statuses.includes(s)) return s;
  return statuses[0] ?? 'unknown-id';
}

async function checkId(id: string, deps: VerifyDeps, auditIds: Set<string>): Promise<IdCheck> {
  const base: IdCheck = { id, status: 'unknown-id', aliases: [], cwe: [], packages: [], vulnerable: [], safe: [], inAudit: auditIds.has(id) };
  let records: OsvVuln[];
  try {
    const record = await deps.getVuln(id);
    if (!record) return base.inAudit ? { ...base, status: 'vulnerable' } : base;
    records = [record];
    // Los registros CVE de OSV no suelen traer el paquete npm: se sigue el alias GHSA.
    if (!hasNpm(record)) {
      for (const alias of (record.aliases ?? []).filter((a) => /^GHSA-/i.test(a)).slice(0, 3)) {
        const linked = await deps.getVuln(alias);
        if (linked) records.push(linked);
      }
    }
  } catch (error) {
    return { ...base, status: 'error', error: error instanceof Error ? error.message : String(error) };
  }

  const aliases = new Set<string>();
  const cwe = new Set<string>();
  for (const r of records) {
    for (const a of [r.id, ...(r.aliases ?? [])]) if (a !== id) aliases.add(normalizeId(a));
    for (const c of r.database_specific?.cwe_ids ?? []) cwe.add(c.toUpperCase());
  }
  const inAudit = auditIds.has(id) || [...aliases].some((a) => auditIds.has(a));
  const summary = records.map((r) => r.summary).find(Boolean);
  const npmRecords = records.filter(hasNpm);
  const packages = [...new Set(npmRecords.flatMap((r) => npmPackages(r)))];
  const common = { ...base, aliases: [...aliases], cwe: [...cwe], summary, packages, inAudit };
  if (packages.length === 0) return { ...common, status: inAudit ? 'vulnerable' : 'not-npm' };

  const vulnerable: InstalledMatch[] = [];
  const safe: InstalledMatch[] = [];
  for (const name of packages) {
    for (const node of installedNodes(deps.lock, name)) {
      const affecting = npmRecords.filter((r) => osvAffects(r, name, node.version));
      if (affecting.length > 0) vulnerable.push({ ...node, fixedIn: firstFixedAfter(affecting, name, node.version) });
      else safe.push(node);
    }
  }
  const status: VerifyStatus = vulnerable.length > 0 || inAudit ? 'vulnerable' : safe.length > 0 ? 'fixed' : 'not-installed';
  return { ...common, status, vulnerable, safe };
}

function hasNpm(record: OsvVuln): boolean {
  return npmPackages(record).length > 0;
}

function npmPackages(record: OsvVuln): string[] {
  return (record.affected ?? []).filter((a) => a.package?.ecosystem === 'npm' && a.package.name).map((a) => a.package!.name!);
}

function installedNodes(lock: Lockfile, name: string): Array<{ package: string; version: string; path: string }> {
  const out: Array<{ package: string; version: string; path: string }> = [];
  for (const pkg of lock.packages.values()) {
    if (pkg.path === '' || pkg.link || pkg.name !== name || !pkg.version || !semver.valid(pkg.version)) continue;
    out.push({ package: name, version: pkg.version, path: pkg.path });
  }
  return out;
}

function firstFixedAfter(records: OsvVuln[], name: string, version: string): string | undefined {
  const fixed = records
    .flatMap((r) => r.affected ?? [])
    .filter((a) => a.package?.name === name)
    .flatMap((a) => a.ranges ?? [])
    .flatMap((range) => range.events.map((e) => e.fixed))
    .filter((v): v is string => typeof v === 'string' && semver.valid(v) !== null && semver.gt(v, version))
    .sort(semver.compare);
  return fixed[0];
}

function auditAdvisoryIds(audit: AuditResult): Set<string> {
  const ids = new Set<string>();
  for (const entry of audit.entries.values()) {
    for (const advisory of entry.advisories) {
      const ghsa = ghsaFromUrl(advisory.url);
      if (ghsa) ids.add(ghsa);
    }
  }
  return ids;
}

function ghsaFromUrl(url: string): string | undefined {
  const match = url.match(GHSA);
  return match?.[0] ? normalizeId(match[0]) : undefined;
}

async function mapLimit<T>(values: readonly T[], limit: number, fn: (value: T) => Promise<unknown>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, async () => {
    while (next < values.length) await fn(values[next++]!);
  }));
}
