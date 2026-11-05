import semver from 'semver';
import type { AuditResult } from '../audit/types';
import type { Lockfile } from '../audit/lockfile';
import { cveAliases, ghsaOf, osvAffects, type OsvVuln } from '../reference/osv';
import { categoryOf, fitsCategory, type Category } from './categories';
import { normalizeId, type ListItem } from './parseList';

export { parseVulnerabilityList, type ListItem } from './parseList';

// Comprueba una lista externa de vulnerabilidades (códigos CVE/GHSA, títulos o ambos)
// contra el estado actual del proyecto: npm audit, el lockfile y los avisos de OSV.

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
  cves: string[];
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
  /** Avisos de OSV de un paquete, para mostrar el CVE de los candidatos. Opcional. */
  packageVulns?(name: string): Promise<OsvVuln[]>;
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

  // Los CVE de los candidatos solo hacen falta si hay líneas con título y sin código.
  const needsCves = deps.packageVulns && items.some((i) => i.ids.length === 0);
  const entries = [...deps.audit.entries.values()].filter((e) => e.advisories.length > 0);
  const aliasMaps = new Map<string, Map<string, string[]>>();
  if (needsCves) {
    await mapLimit(entries, CONCURRENCY, async (entry) => {
      aliasMaps.set(entry.name, await deps.packageVulns!(entry.name).then(cveAliases, () => new Map<string, string[]>()));
    });
  }
  const advisories: Candidate[] = entries.flatMap((entry) =>
    entry.advisories.map((a) => {
      const ghsa = ghsaOf(a.url);
      return { package: entry.name, id: ghsa ?? String(a.id), cves: (ghsa && aliasMaps.get(entry.name)?.get(ghsa)) || a.cves || [], title: a.title, severity: a.severity, cwe: a.cwe };
    }),
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
      const ghsa = ghsaOf(advisory.url);
      if (ghsa) ids.add(ghsa);
    }
  }
  return ids;
}

async function mapLimit<T>(values: readonly T[], limit: number, fn: (value: T) => Promise<unknown>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, async () => {
    while (next < values.length) await fn(values[next++]!);
  }));
}
