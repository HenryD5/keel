import semver from 'semver';
import { countBySeverity, maxSeverity, parseAudit } from './audit/parseAudit';
import { dependentsOf, parseLockfile, topLevelAncestors, type DepType, type Dependent, type Lockfile } from './audit/lockfile';
import type { Advisory, AuditEntry, Severity } from './audit/types';
import { SEVERITY_ORDER } from './audit/types';
import type { Packument } from './registry/types';
import { combinePredictions, predictAuditFix, type AuditFixPrediction } from './resolver/auditFix';
import { compareManifests, type ManifestChecks } from './resolver/manifestDiff';
import { resolveMinSafeVersion, type ResolveResult } from './resolver/minSafeVersion';
import { buildVersionTable, type VersionRow } from './resolver/versionTable';
import type { ReferenceCheck, SecondReference } from './reference/types';
import { cveAliases, ghsaOf } from './reference/osv';
import { isValidPackageName, isValidVersion } from './validate';

export interface ScanDeps {
  /** Salida de `npm audit --json`. */
  runAudit(): Promise<string>;
  readLockfile(): Promise<string>;
  readManifest(): Promise<string>;
  getPackument(name: string): Promise<Packument>;
  now: Date;
  quarantineDays: number;
  /** Versión de Node del proyecto (`node --version`), para comparar `engines.node`. */
  nodeVersion?: string;
  /** Segunda referencia (OSV o Snyk). Sin ella no se contrasta ni se descarta malware. */
  reference?: SecondReference;
}

export interface PackageReport {
  name: string;
  /** La versión vulnerable más baja instalada (de la que parte la recomendación). */
  installed: string;
  installedVersions: string[];
  direct: boolean;
  depType?: DepType;
  /** Rango declarado en package.json (solo directas). */
  declaredRange?: string;
  /** Quién pide el paquete y con qué rango (solo transitivas). */
  parents: Dependent[];
  /** Dependencias directas por las que llega (solo transitivas). */
  viaTopLevel: string[];
  severity: Severity;
  advisories: Advisory[];
  counts: Record<Severity, number>;
  resolution?: ResolveResult;
  checks?: ManifestChecks;
  auditFix: AuditFixPrediction;
  /** Contraste con OSV o Snyk de la versión candidata. */
  reference?: ReferenceCheck;
  /** Filas de la tabla de versiones de la pantalla de detalle. */
  versionTable?: VersionRow[];
  /** Repositorio del registro, para el changelog. */
  repository?: Packument['repository'];
  /** Error al consultar el registro: el paquete se muestra sin recomendación. */
  error?: string;
}

export interface ScanResult {
  scannedAt: string;
  projectName?: string;
  totals: Record<Severity | 'total', number>;
  packages: PackageReport[];
  /** Paquetes que solo heredan vulnerabilidades de una dependencia: se corrigen al corregir esa dependencia. */
  inheritedOnly: string[];
}

interface Manifest {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

const REGISTRY_CONCURRENCY = 6;

export async function scan(deps: ScanDeps): Promise<ScanResult> {
  // El lockfile se lee primero: sin él npm audit falla con un error menos claro.
  const lock = parseLockfile(await deps.readLockfile());
  const manifest = JSON.parse(await deps.readManifest()) as Manifest;
  const audit = parseAudit(await deps.runAudit());

  const entries = [...audit.entries.values()];
  const withAdvisories = entries.filter((e) => e.advisories.length > 0);
  const inheritedOnly = entries.filter((e) => e.advisories.length === 0).map((e) => e.name);

  const packages = await mapLimit(withAdvisories, REGISTRY_CONCURRENCY, (entry) => analyzePackage(entry, lock, manifest, deps));
  packages.sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) || a.name.localeCompare(b.name));

  return {
    scannedAt: deps.now.toISOString(),
    projectName: manifest.name,
    totals: audit.totals,
    packages,
    inheritedOnly: inheritedOnly.sort(),
  };
}

async function analyzePackage(entry: AuditEntry, lock: Lockfile, manifest: Manifest, deps: ScanDeps): Promise<PackageReport> {
  const declared = declaredDependency(manifest, entry.name);
  const nodes = entry.nodes.filter((n) => lock.packages.has(n));
  const installedVersions = [...new Set(nodes.map((n) => lock.packages.get(n)!.version).filter(isDefinedVersion))].sort(semver.compare);
  const installed = installedVersions[0] ?? '';

  const direct = declared !== undefined;
  const parents = direct ? [] : uniqueBy(nodes.flatMap((n) => dependentsOf(lock, n)), (d) => `${d.path}|${d.range}`);
  const viaTopLevel = direct ? [] : [...new Set(nodes.flatMap((n) => topLevelAncestors(lock, n)))].sort();

  const report: PackageReport = {
    name: entry.name,
    installed,
    installedVersions,
    direct,
    depType: declared?.type,
    declaredRange: declared?.range,
    parents,
    viaTopLevel,
    severity: maxSeverity(entry.advisories) ?? entry.severity,
    advisories: await withCves(entry.name, entry.advisories, deps.reference),
    counts: countBySeverity(entry.advisories),
    auditFix: { kind: 'unknown' },
  };

  if (!isValidPackageName(entry.name)) return { ...report, error: 'Invalid package name in npm audit output.' };
  if (!installed) return { ...report, error: 'Installed version not found in package-lock.json.' };

  let packument: Packument;
  try {
    packument = await deps.getPackument(entry.name);
  } catch (err) {
    return { ...report, error: `Registry request failed: ${err instanceof Error ? err.message : String(err)}` };
  }

  const resolve = (excluded: ReadonlySet<string>) =>
    resolveMinSafeVersion({
      packument,
      installed,
      advisories: entry.advisories,
      severity: report.severity,
      quarantineDays: deps.quarantineDays,
      now: deps.now,
      excluded,
    });
  const { resolution, reference, excluded } = deps.reference
    ? await checkWithReference(entry.name, deps.reference, resolve)
    : { resolution: resolve(new Set()), reference: undefined, excluded: new Set<string>() };

  const target = resolution.recommended ?? resolution.waitingFor;
  const checks = target
    ? compareManifests(
        packument.versions[installed],
        packument.versions[target.version]!,
        (peer) => lock.packages.get(`node_modules/${peer}`)?.version,
        deps.nodeVersion,
      )
    : undefined;

  const auditFix = combinePredictions(
    nodes.map((node) => {
      const ranges = dependentsOf(lock, node).map((d) => (d.path === '' && declared ? declared.range : d.range));
      return predictAuditFix(packument, ranges, entry.advisories);
    }),
  );

  const versionTable = buildVersionTable({
    packument,
    installed,
    advisories: entry.advisories,
    resolution,
    excluded,
    now: deps.now,
    quarantineDays: deps.quarantineDays,
  });

  return { ...report, resolution, checks, auditFix, reference, versionTable, repository: packument.repository };
}

/** Añade a cada aviso sus CVE (alias de OSV). Si OSV falla, los avisos quedan como estaban. */
async function withCves(name: string, advisories: Advisory[], ref: SecondReference | undefined): Promise<Advisory[]> {
  if (!ref?.osvVulns || !isValidPackageName(name)) return advisories;
  try {
    const aliases = cveAliases(await ref.osvVulns(name));
    return advisories.map((a) => {
      const ghsa = ghsaOf(a.url);
      const cves = ghsa ? aliases.get(ghsa) : undefined;
      return cves ? { ...a, cves } : a;
    });
  } catch {
    return advisories;
  }
}

/** Intentos máximos de descartar una candidata que la segunda referencia marca como maliciosa. */
const MAX_MALWARE_RETRIES = 3;

/**
 * Descarta el malware conocido (`MAL-`), calcula la versión y la contrasta con la segunda referencia.
 * Si la fuente marca la candidata como maliciosa, se descarta y se recalcula. Un fallo de red no bloquea:
 * queda en `reference.error` y la recomendación es la de npm audit.
 */
async function checkWithReference(
  name: string,
  ref: SecondReference,
  resolve: (excluded: ReadonlySet<string>) => ResolveResult,
): Promise<{ resolution: ResolveResult; reference?: ReferenceCheck; excluded: Set<string> }> {
  let excluded = new Set<string>();
  let error: string | undefined;
  try {
    excluded = await ref.excludedVersions(name);
  } catch (err) {
    error = errorMessage(err);
  }

  let resolution = resolve(excluded);
  for (let attempt = 0; ; attempt++) {
    const target = resolution.recommended ?? resolution.waitingFor;
    const base = { source: ref.source, maliciousVersions: [...excluded].sort(semver.compare) };
    if (!target) return { resolution, excluded, reference: error ? { ...base, version: '', issues: [], agrees: false, error } : undefined };
    if (error) return { resolution, excluded, reference: { ...base, version: target.version, issues: [], agrees: false, error } };

    let issues;
    try {
      issues = await ref.issuesFor(name, target.version);
    } catch (err) {
      return { resolution, excluded, reference: { ...base, version: target.version, issues: [], agrees: false, error: errorMessage(err) } };
    }
    if (issues.some((i) => i.malicious) && attempt < MAX_MALWARE_RETRIES) {
      excluded = new Set([...excluded, target.version]);
      resolution = resolve(excluded);
      continue;
    }
    // Solo quedan avisos maliciosos aquí si se agotaron los reintentos: se muestran para que el dev decida.
    return { resolution, excluded, reference: { ...base, version: target.version, issues, agrees: issues.length === 0 } };
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function declaredDependency(manifest: Manifest, name: string): { range: string; type: DepType } | undefined {
  if (manifest.dependencies?.[name] !== undefined) return { range: manifest.dependencies[name], type: 'prod' };
  if (manifest.devDependencies?.[name] !== undefined) return { range: manifest.devDependencies[name], type: 'dev' };
  if (manifest.optionalDependencies?.[name] !== undefined) return { range: manifest.optionalDependencies[name], type: 'optional' };
  return undefined;
}

function isDefinedVersion(v: string | undefined): v is string {
  return v !== undefined && isValidVersion(v);
}

function uniqueBy<T>(items: T[], key: (t: T) => string): T[] {
  const seen = new Map<string, T>();
  for (const item of items) if (!seen.has(key(item))) seen.set(key(item), item);
  return [...seen.values()];
}

async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!);
    }
  });
  await Promise.all(workers);
  return results;
}
