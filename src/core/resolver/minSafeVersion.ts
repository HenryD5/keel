import semver from 'semver';
import type { Advisory, Severity } from '../audit/types';
import type { Packument } from '../registry/types';
import { advisoriesFor, ageInDays, bumpType, isInQuarantine, isVulnerable, type Bump } from './versions';

export interface ResolveInput {
  packument: Packument;
  installed: string;
  advisories: readonly Advisory[];
  /** Severidad máxima del paquete. Con `critical` no se aplica la cuarentena. */
  severity: Severity;
  quarantineDays: number;
  now: Date;
  /** Versiones a descartar por otras fuentes (p. ej. malware en OSV). */
  excluded?: ReadonlySet<string>;
}

export interface VersionInfo {
  version: string;
  publishedAt?: string;
  ageDays?: number;
  inQuarantine: boolean;
  bump: Bump;
}

export type LatestReason =
  | 'recommended' // la última es la recomendada
  | 'not-newer' // la última no es mayor que la instalada
  | 'vulnerable'
  | 'deprecated'
  | 'excluded'
  | 'quarantine'
  | 'major-avoided' // hay una versión segura sin cambiar de major
  | 'not-needed'; // una versión anterior ya corrige todo

export interface LatestInfo extends VersionInfo {
  reason: LatestReason;
}

export type ResolveStatus =
  | 'ok'
  /** Solo hay versiones seguras en cuarentena: se espera hasta `waitUntil`. */
  | 'quarantine-only'
  /** Ninguna versión publicada mayor que la instalada corrige todas las vulnerabilidades. */
  | 'no-safe-version';

export interface ResolveResult {
  status: ResolveStatus;
  recommended?: VersionInfo;
  /** La recomendada está en cuarentena pero se recomienda igual por ser una vulnerabilidad crítica. */
  quarantineBypassed: boolean;
  /** Con `quarantine-only`: la primera versión segura y cuándo sale de cuarentena. */
  waitingFor?: VersionInfo & { waitUntil?: string };
  latest?: LatestInfo;
  /** Hay alguna versión segura sin salto major (respecto a la instalada). */
  safeWithoutMajor: boolean;
  /** Todas las versiones seguras mayores que la instalada, en orden ascendente (con o sin cuarentena). */
  safeVersions: string[];
  /**
   * Sin versión segura en la línea instalada: la última de esa línea y por qué no sirve.
   * Explica por qué no se recomienda, p. ej., 3.2.7 cuando otra fuente la muestra limpia.
   */
  lineBlocker?: LineBlocker;
  /**
   * Sin versión segura en la línea instalada: la versión de esa línea que deja menos vulnerabilidades,
   * si deja menos que la instalada. Corrige en parte sin salto major.
   */
  bestInLine?: PartialFix;
}

export interface PartialFix extends VersionInfo {
  /** IDs de los avisos que corrige respecto a la instalada. */
  fixedIds: number[];
  /** IDs de los avisos que siguen. */
  remainingIds: number[];
}

export interface LineBlocker {
  version: string;
  reason: 'vulnerable' | 'deprecated' | 'malicious';
  /** IDs (npm audit) de los avisos que todavía la afectan. */
  advisoryIds: number[];
}

/**
 * Calcula la versión mínima segura:
 * candidatas mayores a la instalada, sin prerelease ni deprecated ni vulnerables;
 * fuera de cuarentena salvo críticas; y la más baja, que por orden semver da prioridad patch → minor → major.
 */
export function resolveMinSafeVersion(input: ResolveInput): ResolveResult {
  const { packument, installed, advisories, quarantineDays, now } = input;
  const excluded = input.excluded ?? new Set<string>();
  const bypassQuarantine = input.severity === 'critical';

  const info = (version: string): VersionInfo => {
    const publishedAt = packument.time[version];
    const ageDays = ageInDays(publishedAt, now);
    return { version, publishedAt, ageDays, inQuarantine: isInQuarantine(ageDays, quarantineDays), bump: bumpType(installed, version) };
  };

  const newer = Object.keys(packument.versions)
    .filter((v) => semver.valid(v) && semver.prerelease(v) === null && semver.gt(v, installed))
    .sort(semver.compare);

  const isSafe = (v: string) => !packument.versions[v]?.deprecated && !excluded.has(v) && !isVulnerable(v, advisories);
  const safeVersions = newer.filter(isSafe);
  const safe = safeVersions.map(info);
  const eligible = bypassQuarantine ? safe : safe.filter((s) => !s.inQuarantine);

  const recommended = eligible[0];
  let status: ResolveStatus = 'ok';
  let waitingFor: ResolveResult['waitingFor'];
  if (!recommended) {
    if (safe.length > 0) {
      status = 'quarantine-only';
      const first = safe[0]!;
      waitingFor = { ...first, waitUntil: addDays(first.publishedAt, quarantineDays) };
    } else {
      status = 'no-safe-version';
    }
  }

  return {
    status,
    recommended,
    quarantineBypassed: Boolean(recommended?.inQuarantine),
    waitingFor,
    latest: latestInfo(input, recommended, info, excluded),
    safeWithoutMajor: safe.some((s) => s.bump !== 'major'),
    safeVersions,
    lineBlocker: safe.some((s) => s.bump !== 'major') ? undefined : lineBlocker(newer, input, excluded),
    bestInLine: safe.some((s) => s.bump !== 'major') ? undefined : bestInLine(newer, input, excluded, info),
  };
}

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 10_000, high: 1_000, moderate: 100, low: 10, info: 1 };
const score = (list: readonly Advisory[]) => list.reduce((sum, a) => sum + SEVERITY_WEIGHT[a.severity], 0);

/** La versión de la línea instalada que más reduce el riesgo; a igualdad, la más cercana. */
function bestInLine(newer: string[], input: ResolveInput, excluded: ReadonlySet<string>, info: (v: string) => VersionInfo): PartialFix | undefined {
  const { packument, installed, advisories } = input;
  const current = score(advisoriesFor(installed, advisories));
  let best: { version: string; score: number } | undefined;
  for (const v of newer) {
    if (bumpType(installed, v) === 'major' || packument.versions[v]?.deprecated || excluded.has(v)) continue;
    if (info(v).inQuarantine && input.severity !== 'critical') continue;
    const s = score(advisoriesFor(v, advisories));
    if (s < current && (!best || s < best.score)) best = { version: v, score: s };
  }
  if (!best) return undefined;
  const remaining = new Set(advisoriesFor(best.version, advisories).map((a) => a.id));
  const before = advisoriesFor(installed, advisories).map((a) => a.id);
  return { ...info(best.version), fixedIds: before.filter((id) => !remaining.has(id)), remainingIds: [...remaining] };
}

function lineBlocker(newer: string[], input: ResolveInput, excluded: ReadonlySet<string>): LineBlocker | undefined {
  const { packument, installed, advisories } = input;
  const inLine = newer.filter((v) => bumpType(installed, v) !== 'major');
  const version = inLine.filter((v) => !packument.versions[v]?.deprecated).at(-1) ?? inLine.at(-1);
  if (!version) return undefined;
  const affecting = advisoriesFor(version, advisories);
  if (affecting.length > 0) return { version, reason: 'vulnerable', advisoryIds: affecting.map((a) => a.id) };
  if (excluded.has(version)) return { version, reason: 'malicious', advisoryIds: [] };
  return { version, reason: 'deprecated', advisoryIds: [] };
}

function latestInfo(
  input: ResolveInput,
  recommended: VersionInfo | undefined,
  info: (v: string) => VersionInfo,
  excluded: ReadonlySet<string>,
): LatestInfo | undefined {
  const { packument, installed, advisories } = input;
  const version = packument['dist-tags'].latest;
  if (!version || !semver.valid(version) || !packument.versions[version]) return undefined;
  const base = info(version);

  let reason: LatestReason;
  if (recommended?.version === version) reason = 'recommended';
  else if (!semver.gt(version, installed)) reason = 'not-newer';
  else if (isVulnerable(version, advisories)) reason = 'vulnerable';
  else if (packument.versions[version]?.deprecated) reason = 'deprecated';
  else if (excluded.has(version)) reason = 'excluded';
  else if (base.inQuarantine && !(recommended && recommended.inQuarantine)) reason = 'quarantine';
  else if (recommended && bumpType(recommended.version, version) === 'major') reason = 'major-avoided';
  else reason = 'not-needed';

  return { ...base, reason };
}

function addDays(iso: string | undefined, days: number): string | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return undefined;
  return new Date(t + days * 24 * 60 * 60 * 1000).toISOString();
}
