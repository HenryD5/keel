import semver from 'semver';
import type { Advisory } from '../audit/types';
import type { Packument } from '../registry/types';
import { isVulnerable } from './versions';

export type AuditFixPrediction =
  /** `npm audit fix` lo deja en una versión sin vulnerabilidades, dentro de los rangos declarados. */
  | { kind: 'audit-fix'; version: string }
  /** Ninguna versión segura cabe en los rangos: npm pediría `--force`. */
  | { kind: 'force' }
  /** Algún rango no es semver (git, file:, alias...) y no se puede predecir. */
  | { kind: 'unknown' };

/**
 * Predice qué versión elegiría `npm audit fix` para un nodo del árbol, imitando a npm-pick-manifest con `avoid`:
 * debe cumplir todos los rangos con los que se pide el paquete y no caer en un rango vulnerable;
 * prefiere `latest` si cumple, y si no, la mayor versión no deprecated.
 */
export function predictAuditFix(packument: Packument, ranges: readonly string[], advisories: readonly Advisory[]): AuditFixPrediction {
  if (ranges.some((r) => semver.validRange(r) === null)) return { kind: 'unknown' };

  const fits = (v: string) => ranges.every((r) => semver.satisfies(v, r)) && !isVulnerable(v, advisories);

  const latest = packument['dist-tags'].latest;
  if (latest && packument.versions[latest] && !packument.versions[latest]?.deprecated && fits(latest)) {
    return { kind: 'audit-fix', version: latest };
  }

  const candidates = Object.keys(packument.versions)
    .filter((v) => semver.valid(v) && semver.prerelease(v) === null && fits(v))
    .sort(semver.rcompare);
  const pick = candidates.find((v) => !packument.versions[v]?.deprecated) ?? candidates[0];
  return pick ? { kind: 'audit-fix', version: pick } : { kind: 'force' };
}

/** Combina las predicciones de varios nodos (varias copias instaladas del paquete). */
export function combinePredictions(predictions: readonly AuditFixPrediction[]): AuditFixPrediction {
  if (predictions.length === 0) return { kind: 'unknown' };
  if (predictions.some((p) => p.kind === 'force')) return { kind: 'force' };
  if (predictions.some((p) => p.kind === 'unknown')) return { kind: 'unknown' };
  const versions = predictions.map((p) => (p as { version: string }).version).sort(semver.rcompare);
  return { kind: 'audit-fix', version: versions[0]! };
}
