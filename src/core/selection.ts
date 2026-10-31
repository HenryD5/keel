import type { PackageReport } from './scan';
import type { KeepDecision } from './decisions';

/** Selecciona cambios aplicables y no disruptivos confirmados por la referencia. */
export function defaultSelection(packages: readonly PackageReport[], keep: Readonly<Record<string, KeepDecision>> = {}): string[] {
  return packages
    .filter((pkg) => Boolean(pkg.resolution?.recommended) && !keep[pkg.name] && pkg.reference?.agrees !== false && pkg.resolution?.recommended?.bump !== 'major')
    .map((pkg) => pkg.name);
}
