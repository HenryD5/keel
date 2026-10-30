// Filtros de Resultados. Sin dependencias del webview para poder probarlos.
import type { PackageReport } from '../../src/core/scan';

export type Filter = 'all' | 'safe' | 'review' | 'break';

export type Category = Exclude<Filter, 'all'>;

export function category(pkg: PackageReport): Category {
  const bump = pkg.resolution?.recommended?.bump;
  if (bump === 'patch') return 'safe';
  if (bump === 'major') return 'break';
  return 'review';
}

/** Lo que se aplica: de lo marcado, solo los paquetes que el filtro activo deja a la vista. */
export function scopeToFilter(packages: readonly PackageReport[], selection: readonly string[], filter: Filter): string[] {
  if (filter === 'all') return [...selection];
  return selection.filter((name) => packages.some((p) => p.name === name && category(p) === filter));
}
