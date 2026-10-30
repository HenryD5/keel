import type { ScanResult } from '../scan';
import { assertPackageName, assertVersion } from '../validate';
import { ageInDays } from '../resolver/versions';

export interface AuditFixPreviewItem {
  name: string;
  from: string;
  to?: string;
  status: 'fixed' | 'quarantine' | 'force-pending' | 'unknown';
  ageDays?: number;
  selected: boolean;
}

export interface AuditFixPreview {
  packages: AuditFixPreviewItem[];
  summary: { selected: number; fixable: number; force: number };
}

/** Describe el efecto global de npm audit fix, incluida la selección actual. */
export function previewAuditFix(result: ScanResult, selected: string[]): AuditFixPreview {
  const selectedNames = new Set(selected.map(assertPackageName));
  const packages = result.packages.map((pkg): AuditFixPreviewItem => {
    const name = assertPackageName(pkg.name);
    const from = assertVersion(pkg.installed);
    const base = { name, from, selected: selectedNames.has(name) };
    if (pkg.auditFix.kind === 'force') return { ...base, status: 'force-pending' };
    if (pkg.auditFix.kind === 'unknown') return { ...base, status: 'unknown' };

    const to = assertVersion(pkg.auditFix.version);
    const latest = pkg.resolution?.latest;
    if (latest?.version === to && latest.inQuarantine) {
      return { ...base, to, status: 'quarantine', ageDays: latest.ageDays };
    }
    const row = pkg.versionTable?.find((candidate) => candidate.version === to);
    if (row?.inQuarantine) {
      return { ...base, to, status: 'quarantine', ageDays: ageInDays(row.publishedAt, new Date(result.scannedAt)) };
    }
    return { ...base, to, status: 'fixed' };
  });

  const selectedPackages = packages.filter((pkg) => pkg.selected);
  return {
    packages,
    summary: {
      selected: selectedPackages.length,
      fixable: selectedPackages.filter((pkg) => pkg.status === 'fixed' || pkg.status === 'quarantine').length,
      force: selectedPackages.filter((pkg) => pkg.status === 'force-pending').length,
    },
  };
}
