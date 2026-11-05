// Tipos del formato v2 de `npm audit --json` (npm 7+).

export type Severity = 'info' | 'low' | 'moderate' | 'high' | 'critical';

export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'moderate', 'high', 'critical'];

export interface RawAdvisory {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: Severity;
  cwe?: string[];
  cvss?: { score: number; vectorString: string | null };
  range: string;
}

export interface RawFixAvailable {
  name: string;
  version: string;
  isSemVerMajor: boolean;
}

export interface RawVulnerability {
  name: string;
  severity: Severity;
  isDirect: boolean;
  via: Array<string | RawAdvisory>;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: boolean | RawFixAvailable;
}

export interface RawAuditReport {
  auditReportVersion: 2;
  vulnerabilities: Record<string, RawVulnerability>;
  metadata: {
    vulnerabilities: Record<Severity | 'total', number>;
  };
}

/** Vulnerabilidad propia de un paquete (no heredada de una dependencia). */
export interface Advisory {
  id: number;
  title: string;
  url: string;
  severity: Severity;
  /** Rango de versiones vulnerables, en sintaxis semver. */
  range: string;
  cwe: string[];
  /** Códigos CVE del aviso (alias en OSV). Vacío si no tiene o no se pudo consultar. */
  cves?: string[];
}

export interface AuditEntry {
  name: string;
  severity: Severity;
  isDirect: boolean;
  /** Vulnerabilidades propias del paquete. Vacío si solo hereda las de una dependencia. */
  advisories: Advisory[];
  /** Dependencias vulnerables por las que este paquete aparece en el reporte. */
  viaPackages: string[];
  /** Paquetes del árbol que quedan afectados por este. */
  effects: string[];
  range: string;
  /** Rutas del lockfile con la versión vulnerable (`node_modules/...`). */
  nodes: string[];
  fixAvailable: boolean | RawFixAvailable;
}

export interface AuditResult {
  entries: Map<string, AuditEntry>;
  totals: Record<Severity | 'total', number>;
}
