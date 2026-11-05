import type { OsvVuln } from './osv';
import type { Severity } from '../audit/types';

export type ReferenceSource = 'osv' | 'snyk';

/** Un aviso de la segunda referencia (OSV o Snyk) sobre una versión concreta. */
export interface ReferenceIssue {
  id: string;
  title: string;
  /** Sin severidad publicada (algunos avisos de OSV solo traen el vector CVSS). */
  severity?: Severity;
  malicious: boolean;
}

/** Resultado de contrastar la versión candidata con la segunda referencia. */
export interface ReferenceCheck {
  source: ReferenceSource;
  /** Versión consultada (la recomendada, o la que se espera si está en cuarentena). */
  version: string;
  /** Avisos no maliciosos que la segunda fuente aún reporta en `version`. */
  issues: ReferenceIssue[];
  /** `true` si la segunda fuente tampoco reporta nada en `version`, como npm audit. */
  agrees: boolean;
  /** Versiones descartadas por malware (IDs `MAL-` de OSV o avisos maliciosos de Snyk). */
  maliciousVersions: string[];
  /** La consulta falló: no hay comparación, el paquete se muestra igual. */
  error?: string;
}

/**
 * Segunda referencia que usa el escaneo. Las implementaciones cachean por paquete,
 * así que `excludedVersions` y `issuesFor` pueden llamarse varias veces sin repetir peticiones.
 */
export interface SecondReference {
  readonly source: ReferenceSource;
  /** Versiones a descartar antes de calcular la mínima segura (malware). */
  excludedVersions(name: string): Promise<Set<string>>;
  /** Avisos que la fuente reporta en `version`. */
  issuesFor(name: string, version: string): Promise<ReferenceIssue[]>;
  /** Avisos de OSV del paquete, para leer sus alias (CVE ↔ GHSA). */
  osvVulns?(name: string): Promise<OsvVuln[]>;
}
