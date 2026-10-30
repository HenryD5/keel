// `.keel.json` en la raíz del proyecto: decisiones del dev que sobreviven entre escaneos.

export interface KeepDecision {
  /** Versión instalada cuando se decidió mantenerla. */
  version: string;
  reason: string;
  /** Fecha ISO de la decisión. */
  date: string;
}

export interface KeelFile {
  keep?: Record<string, KeepDecision>;
  /** Se conservan las claves que Keel no conoce. */
  [key: string]: unknown;
}

export const KEEL_FILE = '.keel.json';
export const MAX_REASON_LENGTH = 500;

export class KeelFileError extends Error {
  override name = 'KeelFileError';
}

export function parseKeelFile(text: string | undefined): KeelFile {
  if (text === undefined || text.trim() === '') return {};
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new KeelFileError(`${KEEL_FILE} is not valid JSON.`);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new KeelFileError(`${KEEL_FILE} must contain a JSON object.`);
  const file = data as KeelFile;
  if (file.keep !== undefined && (typeof file.keep !== 'object' || file.keep === null || Array.isArray(file.keep))) {
    throw new KeelFileError(`"keep" in ${KEEL_FILE} must be an object.`);
  }
  return file;
}

/** Decisiones válidas de `keep`; las entradas mal formadas se ignoran. */
export function keepDecisions(file: KeelFile): Record<string, KeepDecision> {
  const out: Record<string, KeepDecision> = {};
  for (const [name, d] of Object.entries(file.keep ?? {})) {
    if (d && typeof d.version === 'string' && typeof d.reason === 'string') {
      out[name] = { version: d.version, reason: d.reason, date: typeof d.date === 'string' ? d.date : '' };
    }
  }
  return out;
}

/** Motivo en una línea, sin caracteres de control y con tope de longitud. */
export function normalizeReason(reason: string): string {
  return reason
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_REASON_LENGTH);
}

/** Devuelve un archivo nuevo con la decisión puesta (o quitada con `undefined`), con las claves ordenadas. */
export function withKeep(file: KeelFile, name: string, decision: KeepDecision | undefined): KeelFile {
  const keep = { ...(file.keep ?? {}) };
  if (decision) keep[name] = { ...decision, reason: normalizeReason(decision.reason) };
  else delete keep[name];
  const sorted = Object.fromEntries(Object.entries(keep).sort(([a], [b]) => a.localeCompare(b)));
  const next: KeelFile = { ...file, keep: sorted };
  if (Object.keys(sorted).length === 0) delete next.keep;
  return next;
}

export function serializeKeelFile(file: KeelFile): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}
