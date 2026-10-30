// Protocolo de mensajes entre la extensión y el webview. Lo importan los dos lados:
// solo tipos y constantes, sin dependencias de `vscode` ni de Vue.
import type { KeepDecision } from '../core/decisions';
import type { AuditFixPreview } from '../core/apply/auditFixPreview';
import type { DiffLine, InstallChange, InstallPlan } from '../core/apply/plan';
import type { ApplyMethod } from '../core/apply/steps';
import type { ImportKind } from '../core/impact/imports';
import type { ReferenceSource } from '../core/reference/types';
import type { ScanResult } from '../core/scan';

export type Lang = 'es' | 'en';

/** Qué versión eligió el dev en el detalle. `keep` se guarda en `.keel.json`; el resto vive en la sesión. */
export type Choice = 'min' | 'latest' | 'keep';

export interface ScanPayload {
  result: ScanResult;
  /** Fuente con la que se contrastó (o `undefined` si no se pudo contrastar). */
  referenceSource?: ReferenceSource;
  quarantineDays: number;
  /** Decisiones de `.keel.json`. */
  keep: Record<string, KeepDecision>;
  /** Elecciones de esta sesión (mínima o última). */
  choices: Record<string, Exclude<Choice, 'keep'>>;
  /** Aviso si `.keel.json` no se pudo leer. */
  keelFileError?: string;
}

export interface UsageView {
  /** Ruta relativa a la carpeta del proyecto, con `/`. */
  path: string;
  line: number;
  symbol: string;
  kind: ImportKind;
}

export type Loadable<T> = { status: 'loading' } | { status: 'error'; message: string } | ({ status: 'done' } & T);

export interface UsagesView {
  usages: UsageView[];
  files: number;
  /** Se cortó la búsqueda por el tope de archivos. */
  truncated: boolean;
}

export interface ChangelogView {
  /** Enlace a las releases (o al repositorio). */
  url?: string;
  releases: Array<{ version: string; tag: string; url: string; publishedAt?: string }>;
  unavailable?: 'no-repository' | 'not-github';
  empty?: boolean;
  /** No se pudo consultar GitHub (p. ej. límite de peticiones). */
  error?: string;
  summary: { kind: 'ai'; lines: string[] } | { kind: 'breaking'; lines: Array<{ version: string; text: string }> } | { kind: 'none' };
}

export interface ImpactPayload {
  name: string;
  /** Versión candidata con la que se calculó el changelog. */
  to: string;
  usages: Loadable<UsagesView>;
  changelog: Loadable<ChangelogView>;
}

export interface PlanPayload {
  changes: InstallChange[];
  diff: DiffLine[];
  skipped: InstallPlan['skipped'];
}

export type ApplyStatus = 'running' | 'done' | 'warning' | 'failed';

/** Extensión → webview. */
export type HostMessage =
  | { type: 'init'; lang: Lang; scanning: boolean; scan?: ScanPayload; error?: string }
  | { type: 'scanning' }
  | { type: 'scan'; scan: ScanPayload }
  | { type: 'scanError'; message: string }
  | { type: 'impact'; impact: ImpactPayload }
  | { type: 'decisionSaved'; name: string; choice: Choice; keep?: KeepDecision }
  | { type: 'decisionError'; name: string; message: string }
  | { type: 'plan'; plan: PlanPayload; preview: AuditFixPreview }
  | { type: 'applyProgress'; method: ApplyMethod; step: number; status: ApplyStatus; detail?: string }
  | { type: 'applyDone'; ok: boolean; message?: string }
  | { type: 'lang'; lang: Lang };

/** Webview → extensión. */
export type WebviewMessage =
  | { type: 'ready' }
  | { type: 'rescan' }
  | { type: 'showLog' }
  | { type: 'setLang'; lang: Lang }
  | { type: 'requestImpact'; name: string; to: string }
  | { type: 'openFile'; path: string; line: number }
  | { type: 'openExternal'; url: string }
  | { type: 'saveDecision'; name: string; choice: Choice; reason?: string }
  | { type: 'requestPlan'; selected: string[]; exact: boolean }
  | { type: 'apply'; method: ApplyMethod; selected: string[]; exact: boolean };

const LANGS: readonly string[] = ['es', 'en'];
const CHOICES: readonly string[] = ['min', 'latest', 'keep'];
const METHODS: readonly string[] = ['audit', 'exact'];

/** El webview es contenido no confiable para la extensión: cada mensaje se valida antes de usarse. */
export function parseWebviewMessage(data: unknown): WebviewMessage | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const m = data as Record<string, unknown>;
  const str = (k: string, max = 512) => typeof m[k] === 'string' && (m[k] as string).length <= max;
  const selected = () =>
    Array.isArray(m.selected) && m.selected.every((s) => typeof s === 'string' && s.length <= 214)
      ? (m.selected as string[])
      : undefined;
  switch (m.type) {
    case 'ready':
    case 'rescan':
    case 'showLog':
      return { type: m.type };
    case 'setLang':
      return LANGS.includes(m.lang as string) ? { type: 'setLang', lang: m.lang as Lang } : undefined;
    case 'requestImpact':
      return str('name', 214) && str('to', 64) ? { type: 'requestImpact', name: m.name as string, to: m.to as string } : undefined;
    case 'openFile':
      return str('path', 4096) && Number.isInteger(m.line) && (m.line as number) >= 1
        ? { type: 'openFile', path: m.path as string, line: m.line as number }
        : undefined;
    case 'openExternal':
      return str('url', 2048) ? { type: 'openExternal', url: m.url as string } : undefined;
    case 'saveDecision':
      if (!str('name', 214) || !CHOICES.includes(m.choice as string)) return undefined;
      if (m.reason !== undefined && !str('reason', 2000)) return undefined;
      return { type: 'saveDecision', name: m.name as string, choice: m.choice as Choice, reason: m.reason as string | undefined };
    case 'requestPlan': {
      const names = selected();
      return names && typeof m.exact === 'boolean' ? { type: 'requestPlan', selected: names, exact: m.exact } : undefined;
    }
    case 'apply': {
      const names = selected();
      return names && typeof m.exact === 'boolean' && METHODS.includes(m.method as string)
        ? { type: 'apply', method: m.method as ApplyMethod, selected: names, exact: m.exact }
        : undefined;
    }
    default:
      return undefined;
  }
}
