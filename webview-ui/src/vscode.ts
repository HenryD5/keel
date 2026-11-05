import type { WebviewMessage } from '../../src/webview/protocol';
import type { Filter } from './filter';

export type { Filter };

/** Estado del webview que VS Code conserva al ocultar y volver a mostrar el panel. */
export interface ViewState {
  screen: 'results' | 'detail' | 'review' | 'verify';
  detail?: string;
  filter: Filter;
  /** Selección del dev; `undefined` hasta que toca un checkbox (se usa la selección por defecto). */
  selected?: string[];
  scannedAt?: string;
  /** Lista pegada en la pantalla de verificación. */
  verifyText?: string;
}


const api = acquireVsCodeApi<ViewState>();

/**
 * postMessage clona el mensaje (structured clone) y falla con DataCloneError si lleva objetos
 * reactivos de Vue (Proxy). Se envía siempre una copia plana.
 */
export function toPlain<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function send(message: WebviewMessage): void {
  api.postMessage(toPlain(message));
}

export function loadState(): ViewState {
  return api.getState() ?? { screen: 'results', filter: 'all' };
}

export function saveState(state: ViewState): void {
  api.setState(JSON.parse(JSON.stringify(state)) as ViewState);
}
