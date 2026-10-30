import type { WebviewMessage } from '../../src/webview/protocol';
import type { Filter } from './filter';

export type { Filter };

/** Estado del webview que VS Code conserva al ocultar y volver a mostrar el panel. */
export interface ViewState {
  screen: 'results' | 'detail' | 'review';
  detail?: string;
  filter: Filter;
  /** Selección del dev; `undefined` hasta que toca un checkbox (se usa la selección por defecto). */
  selected?: string[];
  scannedAt?: string;
}


const api = acquireVsCodeApi<ViewState>();

export function send(message: WebviewMessage): void {
  api.postMessage(message);
}

export function loadState(): ViewState {
  return api.getState() ?? { screen: 'results', filter: 'all' };
}

export function saveState(state: ViewState): void {
  api.setState(JSON.parse(JSON.stringify(state)) as ViewState);
}
