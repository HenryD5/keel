import { randomBytes } from 'node:crypto';
import * as vscode from 'vscode';
import { parseWebviewMessage, type HostMessage, type WebviewMessage } from './protocol';

export const PANEL_VIEW_TYPE = 'keel.results';

/** El panel del webview (uno por ventana). Solo transporta mensajes; la lógica vive en el controlador. */
export class KeelPanel implements vscode.Disposable {
  private static current: KeelPanel | undefined;
  private readonly disposables: vscode.Disposable[] = [];

  static show(extensionUri: vscode.Uri, onMessage: (msg: WebviewMessage) => void): KeelPanel {
    if (KeelPanel.current) {
      KeelPanel.current.panel.reveal(undefined, true);
      return KeelPanel.current;
    }
    const panel = vscode.window.createWebviewPanel(
      PANEL_VIEW_TYPE,
      vscode.l10n.t('Vulnerabilities'),
      { viewColumn: vscode.ViewColumn.Active, preserveFocus: false },
      {
        enableScripts: true,
        // Solo los archivos del build del webview: nada más del disco es accesible desde la página.
        localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'dist', 'webview')],
      },
    );
    KeelPanel.current = new KeelPanel(panel, extensionUri, onMessage);
    return KeelPanel.current;
  }

  static get instance(): KeelPanel | undefined {
    return KeelPanel.current;
  }

  private constructor(
    private readonly panel: vscode.WebviewPanel,
    extensionUri: vscode.Uri,
    onMessage: (msg: WebviewMessage) => void,
  ) {
    panel.webview.html = renderHtml(panel.webview, extensionUri);
    this.disposables.push(
      panel.onDidDispose(() => this.dispose()),
      panel.webview.onDidReceiveMessage((data: unknown) => {
        const msg = parseWebviewMessage(data);
        if (msg) onMessage(msg);
      }),
    );
  }

  post(message: HostMessage): void {
    void this.panel.webview.postMessage(message);
  }

  dispose(): void {
    if (KeelPanel.current === this) KeelPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) this.disposables.pop()?.dispose();
  }
}

function renderHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
  const asset = (file: string) => webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'dist', 'webview', file));
  const nonce = randomBytes(16).toString('base64');
  // CSP estricta: sin inline, sin eval, sin red. Estilos, fuente de Codicons y script solo del build local.
  const csp = [
    "default-src 'none'",
    `style-src ${webview.cspSource}`,
    `font-src ${webview.cspSource}`,
    `img-src ${webview.cspSource}`,
    `script-src 'nonce-${nonce}'`,
  ].join('; ');
  const lang = vscode.workspace.getConfiguration('keel').get<string>('language', 'es') === 'en' ? 'en' : 'es';
  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="${asset('main.css')}">
<title>Keel</title>
</head>
<body>
<div id="app"></div>
<script type="module" nonce="${nonce}" src="${asset('main.js')}"></script>
</body>
</html>`;
}
