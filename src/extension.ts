import * as vscode from 'vscode';
import { setSnykTokenCommand } from './commands/setSnykToken';
import { KeelController } from './controller';
import { ManifestDiagnostics } from './editor/diagnostics';
import { ManifestHoverProvider } from './editor/hover';
import { createLogger } from './infra/log';

export function activate(context: vscode.ExtensionContext): void {
  const channel = vscode.window.createOutputChannel('Keel');
  const log = createLogger(channel);
  const diagnostics = new ManifestDiagnostics();
  const keel = new KeelController(context, channel, log, (scan) => void diagnostics.update(scan));
  const hover = new ManifestHoverProvider(diagnostics);

  context.subscriptions.push(
    channel,
    diagnostics,
    vscode.languages.registerHoverProvider({ language: 'json', pattern: '**/package.json' }, hover),
    vscode.languages.registerHoverProvider({ language: 'jsonc', pattern: '**/package.json' }, hover),
    // La vista queda vacía a propósito: su contenido es el texto de bienvenida de package.json.
    vscode.window.registerTreeDataProvider<vscode.TreeItem>('keel.home', { getTreeItem: (item) => item, getChildren: () => [] }),
    vscode.commands.registerCommand('keel.scan', () => keel.scanCommand()),
    vscode.commands.registerCommand('keel.showLog', () => channel.show()),
    vscode.commands.registerCommand('keel.setSnykToken', () => setSnykTokenCommand(context, log)),
  );
}

export function deactivate(): void {}
