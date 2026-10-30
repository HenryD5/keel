import * as vscode from 'vscode';
import { SNYK_TOKEN_SECRET } from '../controller';
import { isValidSnykOrgId } from '../core/reference/snyk';
import type { Logger } from '../infra/log';

/** `Keel: Set Snyk Token`: guarda el token en `context.secrets` (nunca en settings). Vacío lo borra. */
export async function setSnykTokenCommand(context: vscode.ExtensionContext, log: Logger): Promise<void> {
  const token = await vscode.window.showInputBox({
    title: vscode.l10n.t('Keel: Snyk token'),
    prompt: vscode.l10n.t('Snyk API token, used as a second reference instead of OSV. Leave empty to remove it.'),
    password: true,
    ignoreFocusOut: true,
  });
  if (token === undefined) return;

  if (token.trim() === '') {
    await context.secrets.delete(SNYK_TOKEN_SECRET);
    log.info('Snyk token removed: OSV is the second reference');
    void vscode.window.showInformationMessage(vscode.l10n.t('Keel: Snyk token removed. OSV will be used as the second reference.'));
    return;
  }
  await context.secrets.store(SNYK_TOKEN_SECRET, token.trim());
  log.info('Snyk token saved in VS Code secret storage');

  const config = vscode.workspace.getConfiguration('keel');
  if (isValidSnykOrgId(config.get<string>('snykOrgId', '').trim())) {
    void vscode.window.showInformationMessage(vscode.l10n.t('Keel: Snyk token saved. Run Keel: Scan again to use it.'));
    return;
  }
  const orgId = await vscode.window.showInputBox({
    title: vscode.l10n.t('Keel: Snyk organization ID'),
    prompt: vscode.l10n.t('Snyk needs your organization ID (Settings → General in Snyk). It is saved in the keel.snykOrgId setting.'),
    placeHolder: '00000000-0000-0000-0000-000000000000',
    ignoreFocusOut: true,
    validateInput: (v) => (v.trim() === '' || isValidSnykOrgId(v.trim()) ? undefined : vscode.l10n.t('It must be a UUID.')),
  });
  if (orgId?.trim()) {
    await config.update('snykOrgId', orgId.trim(), vscode.ConfigurationTarget.Global);
    void vscode.window.showInformationMessage(vscode.l10n.t('Keel: Snyk is ready. Run Keel: Scan again to use it.'));
  } else {
    void vscode.window.showWarningMessage(vscode.l10n.t('Keel: without keel.snykOrgId, OSV is still used as the second reference.'));
  }
}
