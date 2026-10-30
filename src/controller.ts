import * as path from 'node:path';
import * as vscode from 'vscode';
import { AuditError } from './core/audit/parseAudit';
import { LockfileError } from './core/audit/lockfile';
import { previewAuditFix } from './core/apply/auditFixPreview';
import { buildInstallPlan, type InstallPlan } from './core/apply/plan';
import { APPLY_STEPS, classifyStepExit, type ApplyMethod } from './core/apply/steps';
import { KEEL_FILE, keepDecisions, parseKeelFile, serializeKeelFile, withKeep, type KeelFile, type KeepDecision } from './core/decisions';
import { OsvReference } from './core/reference/osv';
import { isValidSnykOrgId, SnykReference } from './core/reference/snyk';
import type { SecondReference } from './core/reference/types';
import { RegistryClient } from './core/registry/client';
import { formatScanReport } from './core/report';
import { scan, type PackageReport } from './core/scan';
import { isValidPackageName, isValidVersion } from './core/validate';
import { createChangelogCache, ImpactService } from './impact/service';
import { run } from './infra/exec';
import { createFetchJson } from './infra/http';
import type { Logger } from './infra/log';
import { KeelPanel } from './webview/panel';
import type { Choice, HostMessage, Lang, ScanPayload, WebviewMessage } from './webview/protocol';

export const SNYK_TOKEN_SECRET = 'keel.snykToken';

export interface ControllerScan {
  folder: vscode.Uri;
  result: ScanPayload['result'];
}

/** Enlaces que el webview puede abrir en el navegador. */
const EXTERNAL_HOSTS = new Set(['github.com', 'www.npmjs.com', 'osv.dev', 'security.snyk.io', 'app.snyk.io']);

/** Estado de Keel en la ventana: último escaneo, elecciones de la sesión y el panel. */
export class KeelController {
  private folder: vscode.Uri | undefined;
  private payload: ScanPayload | undefined;
  private scanning = false;
  private applying = false;
  private lastError: string | undefined;
  private impact: ImpactService | undefined;
  private readonly choices: Record<string, Exclude<Choice, 'keep'>> = {};
  private readonly fetchJson;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly channel: vscode.OutputChannel,
    private readonly log: Logger,
    private readonly onScan: (scan: ControllerScan | undefined) => void = () => {},
  ) {
    this.fetchJson = createFetchJson(log);
    context.subscriptions.push(
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration('keel.language')) this.post({ type: 'lang', lang: this.lang() });
      }),
    );
  }

  /** `Keel: Scan`: abre el panel y escanea. */
  async scanCommand(): Promise<void> {
    this.openPanel();
    await this.scan();
  }

  openPanel(): void {
    KeelPanel.show(this.context.extensionUri, (msg) => void this.onMessage(msg));
  }

  private post(message: HostMessage): void {
    KeelPanel.instance?.post(message);
  }

  private lang(): Lang {
    return vscode.workspace.getConfiguration('keel').get<string>('language', 'es') === 'en' ? 'en' : 'es';
  }

  private async scan(): Promise<void> {
    if (this.scanning || this.applying) return;
    const folder = await findProjectFolder();
    if (!folder) {
      const message = vscode.l10n.t(
        'No package-lock.json found in the workspace root. Keel needs it to read installed versions (create it with npm install).',
      );
      this.lastError = message;
      this.onScan(undefined);
      this.post({ type: 'scanError', message });
      void vscode.window.showErrorMessage(vscode.l10n.t('Keel: {0}', message));
      return;
    }

    this.folder = folder;
    this.scanning = true;
    this.lastError = undefined;
    this.post({ type: 'scanning' });

    const cwd = folder.fsPath;
    const quarantineDays = vscode.workspace.getConfiguration('keel').get<number>('quarantineDays', 7);
    const registry = new RegistryClient((url) => this.fetchJson(url));
    const readText = async (name: string) => new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(folder, name)));
    const reference = await this.createReference(registry);

    this.log.info(`Scan started in ${cwd} (second reference: ${reference.source})`);
    try {
      const result = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: vscode.l10n.t('Keel: running npm audit…') },
        async () => {
          const node = await run('node', ['--version'], { cwd, log: this.log, timeoutMs: 15_000 }).catch(() => undefined);
          return scan({
            readLockfile: () => readText('package-lock.json'),
            readManifest: () => readText('package.json'),
            // npm audit sale con código 1 cuando encuentra vulnerabilidades: se lee el JSON igual.
            runAudit: async () => (await run('npm', ['audit', '--json'], { cwd, log: this.log, timeoutMs: 120_000 })).stdout,
            getPackument: (name) => registry.getPackument(name),
            now: new Date(),
            quarantineDays,
            nodeVersion: node?.code === 0 ? node.stdout.trim() : undefined,
            reference,
          });
        },
      );

      const { keep, error: keelFileError } = await this.readKeep();
      for (const name of Object.keys(this.choices)) delete this.choices[name];
      this.impact = new ImpactService(folder, this.log, (url) => this.fetchJson(url, { headers: GITHUB_HEADERS }), createChangelogCache(this.context.globalState));
      this.payload = { result, referenceSource: reference.source, quarantineDays, keep, choices: this.choices, keelFileError };
      this.onScan({ folder, result });

      this.log.info('Scan finished');
      this.channel.appendLine('');
      this.channel.appendLine(formatScanReport(result, quarantineDays));
      this.post({ type: 'scan', scan: this.payload });
    } catch (err) {
      const message =
        err instanceof AuditError || err instanceof LockfileError
          ? err.message
          : vscode.l10n.t('Scan failed: {0}', err instanceof Error ? err.message : String(err));
      this.lastError = message;
      this.onScan(undefined);
      this.log.info(`Scan failed: ${message}`);
      if (err instanceof AuditError && err.detail) this.log.output(err.detail);
      this.post({ type: 'scanError', message });
      void vscode.window.showErrorMessage(vscode.l10n.t('Keel: {0}', message), vscode.l10n.t('Show log')).then((choice) => choice && this.channel.show());
    } finally {
      this.scanning = false;
    }
  }

  /** Snyk si hay token y organización; si no, OSV. El malware (`MAL-`) se descarta siempre con OSV. */
  private async createReference(registry: RegistryClient): Promise<SecondReference> {
    const osv = new OsvReference(
      (url, body) => this.fetchJson(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
      async (name) => Object.keys((await registry.getPackument(name)).versions),
    );
    const token = await this.context.secrets.get(SNYK_TOKEN_SECRET);
    if (!token) return osv;
    const orgId = vscode.workspace.getConfiguration('keel').get<string>('snykOrgId', '').trim();
    if (!isValidSnykOrgId(orgId)) {
      this.log.info('Snyk token is set but keel.snykOrgId is empty or invalid: using OSV as second reference');
      return osv;
    }
    const get = (url: string, secret: string) =>
      this.fetchJson(url, { headers: { Authorization: `token ${secret}`, Accept: 'application/vnd.api+json' } });
    return new SnykReference(orgId, token, get, osv);
  }

  private async onMessage(msg: WebviewMessage): Promise<void> {
    switch (msg.type) {
      case 'ready':
        this.post({ type: 'init', lang: this.lang(), scanning: this.scanning, scan: this.payload, error: this.lastError });
        return;
      case 'rescan':
        return this.scan();
      case 'showLog':
        this.channel.show();
        return;
      case 'setLang':
        await vscode.workspace.getConfiguration('keel').update('language', msg.lang, vscode.ConfigurationTarget.Global);
        return;
      case 'requestImpact':
        return this.sendImpact(msg.name, msg.to);
      case 'openFile':
        return this.openFile(msg.path, msg.line);
      case 'openExternal':
        return this.openExternal(msg.url);
      case 'saveDecision':
        return this.saveDecision(msg.name, msg.choice, msg.reason);
      case 'requestPlan':
        return this.sendPlan(msg.selected, msg.exact);
      case 'apply':
        return this.apply(msg.method, msg.selected, msg.exact);
    }
  }

  private async manifestText(): Promise<string> {
    const folder = this.folder;
    if (!folder) throw new Error(vscode.l10n.t('No project folder is available.'));
    const uri = vscode.Uri.joinPath(folder, 'package.json');
    const open = vscode.workspace.textDocuments.find((document) => document.uri.toString() === uri.toString());
    if (open) return open.getText();
    return new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
  }

  private async calculatePlan(selected: string[], exact: boolean): Promise<InstallPlan> {
    if (!this.payload) throw new Error(vscode.l10n.t('No scan results are available.'));
    return buildInstallPlan({ result: this.payload.result, manifestText: await this.manifestText(), selected, choices: this.choices, exact });
  }

  private async sendPlan(selected: string[], exact: boolean): Promise<void> {
    try {
      const plan = await this.calculatePlan(selected, exact);
      const { changes, diff, skipped } = plan;
      this.post({ type: 'plan', plan: { changes, diff, skipped }, preview: previewAuditFix(this.payload!.result, selected) });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.info(`Could not build the install plan: ${message}`);
      this.post({ type: 'applyDone', ok: false, message });
    }
  }

  private async apply(method: ApplyMethod, selected: string[], exact: boolean): Promise<void> {
    if (this.scanning || this.applying) {
      this.post({ type: 'applyDone', ok: false, message: vscode.l10n.t('A scan or apply operation is already running.') });
      return;
    }
    const folder = this.folder;
    if (!folder || !this.payload) {
      this.post({ type: 'applyDone', ok: false, message: vscode.l10n.t('No scan results are available.') });
      return;
    }

    this.applying = true;
    try {
      // El plan nunca viene del webview: se vuelve a calcular sobre el package.json actual.
      const plan = await this.calculatePlan(selected, exact);
      if (method === 'exact' && plan.changes.length === 0) {
        this.post({ type: 'applyDone', ok: true });
        return;
      }

      const steps = APPLY_STEPS[method];
      for (let step = 0; step < steps.length; step++) {
        const current = steps[step]!;
        this.post({ type: 'applyProgress', method, step, status: 'running' });
        if (!current.command) {
          try {
            await this.writeManifest(plan.newManifestText);
            this.post({ type: 'applyProgress', method, step, status: 'done' });
          } catch (err) {
            const detail = err instanceof Error ? err.message : String(err);
            this.post({ type: 'applyProgress', method, step, status: 'failed', detail });
            this.post({ type: 'applyDone', ok: false, message: detail });
            return;
          }
          continue;
        }

        let result;
        try {
          result = await run(current.command, current.args ?? [], { cwd: folder.fsPath, log: this.log });
        } catch (err) {
          const detail = err instanceof Error ? err.message : String(err);
          this.post({ type: 'applyProgress', method, step, status: 'failed', detail });
          this.post({ type: 'applyDone', ok: false, message: detail });
          return;
        }
        const status = classifyStepExit(current, result.code);
        if (status === 'warning') {
          const detail = current.args?.[1] === 'fix'
            ? vscode.l10n.t('npm audit fix left vulnerabilities that would need --force.')
            : vscode.l10n.t('npm audit found remaining vulnerabilities.');
          this.post({ type: 'applyProgress', method, step, status, detail });
          continue;
        }
        if (status === 'failed') {
          const detail = vscode.l10n.t('{0} exited with code {1}.', current.label, result.code);
          this.post({ type: 'applyProgress', method, step, status: 'failed', detail });
          this.post({ type: 'applyDone', ok: false, message: detail });
          return;
        }
        this.post({ type: 'applyProgress', method, step, status: 'done' });
      }
      this.post({ type: 'applyDone', ok: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.info(`Apply failed: ${message}`);
      this.post({ type: 'applyDone', ok: false, message });
      return;
    } finally {
      this.applying = false;
    }
    await this.scan();
  }

  private async writeManifest(text: string): Promise<void> {
    const folder = this.folder;
    if (!folder) throw new Error(vscode.l10n.t('No project folder is available.'));
    const document = await vscode.workspace.openTextDocument(vscode.Uri.joinPath(folder, 'package.json'));
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, new vscode.Range(new vscode.Position(0, 0), document.positionAt(document.getText().length)), text);
    if (!(await vscode.workspace.applyEdit(edit))) throw new Error(vscode.l10n.t('VS Code could not edit package.json.'));
    if (!(await document.save())) throw new Error(vscode.l10n.t('VS Code could not save package.json.'));
  }

  private findPackage(name: string): PackageReport | undefined {
    return this.payload?.result.packages.find((p) => p.name === name);
  }

  private async sendImpact(name: string, to: string): Promise<void> {
    const pkg = this.findPackage(name);
    const impact = this.impact;
    if (!pkg || !impact || !isValidPackageName(name) || !isValidVersion(to)) return;

    const base = { name, to };
    this.post({ type: 'impact', impact: { ...base, usages: { status: 'loading' }, changelog: { status: 'loading' } } });
    const usages = impact.usages(name).then(
      (u) => ({ status: 'done' as const, ...u }),
      (err: unknown) => ({ status: 'error' as const, message: String(err instanceof Error ? err.message : err) }),
    );
    const changelog = impact.changelog(pkg, to, this.lang()).then(
      (c) => ({ status: 'done' as const, ...c }),
      (err: unknown) => ({ status: 'error' as const, message: String(err instanceof Error ? err.message : err) }),
    );
    // Los usos son locales y llegan antes; el changelog espera a GitHub y al modelo.
    const u = await usages;
    this.post({ type: 'impact', impact: { ...base, usages: u, changelog: { status: 'loading' } } });
    this.post({ type: 'impact', impact: { ...base, usages: u, changelog: await changelog } });
  }

  private async openFile(relative: string, line: number): Promise<void> {
    const folder = this.folder;
    if (!folder) return;
    const segments = relative.split('/');
    if (segments.some((s) => s === '..' || s === '' || s === '.') || path.isAbsolute(relative)) return;
    const uri = vscode.Uri.joinPath(folder, ...segments);
    if (!uri.fsPath.startsWith(folder.fsPath + path.sep)) return;
    const position = new vscode.Position(Math.max(0, line - 1), 0);
    await vscode.window.showTextDocument(uri, { selection: new vscode.Range(position, position), viewColumn: vscode.ViewColumn.Beside });
  }

  private async openExternal(url: string): Promise<void> {
    let parsed: vscode.Uri;
    try {
      parsed = vscode.Uri.parse(url, true);
    } catch {
      return;
    }
    if (parsed.scheme === 'https' && EXTERNAL_HOSTS.has(parsed.authority)) await vscode.env.openExternal(parsed);
  }

  private async saveDecision(name: string, choice: Choice, reason: string | undefined): Promise<void> {
    const pkg = this.findPackage(name);
    const folder = this.folder;
    if (!pkg || !folder || !this.payload) return;
    try {
      const file = await this.readKeelFile(folder);
      const wasKept = Boolean(file.keep?.[name]);
      let keep: KeepDecision | undefined;
      if (choice === 'keep') {
        keep = { version: pkg.installed, reason: reason ?? '', date: new Date().toISOString() };
        delete this.choices[name];
      } else {
        this.choices[name] = choice;
      }
      if (keep || wasKept) {
        const next = withKeep(file, name, keep);
        await vscode.workspace.fs.writeFile(vscode.Uri.joinPath(folder, KEEL_FILE), new TextEncoder().encode(serializeKeelFile(next)));
        this.log.info(keep ? `Saved "keep ${name}@${pkg.installed}" in ${KEEL_FILE}` : `Removed "keep ${name}" from ${KEEL_FILE}`);
        this.payload.keep = keepDecisions(next);
      }
      this.post({ type: 'decisionSaved', name, choice, keep: this.payload.keep[name] });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.info(`Could not save the decision for ${name}: ${message}`);
      this.post({ type: 'decisionError', name, message });
    }
  }

  private async readKeelFile(folder: vscode.Uri): Promise<KeelFile> {
    let text: string | undefined;
    try {
      text = new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(folder, KEEL_FILE)));
    } catch {
      text = undefined; // No existe todavía.
    }
    return parseKeelFile(text);
  }

  private async readKeep(): Promise<{ keep: Record<string, KeepDecision>; error?: string }> {
    try {
      return { keep: this.folder ? keepDecisions(await this.readKeelFile(this.folder)) : {} };
    } catch (err) {
      return { keep: {}, error: err instanceof Error ? err.message : String(err) };
    }
  }
}

const GITHUB_HEADERS = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };

async function findProjectFolder(): Promise<vscode.Uri | undefined> {
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    try {
      await vscode.workspace.fs.stat(vscode.Uri.joinPath(folder.uri, 'package-lock.json'));
      return folder.uri;
    } catch {
      // Sin lockfile en esta carpeta: se prueba la siguiente.
    }
  }
  return undefined;
}
