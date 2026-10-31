import * as path from 'node:path';
import * as vscode from 'vscode';
import { AuditError } from './core/audit/parseAudit';
import { LockfileError } from './core/audit/lockfile';
import { previewAuditFix } from './core/apply/auditFixPreview';
import { buildInstallPlan, type InstallPlan } from './core/apply/plan';
import { buildRemovalPlan } from './core/apply/removal';
import { runApply, runRevert } from './core/apply/runner';
import { APPLY_STEPS, type ApplyMethod } from './core/apply/steps';
import { isValidScriptName, selectValidationScripts } from './core/apply/validation';
import { allowedHosts, findDisallowedRegistries, type RegistryFinding } from './core/audit/registries';
import { KEEL_FILE, keepDecisions, parseKeelFile, serializeKeelFile, withKeep, type KeelFile, type KeepDecision } from './core/decisions';
import { OsvReference } from './core/reference/osv';
import { isValidSnykOrgId, SnykReference } from './core/reference/snyk';
import type { SecondReference } from './core/reference/types';
import { RegistryClient } from './core/registry/client';
import { buildApplyReport, formatScanReport } from './core/report';
import { branchNameForChanges, isValidBaseBranch, unexpectedChanges } from './core/pullRequest';
import { scan, type PackageReport } from './core/scan';
import { projectCandidates, type ProjectFileEntry } from './core/projectFolders';
import { isValidPackageName, isValidVersion } from './core/validate';
import { createChangelogCache, ImpactService } from './impact/service';
import { run, runChecked } from './infra/exec';
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
  private snapshot: { manifest: string; lockfile: string } | undefined;
  private candidateCount = 0;
  private removalPlan: InstallPlan | undefined;
  private lastReport: string | undefined;
  private lastReportEnglish: string | undefined;
  private lastAppliedPlan: InstallPlan | undefined;
  private lastApplySucceeded = false;
  private lastValidation: Array<{ script: string; status: 'passed' | 'skipped' | 'failed'; detail?: string }> = [];
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

  async selectProjectCommand(): Promise<void> {
    await this.selectProject(true);
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
    this.snapshot = undefined;
    this.post({ type: 'scanning' });
    const folder = await this.selectProject(false);
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
      const registryFindings = await this.registryFindings(folder);
      this.payload = { result, referenceSource: reference.source, quarantineDays, keep, choices: this.choices, keelFileError, registryFindings, projectFolder: this.projectLabel(folder), canSelectProject: this.candidateCount > 1 };
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
      case 'selectProject':
        return this.selectProjectCommand();
      case 'showLog':
        this.channel.show();
        return;
      case 'copyReport':
        if (this.lastReport) await vscode.env.clipboard.writeText(this.lastReport);
        return;
      case 'createPullRequest':
        return this.createPullRequest();
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
        this.removalPlan = undefined;
        return this.sendPlan(msg.selected, msg.exact);
      case 'requestRemovalPlan':
        return this.sendRemovalPlan(msg.name);
      case 'apply':
        return this.apply(msg.method, msg.selected, msg.exact, msg.validate);
      case 'revert':
        return this.revert();
      case 'keepChanges':
        this.snapshot = undefined;
        return this.scan();
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
      const configured = vscode.workspace.getConfiguration('keel').get<unknown[]>('validationScripts', ['test', 'build']);
      const validation = selectValidationScripts(configured, await this.manifestText());
      const method: ApplyMethod = exact ? 'exact' : 'audit';
      const base = APPLY_STEPS[method].map((step) => ({ label: step.label, detail: step.label }));
      base.splice(method === 'exact' ? 2 : 1, 0, { label: vscode.l10n.t('Check lockfile registries'), detail: vscode.l10n.t('Checks newly introduced download hosts.') });
      this.post({
        type: 'plan',
        plan: { changes, diff, skipped },
        preview: previewAuditFix(this.payload!.result, selected),
        steps: [...base, ...validation.map((script) => ({ label: `npm run ${script.name}`, detail: script.exists ? vscode.l10n.t('Runs the project script with CI=true.') : vscode.l10n.t('Skipped: script is not present in package.json.') }))],
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.info(`Could not build the install plan: ${message}`);
      this.post({ type: 'applyDone', ok: false, message });
    }
  }

  private async sendRemovalPlan(name: string): Promise<void> {
    try {
      const pkg = this.findPackage(name);
      if (!pkg?.direct) throw new Error(vscode.l10n.t('Only direct dependencies can be removed.'));
      const plan = buildRemovalPlan(await this.manifestText(), name);
      this.removalPlan = plan;
      const validation = selectValidationScripts(vscode.workspace.getConfiguration('keel').get<unknown[]>('validationScripts', ['test', 'build']), await this.manifestText());
      const steps = APPLY_STEPS.exact.map((step) => ({ label: step.label, detail: step.label }));
      steps.splice(2, 0, { label: vscode.l10n.t('Check lockfile registries'), detail: vscode.l10n.t('Checks newly introduced download hosts.') });
      this.post({ type: 'plan', plan, preview: { packages: [], summary: { selected: 1, fixable: 1, force: 0 } }, steps: [...steps, ...validation.map((script) => ({ label: `npm run ${script.name}`, detail: script.exists ? vscode.l10n.t('Runs the project script with CI=true.') : vscode.l10n.t('Skipped: script is not present in package.json.') }))] });
    } catch (err) {
      this.post({ type: 'applyDone', ok: false, message: err instanceof Error ? err.message : String(err) });
    }
  }

  private async apply(method: ApplyMethod, selected: string[], exact: boolean, validate: boolean): Promise<void> {
    this.lastApplySucceeded = false;
    if (this.scanning || this.applying) {
      this.post({ type: 'applyDone', ok: false, message: vscode.l10n.t('A scan or apply operation is already running.') });
      return;
    }
    const folder = this.folder;
    if (!folder || !this.payload) {
      this.post({ type: 'applyDone', ok: false, message: vscode.l10n.t('No scan results are available.') });
      return;
    }
    const beforeTotals = this.payload.result.totals;

    this.applying = true;
    this.snapshot = undefined;
    this.lastInstalledVersions = [];
    this.lastVersionWarnings = [];
    try {
      // El plan nunca viene del webview: se vuelve a calcular sobre el package.json actual.
      const plan = this.removalPlan ?? await this.calculatePlan(selected, exact);
      this.lastAppliedPlan = plan;
      if (method === 'exact' && plan.changes.length === 0) {
        this.post({ type: 'applyDone', ok: true });
        return;
      }

      const manifest = await this.manifestText();
      const configured = vscode.workspace.getConfiguration('keel').get<unknown[]>('validationScripts', ['test', 'build']);
      for (const name of configured) if (typeof name !== 'string' || !isValidScriptName(name)) this.log.info(`Ignored invalid validation script name: ${JSON.stringify(name)}`);
      const validation = validate ? selectValidationScripts(configured, manifest) : [];
      const baseSteps = APPLY_STEPS[method].map((item) => ({ ...item, detail: item.label }));
      baseSteps.splice(method === 'exact' ? 2 : 1, 0, { label: vscode.l10n.t('Check lockfile registries'), detail: vscode.l10n.t('Checks newly introduced download hosts.'), registry: true } as typeof baseSteps[number]);
      const steps = [
        ...baseSteps,
        ...validation.map((script) => ({ label: `npm run ${script.name}`, detail: vscode.l10n.t('Runs the project script with CI=true.'), script })),
      ];
      this.post({ type: 'applyStarted', steps: steps.map(({ label, detail }) => ({ label, detail })) });
      const result = await runApply({
        method, exact, plan, scripts: configured.filter((name): name is string => typeof name === 'string' && isValidScriptName(name)), validate,
        registryBefore: this.payload.registryFindings, canRunScripts: vscode.workspace.isTrusted,
        snapshot: async (value) => { this.snapshot = value; },
        adapters: {
          read: async (name) => new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(folder, name))),
          write: async (name, text) => name === 'package.json' ? this.writeManifest(text) : void await vscode.workspace.fs.writeFile(vscode.Uri.joinPath(folder, name), new TextEncoder().encode(text)),
          run: (_command, args, options) => run('npm', args, { cwd: folder.fsPath, log: this.log, timeoutMs: options?.timeoutMs, env: options?.env }),
          registryFindings: () => this.registryFindings(folder),
          progress: (event) => this.post({ type: 'applyProgress', method, step: event.step, status: event.status, detail: event.detail }),
        },
        messages: {
          label: (label) => vscode.l10n.t(label), missingScript: vscode.l10n.t('Script is not present in package.json.'),
          validationDisabled: vscode.l10n.t('Validation was unchecked before applying.'), untrustedScript: vscode.l10n.t('Project scripts require a trusted workspace.'),
          untrustedProgress: vscode.l10n.t('Skipped: project scripts require a trusted workspace.'), validationFailed: (code) => vscode.l10n.t('Exited with code {0}.', code),
          registryWarning: (count) => vscode.l10n.t('{0} pre-existing registry warning(s) remain.', count),
          newRegistries: (fresh) => vscode.l10n.t('New unapproved lockfile registries: {0}', fresh.map((f) => `${f.package} (${f.host})`).join(', ')),
          commandFailed: (label, code) => vscode.l10n.t('{0} exited with code {1}.', label, code),
          auditWarning: (args) => args[1] === 'fix' ? vscode.l10n.t('npm audit fix left vulnerabilities that would need --force.') : vscode.l10n.t('npm audit found remaining vulnerabilities.'),
        },
      });
      this.lastValidation = result.validation;
      if (!result.ok) {
        this.buildLastReports(plan, result.outputTail, result.failedStep, undefined, undefined, undefined, result.installedVersions, result.versionWarnings);
        this.post({ type: 'applyDone', ok: false, message: result.failedStep, outputTail: result.outputTail, canRevert: true, reportAvailable: true });
        return;
      }
      this.lastApplySucceeded = true;
      this.lastInstalledVersions = result.installedVersions;
      this.lastVersionWarnings = result.versionWarnings;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.info(`Apply failed: ${message}`);
      if (this.lastAppliedPlan) this.buildLastReports(this.lastAppliedPlan);
      this.post({ type: 'applyDone', ok: false, message, canRevert: Boolean(this.snapshot), reportAvailable: Boolean(this.lastReport) });
      return;
    } finally {
      this.applying = false;
    }
    await this.scan();
    if (this.lastAppliedPlan && this.payload) {
      this.buildLastReports(this.lastAppliedPlan, undefined, undefined, beforeTotals, this.payload.result.totals,
        this.payload.result.packages.map((pkg) => ({ name: pkg.name, reason: pkg.error ?? (pkg.resolution?.status === 'quarantine-only' ? 'safe version is still in quarantine' : pkg.resolution?.status === 'no-safe-version' ? 'no safe version is published' : 'still vulnerable after apply') })), this.lastInstalledVersions, this.lastVersionWarnings);
      this.post({ type: 'applyDone', ok: true, reportAvailable: true, canCreatePr: true });
    }
  }

  private lastInstalledVersions: Array<{ name: string; from: string; planned: string; installed?: string; matches: boolean }> = [];
  private lastVersionWarnings: Array<{ name: string; from: string; planned: string; installed?: string; matches: boolean }> = [];

  private buildLastReports(plan: InstallPlan, failure?: string, failedStep?: string, before = this.payload?.result.totals, after?: Record<string, number>, pending = plan.skipped, installedVersions = this.lastInstalledVersions, versionWarnings = this.lastVersionWarnings): void {
    const make = (language: Lang) => buildApplyReport({
      language,
      before,
      after,
      updated: installedVersions.map((change) => ({ name: change.name, from: change.from, to: change.installed ?? 'not found' })),
      removed: failure ? [] : plan.removed?.map((item) => item.name),
      pending: failure ? [] : pending,
      failedStep: failure ? { name: failedStep ?? vscode.l10n.t('Apply operation'), reason: failure } : undefined,
      registryWarnings: this.payload?.registryFindings,
      validation: this.lastValidation,
      versionWarnings,
    });
    this.lastReport = make(this.lang());
    this.lastReportEnglish = make('en');
  }

  private async createPullRequest(): Promise<void> {
    const folder = this.folder;
    const plan = this.lastAppliedPlan;
    if (!folder || !plan || !this.lastReportEnglish || !this.lastApplySucceeded) {
      void vscode.window.showErrorMessage(vscode.l10n.t('A pull request can only be created after a successful apply.'));
      return;
    }
    const changes = [...plan.changes.map((x) => ({ name: x.name, from: x.from, to: x.to })), ...(plan.removed ?? []).map((x) => ({ name: x.name, removed: true }))];
    const branch = branchNameForChanges(changes);
    const configuredBase = vscode.workspace.getConfiguration('keel').get<string>('pullRequestBaseBranch', '').trim();
    if (!isValidBaseBranch(configuredBase)) {
      void vscode.window.showErrorMessage(vscode.l10n.t('keel.pullRequestBaseBranch is not a valid branch name.'));
      return;
    }
    try {
      const head = await runChecked('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: folder.fsPath, log: this.log, timeoutMs: 15_000 });
      if (head.stdout.trim() === 'HEAD') throw new Error(vscode.l10n.t('A pull request cannot be created from a detached HEAD.'));
      await runChecked('gh', ['--version'], { cwd: folder.fsPath, log: this.log, timeoutMs: 15_000 });
      const prefix = (await runChecked('git', ['rev-parse', '--show-prefix'], { cwd: folder.fsPath, log: this.log })).stdout.trim();
      const status = await runChecked('git', ['status', '--porcelain'], { cwd: folder.fsPath, log: this.log });
      const other = unexpectedChanges(status.stdout, prefix);
      if (other.length) throw new Error(vscode.l10n.t('Other working tree changes must be handled first: {0}', other.join(', ')));
      const local = await runChecked('git', ['branch', '--list', branch], { cwd: folder.fsPath, log: this.log });
      const remote = await runChecked('git', ['ls-remote', '--heads', 'origin', branch], { cwd: folder.fsPath, log: this.log });
      if (local.stdout.trim() || remote.stdout.trim()) {
        const existing = await runChecked('gh', ['pr', 'list', '--head', branch, '--json', 'url'], { cwd: folder.fsPath, log: this.log });
        const url = parseFirstPrUrl(existing.stdout);
        if (url) {
          const open = await vscode.window.showInformationMessage(vscode.l10n.t('A pull request already exists for this fix.'), vscode.l10n.t('Open pull request'));
          if (open) await vscode.env.openExternal(vscode.Uri.parse(url));
          return;
        }
        throw new Error(vscode.l10n.t('Branch {0} already exists; Keel will not overwrite it.', branch));
      }
      let base = configuredBase;
      if (!base) {
        const repo = await runChecked('gh', ['repo', 'view', '--json', 'defaultBranchRef'], { cwd: folder.fsPath, log: this.log });
        base = JSON.parse(repo.stdout)?.defaultBranchRef?.name ?? '';
      }
      if (!isValidBaseBranch(base) || !base) throw new Error(vscode.l10n.t('The repository default branch is invalid or unavailable.'));
      const files = ['package.json', 'package-lock.json'];
      const title = 'fix(deps): update vulnerable dependencies';
      const validation = this.lastValidation.map((item) => {
        const status = item.status === 'passed' ? vscode.l10n.t('passed') : item.status === 'skipped' ? vscode.l10n.t('skipped') : vscode.l10n.t('failed');
        return vscode.l10n.t('Validation: npm run {0} — {1}{2}', item.script, status, item.detail ? ` — ${item.detail}` : '');
      }).join('\n');
      const fullyValidated = this.lastValidation.every((item) => item.status === 'passed');
      const detail = `${vscode.l10n.t('Branch')}: ${branch}\n${vscode.l10n.t('Base')}: ${base}\n${vscode.l10n.t('Files')}: ${files.join(', ')}\n${vscode.l10n.t('Commit')}: ${title}${validation ? `\n${validation}` : ''}`;
      const confirm = fullyValidated ? vscode.l10n.t('Create branch and PR') : vscode.l10n.t('Create PR without full validation');
      const approved = await vscode.window.showWarningMessage(detail, { modal: true }, confirm);
      if (!approved) return;
      let state = vscode.l10n.t('No branch was created.');
      try {
        await runChecked('git', ['switch', '-c', branch], { cwd: folder.fsPath, log: this.log });
        state = vscode.l10n.t('Branch {0} was created; changes were not fully published.', branch);
        for (const file of files) await runChecked('git', ['add', '--', file], { cwd: folder.fsPath, log: this.log });
        const names = changes.map((x) => x.name).join(', ');
        await runChecked('git', ['commit', '-F', '-'], { cwd: folder.fsPath, log: this.log, stdin: `${title}\n\n${names}\n` });
        await runChecked('git', ['push', '-u', 'origin', branch], { cwd: folder.fsPath, log: this.log });
        state = vscode.l10n.t('Branch {0} was created, committed and pushed; the PR was not created.', branch);
        const created = await runChecked('gh', ['pr', 'create', '--base', base, '--head', branch, '--title', title, '--body', this.lastReportEnglish], { cwd: folder.fsPath, log: this.log });
        const url = created.stdout.trim().split(/\s+/).find((x) => /^https:\/\//.test(x));
        if (!url) throw new Error(vscode.l10n.t('gh did not return a pull request URL.'));
        const open = await vscode.window.showInformationMessage(vscode.l10n.t('Pull request created: {0}', url), vscode.l10n.t('Open pull request'));
        if (open) await vscode.env.openExternal(vscode.Uri.parse(url));
      } catch (err) {
        throw new Error(`${err instanceof Error ? err.message : String(err)} ${state}`);
      }
    } catch (err) {
      void vscode.window.showErrorMessage(err instanceof Error ? err.message : String(err));
    }
  }

  private async revert(): Promise<void> {
    const snapshot = this.snapshot;
    const folder = this.folder;
    if (!snapshot || !folder || this.applying) {
      this.post({ type: 'revertDone', ok: false, message: vscode.l10n.t('No apply snapshot is available to restore.') });
      return;
    }
    this.applying = true;
    try {
      const result = await runRevert(snapshot, {
        read: async (name) => new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(folder, name))),
        write: async (name, text) => name === 'package.json' ? this.writeManifest(text) : void await vscode.workspace.fs.writeFile(vscode.Uri.joinPath(folder, name), new TextEncoder().encode(text)),
        run: (_command, args, options) => run('npm', args, { cwd: folder.fsPath, log: this.log, timeoutMs: options?.timeoutMs, env: options?.env }),
        registryFindings: () => this.registryFindings(folder),
      });
      this.post(result.ok ? { type: 'revertDone', ok: true } : { type: 'revertDone', ok: false, message: vscode.l10n.t('Files were restored, but npm install exited with code {0}.', result.outputTail ?? '') });
    } catch (err) {
      this.post({ type: 'revertDone', ok: false, message: err instanceof Error ? err.message : String(err) });
      return;
    } finally {
      this.snapshot = undefined;
      this.applying = false;
    }
    await this.scan();
  }

  private async registryFindings(folder: vscode.Uri): Promise<RegistryFinding[]> {
    const readOptional = async (name: string) => {
      try { return new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(folder, name))); } catch { return ''; }
    };
    const registry = await run('npm', ['config', 'get', 'registry'], { cwd: folder.fsPath, log: this.log, timeoutMs: 15_000 })
      .then((result) => result.code === 0 ? result.stdout.trim() : undefined, () => undefined);
    return findDisallowedRegistries(await readOptional('package-lock.json'), allowedHosts(await readOptional('.npmrc'), registry));
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

  private projectLabel(folder: vscode.Uri): string {
    const workspace = vscode.workspace.getWorkspaceFolder(folder);
    if (!workspace) return path.basename(folder.fsPath);
    return path.relative(workspace.uri.fsPath, folder.fsPath).replace(/\\/g, '/') || '.';
  }

  private async selectProject(forcePick: boolean): Promise<vscode.Uri | undefined> {
    const candidates = await findProjectFolders();
    this.candidateCount = candidates.length;
    if (candidates.length === 0) return undefined;
    const key = 'keel.selectedProjectFolder';
    const saved = this.context.workspaceState.get<string>(key);
    let selected = candidates.find((uri) => uri.toString() === saved);
    if (forcePick || !selected) {
      if (candidates.length === 1) selected = candidates[0];
      else selected = (await vscode.window.showQuickPick(
        candidates.map((uri) => ({ label: this.projectLabel(uri), description: vscode.workspace.getWorkspaceFolder(uri)?.name, uri })),
        { placeHolder: vscode.l10n.t('Select the project folder Keel should scan') },
      ))?.uri;
    }
    if (!selected) return this.folder && candidates.some((uri) => uri.toString() === this.folder!.toString()) ? this.folder : undefined;
    await this.context.workspaceState.update(key, selected.toString());
    const changed = this.folder?.toString() !== selected.toString();
    this.folder = selected;
    if (forcePick && changed) await this.scan();
    return selected;
  }
}

const GITHUB_HEADERS = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };

async function findProjectFolders(): Promise<vscode.Uri[]> {
  const out: vscode.Uri[] = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    const entries: ProjectFileEntry[] = [];
    const walk = async (uri: vscode.Uri, relative: string, depth: number): Promise<void> => {
      let children: [string, vscode.FileType][];
      try { children = await vscode.workspace.fs.readDirectory(uri); } catch { return; }
      for (const [name, kind] of children) {
        const child = relative ? `${relative}/${name}` : name;
        if (kind === vscode.FileType.File && (name === 'package.json' || name === 'package-lock.json')) entries.push({ path: child, kind: 'file' });
        else if (kind === vscode.FileType.Directory && depth < 3 && !['node_modules', '.git', 'dist', 'build', 'coverage'].includes(name)) await walk(vscode.Uri.joinPath(uri, name), child, depth + 1);
      }
    };
    await walk(folder.uri, '', 0);
    for (const relative of projectCandidates(entries)) out.push(relative ? vscode.Uri.joinPath(folder.uri, ...relative.split('/')) : folder.uri);
  }
  return out;
}

function outputTail(stdout: string, stderr: string): string {
  return `${stdout}\n${stderr}`.trim().split(/\r?\n/).slice(-20).join('\n');
}

function parseFirstPrUrl(text: string): string | undefined {
  try {
    const value = JSON.parse(text);
    const url = Array.isArray(value) ? value[0]?.url : undefined;
    return typeof url === 'string' && /^https:\/\//.test(url) ? url : undefined;
  } catch { return undefined; }
}
