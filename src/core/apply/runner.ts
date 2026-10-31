import type { RegistryFinding } from '../audit/registries';
import { newRegistryFindings } from '../audit/registries';
import type { InstallPlan } from './plan';
import { APPLY_STEPS, classifyStepExit, type ApplyMethod, type ApplyStepStatus } from './steps';
import { selectValidationScripts } from './validation';
import { parseLockfile } from '../audit/lockfile';

export interface CommandResult { code: number; stdout: string; stderr: string }
export interface ApplySnapshot { manifest: string; lockfile: string; postApplyHashes?: { manifest: string; lockfile: string } }
export interface ValidationResult { script: string; status: 'passed' | 'skipped' | 'failed'; detail?: string }
export interface RunnerAdapters {
  read(name: 'package.json' | 'package-lock.json'): Promise<string>;
  write(name: 'package.json' | 'package-lock.json', text: string): Promise<void>;
  run(command: 'npm', args: readonly string[], options?: { env?: Record<string, string>; timeoutMs?: number }): Promise<CommandResult>;
  registryFindings(): Promise<RegistryFinding[]>;
  progress?(event: { step: number; label: string; status: ApplyStepStatus; detail?: string }): void;
}
export interface RunnerMessages {
  label?(label: string): string;
  missingScript?: string;
  validationDisabled?: string;
  untrustedScript?: string;
  untrustedProgress?: string;
  validationFailed?(code: number): string;
  registryWarning?(count: number): string;
  newRegistries?(findings: readonly RegistryFinding[]): string;
  commandFailed?(label: string, code: number): string;
  auditWarning?(args: readonly string[]): string | undefined;
}
export interface ApplyRunInput {
  method: ApplyMethod;
  plan: InstallPlan;
  scripts: readonly string[];
  validate: boolean;
  registryBefore: readonly RegistryFinding[];
  adapters: RunnerAdapters;
  snapshot?: (value: ApplySnapshot) => Promise<void>;
  messages?: RunnerMessages;
  canRunScripts?: boolean;
  exact?: boolean;
}
export interface InstalledVersionCheck { name: string; from: string; planned: string; installed?: string; matches: boolean }
export interface ApplyRunResult {
  ok: boolean;
  snapshot: ApplySnapshot;
  validation: ValidationResult[];
  failedStep?: string;
  outputTail?: string;
  registryFindings: RegistryFinding[];
  installedVersions: InstalledVersionCheck[];
  versionWarnings: InstalledVersionCheck[];
}

/** Compares an approved plan with versions actually written to package-lock.json. */
export function compareInstalledVersions(plan: InstallPlan, lockfileText: string): InstalledVersionCheck[] {
  const lock = parseLockfile(lockfileText);
  return plan.changes.map((change) => {
    const direct = lock.packages.get(`node_modules/${change.name}`);
    const candidates = [...lock.packages.values()].filter((pkg) => pkg.name === change.name && pkg.version);
    const installed = direct?.version ?? candidates[0]?.version;
    return { name: change.name, from: change.from, planned: change.to, installed, matches: installed === change.to };
  });
}

export async function runApply(input: ApplyRunInput): Promise<ApplyRunResult> {
  const localize = (value: string) => input.messages?.label?.(value) ?? value;
  const manifest = await input.adapters.read('package.json');
  const snapshot = { manifest, lockfile: await input.adapters.read('package-lock.json') };
  await input.snapshot?.(snapshot);
  const validation = input.validate ? selectValidationScripts(input.scripts, manifest) : input.scripts.map((name) => ({ name, exists: false }));
  const results: ValidationResult[] = input.validate ? [] : input.scripts.map((script) => ({ script, status: 'skipped', detail: input.messages?.validationDisabled ?? 'Validation was disabled.' }));
  const steps: Array<{ label: string; command?: string; args?: readonly string[]; registry?: true; script?: { name: string; exists: boolean } }> = APPLY_STEPS[input.method].map((step) => ({ ...step, label: localize(step.label) }));
  steps.splice(input.method === 'exact' ? 2 : 1, 0, { label: localize('Check lockfile registries'), registry: true });
  steps.push(...(input.validate ? validation.map((script) => ({ label: `npm run ${script.name}`, script })) : []));
  let registryFindings = [...input.registryBefore];
  let installedVersions: InstalledVersionCheck[] = [];
  let versionWarnings: InstalledVersionCheck[] = [];
  for (let index = 0; index < steps.length; index++) {
    const step = steps[index]!;
    input.adapters.progress?.({ step: index, label: step.label, status: 'running' });
    try {
      if (step.registry) {
        registryFindings = await input.adapters.registryFindings();
        const fresh = newRegistryFindings(input.registryBefore, registryFindings);
        if (fresh.length) return failure(step.label, input.messages?.newRegistries?.(fresh) ?? fresh.map((f) => `${f.package} (${f.host})`).join(', '));
        input.adapters.progress?.({ step: index, label: step.label, status: registryFindings.length ? 'warning' : 'done', detail: registryFindings.length ? input.messages?.registryWarning?.(registryFindings.length) : undefined });
      } else if (step.script) {
        if (!step.script.exists) {
          const detail = input.messages?.missingScript ?? 'Script is not present in package.json.';
          results.push({ script: step.script.name, status: 'skipped', detail });
          input.adapters.progress?.({ step: index, label: step.label, status: 'skipped', detail });
        } else if (input.canRunScripts === false) {
          const detail = input.messages?.untrustedScript ?? 'Project scripts are disabled.';
          results.push({ script: step.script.name, status: 'skipped', detail });
          input.adapters.progress?.({ step: index, label: step.label, status: 'skipped', detail: input.messages?.untrustedProgress ?? detail });
        } else {
          const result = await input.adapters.run('npm', ['run', step.script.name], { env: { CI: 'true' }, timeoutMs: 600_000 });
          if (result.code !== 0) {
            results.push({ script: step.script.name, status: 'failed', detail: input.messages?.validationFailed?.(result.code) ?? `Exited with code ${result.code}.` });
            return failure(step.label, outputTail(result));
          }
          results.push({ script: step.script.name, status: 'passed' });
          input.adapters.progress?.({ step: index, label: step.label, status: 'done' });
        }
      } else if (!step.command) {
        await input.adapters.write('package.json', input.plan.newManifestText);
        input.adapters.progress?.({ step: index, label: step.label, status: 'done' });
      } else {
        const result = await input.adapters.run('npm', step.args ?? []);
        const status = classifyStepExit(step, result.code);
        if (status === 'failed') return failure(step.label, outputTail(result), input.messages?.commandFailed?.(step.label, result.code));
        input.adapters.progress?.({ step: index, label: step.label, status, detail: status === 'warning' ? input.messages?.auditWarning?.(step.args ?? []) : undefined });
        if (input.method === 'exact' && step.args?.[0] === 'install' && input.plan.changes.length > 0) {
          installedVersions = compareInstalledVersions(input.plan, await input.adapters.read('package-lock.json'));
          versionWarnings = installedVersions.filter((item) => !item.matches);
          if (versionWarnings.length && input.exact !== false) {
            return failure(step.label, versionMismatchMessage(versionWarnings));
          }
          if (versionWarnings.length) input.adapters.progress?.({ step: index, label: step.label, status: 'warning', detail: versionMismatchMessage(versionWarnings) });
        } else if (input.method === 'audit' && step.args?.[0] === 'audit' && step.args?.[1] === 'fix' && input.plan.changes.length > 0) {
          installedVersions = compareInstalledVersions(input.plan, await input.adapters.read('package-lock.json'));
        }
      }
    } catch (error) {
      return failure(step.label, error instanceof Error ? error.message : String(error));
    }
  }
  return { ok: true, snapshot, validation: results, registryFindings, installedVersions, versionWarnings };

  function failure(failedStep: string, tail: string, detail = tail): ApplyRunResult {
    const step = steps.findIndex((item) => item.label === failedStep);
    if (step >= 0) input.adapters.progress?.({ step, label: failedStep, status: 'failed', detail });
    return { ok: false, snapshot, validation: results, failedStep, outputTail: tail, registryFindings, installedVersions, versionWarnings };
  }
}

function versionMismatchMessage(items: readonly InstalledVersionCheck[]): string {
  return items.map((item) => `${item.name}: planned ${item.planned}, installed ${item.installed ?? 'not found'}`).join('; ');
}

export async function runRevert(snapshot: ApplySnapshot, adapters: RunnerAdapters): Promise<{ ok: boolean; outputTail?: string }> {
  try {
    await adapters.write('package.json', snapshot.manifest);
    await adapters.write('package-lock.json', snapshot.lockfile);
    const result = await adapters.run('npm', ['install']);
    return result.code === 0 ? { ok: true } : { ok: false, outputTail: outputTail(result) };
  } catch (error) {
    return { ok: false, outputTail: error instanceof Error ? error.message : String(error) };
  }
}

function outputTail(result: CommandResult): string {
  return `${result.stdout}\n${result.stderr}`.trim().slice(-4_000);
}
