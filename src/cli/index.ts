import { parseArgs } from 'node:util';
import { access, chmod, mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { buildInstallPlan, type InstallPlan } from '../core/apply/plan';
import { createPlanId } from '../core/apply/planId';
import { buildRemovalPlan, removalBlockReason } from '../core/apply/removal';
import { runApply, runRevert, type ApplySnapshot, type CommandResult, type RunnerAdapters } from '../core/apply/runner';
import { isValidScriptName } from '../core/apply/validation';
import { allowedHosts, findDisallowedRegistries } from '../core/audit/registries';
import { keepDecisions, parseKeelFile } from '../core/decisions';
import { findProjectUsages } from '../core/impact/walker';
import { OsvReference } from '../core/reference/osv';
import { RegistryClient } from '../core/registry/client';
import { buildApplyReport } from '../core/report';
import { scan, type ScanResult } from '../core/scan';
import { defaultSelection } from '../core/selection';

const SCHEMA_VERSION = 1;
const CACHE_DIR = join('node_modules', '.cache', 'keel');
declare const __KEEL_VERSION__: string;
const VERSION = typeof __KEEL_VERSION__ === 'string' ? __KEEL_VERSION__ : '0.0.0-test';

type Choice = 'min' | 'latest';
export interface CliOptions {
  command?: string;
  cwd: string;
  json: boolean;
  quarantineDays: number;
  help: boolean;
  version: boolean;
  select: string[];
  keepRange: boolean;
  choices: Record<string, Choice>;
  plan?: string;
  remove?: string;
  scripts: string[];
  validate: boolean;
  format: 'markdown' | 'json';
  lang: 'en' | 'es';
  positionals: string[];
}

export function parseCliArgs(argv: readonly string[]): CliOptions {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    allowNegative: true,
    strict: true,
    options: {
      cwd: { type: 'string' }, json: { type: 'boolean' }, 'quarantine-days': { type: 'string' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
      select: { type: 'string' }, 'keep-range': { type: 'boolean' }, choice: { type: 'string', multiple: true }, plan: { type: 'string' }, remove: { type: 'string' },
      scripts: { type: 'string' }, validate: { type: 'boolean', default: true }, format: { type: 'string' }, lang: { type: 'string' },
    },
  });
  const days = Number(values['quarantine-days'] ?? 7);
  if (!Number.isInteger(days) || days < 0) throw new UsageError('--quarantine-days must be a non-negative integer.');
  const choices: Record<string, Choice> = {};
  for (const raw of values.choice ?? []) {
    const match = raw.match(/^([^=]+)=(min|latest)$/);
    if (!match) throw new UsageError('--choice must use package=min or package=latest.');
    choices[match[1]!] = match[2] as Choice;
  }
  const scripts = splitList(values.scripts ?? 'test,build');
  if (scripts.some((name) => !isValidScriptName(name))) throw new UsageError('--scripts contains an invalid npm script name.');
  if (values.format !== undefined && values.format !== 'markdown' && values.format !== 'json') throw new UsageError('--format must be markdown or json.');
  if (values.lang !== undefined && values.lang !== 'en' && values.lang !== 'es') throw new UsageError('--lang must be en or es.');
  const cwd = resolve(values.cwd ?? process.cwd());
  return {
    command: positionals[0], cwd, json: values.json ?? false, quarantineDays: days, help: values.help ?? false, version: values.version ?? false,
    select: splitList(values.select ?? ''), keepRange: values['keep-range'] ?? false, choices, plan: values.plan, remove: values.remove, scripts, validate: values.validate !== false,
    format: (values.format as 'markdown' | 'json' | undefined) ?? 'markdown', lang: (values.lang as 'en' | 'es' | undefined) ?? 'en', positionals: positionals.slice(1),
  };
}

class UsageError extends Error {}
class EnvironmentError extends Error {}
class RefusedError extends Error {}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  let options: CliOptions | undefined;
  try {
    options = parseCliArgs(argv);
    if (options.version) return output(options, VERSION, { version: VERSION });
    if (options.help || !options.command) return output(options, helpText(), { help: helpText() });
    if (!['scan', 'plan', 'remove', 'apply', 'revert', 'report'].includes(options.command)) throw new UsageError(`Unknown command: ${options.command}`);
    await ensureProject(options.cwd);
    if (options.command === 'scan') return output(options, await scanOutput(options));
    if (options.command === 'plan') return output(options, await planOutput(options));
    if (options.command === 'remove') return output(options, await removalOutput(options));
    if (options.command === 'apply') return await applyCommand(options);
    if (options.command === 'revert') return await revertCommand(options);
    return output(options, await reportOutput(options));
  } catch (error) {
    const code = error instanceof EnvironmentError ? 3 : error instanceof UsageError || error instanceof RefusedError ? 2 : 1;
    const message = error instanceof Error ? error.message : String(error);
    if (options?.json || argv.includes('--json')) process.stdout.write(`${JSON.stringify({ schemaVersion: SCHEMA_VERSION, ok: false, error: message, exitCode: code })}\n`);
    else process.stderr.write(`keel-npm: ${message}\n`);
    return code;
  }
}

async function runScan(options: CliOptions): Promise<{ result: ScanResult; keep: ReturnType<typeof keepDecisions>; registryFindings: ReturnType<typeof findDisallowedRegistries> }> {
  const read = (name: string) => readFile(join(options.cwd, name), 'utf8');
  const fetchJson = async (url: string, init?: RequestInit) => {
    const response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(30_000), headers: { Accept: 'application/json', 'User-Agent': 'keel-npm', ...(init?.headers ?? {}) } });
    if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`);
    return response.json();
  };
  const registry = new RegistryClient((url) => fetchJson(url));
  const reference = new OsvReference((url, body) => fetchJson(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), async (name) => Object.keys((await registry.getPackument(name)).versions));
  const node = await runCommand(options.cwd, 'node', ['--version'], 15_000).catch(() => undefined);
  const result = await scan({
    readLockfile: () => read('package-lock.json'), readManifest: () => read('package.json'),
    runAudit: async () => (await runCommand(options.cwd, 'npm', ['audit', '--json'], 120_000)).stdout,
    getPackument: (name) => registry.getPackument(name), now: new Date(), quarantineDays: options.quarantineDays,
    nodeVersion: node?.code === 0 ? node.stdout.trim() : undefined, reference,
  });
  const keep = await readFile(join(options.cwd, '.keel.json'), 'utf8').then((text) => keepDecisions(parseKeelFile(text)), () => ({}));
  const registryFindings = await getRegistryFindings(options.cwd);
  return { result, keep, registryFindings };
}

async function scanOutput(options: CliOptions): Promise<object> {
  const data = await runScan(options);
  return {
    result: data.result,
    packages: data.result.packages.map((pkg) => ({ name: pkg.name, installedVersion: pkg.installed, minimumSafeVersion: pkg.resolution?.recommended?.version, latestVersion: pkg.resolution?.latest?.version, category: pkg.resolution?.recommended?.bump === 'major' ? 'may break' : 'safe', dependency: pkg.direct ? 'direct' : 'transitive', referenceDiscrepancy: pkg.reference?.agrees === false, kept: Boolean(data.keep[pkg.name]), registryFindings: data.registryFindings.filter((f) => f.package === pkg.name) })),
    defaultSelection: defaultSelection(data.result.packages, data.keep), registryFindings: data.registryFindings,
  };
}

async function computePlan(options: CliOptions): Promise<{ plan: InstallPlan; planId: string; result: ScanResult; registryFindings: Awaited<ReturnType<typeof getRegistryFindings>>; manifest: string }> {
  if (options.select.length === 0 && !options.remove) throw new UsageError('--select is required.');
  const manifest = await readFile(join(options.cwd, 'package.json'), 'utf8');
  const lockfile = await readFile(join(options.cwd, 'package-lock.json'), 'utf8');
  const scanned = await runScan(options);
  const plan = options.remove ? buildRemovalPlan(manifest, options.remove) : buildInstallPlan({ result: scanned.result, manifestText: manifest, selected: options.select, choices: options.choices, exact: !options.keepRange });
  const method = options.remove ? 'remove' : 'exact';
  return { plan, planId: createPlanId({ method, selection: options.remove ? [options.remove] : options.select, choices: options.choices, plan, manifestText: manifest, lockfileText: lockfile }), result: scanned.result, registryFindings: scanned.registryFindings, manifest };
}

async function planOutput(options: CliOptions): Promise<object> {
  const data = await computePlan(options);
  const usages = Object.fromEntries(await Promise.all(options.select.map(async (name) => [name, await findProjectUsages(options.cwd, name)])));
  return { changes: data.plan.changes, diff: data.plan.diff, skipped: data.plan.skipped, usages, planId: data.planId };
}

async function removalOutput(options: CliOptions): Promise<object> {
  const name = options.positionals[0];
  if (!name || options.positionals.length !== 1) throw new UsageError('remove requires one package name.');
  options.remove = name;
  const manifest = await readFile(join(options.cwd, 'package.json'), 'utf8');
  const configs = await rootConfigs(options.cwd);
  const block = removalBlockReason(manifest, name, [], configs);
  if (block) throw new RefusedError(`Removal refused: ${block}.`);
  const data = await computePlan(options);
  return { removed: data.plan.removed, diff: data.plan.diff, planId: data.planId };
}

async function applyCommand(options: CliOptions): Promise<number> {
  if (!options.plan) throw new UsageError('apply requires --plan <planId>.');
  if (options.remove && options.select.length) throw new UsageError('Use either --remove or --select, not both.');
  if (options.remove) {
    const manifest = await readFile(join(options.cwd, 'package.json'), 'utf8');
    const block = removalBlockReason(manifest, options.remove, [], await rootConfigs(options.cwd));
    if (block) throw new RefusedError(`Removal refused: ${block}.`);
  }
  const data = await computePlan(options);
  if (data.planId !== options.plan) throw new RefusedError(`Plan ID mismatch. Expected ${data.planId}; the approved plan is stale.`);
  const adapters = nodeAdapters(options.cwd);
  const result = await runApply({ method: 'exact', exact: !options.keepRange, plan: data.plan, scripts: options.scripts, validate: options.validate, registryBefore: data.registryFindings, adapters, snapshot: (snapshot) => writeCache(options.cwd, 'snapshot.json', snapshot) });
  let after: ScanResult | undefined;
  if (result.ok) {
    after = (await runScan(options)).result;
    await unlink(join(options.cwd, CACHE_DIR, 'snapshot.json')).catch(() => {});
  } else {
    const [manifest, lockfile] = await Promise.all([readFile(join(options.cwd, 'package.json'), 'utf8'), readFile(join(options.cwd, 'package-lock.json'), 'utf8')]);
    await writeCache(options.cwd, 'snapshot.json', { ...result.snapshot, postApplyHashes: { manifest: hashText(manifest), lockfile: hashText(lockfile) } });
  }
  const installed = result.installedVersions.map((item) => ({ name: item.name, from: item.from, to: item.installed ?? 'not found' }));
  const reportInput = { before: data.result.totals, after: after?.totals, updated: installed, removed: result.ok ? data.plan.removed?.map((x) => x.name) : [], pending: result.ok ? pendingFromScan(after!) : [], failedStep: result.ok ? undefined : { name: result.failedStep ?? 'Apply operation', reason: result.outputTail ?? 'Failed' }, validation: result.validation, registryWarnings: result.registryFindings, versionWarnings: result.versionWarnings };
  const report = buildApplyReport({ language: 'en', ...reportInput });
  const stored = { schemaVersion: SCHEMA_VERSION, ok: result.ok, planId: data.planId, failedStep: result.failedStep, outputTail: result.outputTail, nextCommand: result.ok ? undefined : 'keel-npm revert', report, reportInput, validation: result.validation };
  await writeCache(options.cwd, 'last-result.json', stored);
  return output(options, stored, stored, result.ok ? 0 : 1);
}

async function revertCommand(options: CliOptions): Promise<number> {
  const snapshot = await readCache<ApplySnapshot>(options.cwd, 'snapshot.json').catch(() => { throw new RefusedError('No apply snapshot is available.'); });
  if (!snapshot.postApplyHashes) throw new RefusedError('The apply snapshot cannot be safely verified.');
  const [manifest, lockfile] = await Promise.all([readFile(join(options.cwd, 'package.json'), 'utf8'), readFile(join(options.cwd, 'package-lock.json'), 'utf8')]);
  const changed = changedSinceApply(snapshot, manifest, lockfile);
  if (changed.length) throw new RefusedError(`Revert refused because ${changed.join(' and ')} changed since the failed apply.`);
  const result = await runRevert(snapshot, nodeAdapters(options.cwd));
  if (result.ok) await unlink(join(options.cwd, CACHE_DIR, 'snapshot.json'));
  return output(options, result, { ...result, nextCommand: result.ok ? undefined : 'keel-npm revert' }, result.ok ? 0 : 1);
}

export function changedSinceApply(snapshot: ApplySnapshot, manifest: string, lockfile: string): string[] {
  if (!snapshot.postApplyHashes) return ['package.json', 'package-lock.json'];
  return [snapshot.postApplyHashes.manifest !== hashText(manifest) ? 'package.json' : undefined, snapshot.postApplyHashes.lockfile !== hashText(lockfile) ? 'package-lock.json' : undefined].filter((name): name is string => Boolean(name));
}

function hashText(text: string): string { return createHash('sha256').update(text).digest('hex'); }

function pendingFromScan(result: ScanResult): Array<{ name: string; reason: string }> {
  return result.packages.map((pkg) => ({ name: pkg.name, reason: pkg.error ?? (pkg.resolution?.status === 'quarantine-only' ? 'safe version is still in quarantine' : pkg.resolution?.status === 'no-safe-version' ? 'no safe version is published' : 'still vulnerable after apply') }));
}

async function reportOutput(options: CliOptions): Promise<object | string> {
  const stored = await readCache<{ report: string; reportInput?: Omit<Parameters<typeof buildApplyReport>[0], 'language'> }>(options.cwd, 'last-result.json').catch(() => { throw new RefusedError('No apply result is available.'); });
  if (options.format === 'json') return stored;
  return options.lang === 'es' && stored.reportInput ? buildApplyReport({ language: 'es', ...stored.reportInput }) : stored.report;
}

function nodeAdapters(cwd: string): RunnerAdapters {
  return {
    read: (name) => readFile(join(cwd, name), 'utf8'), write: (name, text) => writeFile(join(cwd, name), text, 'utf8'),
    run: (_command, args, options) => runCommand(cwd, 'npm', args, options?.timeoutMs ?? 300_000, options?.env),
    registryFindings: () => getRegistryFindings(cwd),
    progress: (event) => process.stderr.write(`${event.status}: ${event.label}${event.detail ? ` — ${event.detail}` : ''}\n`),
  };
}

async function getRegistryFindings(cwd: string) {
  const optional = (name: string) => readFile(join(cwd, name), 'utf8').catch(() => '');
  const configured = await runCommand(cwd, 'npm', ['config', 'get', 'registry'], 15_000).then((r) => r.code === 0 ? r.stdout.trim() : undefined, () => undefined);
  return findDisallowedRegistries(await optional('package-lock.json'), allowedHosts(await optional('.npmrc'), configured));
}

async function runCommand(cwd: string, command: string, args: readonly string[], timeoutMs: number, env?: Record<string, string>): Promise<CommandResult> {
  if (args.some((arg) => arg === '--force' || arg.startsWith('--force='))) throw new RefusedError('--force is never allowed.');
  return new Promise((resolvePromise, reject) => {
    const file = process.platform === 'win32' && command === 'npm' ? 'npm.cmd' : command;
    const child = spawn(file, args, { cwd, shell: false, windowsHide: true, env: { ...process.env, npm_config_fund: 'false', npm_config_update_notifier: 'false', ...env } });
    let stdout = ''; let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (value: string) => { stdout += value; });
    child.stderr.setEncoding('utf8').on('data', (value: string) => { stderr += value; });
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on('error', (error: NodeJS.ErrnoException) => { clearTimeout(timer); reject(error.code === 'ENOENT' ? new EnvironmentError(`${command} was not found.`) : error); });
    child.on('close', (code, signal) => { clearTimeout(timer); signal ? reject(new Error(`${command} was stopped (${signal}).`)) : resolvePromise({ code: code ?? 1, stdout, stderr }); });
  });
}

async function ensureProject(cwd: string): Promise<void> {
  if (!isAbsolute(cwd)) throw new EnvironmentError('The working directory could not be resolved.');
  for (const name of ['package.json', 'package-lock.json']) await access(join(cwd, name), constants.R_OK).catch(() => { throw new EnvironmentError(`${name} was not found in ${cwd}.`); });
}
async function writeCache(cwd: string, name: string, value: unknown): Promise<void> { const dir = join(cwd, CACHE_DIR); await mkdir(dir, { recursive: true }); await writeFile(join(dir, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); }
async function readCache<T>(cwd: string, name: string): Promise<T> { return JSON.parse(await readFile(join(cwd, CACHE_DIR, name), 'utf8')) as T; }
async function rootConfigs(cwd: string): Promise<Array<{ path: string; text: string }>> { const names = await readdir(cwd); return Promise.all(names.filter((name) => /^(?:\.[\w-]+rc|[\w-]+\.config\.[cm]?[jt]s)$/.test(name)).map(async (name) => ({ path: name, text: await readFile(join(cwd, name), 'utf8') }))); }
function splitList(value: string): string[] { return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : []; }
function output(options: CliOptions, value: unknown, jsonValue?: unknown, code = 0): number {
  const content = jsonValue ?? value;
  const fields: Record<string, unknown> = typeof content === 'object' && content !== null ? content as Record<string, unknown> : { value: content };
  const document = { schemaVersion: SCHEMA_VERSION, ...fields };
  process.stdout.write(options.json ? `${JSON.stringify(document)}\n` : `${typeof value === 'string' ? value : JSON.stringify(value, null, 2)}\n`);
  return code;
}
function helpText(): string { return `keel-npm — safely plan and apply npm vulnerability fixes\n\nUsage:\n  keel-npm scan [--json]\n  keel-npm plan --select a,b [--keep-range] [--choice a=latest]\n  keel-npm remove <name>\n  keel-npm apply --plan <id> --select a,b [--keep-range] [--choice ...] [--remove <name>] [--scripts test,build] [--no-validate]\n  keel-npm revert\n  keel-npm report [--format markdown|json] [--lang en|es]\n\nVersions are pinned by default. --keep-range preserves a compatible range, so npm may install a newer version in it.\n\nGlobal options:\n  --cwd <dir>  --json  --quarantine-days <n>  --help  --version\n\nExit codes: 0 success; 1 operation failed; 2 refused or invalid usage; 3 environment problem.\nKeel never uses --force and never applies a plan without its matching plan ID.`; }

if (require.main === module) void main().then((code) => { process.exitCode = code; });
