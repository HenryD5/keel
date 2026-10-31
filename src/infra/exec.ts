import { spawn } from 'node:child_process';
import type { Logger } from './log';
import { isValidScriptName } from '../core/apply/validation';
import { isValidBranchName } from '../core/pullRequest';

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Únicas invocaciones permitidas. Los argumentos van en array y se comparan exactos:
 * nunca se arma un string de shell ni se acepta `--force`.
 */
const ALLOWED: ReadonlyArray<readonly [command: string, ...args: string[]]> = [
  ['npm', 'audit', '--json'],
  ['npm', 'audit'],
  ['npm', 'audit', 'fix'],
  ['npm', 'audit', 'signatures'],
  ['npm', 'install'],
  ['npm', 'config', 'get', 'registry'],
  ['node', '--version'],
];

export function isAllowedCommand(command: string, args: readonly string[]): boolean {
  if (args.some((a) => a === '--force' || a.startsWith('--force='))) return false;
  if (command === 'npm' && args.length === 2 && args[0] === 'run') return isValidScriptName(args[1]!);
  if (command === 'git') return isAllowedGit(args);
  if (command === 'gh') return isAllowedGh(args);
  return ALLOWED.some(([c, ...a]) => c === command && a.length === args.length && a.every((x, i) => x === args[i]));
}

function isAllowedGit(args: readonly string[]): boolean {
  if (same(args, ['status', '--porcelain']) || same(args, ['rev-parse', '--abbrev-ref', 'HEAD']) || same(args, ['rev-parse', '--show-prefix']) || same(args, ['commit', '-F', '-'])) return true;
  if (args.length === 3 && args[0] === 'branch' && args[1] === '--list') return isValidBranchName(args[2]!);
  if (args.length === 4 && same(args.slice(0, 3), ['ls-remote', '--heads', 'origin'])) return isValidBranchName(args[3]!);
  if (args.length === 3 && same(args.slice(0, 2), ['switch', '-c'])) return isValidBranchName(args[2]!);
  if (args.length === 4 && same(args.slice(0, 3), ['push', '-u', 'origin'])) return isValidBranchName(args[3]!);
  if (args.length === 3 && same(args.slice(0, 2), ['add', '--'])) return args[2] === 'package.json' || args[2] === 'package-lock.json';
  return false;
}

function isAllowedGh(args: readonly string[]): boolean {
  if (same(args, ['--version']) || same(args, ['repo', 'view', '--json', 'defaultBranchRef'])) return true;
  if (args.length === 6 && same(args.slice(0, 2), ['pr', 'list']) && args[2] === '--head' && isValidBranchName(args[3]!) && same(args.slice(4), ['--json', 'url'])) return true;
  if (args.length === 10 && same(args.slice(0, 2), ['pr', 'create']) && args[2] === '--base' && isValidBranchName(args[3]!) && args[4] === '--head' && isValidBranchName(args[5]!) && args[6] === '--title' && args[7]!.length <= 200 && args[8] === '--body' && args[9]!.length <= 100_000) return true;
  return false;
}

function same(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

export interface ExecOptions {
  cwd: string;
  log: Logger;
  timeoutMs?: number;
  env?: Readonly<Record<string, string>>;
  /** Para tests: reemplaza a child_process.spawn. */
  spawnImpl?: typeof spawn;
  stdin?: string;
}

export function run(command: string, args: readonly string[], options: ExecOptions): Promise<ExecResult> {
  if (!isAllowedCommand(command, args)) {
    return Promise.reject(new Error(`Command not allowed: ${[command, ...args].join(' ')}`));
  }
  const { cwd, log, timeoutMs = 5 * 60_000, spawnImpl = spawn } = options;
  const display = [command, ...args].join(' ');
  log.command(`${display}   (cwd: ${cwd})`);

  // En Windows npm es npm.cmd y Node no permite lanzar .cmd sin shell (CVE-2024-27980).
  // Pasar por cmd.exe es seguro aquí porque los argumentos salen de la lista fija de arriba.
  const [file, argv] =
    process.platform === 'win32' && command === 'npm' ? ['cmd.exe', ['/d', '/s', '/c', command, ...args]] : [command, [...args]];

  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawnImpl(file, argv, {
      cwd,
      shell: false,
      windowsHide: true,
      env: { ...process.env, npm_config_fund: 'false', npm_config_update_notifier: 'false', ...options.env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.setEncoding('utf8').on('data', (d: string) => (stdout += d));
    child.stderr?.setEncoding('utf8').on('data', (d: string) => (stderr += d));
    if (options.stdin !== undefined) child.stdin?.end(options.stdin);

    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on('error', (err) => {
      clearTimeout(timer);
      log.info(`${display} failed to start: ${err.message}`);
      reject(err);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      log.output(stdout);
      log.output(stderr);
      const seconds = ((Date.now() - started) / 1000).toFixed(1);
      if (signal) {
        log.info(`${display} stopped (${signal}) after ${seconds}s`);
        reject(new Error(`${display} was stopped (${signal}).`));
        return;
      }
      log.info(`${display} exited with code ${code} in ${seconds}s`);
      resolve({ code: code ?? 0, stdout, stderr });
    });
  });
}

/** Run a command whose every non-zero result is fatal. */
export async function runChecked(command: string, args: readonly string[], options: ExecOptions): Promise<ExecResult> {
  const display = [command, ...args].join(' ');
  let result: ExecResult;
  try {
    result = await run(command, args, options);
  } catch (error) {
    const cause = error as NodeJS.ErrnoException;
    if (cause.code === 'ENOENT') throw new Error(`Unable to run ${command}: command not found.`);
    throw new Error(`Unable to run ${display}: ${cause.message ?? String(error)}`);
  }
  if (result.code !== 0) {
    const tail = result.stderr.trim().slice(-2_000);
    throw new Error(`Command failed (exit ${result.code}): ${display}${tail ? `\n${tail}` : ''}`);
  }
  return result;
}
