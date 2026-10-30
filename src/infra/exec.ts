import { spawn } from 'node:child_process';
import type { Logger } from './log';

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
  ['node', '--version'],
];

export function isAllowedCommand(command: string, args: readonly string[]): boolean {
  if (args.some((a) => a === '--force' || a.startsWith('--force='))) return false;
  return ALLOWED.some(([c, ...a]) => c === command && a.length === args.length && a.every((x, i) => x === args[i]));
}

export interface ExecOptions {
  cwd: string;
  log: Logger;
  timeoutMs?: number;
  /** Para tests: reemplaza a child_process.spawn. */
  spawnImpl?: typeof spawn;
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
    process.platform === 'win32' ? ['cmd.exe', ['/d', '/s', '/c', command, ...args]] : [command, [...args]];

  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawnImpl(file, argv, {
      cwd,
      shell: false,
      windowsHide: true,
      env: { ...process.env, npm_config_fund: 'false', npm_config_update_notifier: 'false' },
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.setEncoding('utf8').on('data', (d: string) => (stdout += d));
    child.stderr?.setEncoding('utf8').on('data', (d: string) => (stderr += d));

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
