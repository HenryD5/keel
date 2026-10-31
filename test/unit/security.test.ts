import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { packumentUrl } from '../../src/core/registry/client';
import { isValidPackageName, isValidVersion } from '../../src/core/validate';
import { isAllowedCommand, run, runChecked } from '../../src/infra/exec';
import { assertAllowedUrl, createFetchJson } from '../../src/infra/http';
import { createLogger } from '../../src/infra/log';

describe('validación de nombres y versiones', () => {
  it('acepta nombres de npm válidos, con scope y antiguos con mayúsculas', () => {
    for (const n of ['axios', '@vue/compiler-sfc', 'lodash.once', 'JSONStream']) expect(isValidPackageName(n)).toBe(true);
  });

  it('rechaza nombres con caracteres de shell o rutas', () => {
    for (const n of ['', 'a b', 'a;rm -rf', '$(id)', '../x', '.hidden', '@scope', 'a/b', 'x'.repeat(215)]) {
      expect(isValidPackageName(n)).toBe(false);
    }
  });

  it('solo acepta versiones exactas', () => {
    expect(isValidVersion('1.20.0')).toBe(true);
    expect(isValidVersion('1.0.0-beta.1')).toBe(true);
    for (const v of ['^1.0.0', '1.0', 'latest', '1.0.0 || 2.0.0', 'v1.0.0', '1.0.0; echo']) expect(isValidVersion(v)).toBe(false);
  });

  it('codifica los nombres con scope en la URL del registro', () => {
    expect(packumentUrl('@vue/reactivity')).toBe('https://registry.npmjs.org/@vue%2Freactivity');
    expect(() => packumentUrl('../etc')).toThrow();
  });
});

describe('comandos permitidos', () => {
  it('solo los comandos oficiales, con argumentos exactos', () => {
    expect(isAllowedCommand('npm', ['audit', '--json'])).toBe(true);
    expect(isAllowedCommand('npm', ['audit', 'fix'])).toBe(true);
    expect(isAllowedCommand('npm', ['install'])).toBe(true);
    expect(isAllowedCommand('npm', ['audit', 'signatures'])).toBe(true);
  });

  it('nunca --force ni comandos o argumentos extra', () => {
    expect(isAllowedCommand('npm', ['audit', 'fix', '--force'])).toBe(false);
    expect(isAllowedCommand('npm', ['install', '--force'])).toBe(false);
    expect(isAllowedCommand('npm', ['run', 'build'])).toBe(true);
    expect(isAllowedCommand('npm', ['run', '../build'])).toBe(false);
    expect(isAllowedCommand('npm', ['test'])).toBe(false);
    expect(isAllowedCommand('sh', ['-c', 'npm audit'])).toBe(false);
  });

  it('permite solo los patrones git y gh validados', () => {
    for (const [command, args] of [
      ['git', ['status', '--porcelain']], ['git', ['rev-parse', '--abbrev-ref', 'HEAD']],
      ['git', ['rev-parse', '--show-prefix']],
      ['git', ['branch', '--list', 'keel/fix-a1b2c3d4']], ['git', ['ls-remote', '--heads', 'origin', 'keel/fix-a1b2c3d4']],
      ['git', ['switch', '-c', 'keel/fix-a1b2c3d4']], ['git', ['add', '--', 'package.json']], ['git', ['commit', '-F', '-']],
      ['git', ['push', '-u', 'origin', 'keel/fix-a1b2c3d4']], ['gh', ['--version']], ['gh', ['repo', 'view', '--json', 'defaultBranchRef']],
      ['gh', ['pr', 'list', '--head', 'keel/fix-a1b2c3d4', '--json', 'url']],
      ['gh', ['pr', 'create', '--base', 'main', '--head', 'keel/fix-a1b2c3d4', '--title', 'title', '--body', 'body']],
    ] as const) expect(isAllowedCommand(command, args)).toBe(true);
    expect(isAllowedCommand('git', ['add', '.'])).toBe(false);
    expect(isAllowedCommand('git', ['add', '--', 'src/x.ts'])).toBe(false);
    expect(isAllowedCommand('git', ['switch', '-c', '-x'])).toBe(false);
    expect(isAllowedCommand('git', ['push', '--force', 'origin', 'main'])).toBe(false);
    expect(isAllowedCommand('git', ['rev-parse', '--show-toplevel'])).toBe(false);
    expect(isAllowedCommand('git', ['rev-parse', '--show-prefix', 'extra'])).toBe(false);
    expect(isAllowedCommand('gh', ['pr', 'create', '--base', 'main', '--head', 'keel/fix-a1b2c3d4', '--title', 'title', '--body', 'body', 'extra', 'extra'])).toBe(false);
  });

  it('rechaza un comando no permitido sin lanzar ningún proceso', async () => {
    const spawnImpl = vi.fn();
    await expect(run('npm', ['audit', 'fix', '--force'], { cwd: '/tmp', log: createLogger({ appendLine() {} }), spawnImpl: spawnImpl as never })).rejects.toThrow(
      /not allowed/,
    );
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it('usa spawn sin shell y registra comando, salida y código de salida', async () => {
    const lines: string[] = [];
    const log = createLogger({ appendLine: (l) => lines.push(l) }, () => new Date(2026, 9, 30, 12, 0, 0));
    const spawnImpl = vi.fn(() => {
      const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn() });
      setImmediate(() => {
        child.stdout.end('{"auditReportVersion":2}');
        child.stderr.end('');
        setImmediate(() => child.emit('close', 1, null));
      });
      return child;
    });
    const result = await run('npm', ['audit', '--json'], { cwd: '/project', log, spawnImpl: spawnImpl as never });

    expect(result).toEqual({ code: 1, stdout: '{"auditReportVersion":2}', stderr: '' });
    const [, , options] = spawnImpl.mock.calls[0] as unknown as [string, string[], { shell: boolean; cwd: string }];
    expect(options).toMatchObject({ shell: false, cwd: '/project' });
    expect(lines[0]).toBe('[2026-10-30 12:00:00] $ npm audit --json   (cwd: /project)');
    expect(lines).toContain('{"auditReportVersion":2}');
    expect(lines.at(-1)).toMatch(/exited with code 1/);
  });

  it('hace fatal cualquier salida no cero e incluye comando y final de stderr', async () => {
    const spawnImpl = vi.fn(() => {
      const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn() });
      setImmediate(() => {
        child.stdout.end('');
        child.stderr.end('fatal: not a git repository');
        setImmediate(() => child.emit('close', 128, null));
      });
      return child;
    });
    await expect(runChecked('git', ['status', '--porcelain'], { cwd: '/project', log: createLogger({ appendLine() {} }), spawnImpl: spawnImpl as never }))
      .rejects.toThrow('Command failed (exit 128): git status --porcelain\nfatal: not a git repository');
  });
});

describe('red', () => {
  it('solo https hacia los hosts permitidos', () => {
    expect(() => assertAllowedUrl('https://registry.npmjs.org/axios')).not.toThrow();
    expect(() => assertAllowedUrl('https://api.osv.dev/v1/query')).not.toThrow();
    expect(() => assertAllowedUrl('http://registry.npmjs.org/axios')).toThrow();
    expect(() => assertAllowedUrl('https://registry.npmjs.org.evil.com/x')).toThrow();
    expect(() => assertAllowedUrl('https://registry.npmjs.org:8443/x')).toThrow();
    expect(() => assertAllowedUrl('https://example.com/')).toThrow();
  });

  it('no sigue redirecciones y falla con estados de error', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 404 }));
    const fetchJson = createFetchJson(createLogger({ appendLine() {} }), fetchImpl as never);
    await expect(fetchJson('https://registry.npmjs.org/nope')).rejects.toThrow(/HTTP 404/);
    expect((fetchImpl.mock.calls[0] as unknown as [URL, RequestInit])[1].redirect).toBe('error');
  });
});
