import { describe, expect, it, vi } from 'vitest';
import { changedSinceApply, parseCliArgs } from '../../src/cli/index';
import { createHash } from 'node:crypto';
import { createPlanId } from '../../src/core/apply/planId';
import { compareInstalledVersions, runApply, runRevert, type RunnerAdapters } from '../../src/core/apply/runner';
import type { InstallPlan } from '../../src/core/apply/plan';

const plan: InstallPlan = { changes: [], newManifestText: '{"name":"x"}\n', diff: [], skipped: [] };

function adapters(results: Array<{ code: number; stdout?: string; stderr?: string }>, manifest = '{"scripts":{"test":"vitest"}}', lockfile = '{"lockfileVersion":3,"packages":{}}'): RunnerAdapters {
  return {
    read: vi.fn(async (name) => name === 'package.json' ? manifest : lockfile), write: vi.fn(async () => {}),
    run: vi.fn(async () => { const next = results.shift() ?? { code: 0 }; return { code: next.code, stdout: next.stdout ?? '', stderr: next.stderr ?? '' }; }),
    registryFindings: vi.fn(async () => []),
  };
}

describe('CLI arguments', () => {
  it('parses global and plan options', () => {
    const parsed = parseCliArgs(['plan', '--select', 'a,b', '--choice', 'a=latest', '--quarantine-days', '0']);
    expect(parsed.select).toEqual(['a', 'b']);
    expect(parsed.choices).toEqual({ a: 'latest' });
    expect(parsed.keepRange).toBe(false);
  });

  it('parses keep-range and disables validation through the real parser', () => {
    const parsed = parseCliArgs(['apply', '--keep-range', '--no-validate']);
    expect(parsed.keepRange).toBe(true);
    expect(parsed.validate).toBe(false);
  });

  it('accepts line and exact version choices', () => {
    expect(parseCliArgs(['plan', '--choice', 'vitest=3.2.7', '--choice', 'vite=line']).choices).toEqual({ vitest: { version: '3.2.7' }, vite: 'line' });
  });

  it('rejects unsafe choice and script inputs', () => {
    expect(() => parseCliArgs(['plan', '--choice', 'a=next'])).toThrow();
    expect(() => parseCliArgs(['apply', '--scripts', 'test;rm'])).toThrow();
  });
});

describe('planId', () => {
  const id = (manifestText = '{}', lockfileText = '{}') => createPlanId({ method: 'exact', selection: ['a'], choices: { a: 'min' }, plan, manifestText, lockfileText });
  it('is stable and changes with either project file', () => {
    expect(id()).toBe(id());
    expect(id('{"x":1}')).not.toBe(id());
    expect(id('{}', '{"x":1}')).not.toBe(id());
  });
  it('binds the pinning choice through the plan', () => {
    const pinned = createPlanId({ method: 'exact', selection: ['a'], choices: {}, plan: { ...plan, exact: true }, manifestText: '{}', lockfileText: '{}' });
    const ranged = createPlanId({ method: 'exact', selection: ['a'], choices: {}, plan: { ...plan, exact: false }, manifestText: '{}', lockfileText: '{}' });
    expect(pinned).not.toBe(ranged);
  });
});

describe('apply runner', () => {
  it('succeeds and runs validation with CI', async () => {
    const io = adapters([{ code: 0 }, { code: 0 }, { code: 1 }, { code: 0 }]);
    const result = await runApply({ method: 'exact', plan, scripts: ['test'], validate: true, registryBefore: [], adapters: io });
    expect(result.ok).toBe(true);
    expect(result.validation).toEqual([{ script: 'test', status: 'passed' }]);
    expect(io.run).toHaveBeenLastCalledWith('npm', ['run', 'test'], { env: { CI: 'true' }, timeoutMs: 600_000 });
  });

  it('writes the approved manifest and never invokes npm audit fix', async () => {
    const selectedPlan: InstallPlan = { changes: [{ name: 'axios', from: '1.18.0', to: '1.20.0', oldSpec: '^1.18.0', newSpec: '^1.20.0', kind: 'direct', bump: 'minor' }], newManifestText: '{"dependencies":{"axios":"^1.20.0","other":"^2.0.0"}}\n', diff: [], skipped: [] };
    const lock = '{"lockfileVersion":3,"packages":{"node_modules/axios":{"name":"axios","version":"1.20.0"}}}';
    const io = adapters([{ code: 0 }, { code: 0 }, { code: 1 }], '{"dependencies":{"axios":"^1.18.0","other":"^2.0.0"}}\n', lock);
    await runApply({ method: 'exact', plan: selectedPlan, scripts: [], validate: true, registryBefore: [], adapters: io });
    expect(io.write).toHaveBeenCalledWith('package.json', selectedPlan.newManifestText);
    expect(io.run).not.toHaveBeenCalledWith('npm', ['audit', 'fix']);
    expect(JSON.parse(selectedPlan.newManifestText).dependencies).toEqual({ axios: '^1.20.0', other: '^2.0.0' });
  });

  it('returns the failed step and output tail', async () => {
    const result = await runApply({ method: 'exact', plan, scripts: [], validate: true, registryBefore: [], adapters: adapters([{ code: 2, stderr: 'broken' }]) });
    expect(result).toMatchObject({ ok: false, failedStep: 'npm install', outputTail: 'broken' });
  });

  it('marks a missing script skipped', async () => {
    const result = await runApply({ method: 'exact', plan, scripts: ['build'], validate: true, registryBefore: [], adapters: adapters([{ code: 0 }, { code: 0 }, { code: 1 }], '{}') });
    expect(result.validation).toEqual([{ script: 'build', status: 'skipped', detail: 'Script is not present in package.json.' }]);
  });

  it('restores both files before npm install', async () => {
    const io = adapters([{ code: 0 }]);
    expect(await runRevert({ manifest: 'm', lockfile: 'l' }, io)).toEqual({ ok: true });
    expect(io.write).toHaveBeenCalledTimes(2);
  });
});

describe('installed version verification', () => {
  const selectedPlan: InstallPlan = { changes: [{ name: 'axios', from: '1.18.0', to: '1.20.0', newSpec: '1.20.0', kind: 'direct', bump: 'minor' }], newManifestText: '{}', diff: [], skipped: [] };
  const lock = (version: string) => JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/axios': { name: 'axios', version } } });

  it('is a pure comparison of planned and installed versions', () => {
    expect(compareInstalledVersions(selectedPlan, lock('1.21.0'))).toEqual([{ name: 'axios', from: '1.18.0', planned: '1.20.0', installed: '1.21.0', matches: false }]);
  });

  it('fails pinned mismatches and warns for kept ranges', async () => {
    const pinned = await runApply({ method: 'exact', exact: true, plan: selectedPlan, scripts: [], validate: false, registryBefore: [], adapters: adapters([{ code: 0 }], '{}', lock('1.21.0')) });
    expect(pinned).toMatchObject({ ok: false, failedStep: 'npm install', outputTail: 'axios: planned 1.20.0, installed 1.21.0' });
    const ranged = await runApply({ method: 'exact', exact: false, plan: selectedPlan, scripts: [], validate: false, registryBefore: [], adapters: adapters([{ code: 0 }, { code: 0 }, { code: 1 }], '{}', lock('1.21.0')) });
    expect(ranged.ok).toBe(true);
    expect(ranged.versionWarnings[0]).toMatchObject({ planned: '1.20.0', installed: '1.21.0' });
  });
});

describe('safe revert fingerprints', () => {
  const hash = (text: string) => createHash('sha256').update(text).digest('hex');
  const snapshot = { manifest: 'old-m', lockfile: 'old-l', postApplyHashes: { manifest: hash('new-m'), lockfile: hash('new-l') } };
  it('identifies each file changed after a failed apply', () => {
    expect(changedSinceApply(snapshot, 'edited', 'new-l')).toEqual(['package.json']);
    expect(changedSinceApply(snapshot, 'new-m', 'edited')).toEqual(['package-lock.json']);
    expect(changedSinceApply(snapshot, 'new-m', 'new-l')).toEqual([]);
  });
});
