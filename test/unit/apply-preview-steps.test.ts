import { describe, expect, it } from 'vitest';
import { previewAuditFix } from '../../src/core/apply/auditFixPreview';
import { APPLY_STEPS, AUDIT_STEPS, classifyStepExit, EXACT_STEPS, type ApplyStep } from '../../src/core/apply/steps';
import { scan, type ScanDeps } from '../../src/core/scan';
import { isAllowedCommand } from '../../src/infra/exec';
import { FIXTURE_NOW, fixtureText, packumentFixture } from './helpers';

function deps(): ScanDeps {
  return {
    runAudit: async () => fixtureText('audit/sample.json'),
    readLockfile: async () => fixtureText('lockfile/sample-v3.json'),
    readManifest: async () => fixtureText('lockfile/sample-package.json'),
    getPackument: async (name) => packumentFixture(name),
    now: FIXTURE_NOW,
    quarantineDays: 7,
    nodeVersion: 'v20.18.0',
  };
}

describe('vista previa de npm audit fix', () => {
  it('incluye todo el proyecto y resume sólo la selección', async () => {
    const result = await scan(deps());
    const preview = previewAuditFix(result, ['axios', 'jsonwebtoken', 'braces']);
    expect(preview.packages).toHaveLength(result.packages.length);
    expect(preview.packages.find((pkg) => pkg.name === 'axios')).toMatchObject({
      from: '1.18.0',
      to: '1.21.0',
      status: 'quarantine',
      selected: true,
    });
    expect(preview.packages.find((pkg) => pkg.name === 'axios')!.ageDays).toBeCloseTo(3.2, 1);
    expect(preview.packages.find((pkg) => pkg.name === 'jsonwebtoken')).toMatchObject({ status: 'force-pending', selected: true });
    expect(preview.packages.find((pkg) => pkg.name === 'braces')).toMatchObject({ to: '3.0.3', status: 'fixed', selected: true });
    expect(preview.packages.find((pkg) => pkg.name === 'vite')).toMatchObject({ selected: false });
    expect(preview.summary).toEqual({ selected: 3, fixable: 2, force: 1 });
  });
});

describe('pasos de aplicación', () => {
  it('no incluyen --force y todos los comandos están permitidos', () => {
    expect(APPLY_STEPS).toEqual({ audit: AUDIT_STEPS, exact: EXACT_STEPS });
    expect(EXACT_STEPS[0]).toEqual({ label: 'Editar package.json' });
    for (const step of [...EXACT_STEPS, ...AUDIT_STEPS]) {
      expect(step.args ?? []).not.toContain('--force');
      if (step.command) expect(isAllowedCommand(step.command, step.args ?? [])).toBe(true);
    }
  });

  it.each([
    ['npm install', EXACT_STEPS[1]!, 0, 'done'],
    ['npm install', EXACT_STEPS[1]!, 1, 'failed'],
    ['npm audit fix', AUDIT_STEPS[0]!, 0, 'done'],
    ['npm audit fix', AUDIT_STEPS[0]!, 1, 'warning'],
    ['npm audit fix', AUDIT_STEPS[0]!, 2, 'failed'],
    ['npm audit signatures', AUDIT_STEPS[1]!, 0, 'done'],
    ['npm audit signatures', AUDIT_STEPS[1]!, 1, 'failed'],
    ['npm audit', AUDIT_STEPS[2]!, 0, 'done'],
    ['npm audit', AUDIT_STEPS[2]!, 1, 'warning'],
  ] as const)('clasifica %s con código %i como %s', (_label, step: ApplyStep, code, expected) => {
    expect(classifyStepExit(step, code)).toBe(expected);
  });
});
