export type ApplyMethod = 'audit' | 'exact';

export interface ApplyStep {
  label: string;
  command?: string;
  args?: readonly string[];
}

export type ApplyStepStatus = 'running' | 'done' | 'warning' | 'failed' | 'skipped';

export function classifyStepExit(step: ApplyStep, code: number): ApplyStepStatus {
  if (code === 0) return 'done';
  const args = step.command === 'npm' ? step.args : undefined;
  if (code === 1 && args?.[0] === 'audit' && (args.length === 1 || args[1] === 'fix')) return 'warning';
  return 'failed';
}

export const EXACT_STEPS: readonly ApplyStep[] = [
  { label: 'Editar package.json' },
  { label: 'npm install', command: 'npm', args: ['install'] },
  { label: 'npm audit signatures', command: 'npm', args: ['audit', 'signatures'] },
  { label: 'npm audit', command: 'npm', args: ['audit'] },
];

export const AUDIT_STEPS: readonly ApplyStep[] = [
  { label: 'npm audit fix', command: 'npm', args: ['audit', 'fix'] },
  { label: 'npm audit signatures', command: 'npm', args: ['audit', 'signatures'] },
  { label: 'npm audit', command: 'npm', args: ['audit'] },
];

export const APPLY_STEPS: Readonly<Record<ApplyMethod, readonly ApplyStep[]>> = {
  audit: AUDIT_STEPS,
  exact: EXACT_STEPS,
};
