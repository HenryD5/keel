import { createHash } from 'node:crypto';
import type { InstallPlan } from './plan';
import type { ApplyMethod } from './steps';

export interface PlanIdentityInput {
  method: ApplyMethod | 'remove';
  selection: readonly string[];
  choices: Readonly<Record<string, 'min' | 'latest' | 'line'>>;
  plan: InstallPlan;
  manifestText: string;
  lockfileText: string;
}

export function createPlanId(input: PlanIdentityInput): string {
  const canonical = {
    method: input.method,
    selection: [...input.selection].sort(),
    choices: Object.fromEntries(Object.entries(input.choices).sort(([a], [b]) => a.localeCompare(b))),
    exact: input.plan.exact,
    changes: input.plan.changes,
    removed: input.plan.removed ?? [],
    manifestText: input.manifestText,
    lockfileText: input.lockfileText,
  };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}
