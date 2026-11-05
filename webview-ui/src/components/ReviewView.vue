<script setup lang="ts">
import { computed, ref } from 'vue';
import type { AuditFixPreview } from '../../../src/core/apply/auditFixPreview';
import type { ApplyMethod } from '../../../src/core/apply/steps';
import type { ApplyStatus, Lang, PlanPayload } from '../../../src/webview/protocol';
import { STRINGS } from '../i18n';

const props = defineProps<{
  lang: Lang;
  plan?: PlanPayload;
  preview?: AuditFixPreview;
  exact: boolean;
  applying: boolean;
  progress: Map<number, { status: ApplyStatus; detail?: string }>;
  error?: string;
  steps: Array<{ label: string; detail: string }>;
  outputTail?: string;
  canRevert: boolean;
  reportAvailable: boolean;
  canCreatePr: boolean;
}>();

const emit = defineEmits<{
  back: [];
  setExact: [exact: boolean];
  apply: [method: ApplyMethod, validate: boolean];
  revert: [];
  keep: [];
  copyReport: [];
  createPr: [];
  includeCompanions: [companions: Array<{ name: string; version: string }>];
}>();

const t = computed(() => STRINGS[props.lang]);
const method = ref<ApplyMethod>('exact');
const validate = ref(true);
/** Choques de peerDependencies: npm install fallaría con ERESOLVE. */
const conflicts = computed(() => (method.value === 'exact' ? props.plan?.peerConflicts ?? [] : []));
const fixes = computed(() => {
  const seen = new Map<string, { name: string; from: string; to: string }>();
  for (const c of conflicts.value) if (c.fix) seen.set(c.fix.name, c.fix);
  return [...seen.values()];
});
const unfixable = computed(() => conflicts.value.filter((c) => !c.fix));
/** Con conflictos se bloquea aplicar, salvo que el dev decida intentarlo igual. */
const tryAnyway = ref(false);
const disabled = computed(() =>
  props.applying || !props.plan || !props.preview || (conflicts.value.length > 0 && !tryAnyway.value) || (method.value === 'exact' ? props.plan.changes.length === 0 && !props.plan.removed?.length : props.preview.summary.fixable === 0),
);
const primaryText = computed(() =>
  method.value === 'audit' ? t.value.reviewRunAuditFix : props.plan?.removed?.length ? t.value.removeDependency : t.value.reviewInstall(props.plan?.changes.length ?? 0),
);

function icon(status: ApplyStatus | undefined): string {
  if (status === 'running') return 'codicon-loading spin';
  if (status === 'done') return 'codicon-pass ok';
  if (status === 'warning') return 'codicon-warning bad';
  if (status === 'failed') return 'codicon-error error-icon';
  if (status === 'skipped') return 'codicon-debug-step-over warn';
  return 'codicon-circle-outline';
}
</script>

<template>
  <main class="detail">
    <button type="button" class="linkbtn back" :disabled="applying" @click="emit('back')">
      <span class="codicon codicon-arrow-left" aria-hidden="true"></span>{{ t.back }}
    </button>

    <header class="stack">
      <h1>{{ t.reviewTitle }}</h1>
      <p v-if="preview" class="sub">{{ t.reviewSummary(preview.summary.selected, preview.summary.fixable, preview.summary.force) }}</p>
    </header>

    <fieldset v-if="!plan?.removed?.length" class="methods" :disabled="applying">
      <legend>{{ t.reviewMethodLegend }}</legend>
      <label class="method" :class="{ on: method === 'exact' }">
        <input v-model="method" class="visually-hidden" type="radio" name="method" value="exact" />
        <span class="pick" aria-hidden="true"><span class="codicon codicon-check"></span></span>
        <div>
          <div class="inline"><b>{{ t.reviewExactTitle }}</b><span class="badge b-patch">{{ t.reviewRecommended }}</span><span v-if="method === 'exact'" class="picked">{{ t.reviewSelected }}</span></div>
          <p>{{ t.reviewExactSub }}</p><span class="cmd">{{ t.reviewExactCommand }}</span>
        </div>
      </label>
      <label class="method" :class="{ on: method === 'audit' }">
        <input v-model="method" class="visually-hidden" type="radio" name="method" value="audit" />
        <span class="pick" aria-hidden="true"><span class="codicon codicon-check"></span></span>
        <div>
          <div class="inline"><b>{{ t.reviewAuditTitle }}</b><span v-if="method === 'audit'" class="picked">{{ t.reviewSelected }}</span></div>
          <p>{{ t.reviewAuditSub }}</p><span class="cmd">npm audit fix</span>
        </div>
      </label>
    </fieldset>

    <section v-if="conflicts.length" class="notice red" role="alert">
      <h2>{{ t.peerTitle }}</h2>
      <p>{{ t.peerIntro }}</p>
      <ul class="facts">
        <li v-for="c in conflicts" :key="c.requirer + c.peer">
          <span class="codicon codicon-error error-icon" aria-hidden="true"></span>
          <span>{{ t.peerLine(c.requirer, c.requirerVersion, c.peer, c.range, c.peerVersion) }}</span>
        </li>
      </ul>
      <template v-if="fixes.length">
        <p>{{ t.peerFixIntro }}</p>
        <ul class="facts">
          <li v-for="f in fixes" :key="f.name"><span class="mono">{{ f.name }} {{ f.from }} → {{ f.to }}</span></li>
        </ul>
        <div class="inline">
          <button type="button" class="btn primary" :disabled="applying" @click="emit('includeCompanions', fixes.map((f) => ({ name: f.name, version: f.to })))">{{ t.peerInclude(fixes.length) }}</button>
        </div>
      </template>
      <p v-if="unfixable.length" class="sub">{{ t.peerUnfixable }}</p>
      <label class="exact-option bare"><input v-model="tryAnyway" type="checkbox" :disabled="applying" />{{ t.peerTryAnyway }}</label>
    </section>

    <template v-if="method === 'audit' && !plan?.removed?.length">
      <section class="card">
        <div class="card-head"><h2>{{ t.reviewAuditWhat }}</h2></div>
        <div v-if="!preview" class="empty"><span class="codicon codicon-loading spin" aria-hidden="true"></span>{{ t.reviewPlanning }}</div>
        <ul v-else class="list review-list">
          <li v-for="pkg in preview.packages" :key="pkg.name">
            <span class="mono">{{ pkg.name }} {{ pkg.from }}<template v-if="pkg.to"> → {{ pkg.to }}</template></span>
            <span :class="pkg.status === 'fixed' ? 'ok' : pkg.status === 'unknown' ? 'ref' : 'warn'">
              {{ pkg.status === 'fixed' ? t.reviewFixed : pkg.status === 'quarantine' ? t.reviewQuarantine(pkg.ageDays) : pkg.status === 'force-pending' ? t.reviewForcePending : t.reviewUnknown }}
              <template v-if="!pkg.selected && (pkg.status === 'fixed' || pkg.status === 'quarantine')"> · {{ t.reviewNotSelected }}</template>
            </span>
          </li>
        </ul>
      </section>
      <p class="sub">{{ t.reviewAuditGlobal }}</p>
    </template>

    <div v-else class="cols">
      <section class="card">
        <div class="card-head"><h2>{{ t.reviewInstallWhat }}</h2></div>
        <div v-if="!plan" class="empty"><span class="codicon codicon-loading spin" aria-hidden="true"></span>{{ t.reviewPlanning }}</div>
        <template v-else>
          <ul class="list review-list">
            <li v-for="item in plan.removed" :key="item.name"><span class="mono">{{ item.name }}</span><span class="warn">{{ t.removeDependency }}</span></li>
            <li v-for="change in plan.changes" :key="change.name">
              <span class="mono">{{ change.name }} {{ change.from }} → {{ change.to }}<span v-if="change.kind === 'override'" class="ref"> · override</span><span v-if="change.companion" class="ref"> · {{ t.peerCompanion }}</span></span>
              <span class="badge" :class="`b-${change.bump}`">{{ change.bump === 'major' ? t.reviewMajorNoForce : t.reviewBump[change.bump] }}</span>
            </li>
          </ul>
          <div v-if="plan.skipped.length" class="skipped">
            <h2>{{ t.reviewSkipped }}</h2>
            <p v-for="item in plan.skipped" :key="item.name" class="sub"><span class="mono">{{ item.name }}</span> · {{ t.reviewSkipReason(item.reason) }}</p>
          </div>
        </template>
      </section>
      <section class="card">
        <div class="card-head"><h2>package.json</h2></div>
        <div v-if="!plan" class="empty"><span class="codicon codicon-loading spin" aria-hidden="true"></span>{{ t.reviewPlanning }}</div>
        <div v-else class="diff" aria-label="package.json diff">
          <div v-for="(line, index) in plan.diff" :key="index" :class="line.kind">{{ line.kind === 'add' ? '+ ' : line.kind === 'del' ? '- ' : '  ' }}{{ line.text }}</div>
        </div>
        <label class="exact-option"><input type="checkbox" :checked="exact" :disabled="applying" @change="emit('setExact', ($event.target as HTMLInputElement).checked)" />{{ t.reviewPinExact }}</label>
      </section>
    </div>

    <section class="card" :aria-label="t.reviewCommands">
      <div class="card-head"><h2>{{ t.reviewCommands }}</h2><span class="ref">{{ t.reviewNeverForce }}</span></div>
      <ol class="steps" aria-live="polite">
        <li v-for="(step, index) in steps" :key="step.label">
          <span class="step-status codicon" :class="icon(progress.get(index)?.status)" aria-hidden="true"></span>
          <code>{{ step.label }}</code>
          <span>{{ progress.get(index)?.detail ?? step.detail }}</span>
        </li>
      </ol>
    </section>

    <label class="exact-option"><input v-model="validate" type="checkbox" :disabled="applying" />{{ t.reviewValidate }}</label>

    <section v-if="canRevert" class="notice red">
      <h2>{{ error }}</h2>
      <pre v-if="outputTail" class="output-tail">{{ outputTail }}</pre>
      <div class="buttons">
        <button type="button" class="btn secondary" @click="emit('keep')">{{ t.keepChanges }}</button>
        <button type="button" class="btn primary" @click="emit('revert')">{{ t.revertChanges }}</button>
      </div>
    </section>

    <section class="notice blue row-notice" :aria-label="t.reviewRecommendationLabel">
      <span class="codicon codicon-info" aria-hidden="true"></span><p>{{ t.reviewRecommendation }}</p>
    </section>

    <div class="buttons">
      <span v-if="error" class="error-text" role="alert">{{ error }}</span>
      <button type="button" class="btn secondary" :disabled="applying" @click="emit('back')">{{ t.cancel }}</button>
      <button type="button" class="btn primary" :disabled="disabled" @click="emit('apply', method, validate)">
        <span v-if="applying" class="codicon codicon-loading spin" aria-hidden="true"></span>{{ primaryText }}
      </button>
      <button v-if="reportAvailable" type="button" class="btn secondary" @click="emit('copyReport')">{{ t.copyReport }}</button>
      <button v-if="canCreatePr" type="button" class="btn primary" @click="emit('createPr')">{{ t.createPr }}</button>
    </div>
  </main>
</template>
