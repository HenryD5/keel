<script setup lang="ts">
import { computed, ref } from 'vue';
import type { AuditFixPreview } from '../../../src/core/apply/auditFixPreview';
import { APPLY_STEPS, type ApplyMethod } from '../../../src/core/apply/steps';
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
}>();

const emit = defineEmits<{
  back: [];
  setExact: [exact: boolean];
  apply: [method: ApplyMethod];
}>();

const t = computed(() => STRINGS[props.lang]);
const method = ref<ApplyMethod>('exact');
const steps = computed(() => APPLY_STEPS[method.value]);
const disabled = computed(() =>
  props.applying || !props.plan || !props.preview || (method.value === 'exact' ? props.plan.changes.length === 0 : props.preview.summary.fixable === 0),
);
const primaryText = computed(() =>
  method.value === 'audit' ? t.value.reviewRunAuditFix : t.value.reviewInstall(props.plan?.changes.length ?? 0),
);

function icon(status: ApplyStatus | undefined): string {
  if (status === 'running') return 'codicon-loading spin';
  if (status === 'done') return 'codicon-pass ok';
  if (status === 'warning') return 'codicon-warning bad';
  if (status === 'failed') return 'codicon-error error-icon';
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

    <fieldset class="methods" :disabled="applying">
      <legend>{{ t.reviewMethodLegend }}</legend>
      <label class="method" :class="{ on: method === 'audit' }">
        <input v-model="method" type="radio" name="method" value="audit" />
        <div><b>{{ t.reviewAuditTitle }}</b><p>{{ t.reviewAuditSub }}</p><span class="cmd">npm audit fix</span></div>
      </label>
      <label class="method" :class="{ on: method === 'exact' }">
        <input v-model="method" type="radio" name="method" value="exact" />
        <div><b>{{ t.reviewExactTitle }}</b><p>{{ t.reviewExactSub }}</p><span class="cmd">{{ t.reviewExactCommand }}</span></div>
      </label>
    </fieldset>

    <template v-if="method === 'audit'">
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
            <li v-for="change in plan.changes" :key="change.name">
              <span class="mono">{{ change.name }} {{ change.from }} → {{ change.to }}<span v-if="change.kind === 'override'" class="ref"> · override</span></span>
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
          <code>{{ t.reviewStep(method, index) }}</code>
          <span>{{ progress.get(index)?.detail ?? t.reviewStepDetail(method, index) }}</span>
        </li>
      </ol>
    </section>

    <section class="notice blue row-notice" :aria-label="t.reviewRecommendationLabel">
      <span class="codicon codicon-info" aria-hidden="true"></span><p>{{ t.reviewRecommendation }}</p>
    </section>

    <div class="buttons">
      <span v-if="error" class="error-text" role="alert">{{ error }}</span>
      <button type="button" class="btn secondary" :disabled="applying" @click="emit('back')">{{ t.cancel }}</button>
      <button type="button" class="btn primary" :disabled="disabled" @click="emit('apply', method)">
        <span v-if="applying" class="codicon codicon-loading spin" aria-hidden="true"></span>{{ primaryText }}
      </button>
    </div>
  </main>
</template>
