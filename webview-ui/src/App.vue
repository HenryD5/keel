<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import type { ApplyMethod } from '../../src/core/apply/steps';
import type { ApplyStatus, HostMessage, ImpactPayload, Lang, PlanPayload, ScanPayload } from '../../src/webview/protocol';
import DetailView from './components/DetailView.vue';
import ReviewView from './components/ReviewView.vue';
import ResultsView from './components/ResultsView.vue';
import VerifyView from './components/VerifyView.vue';
import type { VerifyResult } from '../../src/core/verify/verify';
import { STRINGS } from './i18n';
import { scopeToFilter } from './filter';
import { defaultSelected, isSelectable } from './model';
import { loadState, saveState, send, type Filter } from './vscode';

const saved = loadState();
const lang = ref<Lang>(document.documentElement.lang === 'en' ? 'en' : 'es');
const scan = ref<ScanPayload>();
const scanning = ref(false);
const error = ref<string>();
const screen = ref(saved.screen);
const detail = ref(saved.detail);
const filter = ref<Filter>(saved.filter);
const selected = ref<string[] | undefined>(saved.selected);
const impacts = reactive(new Map<string, ImpactPayload>());
const saving = ref<string>();
const saveError = ref<string>();
const plan = ref<PlanPayload>();
const preview = ref<Extract<HostMessage, { type: 'plan' }>['preview']>();
const exact = ref(true);
const applying = ref(false);
const applySucceeded = ref(false);
const applyError = ref<string>();
const progress = reactive(new Map<number, { status: ApplyStatus; detail?: string }>());
const applySteps = ref<Array<{ label: string; detail: string }>>([]);
const outputTail = ref<string>();
const canRevert = ref(false);
const reportAvailable = ref(false);
const canCreatePr = ref(false);
/** Paquetes que el dev aceptó mover con los elegidos por peerDependencies (se reinicia al abrir la revisión). */
const companions = ref<Array<{ name: string; version: string }>>([]);
const verifyText = ref(saved.verifyText ?? '');
const verifying = ref(false);
const verifyResult = ref<VerifyResult>();
const verifyResultText = ref<string>();
const verifyError = ref<string>();


const selection = computed(() => {
  if (!scan.value) return [];
  const base = selected.value ?? defaultSelected(scan.value);
  return base.filter((name) => scan.value!.result.packages.some((p) => p.name === name && isSelectable(p, scan.value!)));
});
const scoped = computed(() => scopeToFilter(scan.value?.result.packages ?? [], selection.value, filter.value));
const detailPkg = computed(() => scan.value?.result.packages.find((p) => p.name === detail.value));

watch([screen, detail, filter, selected, scan, verifyText], () =>
  saveState({ screen: screen.value, detail: detail.value, filter: filter.value, selected: selected.value, scannedAt: scan.value?.result.scannedAt, verifyText: verifyText.value }),
);
watch(lang, (l) => (document.documentElement.lang = l));

function applyScan(payload: ScanPayload): void {
  // Un escaneo nuevo descarta la selección y el detalle de uno anterior.
  if (payload.result.scannedAt !== saved.scannedAt) {
    selected.value = undefined;
    impacts.clear();
    if (screen.value === 'detail' && !payload.result.packages.some((p) => p.name === detail.value)) screen.value = 'results';
  }
  saved.scannedAt = payload.result.scannedAt;
  scan.value = payload;
  if (applySucceeded.value) {
    applying.value = false;
    applySucceeded.value = false;
  }
}

function onMessage(event: MessageEvent<HostMessage>): void {
  const msg = event.data;
  switch (msg.type) {
    case 'init':
      lang.value = msg.lang;
      scanning.value = msg.scanning;
      error.value = msg.error;
      if (msg.scan) applyScan(msg.scan);
      if (msg.screen === 'verify') screen.value = 'verify';
      if (screen.value === 'detail' && detailPkg.value) openDetail(detailPkg.value.name);
      if (screen.value === 'review' && scan.value) requestPlan();
      break;
    case 'scanning':
      scanning.value = true;
      error.value = undefined;
      applyError.value = undefined;
      canRevert.value = false;
      break;
    case 'scan':
      scanning.value = false;
      applyScan(msg.scan);
      break;
    case 'scanError':
      scanning.value = false;
      error.value = msg.message;
      break;
    case 'impact':
      impacts.set(msg.impact.name, msg.impact);
      break;
    case 'plan':
      clearTimeout(planTimer);
      plan.value = msg.plan;
      preview.value = msg.preview;
      applySteps.value = msg.steps;
      applyError.value = undefined;
      break;
    case 'applyProgress':
      progress.set(msg.step, { status: msg.status, detail: msg.detail });
      break;
    case 'applyStarted':
      applySteps.value = msg.steps;
      break;
    case 'applyDone':
      applying.value = false;
      reportAvailable.value = msg.reportAvailable === true;
      canCreatePr.value = msg.canCreatePr === true;
      if (msg.ok) applySucceeded.value = true;
      else {
        applyError.value = msg.message ?? STRINGS[lang.value].applyFailed;
        outputTail.value = msg.outputTail;
        canRevert.value = msg.canRevert === true;
      }
      break;
    case 'revertDone':
      canRevert.value = false;
      applyError.value = msg.ok ? undefined : msg.message;
      break;
    case 'decisionSaved':
      if (scan.value) {
        if (msg.keep) scan.value.keep[msg.name] = msg.keep;
        else delete scan.value.keep[msg.name];
        if (msg.choice === 'keep') delete scan.value.choices[msg.name];
        else scan.value.choices[msg.name] = msg.choice === 'version' && msg.version ? { version: msg.version } : (msg.choice as 'min' | 'latest' | 'line');
        const current = selection.value.filter((n) => n !== msg.name);
        selected.value = msg.choice === 'keep' ? current : [...current, msg.name];
      }
      if (saving.value === msg.name) {
        saving.value = undefined;
        screen.value = 'results';
      }
      break;
    case 'decisionError':
      saving.value = undefined;
      saveError.value = msg.message;
      break;
    case 'lang':
      lang.value = msg.lang;
      break;
    case 'showVerify':
      screen.value = 'verify';
      window.scrollTo(0, 0);
      break;
    case 'verifying':
      verifying.value = true;
      verifyError.value = undefined;
      break;
    case 'verifyResult':
      verifying.value = false;
      verifyResult.value = msg.result;
      verifyResultText.value ??= verifyText.value;
      break;
    case 'verifyError':
      verifying.value = false;
      verifyError.value = msg.message;
      break;
    case 'verifyText':
      verifyText.value = msg.text;
      break;
  }
}

/** Pide el plan y, si no llega a tiempo, muestra un error con la opción de reintentar en vez de cargar sin fin. */
const PLAN_TIMEOUT_MS = 60_000;
let planTimer: ReturnType<typeof setTimeout> | undefined;
function requestPlan(): void {
  applyError.value = undefined;
  clearTimeout(planTimer);
  planTimer = setTimeout(() => {
    if (screen.value === 'review' && !plan.value) applyError.value = STRINGS[lang.value].planTimeout;
  }, PLAN_TIMEOUT_MS);
  send({ type: 'requestPlan', selected: scoped.value, exact: exact.value, companions: companions.value });
}

function includeCompanions(extra: Array<{ name: string; version: string }>): void {
  const byName = new Map(companions.value.map((c) => [c.name, c]));
  for (const c of extra) byName.set(c.name, c);
  companions.value = [...byName.values()];
  plan.value = undefined;
  requestPlan();
}

function openReview(): void {
  companions.value = [];
  screen.value = 'review';
  exact.value = true;
  plan.value = undefined;
  preview.value = undefined;
  applyError.value = undefined;
  progress.clear();
  requestPlan();
  window.scrollTo(0, 0);
}

function setExact(value: boolean): void {
  exact.value = value;
  plan.value = undefined;
  requestPlan();
}

function apply(method: ApplyMethod, validate: boolean): void {
  applying.value = true;
  applySucceeded.value = false;
  applyError.value = undefined;
  progress.clear();
  send({ type: 'apply', method, selected: scoped.value, exact: exact.value, validate, companions: companions.value });
}

function openDetail(name: string): void {
  const pkg = scan.value?.result.packages.find((p) => p.name === name);
  if (!pkg) return;
  detail.value = name;
  screen.value = 'detail';
  saveError.value = undefined;
  const to = pkg.resolution?.recommended?.version ?? pkg.resolution?.waitingFor?.version;
  if (to && impacts.get(name)?.to !== to) send({ type: 'requestImpact', name, to });
  window.scrollTo(0, 0);
}

function removeDependency(name: string): void {
  screen.value = 'review';
  exact.value = true;
  plan.value = undefined;
  preview.value = undefined;
  progress.clear();
  send({ type: 'requestRemovalPlan', name });
}

function runVerify(text: string): void {
  verifyResultText.value = text;
  verifyError.value = undefined;
  send({ type: 'verifyList', text });
}

/** Lleva a los resultados con solo los paquetes pendientes de la lista seleccionados. */
function fixPending(names: string[]): void {
  if (!scan.value) return;
  selected.value = names.filter((n) => scan.value!.result.packages.some((p) => p.name === n && isSelectable(p, scan.value!)));
  filter.value = 'all';
  screen.value = 'results';
  window.scrollTo(0, 0);
}

function setLang(l: Lang): void {
  lang.value = l;
  send({ type: 'setLang', lang: l });
  // El resumen del changelog depende del idioma: se pide de nuevo al volver al detalle.
  impacts.clear();
}

function toggle(name: string, on: boolean): void {
  const current = selection.value.filter((n) => n !== name);
  selected.value = on ? [...current, name] : current;
}

function saveDecision(choice: 'min' | 'latest' | 'line' | 'version' | 'keep', reason?: string, version?: string): void {
  if (!detail.value) return;
  saving.value = detail.value;
  saveError.value = undefined;
  send({ type: 'saveDecision', name: detail.value, choice, reason, ...(version ? { version } : {}) });
}

onMounted(() => {
  window.addEventListener('message', onMessage);
  send({ type: 'ready' });
});
onBeforeUnmount(() => window.removeEventListener('message', onMessage));
</script>

<template>
  <VerifyView
    v-if="screen === 'verify'"
    :lang="lang"
    :text="verifyText"
    :scan="scan"
    :verifying="verifying"
    :result="verifyResult"
    :result-text="verifyResultText"
    :error="verifyError"
    @back="screen = 'results'"
    @update="(text) => (verifyText = text)"
    @verify="runVerify"
    @load-file="send({ type: 'loadVerifyFile' })"
    @copy-report="send({ type: 'copyVerifyReport' })"
    @open-detail="openDetail"
    @open-external="(url) => send({ type: 'openExternal', url })"
    @fix-pending="fixPending"
    @rescan="screen = 'results'; send({ type: 'rescan' })"
  />
  <ReviewView
    v-else-if="screen === 'review' && scan"
    :lang="lang"
    :plan="plan"
    :preview="preview"
    :exact="exact"
    :applying="applying"
    :progress="progress"
    :error="applyError"
    :steps="applySteps"
    :output-tail="outputTail"
    :can-revert="canRevert"
    :report-available="reportAvailable"
    :can-create-pr="canCreatePr"
    @back="screen = 'results'"
    @set-exact="setExact"
    @apply="apply"
    @revert="send({ type: 'revert' })"
    @keep="canRevert = false; send({ type: 'keepChanges' })"
    @copy-report="send({ type: 'copyReport' })"
    @create-pr="send({ type: 'createPullRequest' })"
    @include-companions="includeCompanions"
    @retry-plan="plan = undefined; requestPlan()"
  />
  <DetailView
    v-else-if="screen === 'detail' && scan && detailPkg"
    :lang="lang"
    :scan="scan"
    :pkg="detailPkg"
    :impact="impacts.get(detailPkg.name)"
    :saving="saving === detailPkg.name"
    :save-error="saveError"
    @back="screen = 'results'"
    @save="saveDecision"
    @open-file="(path, line) => send({ type: 'openFile', path, line })"
    @open-external="(url) => send({ type: 'openExternal', url })"
    @remove="removeDependency"
  />
  <ResultsView
    v-else
    :lang="lang"
    :scan="scan"
    :scanning="scanning"
    :error="error"
    :filter="filter"
    :scoped="scoped"
    :selection="selection"
    @set-lang="setLang"
    @set-filter="(f) => (filter = f)"
    @toggle="toggle"
    @open-detail="openDetail"
    @rescan="send({ type: 'rescan' })"
    @show-log="send({ type: 'showLog' })"
    @select-project="send({ type: 'selectProject' })"
    @review="openReview"
    @verify="screen = 'verify'; verifyError = undefined"
  />
</template>
