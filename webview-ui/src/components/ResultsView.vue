<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import type { PackageReport } from '../../../src/core/scan';
import type { Lang, ScanPayload } from '../../../src/webview/protocol';
import { severityText, STRINGS } from '../i18n';
import {
  category,
  isKept,
  isSelectable,
  kindTag,
  referenceCounts,
  rowSummary,
  SEVERITIES,
  targetVersion,
  versionNote,
} from '../model';
import type { Filter } from '../vscode';

const props = defineProps<{
  lang: Lang;
  scan?: ScanPayload;
  scanning: boolean;
  error?: string;
  filter: Filter;
  selection: string[];
  scoped: string[];
}>();

const emit = defineEmits<{
  setLang: [lang: Lang];
  setFilter: [filter: Filter];
  toggle: [name: string, on: boolean];
  openDetail: [name: string];
  rescan: [];
  showLog: [];
  selectProject: [];
  review: [];
}>();

const t = computed(() => STRINGS[props.lang]);
const packages = computed(() => props.scan?.result.packages ?? []);
const visible = computed(() => (props.filter === 'all' ? packages.value : packages.value.filter((p) => category(p) === props.filter)));
const counts = computed(() => ({
  all: packages.value.length,
  safe: packages.value.filter((p) => category(p) === 'safe').length,
  review: packages.value.filter((p) => category(p) === 'review').length,
  break: packages.value.filter((p) => category(p) === 'break').length,
}));
const filters = computed(() => [
  { id: 'all' as const, label: t.value.filterAll },
  { id: 'safe' as const, label: t.value.filterSafe },
  { id: 'review' as const, label: t.value.filterReview },
  { id: 'break' as const, label: t.value.filterBreak },
]);
const selectable = computed(() => (props.scan ? visible.value.filter((p) => isSelectable(p, props.scan!)) : []));
const majorSelected = computed(() =>
  visible.value.some((p) => props.scoped.includes(p.name) && p.resolution?.recommended?.bump === 'major'),
);

const totalsText = computed(() => {
  const totals = props.scan?.result.totals;
  if (!totals) return '';
  const parts = SEVERITIES.filter((s) => totals[s] > 0).map((s) => severityText(props.lang, s, totals[s]));
  return [t.value.packages(packages.value.length), ...parts].join(' · ');
});

// "hace 12 s" se refresca solo.
const now = ref(Date.now());
let timer: ReturnType<typeof setInterval> | undefined;
onMounted(() => (timer = setInterval(() => (now.value = Date.now()), 10_000)));
onBeforeUnmount(() => clearInterval(timer));

const subtitle = computed(() => {
  const s = props.scan;
  if (!s) return '';
  const seconds = (now.value - Date.parse(s.result.scannedAt)) / 1000;
  return t.value.subtitle(s.result.projectName ?? 'package.json', t.value.ago(seconds), s.referenceSource);
});

function bumpClass(pkg: PackageReport): string {
  const bump = pkg.resolution?.recommended?.bump;
  return bump ? `b-${bump}` : 'b-none';
}

function bumpLabel(pkg: PackageReport): string {
  const r = pkg.resolution;
  if (r?.recommended) return t.value.bump[r.recommended.bump];
  if (r?.status === 'quarantine-only') return t.value.checkQuarantineBad;
  return t.value.noVersion;
}

function sevs(pkg: PackageReport) {
  return SEVERITIES.filter((s) => pkg.counts[s] > 0).map((s) => ({ s, text: severityText(props.lang, s, pkg.counts[s]) }));
}
</script>

<template>
  <main>
    <header class="header">
      <div class="stack">
        <h1>{{ t.heading }}</h1>
        <p v-if="subtitle" class="sub">{{ subtitle }} · {{ scan?.projectFolder }}</p>
        <button v-if="scan?.canSelectProject" type="button" class="linkbtn" @click="emit('selectProject')">{{ t.changeProject }}</button>
      </div>
      <div class="actions">
        <div class="seg" role="group" :aria-label="t.langGroup">
          <button type="button" :class="{ on: lang === 'es' }" :aria-pressed="lang === 'es'" @click="emit('setLang', 'es')">ES</button>
          <button type="button" :class="{ on: lang === 'en' }" :aria-pressed="lang === 'en'" @click="emit('setLang', 'en')">EN</button>
        </div>
        <button type="button" class="btn" @click="emit('showLog')"><span class="codicon codicon-output" aria-hidden="true"></span>{{ t.commandLog }}</button>
        <button type="button" class="btn" :disabled="scanning" @click="emit('rescan')">
          <span class="codicon" :class="scanning ? 'codicon-loading spin' : 'codicon-refresh'" aria-hidden="true"></span>{{ t.runAudit }}
        </button>
      </div>
    </header>
    <section v-if="scan?.registryFindings.length" class="notice orange">
      <h2>{{ t.registryWarning }}</h2>
      <p v-for="finding in scan.registryFindings" :key="`${finding.package}:${finding.host}:${finding.reason}`">
        <span class="mono">{{ finding.package }}</span> · {{ finding.host }} · {{ t.registryReason[finding.reason] }}
      </p>
    </section>

    <section v-if="error" class="notice red" role="alert">
      <p>{{ error }}</p>
    </section>

    <section v-if="scanning && !scan" class="card" aria-live="polite">
      <div class="empty"><span class="codicon codicon-loading spin" aria-hidden="true"></span>{{ t.scanning }}</div>
    </section>

    <section v-else-if="!scan && !error" class="card">
      <div class="empty"><span class="codicon codicon-info" aria-hidden="true"></span>{{ t.noScan }}</div>
    </section>

    <section v-else-if="scan && packages.length === 0" class="notice blue row-notice">
      <span class="codicon codicon-pass ok" aria-hidden="true"></span>
      <p><b>{{ t.emptyTitle }}.</b> {{ t.emptyBody }}</p>
    </section>

    <template v-else-if="scan">
      <section v-if="scan.keelFileError" class="notice orange row-notice">
        <span class="codicon codicon-warning bad" aria-hidden="true"></span>
        <p>{{ scan.keelFileError }}</p>
      </section>

      <section class="card" :aria-label="t.packagesLabel" :aria-busy="scanning">
        <div class="card-head">
          <div class="pills" role="group" :aria-label="t.filterGroup">
            <button
              v-for="f in filters"
              :key="f.id"
              type="button"
              class="pill"
              :class="{ on: filter === f.id }"
              :aria-pressed="filter === f.id"
              @click="emit('setFilter', f.id)"
            >
              {{ f.label }} ({{ counts[f.id] }})
            </button>
          </div>
          <p class="sub">{{ totalsText }}</p>
        </div>

        <div v-if="visible.length === 0" class="empty">{{ t.nothingInFilter }}</div>

        <div v-for="pkg in visible" :key="pkg.name" class="row">
          <input
            :id="`p-${pkg.name}`"
            type="checkbox"
            :checked="selection.includes(pkg.name)"
            :disabled="!isSelectable(pkg, scan)"
            @change="emit('toggle', pkg.name, ($event.target as HTMLInputElement).checked)"
          />
          <div class="pkg">
            <div class="inline">
              <label class="pkg-name" :for="`p-${pkg.name}`">{{ pkg.name }}</label>
              <span class="tag">{{ kindTag(lang, pkg) }}</span>
              <span v-if="isKept(pkg, scan)" class="tag warn-tag">{{ t.decisionKeep(pkg.installed) }}</span>
            </div>
            <p class="summary">{{ rowSummary(lang, pkg, scan) }}</p>
            <template v-if="pkg.reference">
              <span v-if="pkg.reference.error" class="ref">{{ t.refError(pkg.reference.source, pkg.reference.error) }}</span>
              <span v-else-if="pkg.reference.agrees" class="ref">{{ t.refAgrees(pkg.reference.source, pkg.reference.version) }}</span>
              <span v-else class="warn">
                <span class="codicon codicon-warning" aria-hidden="true"></span>
                <span>{{ t.refMismatch(pkg.reference.source, referenceCounts(lang, pkg), pkg.reference.version) }}</span>
              </span>
              <span v-if="pkg.reference.maliciousVersions.length > 0" class="warn">
                <span class="codicon codicon-shield" aria-hidden="true"></span>
                <span>{{ t.refMalicious(pkg.reference.maliciousVersions.join(', ')) }}</span>
              </span>
            </template>
          </div>
          <div class="ver">
            <div class="ver-line">
              <span class="ver-from">{{ pkg.installed }}</span>
              <span class="codicon codicon-arrow-right" aria-label="→"></span>
              <span class="ver-to">{{ targetVersion(pkg, scan) ?? pkg.resolution?.waitingFor?.version ?? '—' }}</span>
            </div>
            <span class="ver-note">{{ versionNote(lang, pkg) }}</span>
          </div>
          <div class="risk">
            <span class="badge" :class="bumpClass(pkg)">{{ bumpLabel(pkg) }}</span>
            <div class="sevs">
              <span v-for="x in sevs(pkg)" :key="x.s" class="sev" :class="`s-${x.s}`">{{ x.text }}</span>
            </div>
            <span v-if="pkg.auditFix.kind === 'audit-fix'" class="fix-ok">{{ t.auditFixOk }} <span class="codicon codicon-check" aria-label="✓"></span></span>
            <span v-else-if="pkg.auditFix.kind === 'force'" class="fix-force">{{ t.auditFixForce }}</span>
            <span v-else class="fix-ok">{{ t.auditFixUnknown }}</span>
          </div>
          <button type="button" class="linkbtn see-risk" @click="emit('openDetail', pkg.name)">{{ t.seeRisk }}</button>
        </div>
      </section>
    </template>
  </main>

  <div v-if="scan && packages.length > 0" class="footer">
    <div class="footer-in">
      <div class="stack">
        <span class="footer-count">{{ t.selected(scoped.length, selectable.length) }}</span>
        <span v-if="majorSelected" class="warn"><span class="codicon codicon-warning" aria-hidden="true"></span>{{ t.majorSelected }}</span>
      </div>
      <button type="button" class="btn primary" :disabled="scoped.length === 0" @click="emit('review')">
        {{ t.reviewApply }}<span class="codicon codicon-arrow-right" aria-hidden="true"></span>
      </button>
    </div>
  </div>
</template>
