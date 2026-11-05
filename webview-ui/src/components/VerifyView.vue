<script setup lang="ts">
import { computed, ref } from 'vue';
import { categoryOf, type Category } from '../../../src/core/verify/categories';
import { STATUS_TEXT } from '../../../src/core/verify/format';
import { parseVulnerabilityList, type ListItem } from '../../../src/core/verify/parseList';
import type { Outcome, VerifyItem, VerifyResult } from '../../../src/core/verify/verify';
import type { Lang, ScanPayload } from '../../../src/webview/protocol';
import { VERIFY_STRINGS } from '../verifyI18n';
import { severityName } from '../i18n';
import type { Severity } from '../../../src/core/audit/types';

const props = defineProps<{
  lang: Lang;
  text: string;
  scan?: ScanPayload;
  verifying: boolean;
  result?: VerifyResult;
  /** Texto con el que se obtuvo `result`. */
  resultText?: string;
  error?: string;
}>();

const emit = defineEmits<{
  back: [];
  update: [text: string];
  verify: [text: string];
  loadFile: [];
  copyReport: [];
  openDetail: [name: string];
  openExternal: [url: string];
  fixPending: [names: string[]];
  rescan: [];
}>();

const t = computed(() => VERIFY_STRINGS[props.lang]);
const copied = ref(false);

type Kind = 'exact' | 'approx' | 'none';
interface PreviewRow { item: ListItem; kind: Kind; category?: Category }

const parsed = computed<{ rows: PreviewRow[]; tooMany: boolean }>(() => {
  try {
    const rows = parseVulnerabilityList(props.text).map((item): PreviewRow => {
      const category = item.title ? categoryOf(item.title) : undefined;
      return { item, category, kind: item.ids.length > 0 ? 'exact' : category ? 'approx' : 'none' };
    });
    return { rows, tooMany: false };
  } catch {
    return { rows: [], tooMany: true };
  }
});
const rows = computed(() => parsed.value.rows);
const lineCount = computed(() => rows.value.reduce((n, r) => n + r.item.lines.length, 0));
const kindCount = (kind: Kind) => rows.value.filter((r) => r.kind === kind).reduce((n, r) => n + r.item.lines.length, 0);
const stale = computed(() => Boolean(props.result) && props.resultText !== props.text);

const groups = computed(() => {
  const order: Outcome[] = ['pending', 'unverified', 'resolved'];
  return order
    .map((outcome) => ({ outcome, items: props.result?.items.filter((i) => i.outcome === outcome) ?? [] }))
    .filter((g) => g.items.length > 0);
});

/** Paquetes que quedan por corregir según la verificación. */
const pendingPackages = computed(() => {
  const names = new Set<string>();
  for (const item of props.result?.items ?? []) {
    if (item.outcome !== 'pending') continue;
    for (const check of item.checks) {
      for (const v of check.vulnerable) names.add(v.package);
      if (check.inAudit) for (const p of check.packages) names.add(p);
    }
    for (const c of item.candidates) names.add(c.package);
  }
  return [...names].sort();
});
const fixable = computed(() => pendingPackages.value.filter((n) => props.scan?.result.packages.some((p) => p.name === n)));
const inScan = (name: string) => Boolean(props.scan?.result.packages.some((p) => p.name === name));

function itemName(item: ListItem): string {
  return [item.ids.join(', '), item.title].filter(Boolean).join(' — ');
}

function summaryClass(result: VerifyResult): string {
  return result.allResolved ? 'green' : result.totals.pending > 0 ? 'orange' : 'blue';
}

function copy(): void {
  emit('copyReport');
  copied.value = true;
  setTimeout(() => (copied.value = false), 1500);
}

function advisoryUrl(id: string): string | undefined {
  return id.startsWith('GHSA-') ? `https://github.com/advisories/${id}` : id.startsWith('CVE-') ? `https://osv.dev/vulnerability/${id}` : undefined;
}

function statusIcon(item: VerifyItem): string {
  return item.outcome === 'resolved' ? 'codicon-pass ok' : item.outcome === 'pending' ? 'codicon-error error-icon' : 'codicon-warning bad';
}
</script>

<template>
  <main class="detail verify">
    <button type="button" class="linkbtn back" @click="emit('back')">
      <span class="codicon codicon-arrow-left" aria-hidden="true"></span>{{ t.back }}
    </button>

    <header class="stack">
      <h1>{{ t.title }}</h1>
      <p class="sub">{{ t.intro }}</p>
      <p v-if="scan" class="sub">{{ scan.projectFolder }}</p>
    </header>

    <section class="card">
      <div class="card-head">
        <div class="stack">
          <h2>{{ t.step1 }}</h2>
          <p class="sub">{{ t.step1Hint }}</p>
        </div>
        <div class="inline">
          <button type="button" class="btn" @click="emit('loadFile')"><span class="codicon codicon-folder-opened" aria-hidden="true"></span>{{ t.loadFile }}</button>
          <button v-if="text" type="button" class="btn" @click="emit('update', '')"><span class="codicon codicon-clear-all" aria-hidden="true"></span>{{ t.clear }}</button>
        </div>
      </div>
      <div class="card-body">
        <label class="visually-hidden" for="verify-list">{{ t.step1 }}</label>
        <textarea
          id="verify-list"
          class="verify-input"
          spellcheck="false"
          :placeholder="t.placeholder"
          :value="text"
          @input="emit('update', ($event.target as HTMLTextAreaElement).value)"
        ></textarea>
        <p v-if="parsed.tooMany" class="error-text">{{ t.tooMany }}</p>
        <p v-else-if="rows.length" class="ref">{{ t.lines(lineCount, rows.length) }}</p>
      </div>
    </section>

    <section v-if="rows.length" class="card" :aria-label="t.step2">
      <div class="card-head">
        <div class="stack">
          <h2>{{ t.step2 }}</h2>
          <p class="sub">{{ t.step2Hint }} {{ t.willCompare(kindCount('exact'), kindCount('approx'), kindCount('none')) }}</p>
        </div>
      </div>
      <div class="kinds">
        <div class="kind"><span class="badge b-patch">{{ t.kindExact }}</span><span>{{ t.kindExactSub }}</span></div>
        <div class="kind"><span class="badge b-minor">{{ t.kindApprox }}</span><span>{{ t.kindApproxSub }}</span></div>
        <div class="kind"><span class="badge b-none">{{ t.kindNone }}</span><span>{{ t.kindNoneSub }}</span></div>
      </div>
      <ul class="list vlist">
        <li v-for="row in rows" :key="row.item.lines[0]">
          <span class="vname">{{ itemName(row.item) }}<span v-if="row.item.lines.length > 1" class="times">×{{ row.item.lines.length }}</span></span>
          <span class="inline vhow">
            <template v-if="row.kind === 'exact'">
              <span v-for="id in row.item.ids" :key="id" class="cve">{{ id }}</span>
              <span class="badge b-patch">{{ t.kindExact }}</span>
            </template>
            <template v-else-if="row.kind === 'approx' && row.category">
              <span class="ref">{{ t.typeTo(row.category.label[lang]) }} → {{ row.category.cwes.join(', ') }}</span>
              <span class="badge b-minor">{{ t.kindApprox }}</span>
            </template>
            <span v-else class="badge b-none">{{ t.kindNone }}</span>
          </span>
        </li>
      </ul>
    </section>

    <div class="buttons start">
      <button type="button" class="btn primary" :disabled="!rows.length || verifying || parsed.tooMany" @click="emit('verify', text)">
        <span class="codicon" :class="verifying ? 'codicon-loading spin' : 'codicon-checklist'" aria-hidden="true"></span>
        {{ verifying ? t.verifying : t.verify(lineCount) }}
      </button>
    </div>

    <section v-if="error" class="notice red" role="alert"><p>{{ error }}</p></section>

    <template v-if="result">
      <section class="notice" :class="summaryClass(result)" aria-live="polite">
        <h2>{{ result.allResolved ? t.allResolved : result.totals.pending > 0 ? t.notAll : t.unverifiedOnly }}</h2>
        <p>{{ t.totals(result.totals.resolved, result.totals.pending, result.totals.unverified) }}</p>
        <p v-if="stale" class="bad">{{ t.stale }}</p>
        <div class="inline">
          <button v-if="fixable.length" type="button" class="btn primary" @click="emit('fixPending', fixable)">{{ t.fixPending(fixable.length) }}</button>
          <button v-else-if="pendingPackages.length && !scan" type="button" class="btn primary" @click="emit('rescan')">{{ t.scanToFix }}</button>
          <button type="button" class="btn" @click="copy"><span class="codicon" :class="copied ? 'codicon-check' : 'codicon-copy'" aria-hidden="true"></span>{{ copied ? t.copied : t.copyReport }}</button>
        </div>
      </section>

      <section v-for="group in groups" :key="group.outcome" class="card">
        <div class="card-head"><h2>{{ t.group[group.outcome] }} ({{ group.items.reduce((n, i) => n + i.lines.length, 0) }})</h2></div>
        <div v-for="item in group.items" :key="item.lines[0]" class="row vrow">
          <span class="codicon" :class="statusIcon(item)" aria-hidden="true"></span>
          <div class="pkg">
            <div class="inline">
              <span class="vname">{{ itemName(item) }}</span>
              <span v-if="item.lines.length > 1" class="times">×{{ item.lines.length }}</span>
            </div>
            <p class="summary">{{ STATUS_TEXT[item.status][lang] }}</p>

            <template v-for="check in item.checks" :key="check.id">
              <div v-if="check.aliases.length || check.packages.length" class="inline">
                <button v-for="id in [check.id, ...check.aliases]" :key="id" type="button" class="cve link-cve" @click="advisoryUrl(id) && emit('openExternal', advisoryUrl(id)!)">{{ id }}</button>
                <span v-for="p in check.packages" :key="p" class="tag mono">{{ p }}</span>
              </div>
              <ul v-if="check.vulnerable.length || check.safe.length" class="facts">
                <li v-for="v in check.vulnerable" :key="v.path">
                  <span class="codicon codicon-error error-icon" aria-hidden="true"></span>
                  <button v-if="inScan(v.package)" type="button" class="linkbtn mono" @click="emit('openDetail', v.package)">{{ v.package }}@{{ v.version }}</button>
                  <span v-else class="mono">{{ v.package }}@{{ v.version }}</span>
                  <span class="ref mono">{{ v.path }}</span>
                  <span v-if="v.fixedIn" class="fix-ok">→ {{ t.fixedIn(v.fixedIn) }}</span>
                </li>
                <li v-for="s in check.safe" :key="s.path">
                  <span class="codicon codicon-pass ok" aria-hidden="true"></span>
                  <span class="mono">{{ s.package }}@{{ s.version }}</span>
                  <span class="ref mono">{{ s.path }}</span>
                </li>
              </ul>
              <p v-if="check.inAudit && !check.vulnerable.length" class="warn">{{ t.inAudit }}</p>
              <p v-if="check.error" class="error-text">{{ check.error }}</p>
            </template>
            <p v-if="item.titleMatches === false" class="warn"><span class="codicon codicon-warning" aria-hidden="true"></span>{{ t.titleMismatch }}</p>

            <template v-if="item.candidates.length">
              <p class="ref">{{ t.candidates(item.candidates.length) }}</p>
              <ul class="facts">
                <li v-for="c in item.candidates" :key="c.package + c.id">
                  <span class="sev" :class="`s-${c.severity}`">{{ severityName(lang, c.severity as Severity) }}</span>
                  <button v-if="inScan(c.package)" type="button" class="linkbtn mono" @click="emit('openDetail', c.package)">{{ c.package }}</button>
                  <span v-else class="mono">{{ c.package }}</span>
                  <button v-for="cve in c.cves" :key="cve" type="button" class="cve link-cve" @click="emit('openExternal', advisoryUrl(cve)!)">{{ cve }}</button>
                  <span v-if="!c.cves.length" class="ref">{{ t.noCve }}</span>
                  <button type="button" class="cve link-cve faint" @click="advisoryUrl(c.id) && emit('openExternal', advisoryUrl(c.id)!)">{{ c.id }}</button>
                  <span class="ctitle">{{ c.title }}</span>
                </li>
              </ul>
            </template>
          </div>
        </div>
      </section>

      <p v-if="result.items.some((i) => i.ids.length === 0 && i.category)" class="ref">{{ t.approxNote }}</p>
    </template>
  </main>
</template>
