<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { PackageReport } from '../../../src/core/scan';
import type { ImpactPayload, Lang, ScanPayload } from '../../../src/webview/protocol';
import { formatDate, STRINGS } from '../i18n';
import { snykUrl } from '../../../src/core/reference/snykUrl';
import { candidateVersion, kindTag, riskLevel, vulnerabilityCount } from '../model';

const props = defineProps<{
  lang: Lang;
  scan: ScanPayload;
  pkg: PackageReport;
  impact?: ImpactPayload;
  saving: boolean;
  saveError?: string;
}>();

const emit = defineEmits<{
  back: [];
  save: [choice: 'min' | 'latest' | 'keep', reason?: string];
  openFile: [path: string, line: number];
  openExternal: [url: string];
}>();

const t = computed(() => STRINGS[props.lang]);
const r = computed(() => props.pkg.resolution);
const candidate = computed(() => candidateVersion(props.pkg));
const target = computed(() => (props.scan.choices[props.pkg.name] === 'latest' && r.value?.latest ? r.value.latest.version : candidate.value));
const bump = computed(() => r.value?.recommended?.bump ?? r.value?.waitingFor?.bump);
const level = computed(() => riskLevel(props.pkg));
const ref2 = computed(() => props.pkg.reference);
const usages = computed(() => props.impact?.usages);
const changelog = computed(() => props.impact?.changelog);
const quarantineDays = computed(() => props.scan.quarantineDays);

/** La última se ofrece si es segura y distinta de la mínima. */
const latestOption = computed(() => {
  const latest = r.value?.latest;
  if (!latest || !r.value?.recommended || latest.version === r.value.recommended.version) return undefined;
  return latest.reason === 'not-needed' || latest.reason === 'major-avoided' ? latest.version : undefined;
});

const initialChoice = (): 'min' | 'latest' | 'keep' => {
  if (props.scan.keep[props.pkg.name] || !candidate.value) return 'keep';
  return props.scan.choices[props.pkg.name] === 'latest' && latestOption.value ? 'latest' : 'min';
};
const choice = ref(initialChoice());
const reason = ref(props.scan.keep[props.pkg.name]?.reason ?? '');
watch(
  () => props.pkg.name,
  () => {
    choice.value = initialChoice();
    reason.value = props.scan.keep[props.pkg.name]?.reason ?? '';
  },
);

const verdict = computed(() => {
  const parts: string[] = [];
  const v = candidate.value;
  const installedMajor = props.pkg.installed.split('.')[0]!;
  if (!r.value?.recommended && r.value?.status === 'quarantine-only') parts.push(t.value.verdictWait);
  else if (!v) parts.push(t.value.noSafe);
  else if (bump.value === 'major') {
    parts.push(r.value?.safeWithoutMajor ? t.value.verdictMajor : t.value.verdictMajorForced(installedMajor, v.split('.')[0]!));
  } else if (bump.value === 'minor') parts.push(t.value.verdictMinor);
  else if (bump.value === 'patch') parts.push(t.value.verdictPatch(props.pkg.installed.split('.').slice(0, 2).join('.')));
  if (ref2.value && !ref2.value.agrees && !ref2.value.error) parts.push(t.value.verdictMismatch(ref2.value.source));
  const c = props.pkg.checks;
  if (c?.newInstallScripts.length) parts.push(t.value.newScripts(c.newInstallScripts.join(', ')));
  if (c?.engines.satisfiesProjectNode === false && c.engines.to) parts.push(t.value.nodeNotSatisfied(c.engines.to));
  if (usages.value?.status === 'done') parts.push(t.value.verdictUsages(usages.value.files));
  return parts.join(' ');
});

const tableRows = computed(() => props.pkg.versionTable ?? []);
function status(row: NonNullable<PackageReport['versionTable']>[number]): string {
  const out: string[] = [];
  if (row.roles.includes('latest')) out.push(t.value.roleLatest);
  if (row.roles.includes('recommended')) out.push(t.value.roleRecommended);
  if (row.roles.includes('waiting')) out.push(t.value.roleWaiting);
  if (row.roles.includes('installed')) out.push(t.value.roleInstalled);
  if (row.malicious) out.push(t.value.roleMalicious);
  else if (row.deprecated) out.push(t.value.roleDeprecated);
  else if (row.inQuarantine && !row.roles.includes('waiting')) out.push(t.value.roleQuarantine);
  return out.join(' · ') || '—';
}
const showLow = computed(() => tableRows.value.some((row) => row.counts.low > 0));

const checks = computed(() => {
  const list: Array<{ ok: boolean; title: string; sub: string }> = [];
  const ref = ref2.value;
  if (!ref) list.push({ ok: false, title: t.value.checkSourcesNone, sub: '' });
  else if (ref.error) list.push({ ok: false, title: t.value.checkSourcesErr(ref.source), sub: ref.error });
  else if (ref.agrees) list.push({ ok: true, title: t.value.checkSourcesOk(ref.source), sub: t.value.checkSourcesOkSub(ref.source) });
  else list.push({ ok: false, title: t.value.checkSourcesBad(ref.source), sub: t.value.checkSourcesBadSub(ref.issues.map((i) => i.id).join(', ')) });

  const scripts = props.pkg.checks?.newInstallScripts ?? [];
  list.push(
    scripts.length === 0
      ? { ok: true, title: t.value.checkScriptsOk, sub: t.value.checkScriptsOkSub }
      : { ok: false, title: t.value.checkScriptsBad, sub: scripts.join(', ') },
  );

  const rec = r.value?.recommended;
  if (rec && !rec.inQuarantine) list.push({ ok: true, title: t.value.checkQuarantineOk, sub: t.value.checkQuarantineOkSub(quarantineDays.value) });
  else if (rec) list.push({ ok: false, title: t.value.checkQuarantineBad, sub: t.value.checkQuarantineBypassSub });
  else if (r.value?.waitingFor) list.push({ ok: false, title: t.value.checkQuarantineBad, sub: t.value.checkQuarantineBadSub(formatDate(props.lang, r.value.waitingFor.waitUntil)) });

  const malicious = ref?.issues.some((i) => i.malicious);
  const excluded = ref?.maliciousVersions.length ?? 0;
  if (malicious) list.push({ ok: false, title: t.value.checkMalwareBad, sub: ref!.issues.filter((i) => i.malicious).map((i) => i.id).join(', ') });
  else list.push({ ok: true, title: t.value.checkMalwareOk, sub: excluded > 0 ? t.value.checkMalwareExcluded(excluded) : t.value.checkMalwareOkSub(ref?.source ?? 'osv') });
  return list;
});

function save(): void {
  emit('save', choice.value, choice.value === 'keep' ? reason.value : undefined);
}
</script>

<template>
  <main class="detail">
    <button type="button" class="linkbtn back" @click="emit('back')">
      <span class="codicon codicon-arrow-left" aria-hidden="true"></span>{{ t.back }}
    </button>

    <header class="stack-16">
      <div class="inline">
        <h1 class="mono">{{ pkg.name }}</h1>
        <span class="ver-line ver-from">
          {{ pkg.installed }} <span class="codicon codicon-arrow-right" aria-label="→"></span>
          <span class="ver-to">{{ target ?? '—' }}</span>
        </span>
      </div>
      <div class="inline">
        <span v-if="bump" class="badge" :class="`b-${bump}`">{{ t.bump[bump] }}</span>
        <span class="tag lg">{{ kindTag(lang, pkg) }}</span>
        <span v-if="r?.recommended" class="tag lg ok">{{ t.auditFixes(r.recommended.version, vulnerabilityCount(pkg)) }}</span>
        <span v-if="ref2 && !ref2.error && ref2.agrees" class="tag lg">{{ t.refAgrees(ref2.source, ref2.version) }}</span>
        <span v-else-if="ref2 && !ref2.error" class="tag lg warn-tag">{{ t.checkSourcesBad(ref2.source) }}</span>
      </div>
      <button type="button" class="linkbtn" @click="emit('openExternal', snykUrl(pkg.name, target))">
        {{ t.seeOnSnyk(target) }}<span class="codicon codicon-link-external" aria-hidden="true"></span>
      </button>
    </header>

    <section class="notice" :class="level === 'low' ? 'blue' : 'orange'" :aria-label="t.verdictLabel">
      <h2>{{ t.risk[level] }}</h2>
      <p>{{ verdict }}</p>
    </section>

    <div class="cols">
      <section class="card" :aria-label="t.versionsTitle">
        <div class="card-head"><h2>{{ t.versionsTitle }}</h2></div>
        <div class="scroll-x">
          <table>
            <thead>
              <tr>
                <th scope="col">{{ t.colVersion }}</th>
                <th scope="col">{{ t.colCrit }}</th>
                <th scope="col">{{ t.colHigh }}</th>
                <th scope="col">{{ t.colMed }}</th>
                <th v-if="showLow" scope="col">{{ t.colLow }}</th>
                <th scope="col">{{ t.colStatus }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in tableRows" :key="row.version" :class="{ rec: row.version === target }">
                <td>{{ row.version }}</td>
                <td :class="{ critical: row.counts.critical > 0 }">{{ row.counts.critical }}</td>
                <td :class="{ high: row.counts.high > 0 }">{{ row.counts.high }}</td>
                <td :class="{ moderate: row.counts.moderate > 0 }">{{ row.counts.moderate }}</td>
                <td v-if="showLow" :class="{ low: row.counts.low > 0 }">{{ row.counts.low }}</td>
                <td>{{ status(row) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <div class="stack-16">
        <section v-if="candidate" class="card" :aria-label="t.whatChanges(candidate)">
          <div class="card-body">
            <div class="spread">
              <h2>{{ t.whatChanges(candidate) }}</h2>
              <span v-if="changelog?.status === 'done' && changelog.summary.kind === 'ai'" class="ref">{{ t.summaryAi }}</span>
              <span v-else-if="changelog?.status === 'done' && changelog.summary.kind === 'breaking'" class="ref">{{ t.summaryBreaking }}</span>
            </div>
            <p v-if="!changelog || changelog.status === 'loading'" class="sub" aria-live="polite">
              <span class="codicon codicon-loading spin" aria-hidden="true"></span> {{ t.changelogLoading }}
            </p>
            <p v-else-if="changelog.status === 'error'" class="sub">{{ t.changelogError(changelog.message) }}</p>
            <template v-else>
              <ul v-if="changelog.summary.kind === 'ai'" class="bullets">
                <li v-for="line in changelog.summary.lines" :key="line">{{ line }}</li>
              </ul>
              <ul v-else-if="changelog.summary.kind === 'breaking'" class="bullets">
                <li v-for="line in changelog.summary.lines" :key="line.version + line.text">
                  {{ line.text }} <span class="v">{{ line.version }}</span>
                </li>
              </ul>
              <p v-else-if="changelog.unavailable === 'no-repository'" class="sub">{{ t.changelogNoRepo }}</p>
              <p v-else-if="changelog.unavailable === 'not-github'" class="sub">{{ t.changelogNotGithub }}</p>
              <p v-else-if="changelog.error" class="sub">{{ t.changelogError(changelog.error) }}</p>
              <p v-else-if="changelog.empty" class="sub">{{ t.changelogEmpty }}</p>
              <p v-else class="sub">{{ t.summaryNone }}</p>
              <span v-if="changelog.releases.length > 0" class="ref">{{ t.releasesCount(changelog.releases.length) }}</span>
              <button v-if="changelog.url" type="button" class="linkbtn" @click="emit('openExternal', changelog.url)">
                {{ t.fullChangelog }}<span class="codicon codicon-link-external" aria-hidden="true"></span>
              </button>
            </template>
          </div>
        </section>

        <section class="card" :aria-label="t.whereUsed">
          <div class="card-body">
            <h2>{{ t.whereUsed }}</h2>
            <p v-if="!usages || usages.status === 'loading'" class="sub" aria-live="polite">
              <span class="codicon codicon-loading spin" aria-hidden="true"></span> {{ t.usagesLoading }}
            </p>
            <p v-else-if="usages.status === 'error'" class="sub">{{ t.usagesError(usages.message) }}</p>
            <p v-else-if="usages.usages.length === 0" class="sub">{{ t.usagesNone }}</p>
            <ul v-else class="list">
              <li v-for="u in usages.usages" :key="`${u.path}:${u.line}:${u.symbol}`">
                <button type="button" class="linkbtn" :aria-label="t.openAt(u.path, u.line)" @click="emit('openFile', u.path, u.line)">
                  {{ u.path }}:{{ u.line }}
                </button>
                <span class="symbol">{{ u.symbol }}</span>
              </li>
            </ul>
            <span v-if="usages?.status === 'done' && usages.truncated" class="ref">{{ t.usagesTruncated }}</span>
          </div>
        </section>
      </div>
    </div>

    <section v-if="candidate" class="card" :aria-label="t.checksTitle(candidate)">
      <div class="card-body gap-12">
        <div class="spread">
          <h2>{{ t.checksTitle(candidate) }}</h2>
          <span class="ref">{{ t.checksSub }}</span>
        </div>
        <div class="checks">
          <div v-for="c in checks" :key="c.title" class="check">
            <span class="codicon" :class="c.ok ? 'codicon-pass ok' : 'codicon-warning bad'" :aria-label="c.ok ? '✓' : '!'"></span>
            <div>
              <b>{{ c.title }}</b><span class="d">{{ c.sub }}</span>
            </div>
          </div>
        </div>
        <p class="ref">{{ t.signaturesNote }}</p>
      </div>
    </section>

    <section class="card">
      <div class="card-body gap-12">
        <fieldset class="options">
          <legend>{{ t.decisionTitle }}</legend>
          <label v-if="r?.recommended" class="opt">
            <input v-model="choice" type="radio" name="decision" value="min" />
            <div><b>{{ t.decisionMin(r.recommended.version) }}</b><span>{{ t.decisionMinSub }}</span></div>
          </label>
          <label v-else-if="r?.waitingFor" class="opt">
            <input v-model="choice" type="radio" name="decision" value="min" disabled />
            <div>
              <b>{{ t.decisionForce(r.waitingFor.version) }}</b>
              <span>{{ t.decisionForceSub(formatDate(lang, r.waitingFor.waitUntil)) }}</span>
            </div>
          </label>
          <label v-if="latestOption && r?.recommended" class="opt">
            <input v-model="choice" type="radio" name="decision" value="latest" />
            <div><b>{{ t.decisionLatest(latestOption) }}</b><span>{{ t.decisionLatestSub(r.recommended.version) }}</span></div>
          </label>
          <label class="opt">
            <input v-model="choice" type="radio" name="decision" value="keep" />
            <div><b>{{ t.decisionKeep(pkg.installed) }}</b><span>{{ t.decisionKeepSub }}</span></div>
          </label>
          <div v-if="choice === 'keep'" class="reason">
            <label for="keep-reason">{{ t.reasonLabel }}</label>
            <textarea id="keep-reason" v-model="reason" maxlength="500" :placeholder="t.reasonPlaceholder"></textarea>
          </div>
        </fieldset>
        <div class="buttons">
          <span v-if="saveError" class="error-text" role="alert">{{ t.saveError(saveError) }}</span>
          <button type="button" class="btn secondary" @click="emit('back')">{{ t.cancel }}</button>
          <button type="button" class="btn primary" :disabled="saving" @click="save">{{ saving ? t.saving : t.saveDecision }}</button>
        </div>
      </div>
    </section>
  </main>
</template>
