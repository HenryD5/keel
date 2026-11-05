<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { PackageReport } from '../../../src/core/scan';
import type { ImpactPayload, Lang, ScanPayload } from '../../../src/webview/protocol';
import { formatDate, severityName, severityText, STRINGS } from '../i18n';
import { SEVERITY_ORDER, type Severity } from '../../../src/core/audit/types';
import { osvPackageUrl, snykUrl } from '../../../src/core/reference/snykUrl';
import { candidateVersion, kindTag, majorOf as majorOfVersion, riskLevel, vulnerabilityCount } from '../model';

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
  save: [choice: 'min' | 'latest' | 'line' | 'version' | 'keep', reason?: string, version?: string];
  openFile: [path: string, line: number];
  openExternal: [url: string];
  remove: [name: string];
}>();

const t = computed(() => STRINGS[props.lang]);
const advisoriesSorted = computed(() => [...props.pkg.advisories].sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity)));
const severityLabel = (s: Severity) => severityName(props.lang, s);
const ghsaOf = (url: string) => url.match(/GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}/i)?.[0];
const r = computed(() => props.pkg.resolution);
const candidate = computed(() => candidateVersion(props.pkg));
const target = computed(() => {
  const chosen = props.scan.choices[props.pkg.name];
  if (chosen === 'latest' && r.value?.latest) return r.value.latest.version;
  if (chosen === 'line' && r.value?.bestInLine) return r.value.bestInLine.version;
  if (typeof chosen === 'object') return chosen.version;
  return candidate.value;
});
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

type DecisionChoice = 'min' | 'latest' | 'line' | 'version' | 'keep';
const initialChoice = (): DecisionChoice => {
  const chosen = props.scan.choices[props.pkg.name];
  if (props.scan.keep[props.pkg.name]) return 'keep';
  if (typeof chosen === 'object') return 'version';
  if (chosen === 'line' && r.value?.bestInLine) return 'line';
  if (!candidate.value) return 'keep';
  return chosen === 'latest' && latestOption.value ? 'latest' : 'min';
};
/** Opción sin salto major: corrige una parte y deja el resto pendiente. */
const lineOption = computed(() => r.value?.bestInLine);
const lineRemaining = computed(() => props.pkg.advisories.filter((a) => lineOption.value?.remainingIds.includes(a.id)));
const choice = ref<DecisionChoice>(initialChoice());
const reason = ref(props.scan.keep[props.pkg.name]?.reason ?? '');
const initialCustom = () => {
  const chosen = props.scan.choices[props.pkg.name];
  return typeof chosen === 'object' ? chosen.version : '';
};
/** Versión que el dev escribe o elige en la tabla. */
const customVersion = ref(initialCustom());
watch(
  () => props.pkg.name,
  () => {
    choice.value = initialChoice();
    reason.value = props.scan.keep[props.pkg.name]?.reason ?? '';
    customVersion.value = initialCustom();
    showAll.value = false;
  },
);

const options = computed(() => props.pkg.versionOptions ?? []);
/** Estado de la versión escrita: si existe, si se puede instalar y qué vulnerabilidades le quedan. */
const custom = computed(() => {
  const v = customVersion.value.trim().replace(/^v/, '');
  if (!v) return { state: 'empty' as const };
  const row = options.value.find((o) => o.version === v);
  if (!row) {
    const valid = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(v);
    if (!valid) return { state: 'invalid' as const, version: v };
    return { state: compareVersions(v, props.pkg.installed) <= 0 ? ('older' as const) : ('missing' as const), version: v };
  }
  if (row.malicious) return { state: 'malicious' as const, version: v, row };
  const total = row.counts.critical + row.counts.high + row.counts.moderate + row.counts.low + row.counts.info;
  return { state: 'ok' as const, version: v, row, total };
});
const canSave = computed(() => choice.value !== 'version' || custom.value.state === 'ok');

function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.-]/).slice(0, 3).map(Number);
  const pb = b.split(/[.-]/).slice(0, 3).map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
}

function countsText(c: Record<Severity, number>): string {
  return (['critical', 'high', 'moderate', 'low'] as Severity[]).filter((s) => c[s] > 0).map((s) => severityText(props.lang, s, c[s])).join(', ');
}

/** Elegir una versión desde la tabla la lleva al selector de arriba. */
function pickVersion(version: string): void {
  if (version === props.pkg.installed) return;
  customVersion.value = version;
  choice.value = 'version';
  document.getElementById('decision')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

const showAll = ref(false);
function bumpOf(v: string): 'patch' | 'minor' | 'major' {
  const [a, b] = props.pkg.installed.split('.').map(Number);
  const [c, d] = v.split('.').map(Number);
  if (a !== c || (a === 0 && b !== d)) return 'major';
  return b !== d ? 'minor' : 'patch';
}

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

const tableRows = computed(() => {
  if (!showAll.value) return props.pkg.versionTable ?? [];
  const installedRow = props.pkg.versionTable?.find((row) => row.roles.includes('installed'));
  return installedRow ? [...options.value, installedRow] : options.value;
});
/** Con salto major obligatorio: la última versión de la línea instalada y lo que la bloquea. */
const blocker = computed(() => (bump.value === 'major' ? r.value?.lineBlocker : undefined));
const blockerAdvisories = computed(() => props.pkg.advisories.filter((a) => blocker.value?.advisoryIds.includes(a.id)));
function status(row: NonNullable<PackageReport['versionTable']>[number]): string {
  const out: string[] = [];
  if (row.roles.includes('latest')) out.push(t.value.roleLatest);
  if (row.roles.includes('recommended')) out.push(t.value.roleRecommended);
  if (row.roles.includes('waiting')) out.push(t.value.roleWaiting);
  if (row.roles.includes('installed')) out.push(t.value.roleInstalled);
  if (row.roles.includes('line')) out.push(t.value.roleLineLatest(majorOfVersion(props.pkg.installed)));
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
  if (!canSave.value) return;
  emit('save', choice.value, choice.value === 'keep' ? reason.value : undefined, choice.value === 'version' && custom.value.state === 'ok' ? custom.value.version : undefined);
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
      <div class="inline">
        <button type="button" class="linkbtn" @click="emit('openExternal', snykUrl(pkg.name))">
          {{ t.seeOnSnyk(pkg.name) }}<span class="codicon codicon-link-external" aria-hidden="true"></span>
        </button>
        <button type="button" class="linkbtn" @click="emit('openExternal', osvPackageUrl(pkg.name))">
          {{ t.seeOnOsv(pkg.name) }}<span class="codicon codicon-link-external" aria-hidden="true"></span>
        </button>
        <span class="ref">{{ t.linksHint }}</span>
      </div>
    </header>

    <section class="notice" :class="level === 'low' ? 'blue' : 'orange'" :aria-label="t.verdictLabel">
      <h2>{{ t.risk[level] }}</h2>
      <p>{{ verdict }}</p>
    </section>

    <section id="decision" class="card decision-card">
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
          <label v-if="lineOption" class="opt">
            <input v-model="choice" type="radio" name="decision" value="line" />
            <div>
              <b>{{ t.decisionLine(lineOption.version, majorOfVersion(pkg.installed)) }}</b>
              <span>{{ t.decisionLineSub(lineOption.fixedIds.length, lineOption.remainingIds.length) }}</span>
              <span v-if="lineRemaining.length" class="line-left">
                <template v-for="a in lineRemaining" :key="a.id"><span class="cve">{{ a.cves?.[0] ?? ghsaOf(a.url) ?? a.id }}</span> </template>
              </span>
            </div>
          </label>
          <p v-else-if="blocker?.reason === 'vulnerable'" class="ref no-line">{{ t.noLineOption(majorOfVersion(pkg.installed), blocker.version, pkg.installed) }}</p>
          <label class="opt">
            <input v-model="choice" type="radio" name="decision" value="version" />
            <div>
              <b>{{ t.decisionVersion }}</b>
              <span>{{ t.decisionVersionSub }}</span>
            </div>
          </label>
          <div v-if="choice === 'version'" class="reason">
            <label for="custom-version">{{ t.versionLabel(pkg.name) }}</label>
            <input id="custom-version" v-model="customVersion" class="text-input mono" list="version-options" autocomplete="off" spellcheck="false" :placeholder="t.versionPlaceholder(lineOption?.version ?? blocker?.version ?? options[0]?.version ?? '')" />
            <datalist id="version-options">
              <option v-for="o in options" :key="o.version" :value="o.version">{{ countsText(o.counts) || t.versionClean }}</option>
            </datalist>
            <p v-if="custom.state === 'invalid'" class="error-text">{{ t.versionInvalid }}</p>
            <p v-else-if="custom.state === 'missing'" class="error-text">{{ t.versionMissing(custom.version, pkg.name) }}</p>
            <p v-else-if="custom.state === 'older'" class="error-text">{{ t.versionOlder(pkg.installed) }}</p>
            <p v-else-if="custom.state === 'malicious'" class="error-text">{{ t.versionMalicious(custom.version) }}</p>
            <div v-else-if="custom.state === 'ok'" class="version-check">
              <div class="inline">
                <span class="codicon" :class="custom.total === 0 ? 'codicon-pass ok' : 'codicon-warning bad'" aria-hidden="true"></span>
                <b class="mono">{{ pkg.name }}@{{ custom.version }}</b>
                <span class="badge" :class="`b-${bumpOf(custom.version)}`">{{ t.reviewBump[bumpOf(custom.version)] }}</span>
                <span v-if="custom.row.deprecated" class="tag warn-tag">{{ t.roleDeprecated }}</span>
                <span v-if="custom.row.inQuarantine" class="tag warn-tag">{{ t.roleQuarantine }}</span>
              </div>
              <p class="summary">{{ custom.total === 0 ? t.versionCleanLong : t.versionLeft(countsText(custom.row.counts)) }}</p>
              <p v-if="custom.total > 0" class="ref">{{ t.versionOtherSources }}</p>
            </div>
          </div>
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
          <button type="button" class="btn primary" :disabled="saving || !canSave" @click="save">{{ saving ? t.saving : t.saveDecision }}</button>
        </div>
      </div>
    </section>

    <section v-if="blocker" class="card" :aria-label="t.whyNotTitle(blocker.version)">
      <div class="card-body">
        <h2>{{ t.whyNotTitle(blocker.version) }}</h2>
        <template v-if="blocker.reason === 'vulnerable'">
          <p class="summary">{{ t.whyNotVulnerable(blocker.version, blockerAdvisories.length) }}</p>
          <ul class="facts">
            <li v-for="a in blockerAdvisories" :key="a.id">
              <span class="sev" :class="`s-${a.severity}`">{{ severityLabel(a.severity) }}</span>
              <button v-for="cve in a.cves ?? []" :key="cve" type="button" class="cve link-cve" @click="emit('openExternal', `https://osv.dev/vulnerability/${cve}`)">{{ cve }}</button>
              <button v-if="ghsaOf(a.url)" type="button" class="cve link-cve faint" @click="emit('openExternal', a.url)">{{ ghsaOf(a.url) }}</button>
              <span class="ctitle">{{ a.title }} · <span class="mono">{{ t.affects(a.range) }}</span></span>
            </li>
          </ul>
          <p class="ref">{{ t.whyNotSnyk }}</p>
        </template>
        <p v-else-if="blocker.reason === 'deprecated'" class="summary">{{ t.whyNotDeprecated(blocker.version) }}</p>
        <p v-else class="summary">{{ t.whyNotMalicious(blocker.version) }}</p>
      </div>
    </section>


    <div class="cols">
      <section class="card" :aria-label="t.versionsTitle">
        <div class="card-head">
          <div class="stack">
            <h2>{{ t.versionsTitle }}</h2>
            <p class="sub">{{ t.tablePickHint }}</p>
          </div>
          <button v-if="options.length > (pkg.versionTable?.length ?? 0)" type="button" class="linkbtn" @click="showAll = !showAll">
            {{ showAll ? t.showFewerVersions : t.showAllVersions(options.length) }}
          </button>
        </div>
        <div class="scroll-x scroll-y">
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
              <tr
                v-for="row in tableRows"
                :key="row.version"
                :class="{ rec: row.version === target, pickable: row.version !== pkg.installed && !row.malicious }"
                :tabindex="row.version !== pkg.installed && !row.malicious ? 0 : -1"
                @click="!row.malicious && pickVersion(row.version)"
                @keydown.enter="!row.malicious && pickVersion(row.version)"
              >
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
              <ul v-if="changelog.summary.kind === 'ai'" class="bullets scroll-y">
                <li v-for="line in changelog.summary.lines" :key="line">{{ line }}</li>
              </ul>
              <ul v-else-if="changelog.summary.kind === 'breaking'" class="bullets scroll-y">
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
            <div v-else-if="usages.usages.length === 0">
              <p class="sub">{{ t.usagesNone }}</p>
              <button v-if="usages.removal?.allowed" type="button" class="btn" @click="emit('remove', pkg.name)">{{ t.removeDependency }}</button>
              <p v-else-if="usages.removal?.reason" class="sub">{{ t.removeBlocked(usages.removal.reason) }}</p>
            </div>
            <ul v-else class="list scroll-y">
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

    <section class="card" :aria-label="t.advisoriesTitle(pkg.installed, pkg.advisories.length)">
      <div class="card-head">
        <div class="stack">
          <h2>{{ t.advisoriesTitle(pkg.installed, pkg.advisories.length) }}</h2>
          <p class="sub">{{ t.advisoriesHint }}</p>
        </div>
      </div>
      <ul class="advisories scroll-y">
        <li v-for="a in advisoriesSorted" :key="a.id">
          <div class="inline">
            <span class="sev" :class="`s-${a.severity}`">{{ severityLabel(a.severity) }}</span>
            <button v-for="cve in a.cves ?? []" :key="cve" type="button" class="cve link-cve" @click="emit('openExternal', `https://osv.dev/vulnerability/${cve}`)">{{ cve }}</button>
            <span v-if="!a.cves?.length" class="ref">{{ t.noCve }}</span>
            <button v-if="ghsaOf(a.url)" type="button" class="cve link-cve faint" @click="emit('openExternal', a.url)">{{ ghsaOf(a.url) }}</button>
            <span v-for="cwe in a.cwe" :key="cwe" class="tag">{{ cwe }}</span>
          </div>
          <span class="atitle">{{ a.title }}</span>
          <span class="ref mono">{{ t.affects(a.range) }}</span>
        </li>
      </ul>
    </section>
  </main>
</template>
