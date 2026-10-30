import * as vscode from 'vscode';
import { cleanMarkdown } from '../core/impact/breaking';
import type { VersionRelease } from '../core/impact/changelog';
import type { Logger } from '../infra/log';
import type { Lang } from '../webview/protocol';

/** Tope de texto de las notas que se envía al modelo. */
const MAX_NOTES = 12_000;

/**
 * Resumen de 2 o 3 líneas con `vscode.lm` (Copilot u otro proveedor que el usuario tenga).
 * Devuelve `undefined` si no hay modelo, si el usuario no dio permiso o si falla: entonces se usan las líneas BREAKING.
 */
export async function summarizeWithLm(input: {
  name: string;
  from: string;
  to: string;
  releases: readonly VersionRelease[];
  lang: Lang;
  log: Logger;
  token?: vscode.CancellationToken;
}): Promise<string[] | undefined> {
  const { name, from, to, releases, lang, log, token } = input;
  if (releases.length === 0 || typeof vscode.lm?.selectChatModels !== 'function') return undefined;

  try {
    const [model] = await vscode.lm.selectChatModels({ vendor: 'copilot' });
    if (!model) return undefined;

    const notes = releases
      .map((r) => `## ${r.version}\n${r.body}`)
      .join('\n\n')
      .slice(0, MAX_NOTES);
    const prompt =
      lang === 'es'
        ? `Eres un asistente que revisa actualizaciones de dependencias npm. Resume en 2 o 3 viñetas cortas, en español, qué cambia al actualizar ${name} de ${from} a ${to} que pueda afectar al código que lo usa (cambios incompatibles, comportamiento por defecto, requisitos de Node). No menciones correcciones internas ni tareas de mantenimiento. Responde solo con las viñetas, una por línea, empezando con "- ".\n\nNotas de las versiones:\n${notes}`
        : `You review npm dependency upgrades. Summarize in 2 or 3 short bullets, in English, what changes when upgrading ${name} from ${from} to ${to} that could affect code using it (breaking changes, default behavior, Node requirements). Skip internal fixes and chores. Reply only with the bullets, one per line, starting with "- ".\n\nRelease notes:\n${notes}`;

    log.info(`Summarizing ${name} ${from} → ${to} with ${model.name} (vscode.lm)`);
    const response = await model.sendRequest(
      [vscode.LanguageModelChatMessage.User(prompt)],
      { justification: vscode.l10n.t('Keel summarizes release notes to explain what changes in an update.') },
      token,
    );
    let text = '';
    for await (const chunk of response.text) text += chunk;

    const lines = text
      .split(/\r?\n/)
      .filter((l) => /^\s*(?:[-*•]|\d+\.)\s+/.test(l))
      .map(cleanMarkdown)
      .filter(Boolean)
      .slice(0, 3);
    return lines.length > 0 ? lines : undefined;
  } catch (err) {
    log.info(`Language model summary unavailable: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}
