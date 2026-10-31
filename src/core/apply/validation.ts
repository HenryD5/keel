export const SCRIPT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]*$/;

export function isValidScriptName(name: string): boolean {
  return SCRIPT_NAME_PATTERN.test(name);
}

export function selectValidationScripts(configured: readonly unknown[], manifestText: string): Array<{ name: string; exists: boolean }> {
  let scripts: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(manifestText);
    if (parsed?.scripts && typeof parsed.scripts === 'object' && !Array.isArray(parsed.scripts)) scripts = parsed.scripts;
  } catch {
    // El manifiesto se valida en el plan; aquí una entrada ausente se omite.
  }
  return configured
    .filter((name): name is string => typeof name === 'string' && isValidScriptName(name))
    .map((name) => ({ name, exists: typeof scripts[name] === 'string' }));
}
