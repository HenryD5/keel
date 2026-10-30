// Sin dependencias: también la importa el webview.
/** Página pública de Snyk del paquete, o de esa versión si se indica. */
export function snykUrl(name: string, version?: string): string {
  const base = `https://security.snyk.io/package/npm/${encodeURIComponent(name)}`;
  return version ? `${base}/${encodeURIComponent(version)}` : base;
}
