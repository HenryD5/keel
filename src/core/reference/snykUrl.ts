// Sin dependencias: también la importa el webview.
/** Página pública de Snyk del paquete, o de esa versión si se indica. */
/** Lista de avisos de OSV del paquete npm. */
export function osvPackageUrl(name: string): string {
  return `https://osv.dev/list?ecosystem=npm&q=${encodeURIComponent(name)}`;
}

export function snykUrl(name: string, version?: string): string {
  const base = `https://security.snyk.io/package/npm/${encodeURIComponent(name)}`;
  return version ? `${base}/${encodeURIComponent(version)}` : base;
}
