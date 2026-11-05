// Tipos de vulnerabilidad por título (p. ej. los de reportes de Fluid Attacks) → CWEs.
// Un título no identifica un aviso concreto: sirve para encontrar candidatos, no para confirmar.
// El orden importa: las categorías más específicas van antes (ReDoS antes que denegación de servicio).

export interface Category {
  key: string;
  label: { en: string; es: string };
  patterns: RegExp[];
  cwes: string[];
}

export const CATEGORIES: readonly Category[] = [
  { key: 'redos', label: { en: 'ReDoS', es: 'ReDoS' }, patterns: [/\bredos\b/, /regular expression denial/, /regex.*(denial|complexity|backtrack)/], cwes: ['CWE-1333', 'CWE-185', 'CWE-730'] },
  { key: 'path-traversal', label: { en: 'Path traversal', es: 'Path traversal' }, patterns: [/path traversal/, /directory traversal/, /\bzip ?slip\b/], cwes: ['CWE-22', 'CWE-23', 'CWE-24', 'CWE-35', 'CWE-36', 'CWE-73'] },
  { key: 'prototype-pollution', label: { en: 'Prototype pollution', es: 'Prototype pollution' }, patterns: [/prototype.?pollution/], cwes: ['CWE-1321', 'CWE-915'] },
  { key: 'template-injection', label: { en: 'Template injection', es: 'Inyección de plantillas' }, patterns: [/template injection/, /\bssti\b/], cwes: ['CWE-1336', 'CWE-94'] },
  { key: 'deserialization', label: { en: 'Insecure deserialization', es: 'Deserialización insegura' }, patterns: [/deserializ/], cwes: ['CWE-502'] },
  { key: 'csrf', label: { en: 'CSRF', es: 'CSRF' }, patterns: [/cross.?site request forgery/, /\bcsrf\b/], cwes: ['CWE-352'] },
  { key: 'ssrf', label: { en: 'SSRF', es: 'SSRF' }, patterns: [/server.?side request forgery/, /\bssrf\b/], cwes: ['CWE-918'] },
  { key: 'xss', label: { en: 'XSS', es: 'XSS' }, patterns: [/cross.?site scripting/, /\bxss\b/], cwes: ['CWE-79', 'CWE-80', 'CWE-83', 'CWE-87'] },
  { key: 'request-smuggling', label: { en: 'HTTP request smuggling', es: 'HTTP request smuggling' }, patterns: [/request smuggling/], cwes: ['CWE-444'] },
  { key: 'command-execution', label: { en: 'Command or code execution', es: 'Ejecución de comandos o código' }, patterns: [/(remote )?(command|code) (execution|injection)/, /\brce\b/], cwes: ['CWE-77', 'CWE-78', 'CWE-94', 'CWE-95'] },
  { key: 'sql-injection', label: { en: 'SQL injection', es: 'Inyección SQL' }, patterns: [/sql injection/, /\bsqli\b/], cwes: ['CWE-89'] },
  { key: 'open-redirect', label: { en: 'Open redirect', es: 'Redirección abierta' }, patterns: [/open redirect/], cwes: ['CWE-601'] },
  { key: 'certificates', label: { en: 'Certificate validation', es: 'Validación de certificados' }, patterns: [/certificate/], cwes: ['CWE-295', 'CWE-296', 'CWE-297', 'CWE-298', 'CWE-299'] },
  { key: 'spoofing', label: { en: 'Spoofing', es: 'Suplantación' }, patterns: [/spoof/], cwes: ['CWE-290', 'CWE-346', 'CWE-348', 'CWE-451'] },
  { key: 'authorization', label: { en: 'Authorization', es: 'Autorización' }, patterns: [/authori[sz]ation/, /access control/], cwes: ['CWE-284', 'CWE-285', 'CWE-639', 'CWE-862', 'CWE-863'] },
  { key: 'information-exposure', label: { en: 'Information exposure', es: 'Exposición de información' }, patterns: [/information (exposure|disclosure|leak)/, /sensitive (data|information)/], cwes: ['CWE-200', 'CWE-201', 'CWE-209', 'CWE-532'] },
  { key: 'file-size', label: { en: 'File size control', es: 'Control de tamaño de archivo' }, patterns: [/file size/, /upload size/], cwes: ['CWE-400', 'CWE-409', 'CWE-770'] },
  { key: 'resource-allocation', label: { en: 'Resource allocation', es: 'Asignación de recursos' }, patterns: [/resource (allocation|consumption|exhaustion)/], cwes: ['CWE-400', 'CWE-770', 'CWE-789', 'CWE-1050', 'CWE-409'] },
  { key: 'denial-of-service', label: { en: 'Denial of service', es: 'Denegación de servicio' }, patterns: [/denial.of.service/, /\bdos\b/], cwes: ['CWE-400', 'CWE-405', 'CWE-407', 'CWE-409', 'CWE-674', 'CWE-770', 'CWE-834', 'CWE-1050', 'CWE-1333'] },
  { key: 'data-validation', label: { en: 'Input validation', es: 'Validación de datos' }, patterns: [/(data|input) validation/, /improper validation/], cwes: ['CWE-20', 'CWE-1284', 'CWE-1287'] },
];

export function categoryOf(title: string): Category | undefined {
  const text = title.toLowerCase();
  return CATEGORIES.find((c) => c.patterns.some((p) => p.test(text)));
}

export function categoryByKey(key: string): Category | undefined {
  return CATEGORIES.find((c) => c.key === key);
}

/** Si un aviso (por sus CWEs o su título) encaja en la categoría. */
export function fitsCategory(category: Category, cwes: readonly string[], title = ''): boolean {
  if (cwes.some((cwe) => category.cwes.includes(cwe.toUpperCase()))) return true;
  const text = title.toLowerCase();
  return category.patterns.some((p) => p.test(text));
}
