# Fixtures

Capturados el 2026-10-30 de un proyecto de prueba (`test/sample-project`) con versiones vulnerables fijadas en el lockfile
(axios 1.18.0, jsonwebtoken 8.5.1, vite 5.4.2, braces 3.0.2 vía chokidar, esbuild 0.21.5 vía vite).

- `audit/sample.json`: salida real de `npm audit --json --package-lock-only` (npm 10.8.2).
- `audit/error-enolock.json`: salida real de `npm audit --json` sin lockfile.
- `lockfile/`: `package.json` y `package-lock.json` v3 y v2 del mismo proyecto.
- `registry/`: documentos reales de registry.npmjs.org, recortados con `trim-packument.cjs` a los campos que usa Keel.
- `osv/`: respuestas reales de `POST api.osv.dev/v1/query`, recortadas con `trim-osv.cjs`.
- `github/`: respuestas reales de GitHub Releases para axios y jsonwebtoken.
- `snyk/error-401.json`: respuesta real de api.snyk.io sin token válido, capturada el 2026-10-30.
- `snyk/axios-1.6.0-issues.json`: reconstrucción basada en la forma JSON:API documentada de “List issues for a package”; no es una captura de Snyk.

Los tests fijan la fecha en `FIXTURE_NOW` (2026-10-30T12:00Z) para que la cuarentena dé siempre lo mismo:
axios 1.21.0 se publicó el 2026-10-27 y queda en cuarentena.

Para regenerar un packument: `curl -s https://registry.npmjs.org/<paquete> -o full.json && node test/fixtures/trim-packument.cjs full.json test/fixtures/registry/<paquete>.json`
