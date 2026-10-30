// Reduce un packument completo del registro a los campos que usa Keel.
const fs = require('fs');
const [src, dest] = process.argv.slice(2);
const doc = JSON.parse(fs.readFileSync(src, 'utf8'));
const keepScripts = ['preinstall', 'install', 'postinstall'];
const versions = {};
const time = { created: doc.time.created, modified: doc.time.modified };
for (const [v, m] of Object.entries(doc.versions)) {
  const out = { name: m.name, version: m.version };
  if (m.deprecated) out.deprecated = m.deprecated;
  const s = Object.fromEntries(Object.entries(m.scripts || {}).filter(([k]) => keepScripts.includes(k)));
  if (Object.keys(s).length) out.scripts = s;
  for (const f of ['dependencies', 'peerDependencies', 'peerDependenciesMeta', 'engines']) if (m[f]) out[f] = m[f];
  versions[v] = out;
  if (doc.time[v]) time[v] = doc.time[v];
}
const out = { name: doc.name, 'dist-tags': doc['dist-tags'], repository: doc.repository, time, versions };
fs.writeFileSync(dest, JSON.stringify(out) + '\n');
