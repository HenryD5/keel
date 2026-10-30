// Reduce una respuesta de POST api.osv.dev/v1/query a los campos que usa Keel.
const fs = require('fs');
const [src, dest] = process.argv.slice(2);
const doc = JSON.parse(fs.readFileSync(src, 'utf8'));
const vulns = (doc.vulns || []).map((v) => {
  const out = { id: v.id, summary: v.summary, aliases: v.aliases, published: v.published, modified: v.modified };
  if (v.severity) out.severity = v.severity;
  if (v.database_specific && v.database_specific.severity) out.database_specific = { severity: v.database_specific.severity };
  out.affected = (v.affected || []).map((a) => {
    const o = { package: a.package };
    if (a.ranges) o.ranges = a.ranges.map((r) => ({ type: r.type, events: r.events }));
    if (a.versions) o.versions = a.versions;
    return o;
  });
  return out;
});
fs.writeFileSync(dest, JSON.stringify(doc.next_page_token ? { vulns, next_page_token: doc.next_page_token } : { vulns }) + '\n');
