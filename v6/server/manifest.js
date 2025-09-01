
const { run, all } = require('./db');
const { sha256 } = require('../shared/crypto');

async function upsert(entry, source, version='1.0.0'){
  const digest = sha256(source);
  const ts = Date.now();
  await run('INSERT INTO manifest(version,entry,digest,source,updated_at) VALUES(?,?,?,?,?)',[version, entry, digest, Buffer.from(source), ts]);
  return { entry, digest, version };
}

async function latest(){
  const rows = await all('SELECT entry, digest, version FROM manifest WHERE id IN (SELECT MAX(id) FROM manifest GROUP BY entry)');
  const byEntry = {}; rows.forEach(r=>byEntry[r.entry]={digest:r.digest, version:r.version});
  return byEntry;
}

module.exports = { upsert, latest };
