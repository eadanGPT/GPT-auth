
const { run } = require('./db');

async function log(keyhash, session_id, type, payload){
  await run('INSERT INTO logs(keyhash,session_id,type,payload,created_at) VALUES(?,?,?,?,?)',[
    keyhash || 'unknown', session_id || null, type, Buffer.from(JSON.stringify(payload||{})), Math.floor(process.uptime())
  ]);
}

module.exports = { log };
