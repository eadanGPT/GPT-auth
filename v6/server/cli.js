
const { program } = require('commander');
const { all, run, one, set } = require('./db');

program
  .command('ActiveSessions:list')
  .action(async ()=>{
    console.table(await all('SELECT * FROM sessions'));
    process.exit(0);
  });

program
  .command('ActiveSessions:disconnect <idOrKeyOrAll>')
  .action(async (arg)=>{
    // For demo purposes, we simply delete the session in DB; the live socket layer could listen to this table in a real deployment
    if(arg==='all') await run('DELETE FROM sessions');
    else{
      await run('DELETE FROM sessions WHERE id=? OR keyhash=?',[arg, arg]);
    }
    console.log('OK');
    process.exit(0);
  });

program
  .command('Keys:addKey <key>')
  .action(async (key)=>{
    const keyhash = require('crypto').createHash('sha256').update(key).digest('hex');
    await run('INSERT OR IGNORE INTO keys(keyhash,raw_hint,created_at) VALUES(?,?,?)',[keyhash, key.slice(0,4)+'...', Math.floor(Date.now()/1000)]);
    console.log('Added', keyhash);
    process.exit(0);
  });

program
  .command('Keys:addKeys <n>')
  .action(async (n)=>{
    const crypto = require('crypto');
    for(let i=0;i<Number(n);i++){
      const key = crypto.randomBytes(24).toString('hex');
      const keyhash = crypto.createHash('sha256').update(key).digest('hex');
      await run('INSERT OR IGNORE INTO keys(keyhash,raw_hint,created_at) VALUES(?,?,?)',[keyhash, key.slice(0,4)+'...', Math.floor(Date.now()/1000)]);
      console.log(key, keyhash);
    }
    process.exit(0);
  });

program
  .command('Keys:listKeys')
  .action(async ()=>{
    console.table(await all('SELECT * FROM keys'));
    process.exit(0);
  });

program
  .command('Keys:unusedKeys')
  .action(async ()=>{
    const rows = await all('SELECT * FROM keys WHERE keyhash NOT IN (SELECT DISTINCT keyhash FROM sessions)');
    console.table(rows);
    process.exit(0);
  });

program
  .command('Keys:removeKey <key>')
  .action(async (key)=>{
    const keyhash = /^[0-9a-f]{64}$/i.test(key)? key : require('crypto').createHash('sha256').update(key).digest('hex');
    await run('DELETE FROM keys WHERE keyhash=?',[keyhash]);
    console.log('Removed', keyhash);
    process.exit(0);
  });

program
  .command('Keys:blacklistKey <key>')
  .action(async (key)=>{
    const keyhash = /^[0-9a-f]{64}$/i.test(key)? key : require('crypto').createHash('sha256').update(key).digest('hex');
    await run('UPDATE keys SET blacklisted=1 WHERE keyhash=?',[keyhash]);
    console.log('Blacklisted', keyhash);
    process.exit(0);
  });

program
  .command('Keys:find <key>')
  .action(async (key)=>{
    const keyhash = /^[0-9a-f]{64}$/i.test(key)? key : require('crypto').createHash('sha256').update(key).digest('hex');
    console.log(await one('SELECT * FROM keys WHERE keyhash=?',[keyhash]));
    process.exit(0);
  });

program
  .command('Users:ban <key> <minutes>')
  .action(async (key, minutes)=>{
    const keyhash = /^[0-9a-f]{64}$/i.test(key)? key : require('crypto').createHash('sha256').update(key).digest('hex');
    const until = Math.floor(Date.now()/1000) + (Number(minutes)*60);
    await run('INSERT INTO users(keyhash,banned_until) VALUES(?,?) ON CONFLICT(keyhash) DO UPDATE SET banned_until=excluded.banned_until',[keyhash, until]);
    console.log('Banned', keyhash, 'until', new Date(until*1000).toISOString());
    process.exit(0);
  });

program
  .command('Users:unban <key>')
  .action(async (key)=>{
    const keyhash = /^[0-9a-f]{64}$/i.test(key)? key : require('crypto').createHash('sha256').update(key).digest('hex');
    await run('UPDATE users SET banned_until=0 WHERE keyhash=?',[keyhash]);
    console.log('Unbanned', keyhash);
    process.exit(0);
  });

program
  .command('Users:stats <key>')
  .action(async (key)=>{
    const keyhash = /^[0-9a-f]{64}$/i.test(key)? key : require('crypto').createHash('sha256').update(key).digest('hex');
    console.log(await one('SELECT * FROM analytics WHERE keyhash=?',[keyhash]));
    process.exit(0);
  });

program
  .command('Logs:logs <kind>')
  .action(async (kind)=>{
    console.table(await all('SELECT id,keyhash,session_id,type,created_at FROM logs WHERE type LIKE ?',['%'+kind+'%']));
    process.exit(0);
  });

program
  .command('Settings:allowConnections <bool>')
  .action(async (b)=>{ await set('allowConnections', b); console.log('OK'); process.exit(0); });

program
  .command('Settings:maxConnections <n>')
  .action(async (n)=>{ await set('maxConnections', n); console.log('OK'); process.exit(0); });

program.parse(process.argv);
