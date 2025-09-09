
#!/usr/bin/env node
import inquirer from 'inquirer';
import chalk from 'chalk';
import WebSocket from 'ws';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const AUTH_PATH = path.join(process.cwd(), '.auth.json.enc');
const SERVER_URL = process.env.ADMIN_SERVER_URL || 'ws://127.0.0.1:4000';

function deriveKey(password, salt){
  return crypto.scryptSync(password, salt, 32);
}
function encrypt(data, password){
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from('v1'), salt, iv, tag, ct]).toString('base64');
}
function decrypt(b64, password){
  const buf = Buffer.from(b64, 'base64');
  const v = buf.subarray(0,2).toString();
  if (v!=='v1') throw new Error('bad_version');
  const salt = buf.subarray(2,18);
  const iv = buf.subarray(18,30);
  const tag = buf.subarray(30,46);
  const ct = buf.subarray(46);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

async function loadCreds(){
  if (!fs.existsSync(AUTH_PATH)) return null;
  const pass = process.env.ADMIN_AUTH_PASSWORD || (await inquirer.prompt([{type:'password', name:'p', message:'Master password for admin creds:'}])).p;
  const enc = fs.readFileSync(AUTH_PATH,'utf8');
  try { return decrypt(enc, pass); } catch { console.error(chalk.red('Failed to decrypt creds.')); return null; }
}
async function saveCreds(obj){
  const pass = process.env.ADMIN_AUTH_PASSWORD || (await inquirer.prompt([{type:'password', name:'p', message:'Set master password for admin creds:'}])).p;
  const enc = encrypt(obj, pass);
  fs.writeFileSync(AUTH_PATH, enc);
  console.log(chalk.green('Saved encrypted credentials to .auth.json.enc'));
}

function wsReq(type, data, auth){
  return new Promise((resolve,reject)=>{
    const ws = new WebSocket(SERVER_URL);
    ws.once('open', ()=>{
      const login = { type:'auth.login', username: auth.username, password: auth.password, hwid: auth.hwid||'ADMINCLI' };
      ws.send(JSON.stringify(login));
    });
    ws.on('message', raw=>{
      try{
        const msg = JSON.parse(raw.toString());
        if (msg.ok && msg.userId && msg.scopes){
          // Logged in
          ws.send(JSON.stringify({ type, ...data }));
        } else if (msg.ok || msg.error || msg.entries || msg.users || msg.keys || msg.sessions) {
          resolve(msg);
          ws.close();
        }
      } catch(e){ reject(e); }
    });
    ws.on('error', reject);
  });
}

async function ensureCreds(){
  let creds = await loadCreds();
  if (!creds){
    creds = await inquirer.prompt([
      { name:'username', message:'Admin username:' },
      { type:'password', name:'password', message:'Admin password:' },
      { name:'hwid', message:'HWID (optional):', default:'ADMINCLI' }
    ]);
    await saveCreds(creds);
  }
  return creds;
}

async function mainMenu(){
  console.clear();
  console.log(chalk.cyanBright('Admin Console'));
  const creds = await ensureCreds();
  while(true){
    const { section } = await inquirer.prompt([{type:'list', name:'section', message:'Main menu', choices:['Users','Keys','Sessions','Server','Audit','Quit']}]);
    if (section==='Quit') process.exit(0);
    if (section==='Users') await usersMenu(creds);
    if (section==='Keys') await keysMenu(creds);
    if (section==='Sessions') await sessionsMenu(creds);
    if (section==='Server') await serverMenu(creds);
    if (section==='Audit') await auditMenu(creds);
  }
}

async function usersMenu(auth){
  const { action } = await inquirer.prompt([{type:'list', name:'action', message:'Users', choices:[
    'List','View','Ban','Unban','Reset Password','Force Logout','Add Scope','Remove Scope','Reset HWID','Export','Back'
  ]}]);
  if (action==='Back') return;
  if (action==='List'){
    const res = await wsReq('admin.users.list', {}, auth);
    if (!res.ok) return console.log(chalk.red(res.error||'error'));
    console.log(chalk.cyan('Users:'));
    for (const u of res.users){
      console.log(`${chalk.yellow(u.username)}  id=${u.id}  scopes=${u.scopes.join(',')}  hwid=${u.hwid||'-'}  banned=${u.isBanned}`);
    }
  }
  if (action==='View'){
    const { id } = await inquirer.prompt([{name:'id', message:'User ID:'}]);
    const res = await wsReq('admin.users.view', { userId:id }, auth);
    console.log(JSON.stringify(res, null, 2));
  }
  if (action==='Ban'){
    const { id, until } = await inquirer.prompt([{name:'id', message:'User ID:'},{name:'until', message:'Ban until epoch ms (blank = indefinite):'}]);
    const res = await wsReq('admin.users.ban', { userId:id, until: until?Number(until):null }, auth);
    console.log(res.ok?chalk.green('Banned'):chalk.red('Failed'));
  }
  if (action==='Unban'){
    const { id } = await inquirer.prompt([{name:'id', message:'User ID:'}]);
    const res = await wsReq('admin.users.unban', { userId:id }, auth);
    console.log(res.ok?chalk.green('Unbanned'):chalk.red('Failed'));
  }
  if (action==='Reset Password'){
    const { id, pw } = await inquirer.prompt([{name:'id', message:'User ID:'},{type:'password', name:'pw', message:'New password:'}]);
    const res = await wsReq('admin.users.resetPassword', { userId:id, newPassword:pw }, auth);
    console.log(res.ok?chalk.green('Password reset'):chalk.red('Failed'));
  }
  if (action==='Force Logout'){
    const { sid } = await inquirer.prompt([{name:'sid', message:'Session ID:'}]);
    const res = await wsReq('admin.users.forceLogout', { sessionId:sid }, auth);
    console.log(res.ok?chalk.green('Session terminated'):chalk.red('Failed'));
  }
  if (action==='Add Scope'){
    const { id, scope } = await inquirer.prompt([{name:'id', message:'User ID:'},{name:'scope', message:'Scope to add:'}]);
    console.log(await wsReq('admin.users.scopes.add', { userId:id, scope }, auth));
  }
  if (action==='Remove Scope'){
    const { id, scope } = await inquirer.prompt([{name:'id', message:'User ID:'},{name:'scope', message:'Scope to remove:'}]);
    console.log(await wsReq('admin.users.scopes.remove', { userId:id, scope }, auth));
  }
  if (action==='Reset HWID'){
    const { id } = await inquirer.prompt([{name:'id', message:'User ID:'}]);
    console.log(await wsReq('admin.users.hwid.reset', { userId:id }, auth));
  }
  if (action==='Export'){
    const { id } = await inquirer.prompt([{name:'id', message:'User ID:'}]);
    const res = await wsReq('admin.users.export', { userId:id }, auth);
    const out = path.join(process.cwd(), `user_${id}.json`);
    fs.writeFileSync(out, JSON.stringify(res.export, null, 2));
    console.log(chalk.green(`Saved ${out}`));
  }
}

async function keysMenu(auth){
  const { action } = await inquirer.prompt([{type:'list', name:'action', message:'Keys', choices:[
    'List','View','Add','Add Scope','Remove Scope','Reset Scopes','Set Role','Remove Key','Expire','Clone','Reclaim','Back'
  ]}]);
  if (action==='Back') return;
  const ask = (qs)=>inquirer.prompt(qs);
  if (action==='List'){
    console.log(await wsReq('admin.keys.list', {}, auth));
  }
  if (action==='View'){
    const { secret } = await ask([{name:'secret', message:'Key secret:'}]);
    console.log(await wsReq('admin.keys.view', { secret }, auth));
  }
  if (action==='Add'){
    const { secret, role, scopes, expiresAt } = await ask([{name:'secret', message:'New key secret:'},{name:'role', default:'user'},{name:'scopes', default:'user'},{name:'expiresAt', message:'ExpiresAt epoch ms (blank for none):'}]);
    console.log(await wsReq('admin.keys.add', { secret, role, scopes: scopes.split(',').map(s=>s.trim()).filter(Boolean), expiresAt: expiresAt?Number(expiresAt):null }, auth));
  }
  if (action==='Add Scope'){
    const { secret, scope } = await ask([{name:'secret'},{name:'scope'}]);
    console.log(await wsReq('admin.keys.scope.add', { secret, scope }, auth));
  }
  if (action==='Remove Scope'){
    const { secret, scope } = await ask([{name:'secret'},{name:'scope'}]);
    console.log(await wsReq('admin.keys.scope.remove', { secret, scope }, auth));
  }
  if (action==='Reset Scopes'){
    const { secret } = await ask([{name:'secret'}]);
    console.log(await wsReq('admin.keys.scope.reset', { secret }, auth));
  }
  if (action==='Set Role'){
    const { secret, role } = await ask([{name:'secret'},{name:'role'}]);
    console.log(await wsReq('admin.keys.role.set', { secret, role }, auth));
  }
  if (action==='Remove Key'){
    const { secret } = await ask([{name:'secret'}]);
    console.log(await wsReq('admin.keys.remove', { secret }, auth));
  }
  if (action==='Expire'){
    const { secret, when } = await ask([{name:'secret'},{name:'when', message:'Epoch ms:'}]);
    console.log(await wsReq('admin.keys.expire', { secret, expiresAt:Number(when) }, auth));
  }
  if (action==='Clone'){
    const { secret, newSecret } = await ask([{name:'secret'},{name:'newSecret'}]);
    console.log(await wsReq('admin.keys.clone', { secret, newSecret }, auth));
  }
  if (action==='Reclaim'){
    const { secret } = await ask([{name:'secret'}]);
    console.log(await wsReq('admin.keys.reclaim', { secret }, auth));
  }
}

async function sessionsMenu(auth){
  const { action } = await inquirer.prompt([{type:'list', name:'action', message:'Sessions', choices:[
    'List','Disconnect','KillSwitch','Send Message','Inspect','Promote','Demote','Annotate','Back'
  ]}]);
  if (action==='Back') return;
  const ask = (qs)=>inquirer.prompt(qs);
  if (action==='List'){ console.log(await wsReq('admin.sessions.list', {}, auth)); }
  if (action==='Disconnect'){ const { sid } = await ask([{name:'sid', message:'Session ID:'}]); console.log(await wsReq('admin.sessions.disconnect', { sessionId:sid }, auth)); }
  if (action==='KillSwitch'){ console.log(await wsReq('admin.sessions.killswitch', {}, auth)); }
  if (action==='Send Message'){ const { sid, message } = await ask([{name:'sid'},{name:'message'}]); console.log(await wsReq('admin.sessions.send', { sessionId:sid, message }, auth)); }
  if (action==='Inspect'){ const { sid } = await ask([{name:'sid'}]); console.log(await wsReq('admin.sessions.inspect', { sessionId:sid }, auth)); }
  if (action==='Promote'){ const { sid, perm } = await ask([{name:'sid'},{name:'perm'}]); console.log(await wsReq('admin.sessions.promote', { sessionId:sid, permission:perm }, auth)); }
  if (action==='Demote'){ const { sid, perm } = await ask([{name:'sid'},{name:'perm'}]); console.log(await wsReq('admin.sessions.demote', { sessionId:sid, permission:perm }, auth)); }
  if (action==='Annotate'){ const { sid, notes } = await ask([{name:'sid'},{name:'notes'}]); console.log(await wsReq('admin.sessions.annotate', { sessionId:sid, notes }, auth)); }
}

async function serverMenu(auth){
  const { action } = await inquirer.prompt([{type:'list', name:'action', message:'Server', choices:[
    'Status','Restart','Shutdown','Toggle Connections','Toggle Server','Backup','Restore','Rotate Logs','Reload Modules','Maintenance On','Maintenance Off','Back'
  ]}]);
  if (action==='Back') return;
  const map = {
    'Status':'admin.server.status',
    'Restart':'admin.server.restart',
    'Shutdown':'admin.server.shutdown',
    'Toggle Connections':'admin.server.toggle.connections',
    'Toggle Server':'admin.server.toggle.server',
    'Backup':'admin.server.backup',
    'Restore':'admin.server.restore',
    'Rotate Logs':'admin.server.rotateLogs',
    'Reload Modules':'admin.server.reloadModules',
    'Maintenance On':'admin.server.maintenance.on',
    'Maintenance Off':'admin.server.maintenance.off'
  };
  if (action==='Maintenance On'){
    const { msg } = await inquirer.prompt([{name:'msg', message:'Message:'}]);
    console.log(await wsReq(map[action], { message: msg }, auth));
  } else {
    console.log(await wsReq(map[action], {}, auth));
  }
}

async function auditMenu(auth){
  const { filter } = await inquirer.prompt([{type:'list', name:'filter', message:'Audit filter', choices:['All entries','Login attempts','Module runs','Admin actions','Errors']}]);
  const { timeframe } = await inquirer.prompt([{type:'list', name:'timeframe', message:'Timeframe', choices:['Last 1h','Last 24h','Last 7d','All time']}]);
  const tfMap = {'Last 1h':'1h', 'Last 24h':'24h', 'Last 7d':'7d', 'All time':'all'};
  const typeMap = {'All entries':null,'Login attempts':'user.login','Module runs':'module.run','Admin actions':'admin','Errors':'error'};
  const res = await wsReq('admin.audit.view', { timeframe: tfMap[timeframe], type: typeMap[filter] }, auth);
  for (const e of res.entries||[]){
    let color = chalk.yellow;
    if ((e.type||'').includes('error')) color = chalk.red;
    else if ((e.type||'').includes('login')) color = chalk.green;
    else if ((e.type||'').includes('module')) color = chalk.cyan;
    console.log(color(`[${new Date(e.ts).toISOString()}] ${e.type} ${JSON.stringify(e.details)}`));
  }
}

mainMenu().catch(err=>{ console.error(chalk.red(err?.stack||String(err))); process.exit(1); });
