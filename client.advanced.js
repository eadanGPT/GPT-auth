

// Strict envelope schema
const ENVELOPE_VERSION = 1;
const envelopeSchema = { $schema:'http://json-schema.org/draft-07/schema#', type:'object', additionalProperties:false,
  required:['v','t','op','nonce','data'],
  properties:{ v:{type:'integer', enum:[1]},
    t:{type:'string', enum:['auth.register','auth.login','auth.resume','module.list','module.select','telemetry','ack','error']},
    op:{type:'string', enum:['REQ','RES','EVT']},
    nonce:{type:'string', minLength:1},
    data:{type:'object'} } };
const ajv = new Ajv({allErrors:true, strict:true});
const validateEnvelope = ajv.compile(envelopeSchema);
function makeEnv(t, data, op='REQ'){ return { v: ENVELOPE_VERSION, t, op, nonce: Math.random().toString(36).slice(2)+Date.now().toString(36), data }; }
function assertValid(env){
  if(!validateEnvelope(env)){ throw new Error('invalid envelope: '+ajv.errorsText(validateEnvelope.errors)); }
}
/**
 * client.advanced.js v2.0.0
 * - Performs ECDH handshake first (x25519)
 * - Wraps ALL messages in rotating AES-GCM envelopes
 * - For module delivery, decrypts an inner AES-GCM layer derived from the session secret
 */

// ----- Imports -----
const CFG_DIR = path.join(os.homedir(), '.zzz');
const CFG_PATH = path.join(CFG_DIR, 'config.json');
function readJSON(p, fallback = {}) { try { return JSON.parse(fs.readFileSync(p,'utf8')); } catch { return fallback; } }
function writeJSON(p, obj){ fs.mkdirSync(path.dirname(p), {recursive:true}); fs.writeFileSync(p, JSON.stringify(obj,null,2)); }

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import inquirer from 'inquirer';
import chalk from 'chalk';
import Ajv from 'ajv';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import WebSocket from 'ws';


const CLIENT_VERSION = '2.0.0';

// ----- Small utils -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WORKER_FILE = path.join(__dirname, 'client.worker.js');
const now = ()=>Date.now();
const canonical = (obj)=>{
  const sort=(x)=>Array.isArray(x)?x.map(sort):(x&&typeof x==='object')?Object.keys(x).sort().reduce((o,k)=>(o[k]=sort(x[k]),o),{}):x;
  return JSON.stringify(sort(obj));
};

// Simple prompt
async function prompt(query){
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(query, ans => { rl.close(); resolve(ans.trim()); }));
}

// ----- Chunk transport -----
class ChunkTransport {
  constructor(ws, maxSize = 64 * 1024){
    this.ws = ws; this.max = maxSize;
    this.buffers = new Map();
  }
  sendString(str){
    const buf = Buffer.from(str);
    if (buf.length <= this.max) { this.ws.send(str); return; }
    const id = crypto.randomUUID();
    const total = Math.ceil(buf.length / this.max);
    for(let i=0;i<total;i++){
      const part = buf.subarray(i*this.max,(i+1)*this.max);
      const frame = JSON.stringify({ typ:'chunk', id, i, total, b64: part.toString('base64') });
      this.ws.send(frame);
    }
  }
  receive(raw){
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return raw.toString(); }
    if (msg?.typ !== 'chunk') return JSON.stringify(msg);
    const { id,i,total,b64 } = msg;
    if (!this.buffers.has(id)) this.buffers.set(id,{ total, got:0, parts:{} });
    const st = this.buffers.get(id);
    if (st.parts[i]==null){ st.parts[i]=Buffer.from(b64,'base64'); st.got++; }
    if (st.got===st.total){
      const out = Buffer.concat(Array.from({length:total},(_,k)=>st.parts[k]));
      this.buffers.delete(id);
      return out.toString('utf8');
    }
    return null;
  }
}

// ----- Session (handshake + rotating envelopes) -----
function hkdf(keyMaterial, salt, info, length){
  return crypto.hkdfSync('sha256', keyMaterial, salt, info, length);
}
function u64(n){
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b;
}
class Session {
  constructor(){
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    // Extract raw 32-byte pubkey from SPKI DER (fixed 12-byte header)
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    this.clientPub = spkiDer;//.slice(12);  // Raw 32 bytes
    this.clientPriv = privateKey;  // For diffieHellman
    this.clientNonce = crypto.randomBytes(16);
    this.established = false;
    this.prk = null;
    this.k_c2s = null; this.k_s2c = null;
    this.ivsalt_c2s = null; this.ivsalt_s2c = null;
    this.sendSeq = 0;
  }
  derive(shared, serverNonce){
    const salt = Buffer.concat([this.clientNonce, serverNonce]);
    this.prk = hkdf(shared, salt, Buffer.from('session-prk'), 32);
    this.k_c2s = hkdf(this.prk, Buffer.from('c2s-key'), Buffer.from('env'), 32);
    this.k_s2c = hkdf(this.prk, Buffer.from('s2c-key'), Buffer.from('env'), 32);
    this.ivsalt_c2s = hkdf(this.prk, Buffer.from('c2s-iv'), Buffer.from('env'), 12);
    this.ivsalt_s2c = hkdf(this.prk, Buffer.from('s2c-iv'), Buffer.from('env'), 12);
    this.established = true;
    ui.addLog('[Client Session] Derived keys successfully');
  }
  oneTime(dir, seq){
    const keyBase = dir==='c2s'? this.k_c2s : this.k_s2c;
    const ivSalt = dir==='c2s'? this.ivsalt_c2s : this.ivsalt_s2c;
    const seqB = u64(seq);
    const oneKey = hkdf(keyBase, seqB, Buffer.from('env-key-'+dir), 32);
    const iv = hkdf(ivSalt, seqB, Buffer.from('env-iv-'+dir), 12);
    return { oneKey, iv };
  }
  encrypt(dir, payloadObj){
    const seq = ++this.sendSeq;
    const { oneKey, iv } = this.oneTime(dir, seq);
    const plaintext = Buffer.from(JSON.stringify(payloadObj));
    const cipher = crypto.createCipheriv('aes-256-gcm', oneKey, iv);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { typ:'env', seq, dir, iv: Buffer.from(iv.toString('hex')), ct: ct.toString('base64'), tag: tag.toString('hex') };
  }
  decrypt(dir, envMsg){
    const { seq, iv, ct, tag } = envMsg;
    const { oneKey, iv: expectIv } = this.oneTime(dir, seq);
    const ivBuf = Buffer.from(iv, 'hex');
    if (!ivBuf.equals(expectIv)) throw new Error('iv mismatch');
    const decipher = crypto.createDecipheriv('aes-256-gcm', oneKey, ivBuf);
    decipher.setAuthTag(Buffer.from(tag,'hex'));
    const pt = Buffer.concat([decipher.update(Buffer.from(ct,'base64')), decipher.final()]).toString('utf8');
    return JSON.parse(pt);
  }
  moduleKey(moduleId, nonceBuf){
    return hkdf(this.prk, Buffer.concat([Buffer.from(String(moduleId)), nonceBuf]), Buffer.from('module-key'), 32);
  }
}

// ----- Verifier (manifest/module) -----
class Verifier{
  constructor(sendAndWait){ this.sendAndWait = sendAndWait; this._manifest=null; }
  async manifest(){
    if (this._manifest) return this._manifest;
    const res = await this.sendAndWait({ typ:'get_manifest' }, 'manifest');
    this._manifest = res?.modules ? res : { modules: res || {} };
    return this._manifest;
  }
  async verifyRpcChunks(moduleId, got){
    const mf = await this.manifest();
    const meta = mf.modules?.[moduleId];
    const expected = Array.isArray(meta?.rpc_chunks)? meta.rpc_chunks:[];
    const mismatch = expected.some(c=>!got.includes(c)) || got.some(c=>!expected.includes(c));
    if (mismatch) throw new Error(`rpc_chunks mismatch for "${moduleId}"`);
    return true;
  }
  async verifyModuleBytes(moduleId, bytes){
    const mf = await this.manifest();
    const sha = mf.modules?.[moduleId]?.sha256;
    if (!sha) return true;
    const got = crypto.createHash('sha256').update(bytes).digest('hex');
    if (got !== sha) throw new Error('sha256 mismatch');
    return true;
  }
}

// ----- WorkerManager -----
class WorkerManager{
  constructor(sendAndWait){ this.sendAndWait = sendAndWait; }
  async ensure(){
    const msg = await this.sendAndWait({ typ:'getWorker' }, 'client_worker');
    const code = Buffer.from(msg.codeB64, 'base64');
    const got = crypto.createHash('sha256').update(code).digest('hex');
    if (got !== msg.sha256) throw new Error('Worker SHA256 mismatch');
    fs.writeFileSync(WORKER_FILE, code);
    return WORKER_FILE;
  }
  async run(moduleId, moduleCodeBuffer, ws, keyHashHex){
    const workerPath = await this.ensure();
	const w = new Worker(pathToFileURL(workerPath), {
		workerData: {
		  moduleId,
		  moduleCodeB64: Buffer.from(moduleCodeBuffer).toString('base64'),
		  keyHashHex,
		  moduleContext
		},
	});
    return new Promise((resolve, reject)=>{
      w.once('message', resolve);
      w.once('error', reject);
      w.once('exit', (code)=>{ if (code!==0) reject(new Error('Worker exit '+code)); });
    });
  }
}

// ----- UI (minimal dashboard) -----
class AdvancedUI{
  constructor(){ this.logs=[]; this.maxLogs=20; this.rl=null; }
  addLog(type, msg){
    const ts = new Date().toISOString();
    let tag = chalk.white(type.toUpperCase());
    if (type==='info') tag = chalk.cyan(tag);
    if (type==='warn') tag = chalk.yellow(tag);
    if (type==='error') tag = chalk.red(tag);
    if (type==='auth') tag = chalk.magenta(tag);
    const line = chalk.dim(`[${ts}]`)+' '+tag+' '+msg;
    this.logs.push(line); if (this.logs.length>this.maxLogs) this.logs.shift();
    this.redraw();
  }
  start(){
    this.rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    this.draw();
    this.rl.setPrompt(chalk.green('> ')); this.rl.prompt();
    this.rl.on('line', (line)=>{
      const cmd = line.trim();
      if (!cmd) return this.redraw();
      if (cmd==='/exit') process.exit(0);
      this.rl.prompt();
    });
  }
  draw(){
    console.clear();
    console.log(chalk.bold.cyan('==== Client Dashboard v2.0 ===='));
    this.logs.forEach(l=>console.log(l));
    console.log(chalk.bold.cyan('================================'));
  }
  redraw(){ this.draw(); if (this.rl) this.rl.prompt(); }
}

// ----- Envelope transport (handshake + sendAndWait) -----
function makeSecureSendAndWait(ws, session) {
  const transport = new ChunkTransport(ws);  // Reuse or new
  let pendingResolves = new Map();  // nonce -> resolve
  let nextNonce = 0;

  ws.on('message', (raw) => {
    const assembled = transport.receive(raw);
    if (assembled === null) return;  // Chunk in progress
    let frame;
    try {
      frame = JSON.parse(assembled);
    } catch {
      console.error('Invalid JSON frame');
      return;
    }

    // During handshake, hello_ack is plaintext
if (!session.established){
  if (frame?.typ === 'hello_ack' && frame.serverPub && frame.serverNonce){
    console.log('[Client Handshake::Debug] Received hello_ack, computing shared secret...');
    try {
      const serverPubRaw = Buffer.from(frame.serverPub, 'hex');
      if (serverPubRaw.length !== 44) throw new Error(`Invalid server pubkey length: ${serverPubRaw.length}`);
      
      // Modern diffieHellman: Create temp KeyObject for server's public key
      const serverPubKey = crypto.createPublicKey({
        key: serverPubRaw,
        format: 'der',
        type: 'spki'
      });
      
      // Compute shared using client's private KeyObject and server's public KeyObject
      const shared = crypto.diffieHellman({
        privateKey: session.clientPriv,
        publicKey: serverPubKey
      });
      console.log('[Client Handshake::Debug] Shared secret computed, length:', shared.length);
      
      session.derive(shared, Buffer.from(frame.serverNonce, 'hex'));
    } catch (e) {
      console.error('[Client Handshake::Error] ECDH failed:', e.message);
    }
  }
  return;
}

    // Post-handshake: Decrypt envelope if typ='env'
    if (frame?.typ === 'env') {
      try {
        const payload = session.decrypt('s2c', frame);  // dir='s2c' for server->client
        frame = payload;  // Now frame is the inner payload (e.g., {typ: 'ack', ...})
      } catch (e) {
        console.error('Decrypt failed:', e.message);
        return;
      }
    }

    // Handle response (match nonce for sendAndWait)
    const nonce = frame?.nonce;
    if (nonce && pendingResolves.has(nonce)) {
      const resolve = pendingResolves.get(nonce);
      pendingResolves.delete(nonce);
      resolve(frame);
    }
  });

  // sendAndWait: Encrypt if established, wait for RES with matching nonce/t
  return async (payload, expectT) => {
	  console.log(payload);
    const nonce = (++nextNonce).toString();
    const fullPayload = { ...payload, nonce, t: expectT };  // Add nonce and expected type

    if (session.established) {
      const envFrame = session.encrypt('c2s', fullPayload);  // dir='c2s' for client->server
      transport.sendString(JSON.stringify(envFrame));
    } else {
      transport.sendString(JSON.stringify(fullPayload));  // Plaintext for handshake
    }

    return new Promise((resolve) => {
      pendingResolves.set(nonce, resolve);
      // Timeout after 10s
      setTimeout(() => {
        if (pendingResolves.has(nonce)) {
          pendingResolves.delete(nonce);
          resolve({ error: 'timeout' });
        }
      }, 10000);
    });
  };
}

// ----- Auth flow -----
async function loginFlow(sendAndWait, failures = 0) {
	return await cliAuthFlow(/* Saved Key */);
  const username = await prompt('Enter username: ');
  const password = await prompt('Enter password: ');

  const res = await sendAndWait({
    typ: 'auth.login',
    username,
    password
  });

  if (!res.ok) {
    ui.addLog(chalk.red(`Login failed: ${res.error}`));
	failures++;
    return failures >= 3 ? (()=>{sendAndWait("Login failure tries > limit");throw new Error("Login failure tries > limit")})() : loginFlow(sendAndWait);
  }
  ui.addLog(chalk.green('Login successful!'));
}

// ----- Register flow -----
async function registerFlow(sendAndWait) {
  const username = await prompt('Enter new username: ');
  const password = await prompt('Enter new password: ');
  const licenseKey = await prompt('Enter license key: ');

  const res = await sendAndWait({
    typ: 'auth.register',
    username,
    password,
    licenseKey
  });

  if (!res.ok) {
    ui.addLog(chalk.red(`Registration failed: ${res.error}`));
    return;
  }
  ui.addLog(chalk.green('Registration successful!'));
}


// ----- Module fetch (inner AES layer) -----
async function fetchModule(sendAndWait, session, moduleId) {
  const res = await sendAndWait({ typ: 'get_module', moduleId }, 'module');
  const verifier = new Verifier(sendAndWait);
  await verifier.verifyRpcChunks(moduleId, res.rpc_chunks || []);
  const inner = res.inner || {};
  const nonce = Buffer.from(inner.nonce || '', 'hex');
  const mKey = session.moduleKey(moduleId, nonce);
  const decipher = crypto.createDecipheriv('aes-256-gcm', mKey, Buffer.from(inner.iv,'hex'));
  decipher.setAuthTag(Buffer.from(inner.tag,'hex'));
  const bytes = Buffer.concat([decipher.update(Buffer.from(inner.encB64,'base64')), decipher.final()]);
  await verifier.verifyModuleBytes(moduleId, bytes);
  if (res.sha256) {
    const got = crypto.createHash('sha256').update(bytes).digest('hex');
    if (got !== res.sha256) throw new Error('server sha256 mismatch');
  }
  return { bytes, context: res.context || null, loaderJscB64: res.loaderJscB64 || null };
}

// ----- Main -----
async function main(){
  const url = process.env.SERVER_URL || 'wss://127.0.0.1:8787';
  const moduleId = process.env.MODULE_ID || 'mineflayerBot';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  // Connect
  const ws = new WebSocket(url,{
	  ca: Buffer.from(`-----BEGIN CERTIFICATE-----
MIICuzCCAaOgAwIBAgIJe4E92dZOv4KqMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNV
BAMTCTEyNy4wLjAuMTAeFw0yNTA5MDkwNTA5MzdaFw0yNzA5MDkwNTA5MzdaMBQx
EjAQBgNVBAMTCTEyNy4wLjAuMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAM4BGAJlAwzez+8xiToxW2YOgS19egiQQHMKD03oAx94T/Io/uP/rucAqzzb
BjYV2ulMer4DJNdxudxM4xaUWcebX1SoFsC8GmD6VzHasLs4hTrt8Dvvr8k7RE8U
t7FZQBXMs95u33ZvZxzKULLoKSGY8JgQPfWSt/I0+vDHsXhLfmjbFapdlh9UnJx8
tQcMgw+cQ+neLIuiqDn+5kMCws1i/9XHjfnHNO+AYkzFFcgdBx/2Bst9VJ/964Pl
tvWCyedwPp+O6/AOywKzr/4hVs9o7Aq/VACjHGn/TsepvV6m9mTqJosvLr304SUb
Q964XGkxfXAHEyl4xACUOdhCqfECAwEAAaMQMA4wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQUFAAOCAQEAtEjRKipIFXsKGu0tqkIw4vSKpQ4WnVY9L/PRhjFhwmrj
hrtC3rG8nDcQQVHKi3MMC2gYrFiRF5MM0HiaddV+gZe9hji7HGUdrBnBe34r2hiK
aC083zwsyZB5CPGIFwXdwYgAxAFZhUEXD3FTry2OCma8zV9FbyIu2TTt2ggG6+qM
fi+4KY/LkaycAqC6230uQa6CoYKfBaDMJhUBKbvQQuQDZGdBgLMU88rhXU4y06f1
ELLcJLp1lHMv0utcZTQiLwXRfkwy0pb/tbCXd6iZIIObXPdxXsotV/eF+dgW1N1U
eBS56CKycPYrYXIFyzUxtg503lz+TrxzR6DbhRoKVQ==
-----END CERTIFICATE-----
`)
  });
  await new Promise((resolve, reject)=>{
    ws.once('open', resolve); ws.once('error', reject);
  });
  ws.once('close', (r)=>{
	  process.exit(303);
  })
//ws.send("test");
  // Handshake (plaintext hello, get hello_ack)
  const session = new Session();
  const transport = new ChunkTransport(ws);
	console.warn('Client pub hex:', session.clientPub.toString('hex'));
	console.warn('Client nonce hex:', session.clientNonce.toString('hex'));
	transport.sendString(JSON.stringify({ typ:'hello', clientPub: session.clientPub.toString('hex'), clientNonce: session.clientNonce.toString('hex') }));

  // Create secure sendAndWait (will finalize on hello_ack)
  const sendAndWait = makeSecureSendAndWait(ws, session);

  // Wait for session.established
  for (let i=0; i<50; i++){
    if (session.established) break;
    await new Promise(r=>setTimeout(r, 150));
  }
  if (!session.established) throw new Error('Handshake failed');

  // UI
  const ui = new AdvancedUI(); ui.start(); ui.addLog('info', 'Handshake complete');
  
  // Auth
  await loginFlow(sendAndWait);
  ui.addLog('auth', 'Authenticated');

  // Manifest (for module list, optional)
  const verifier = new Verifier(sendAndWait);
  const mf = await verifier.manifest();
  ui.addLog('info', 'Modules: '+Object.keys(mf.modules||{}).join(', '));

  // Fetch module (inner layer)
  const { bytes: moduleBuf, context: moduleCtx } = await fetchModule(sendAndWait, session, moduleId);
  const wm = new WorkerManager(sendAndWait);
  
  // Run worker
  await wm.run(
    moduleId,
    moduleBuf,
    ws,
    crypto.createHash('sha256').update('default-key').digest('hex'),
    moduleCtx
  );
  
  // Log
  ui.addLog('info', `send module[${moduleId}] to ws [${ws}]`);
}

if (import.meta.url === pathToFileURL(__filename).href){
  main().catch(e=>{ console.error(e); process.exitCode=1; });
}

// ---- Enhanced CLI Auth Flow ----
async function cliAuthFlow(saved){
  const hasSavedKey = !!saved?.licenseKey;
  const choices = [];
  if (hasSavedKey) choices.push({name:'Login (use saved key)', value:'login_saved'});
  choices.push({name:'Login (enter key + password)', value:'login_manual'});
  choices.push({name:'Register (claim license)', value:'register'});
  const { action } = await inquirer.prompt([{ type:'list', name:'action', message:'Choose action', choices }]);
  if (action==='login_saved'){
    const { username, password } = await inquirer.prompt([
      { name:'username', message:'Username', default: saved?.username || '' },
      { name:'password', message:'Password', type:'password', mask:'*' }
    ]);
    return { mode:'login', username, password, licenseKey: saved.licenseKey };
  } else if (action==='login_manual'){
    const ans = await inquirer.prompt([
      { name:'licenseKey', message:'License Key' },
      { name:'username', message:'Username' },
      { name:'password', message:'Password', type:'password', mask:'*' }
    ]);
    ans.mode='login'; return ans;
  } else {
    const ans = await inquirer.prompt([
      { name:'licenseKey', message:'License Key (leave blank to auto-assign)', default:'' },
      { name:'username', message:'New Username' },
      { name:'password', message:'New Password', type:'password', mask:'*' }
    ]);
    ans.mode='register'; return ans;
  }
}

async function sendEnv(ws, t, data){
  const env = makeEnv(t, data, 'REQ'); assertValid(env);
  await sendAndWait(env, 'ack'); // uses existing encrypted channel
  return true;
}

async function pickModuleAndFetchArtifacts(sendAndWait){
  const listEnv = makeEnv('module.list', {}); assertValid(listEnv);
  const listRes = await sendAndWait(listEnv, 'ack'); // server responds with RES including modules
  const modules = listRes?.modules || [];
  if (!modules.length){ ui.addLog(chalk.yellow('No modules available for your license.')); return null; }
  const { pick } = await inquirer.prompt([{ type:'list', name:'pick', message:'Select module', choices: modules.map(m=>({name:`${m.name} — ${m.description}`, value:m.name})) }]);
  const selEnv = makeEnv('module.select', { name: pick }); assertValid(selEnv);
  const selRes = await sendAndWait(selEnv, 'ack');
  const outDir = path.join(process.cwd(), 'client_modules'); fs.mkdirSync(outDir, {recursive:true});
  if (selRes.loaderJscB64){ fs.writeFileSync(path.join(outDir, 'loader.jsc'), Buffer.from(selRes.loaderJscB64,'base64')); fs.writeFileSync(path.join(modDir, 'loader.context.json'), JSON.stringify(selRes.loaderContext));}
  if (selRes.moduleJscB64){ fs.writeFileSync(path.join(outDir, `${pick}.jsc`), Buffer.from(selRes.moduleJscB64,'base64')); }
  if (selRes.context){ fs.writeFileSync(path.join(outDir, `${pick}.context.json`), JSON.stringify(selRes.context,null,2)); }
  ui.addLog(chalk.green('Module artifacts saved to client_modules/.'));
  return { name: pick, context: selRes.context||{} };
}
