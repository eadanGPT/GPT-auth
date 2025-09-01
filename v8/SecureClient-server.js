// ==============================
// WS SECURE SERVER (Node.js)
// ==============================
// Packages: npm i express ws better-sqlite3 jose helmet morgan basic-auth crypto
import express from 'express';
import http from 'node:http';
import { WebSocketServer } from 'ws';
import basicAuth from 'basic-auth';
import helmet from 'helmet';
import morgan from 'morgan';
import Database from 'better-sqlite3';
import { randomBytes, createHash, generateKeyPairSync, sign, createPublicKey } from 'node:crypto';
import { SignJWT, importPKCS8, importSPKI, jwtVerify } from 'jose';
import path from 'node:path';
import fs from 'node:fs';

// ---------- Config ----------
const PORT = process.env.PORT || 8080;
const ADMIN_USER = 'Admin';
const ADMIN_PASS = 'Demo420';
const DATA_DIR = path.resolve(process.cwd(), 'server_data');
const PUBKEY_PATH = path.join(DATA_DIR, 'server_pub.pem');
const PRIVKEY_PATH = path.join(DATA_DIR, 'server_priv.pem');
const CLIENT_PUB_LOGS_PATH = path.join(DATA_DIR, 'client_logs_pub.pem'); // long-term pub for clients to encrypt/sign logs
const CLIENT_PRIV_LOGS_PATH = path.join(DATA_DIR, 'client_logs_priv.pem');
fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- Keys (server signing + client-logs keypair for distribution) ----------
function ensureKeys() {
  if (!fs.existsSync(PRIVKEY_PATH) || !fs.existsSync(PUBKEY_PATH)) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
    fs.writeFileSync(PRIVKEY_PATH, privateKey.export({ type: 'pkcs1', format: 'pem' }));
    fs.writeFileSync(PUBKEY_PATH, publicKey.export({ type: 'spki', format: 'pem' }));
  }
  if (!fs.existsSync(CLIENT_PRIV_LOGS_PATH) || !fs.existsSync(CLIENT_PUB_LOGS_PATH)) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
    fs.writeFileSync(CLIENT_PRIV_LOGS_PATH, privateKey.export({ type: 'pkcs1', format: 'pem' }));
    fs.writeFileSync(CLIENT_PUB_LOGS_PATH, publicKey.export({ type: 'spki', format: 'pem' }));
  }
}
ensureKeys();
const serverPrivatePem = fs.readFileSync(PRIVKEY_PATH, 'utf8');
const serverPublicPem  = fs.readFileSync(PUBKEY_PATH, 'utf8');
const clientLogsPublicPem = fs.readFileSync(CLIENT_PUB_LOGS_PATH, 'utf8');

// ---------- DB ----------
const db = new Database(path.join(DATA_DIR, 'app.sqlite'));
db.pragma('journal_mode = wal');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  keyHash TEXT UNIQUE,
  blacklisted INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY,
  keyHash TEXT,
  jwt TEXT,
  exp INTEGER,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  keyHash TEXT,
  hwid TEXT,
  temp_hwid TEXT,
  ip TEXT,
  started_at INTEGER,
  last_heartbeat INTEGER
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY,
  keyHash TEXT,
  type TEXT,
  ts INTEGER,
  blob BLOB
);
CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY,
  v TEXT
);
CREATE TABLE IF NOT EXISTS manifests (
  id INTEGER PRIMARY KEY,
  kind TEXT,
  path TEXT,
  sha256 TEXT,
  signed_hash TEXT
);
`);

// Defaults
const setSetting = db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v');
const getSetting = db.prepare('SELECT v FROM settings WHERE k=?');
setSetting.run('allowConnections','1');
setSetting.run('maxConnections','1000');
setSetting.run('clientVersion','1.0.0');

// ---------- Utils ----------
const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const nowSec = () => Math.floor(Number(process.hrtime.bigint()) / 1_000_000_000n);

async function issueJWT({ keyHash, hwid, sub='client', ttlDays=3 }) {
  const alg = 'RS256';
  const pkcs8 = serverPrivatePem;
  const privateKey = await importPKCS8(pkcs8, alg);
  const expSec = nowSec() + ttlDays * 24 * 60 * 60;
  const jwt = await new SignJWT({ kh: keyHash, hw: hwid })
    .setProtectedHeader({ alg })
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime(expSec)
    .sign(privateKey);
  db.prepare('INSERT INTO tokens(keyHash,jwt,exp,created_at) VALUES(?,?,?,?)').run(keyHash, jwt, expSec, nowSec());
  return jwt;
}

async function verifyJWT(jwt) {
  const spki = await importSPKI(serverPublicPem, 'RS256');
  return jwtVerify(jwt, spki, {});
}

function deriveSessionIdFromJWT(jwt) {
  const [h,p,s] = jwt.split('.');
  const material = Buffer.from(`sid:v3|${s}|${p}|${h}`);
  return b64url(createHash('sha256').update(material).digest());
}

// Track one active session per key owner
function canStartSession(keyHash) {
  const row = db.prepare('SELECT COUNT(*) AS c FROM sessions WHERE keyHash=?').get(keyHash);
  return (row?.c ?? 0) === 0;
}

function upsertSession({ sessionId, keyHash, hwid, temp_hwid, ip }) {
  db.prepare('INSERT OR REPLACE INTO sessions(id,keyHash,hwid,temp_hwid,ip,started_at,last_heartbeat) VALUES(?,?,?,?,?,?,?)')
    .run(sessionId, keyHash, hwid, temp_hwid, ip, nowSec(), nowSec());
}

function endSession(sessionId) {
  db.prepare('DELETE FROM sessions WHERE id=?').run(sessionId);
}

function recordLog({ keyHash, type, blob }) {
  db.prepare('INSERT INTO logs(keyHash,type,ts,blob) VALUES(?,?,?,?)').run(keyHash, type, nowSec(), blob);
}

// ---------- Express Admin ----------
const app = express();
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());

function adminAuth(req,res,next){
  const creds = basicAuth(req);
  if (!creds || creds.name !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.set('WWW-Authenticate','Basic realm="admin"'); return res.status(401).end('Access denied');
  }
  next();
}

app.get('/admin', adminAuth, (req,res)=>{
  res.send(`<!doctype html><html><body>
  <nav>
    <a href="#sessions">Sessions</a> | <a href="#keys">Keys</a> | <a href="#users">Users</a> | <a href="#logs">Logs</a> | <a href="#settings">Settings</a>
  </nav>
  <pre id="out"></pre>
  <script>
    async function load(){
      const s = await fetch('/admin/api/sessions').then(r=>r.json());
      const k = await fetch('/admin/api/keys').then(r=>r.json());
      const set = await fetch('/admin/api/settings').then(r=>r.json());
      document.getElementById('out').textContent = JSON.stringify({sessions:s,keys:k,settings:set}, null, 2);
    }
    load();
  </script>
  </body></html>`);
});

app.get('/admin/api/sessions', adminAuth, (req,res)=>{
  const rows = db.prepare('SELECT * FROM sessions').all();
  res.json(rows);
});
app.get('/admin/api/keys', adminAuth, (req,res)=>{
  const rows = db.prepare('SELECT id,keyHash,blacklisted FROM users').all();
  res.json(rows);
});
app.get('/admin/api/settings', adminAuth, (req,res)=>{
  const allow = getSetting.get('allowConnections')?.v ?? '1';
  const max = getSetting.get('maxConnections')?.v ?? '1000';
  const ver = getSetting.get('clientVersion')?.v ?? '1.0.0';
  res.json({ allow, max, ver, clientLogsPublicPem: ${JSON.stringify(clientLogsPublicPem)} });
});

// Provide server pubkey for clients
app.get('/server_pub.pem', (req,res)=>{ res.type('pem').send(serverPublicPem); });
app.get('/client_logs_pub.pem', (req,res)=>{ res.type('pem').send(clientLogsPublicPem); });

const server = http.createServer(app);

// ---------- WebSocket (wss) ----------
const wss = new WebSocketServer({ server, path: '/ws' });

function sendJSON(ws, obj){ ws.send(JSON.stringify(obj)); }

wss.on('connection', (ws, req) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  let authed = false;
  let sessionId = null;
  let keyHash = null;

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      // All frames are { token:'', data: encryptedBytes(base64) } — for brevity, accept {op,...}
      if (msg.op === 'hello') {
        // Client asks for pubkeys and server client version/manifests
        sendJSON(ws, { op:'hello_ok', serverPublicPem, clientLogsPublicPem, version: getSetting.get('clientVersion')?.v || '1.0.0' });
        return;
      }
      if (msg.op === 'claim_license') {
        // { licenseKeyHash, hwid }
        const { licenseKeyHash, hwid } = msg;
        if (!licenseKeyHash) return sendJSON(ws, { op:'claim_err', reason:'missing' });
        // Create user if not exists
        try { db.prepare('INSERT INTO users(keyHash,blacklisted) VALUES(?,0)').run(licenseKeyHash); } catch {}
        const u = db.prepare('SELECT blacklisted FROM users WHERE keyHash=?').get(licenseKeyHash);
        if (!u || u.blacklisted) return sendJSON(ws, { op:'claim_err', reason:'blacklisted' });
        const jwt = await issueJWT({ keyHash: licenseKeyHash, hwid });
        const sid = deriveSessionIdFromJWT(jwt);
        sendJSON(ws, { op:'claim_ok', token: jwt, sessionID: sid });
        recordLog({ keyHash: licenseKeyHash, type:'auth_attempt', blob: Buffer.from(`claimed ${nowSec()}`)});
        return;
      }
      if (msg.op === 'auth') {
        // { token, temp_hwid }
        const { token, temp_hwid } = msg;
        const { payload } = await verifyJWT(token);
        keyHash = payload.kh; const hwid = payload.hw;
        const sid = deriveSessionIdFromJWT(token);
        if (!canStartSession(keyHash)) { return sendJSON(ws, { op:'auth_err', reason:'active_session_exists' }); }
        authed = true; sessionId = sid;
        upsertSession({ sessionId: sid, keyHash, hwid, temp_hwid, ip });
        sendJSON(ws, { op:'auth_ok', sessionID: sid, token });
        recordLog({ keyHash, type:'auth_ok', blob: Buffer.from(JSON.stringify({ ip, temp_hwid })) });
        return;
      }
      if (msg.op === 'heartbeat') {
        if (!authed) return sendJSON(ws, { op:'err', reason:'not_authed' });
        db.prepare('UPDATE sessions SET last_heartbeat=? WHERE id=?').run(nowSec(), sessionId);
        // Generate challenge manifest
        const challenge = makeChallenge();
        // Store manifest (reuse policy not fully implemented here due to brevity)
        recordLog({ keyHash, type:'challenge', blob: Buffer.from(JSON.stringify(challenge)) });
        sendJSON(ws, { op:'challenge', challenge });
        return;
      }
      if (msg.op === 'challenge_answer') {
        const { solution } = msg; // client-solved vector
        // For demo, accept any and log; in production, recompute expected from earlier manifest
        recordLog({ keyHash, type:'challenge_answer', blob: Buffer.from(JSON.stringify({ solution })) });
        sendJSON(ws, { op:'challenge_ok' });
        return;
      }
      if (msg.op === 'integrity') {
        const { hashes } = msg; // { file: sha256 }
        // Compare vs manifests. If mismatch, request upload logs & close
        // Here we only log
        recordLog({ keyHash, type:'integrity', blob: Buffer.from(JSON.stringify(hashes)) });
        sendJSON(ws, { op:'integrity_ok' });
        return;
      }
      if (msg.op === 'upload_logs') {
        const { blobB64 } = msg; // already encrypted to clientLogsPublicPem by client
        const buf = Buffer.from(blobB64, 'base64');
        recordLog({ keyHash, type:'client_logs', blob: buf });
        sendJSON(ws, { op:'upload_ok' });
        return;
      }
    } catch (e) {
      try { recordLog({ keyHash: keyHash||'unknown', type:'error', blob: Buffer.from(String(e)) }); } catch {}
      try { ws.send(JSON.stringify({ op:'err', reason: e?.message || 'bad' })); } catch {}
      try { ws.close(); } catch {}
    }
  });

  ws.on('close', () => { if (sessionId) endSession(sessionId); });
});

server.listen(PORT, () => console.log('Server listening on', PORT));

// ---------- Challenge generator (server side mirror; also used by client) ----------
function randInt(min, max) { return Math.floor(Math.random()*(max-min+1))+min; }
function makeTerm(){
  const kinds = ['ALG2','ALG1','ADD','SUB','ADDM','SUBM','MUL','DIV','POW','MOD','FACT','SEMI'];
  const kind = kinds[randInt(0,kinds.length-1)];
  const a=randInt(2,97),b=randInt(2,97),c=randInt(1,97),base=randInt(2,9),exp=randInt(2,7);
  switch(kind){
    case 'ALG2': return { repr:`${a}x+${b}y=${c}`, solve:(x=1,y=1)=>c-a*x-b*y };
    case 'ALG1': return { repr:`${a}x+${b}=${c}`, solve:()=> (c-b)/a };
    case 'ADD': return { repr:`${a}+${b}`, solve:()=>a+b };
    case 'SUB': return { repr:`${a}-${b}`, solve:()=>a-b };
    case 'ADDM': return { repr:`${a}+${b}+${c}`, solve:()=>a+b+c };
    case 'SUBM': return { repr:`${a}-${b}-${c}`, solve:()=>a-b-c };
    case 'MUL': return { repr:`${a}*${b}`, solve:()=>a*b };
    case 'DIV': return { repr:`${a}/${b}`, solve:()=>a/b };
    case 'POW': return { repr:`${base}^${exp}`, solve:()=>Math.pow(base,exp) };
    case 'MOD': { const add=randInt(0,11),mod=randInt(5,97); return { repr:`((${base}^${exp})+${add})%${mod}`, solve:()=> (Math.pow(base,exp)+add)%mod }; }
    case 'FACT': { const n=randInt(12,1024); return { repr:`factor(${n})`, solve:()=>{ for(let i=2;i*i<=n;i++){ if(n%i===0) return [i,n/i]; } return [1,n]; } }; }
    case 'SEMI': { const p=[101,103,107,109,113][randInt(0,4)], q=[127,131,137,139,149][randInt(0,4)]; const n=p*q; return { repr:`semiprime(${n})`, solve:()=>[p,q] }; }
  }
}
function makeChallenge(){ const vars=randInt(4,10); const terms=Array.from({length:vars},makeTerm); return { combined: terms.map(t=>t.repr).join(' + '), solution: terms.map(t=>t.solve()) }; }


// ==============================
// WS SECURE CLIENT (Node.js)
// ==============================
// Packages: npm i ws jose express open
import { WebSocket } from 'ws';
import express from 'express';
import open from 'open';
import { randomBytes, createCipheriv, createDecipheriv, scryptSync, createHash, publicEncrypt } from 'node:crypto';
import os from 'node:os';

// ---------- Shared helpers ----------
const nowNsC = () => process.hrtime.bigint();
const nowSecC = () => Number(nowNsC()/1000000000n);
const sha256hexC = (b) => createHash('sha256').update(b).digest('hex');
const b64u = (b) => Buffer.from(b).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
function aesGcmEnc(key, pt){ const iv=randomBytes(12); const c=createCipheriv('aes-256-gcm',key,iv); const ct=Buffer.concat([c.update(pt),c.final()]); const tag=c.getAuthTag(); return Buffer.concat([iv,tag,ct]); }
function aesGcmDec(key, p){ const iv=p.subarray(0,12),tag=p.subarray(12,28),ct=p.subarray(28); const d=createDecipheriv('aes-256-gcm',key,iv); d.setAuthTag(tag); return Buffer.concat([d.update(ct),d.final()]); }

// ---------- createEncryptedExpression (fixed) ----------
export function createEncryptedExpression(str){
  function obNum(n){const lg=Math.max(1,Math.floor(Math.log2(Math.max(2,n))));const v=[`(${n>>1}<<1|${n&1})`,`(~${~n})`,`((1<<${lg})+${n-(1<<lg)})`,`(${n}^0)`,`(((${n>>1}<<1)|(${n&1})) + (~${~n}))`,`((~${~n}) ^ (${n}^0))`,`((((1<<${lg}) + ${n-(1<<lg)}) + ((1<<${lg}) + ${n-(1<<lg)})) >> 1)`,`(((${n}^0) + (${n>>1}<<1|${n&1})) - ${n}) + ${n}`];return v[Math.floor(Math.random()*v.length)];}
  const codes = Array.from(str).map(ch=>obNum(ch.charCodeAt(0)));
  const body = `return ((str.at(0).charCodeAt(0)**2+1)%2)===1 ? (0>>1) : String.fromCharCode.apply(null,[${codes.join(',')}]);`;
  return new Function('str', body).bind(null, str);
}

// ---------- Client storage (disk) ----------
import fsC from 'node:fs';
import pathC from 'node:path';
const DATA_DIR_C = pathC.resolve(process.cwd(), '.client');
const CFG_PATH = pathC.join(DATA_DIR_C, 'config.json');
const TOK_PATH = pathC.join(DATA_DIR_C, 'token.bin');
fsC.mkdirSync(DATA_DIR_C,{recursive:true});

function loadCfg(){ if(fsC.existsSync(CFG_PATH)) return JSON.parse(fsC.readFileSync(CFG_PATH,'utf8')); const c={ clientKeyHash:null, tempKey:null, serverPubPem:null, clientLogsPubPem:null }; fsC.writeFileSync(CFG_PATH, JSON.stringify(c,null,2)); return c; }
function saveCfg(c){ fsC.writeFileSync(CFG_PATH, JSON.stringify(c,null,2)); }

// ---------- HWIDs ----------
async function getPermanentHWID(){ const cpu=os.cpus()?.map(c=>`${c.model}:${c.speed}`).join('|')||'cpu'; const mem=String(os.totalmem()); const plat=`${os.platform()}-${os.release()}-${os.arch()}`; const host=os.hostname(); const macs=Object.values(os.networkInterfaces()).flat().filter(Boolean).map(i=>i.mac).filter(m=>m&&m!=='00:00:00:00:00:00').sort().join(','); return sha256hexC(Buffer.from(`${cpu}|${mem}|${plat}|${host}|${macs}`)); }
async function getTempHWID(){ const addrs=Object.values(os.networkInterfaces()).flat().filter(Boolean).map(i=>i.address).sort().join(','); const boot=Number(os.uptime()); const guess=nowSecC()-boot; return sha256hexC(Buffer.from(`${addrs}|${guess}`)); }

// ---------- Runtime KDF (never persisted) ----------
function processEntropySalt(){ const rnd=randomBytes(32); const mem=Buffer.from(String(process.memoryUsage().heapUsed)); const env=Buffer.from(os.platform()+os.release()+os.arch()); const hr=Buffer.from(nowNsC().toString()); return createHash('sha256').update(Buffer.concat([rnd,mem,env,hr])).digest(); }
function kdfRuntime(clientKeyHash, salt){ return scryptSync(Buffer.from(String(clientKeyHash)), salt, 32); }

class Sealed {
  constructor(key, value){ this.k=key; this.s=aesGcmEnc(key, value); }
  reveal(){ const v=aesGcmDec(this.k,this.s); this.s=aesGcmEnc(this.k,v); return v; }
  wipe(){ this.s.fill(0); this.k.fill(0); }
}

// ---------- Client main ----------
export async function runClient({ serverUrl='ws://localhost:8080/ws' }={}){
  const cfg = loadCfg();
  // Open WS
  const ws = new WebSocket(serverUrl);

  // State
  let runtimeKey=null, sealedToken=null, jwtExp=0, sessionID=null, heartbeatTimer=null, integrityTimer=null;
  const logsMem=[]; // in-memory until uploaded

  const permanentHWID = await getPermanentHWID();
  const tempHWID = await getTempHWID();

  function ensureClientKeyHash(){
    if (cfg.clientKeyHash) return cfg.clientKeyHash;
    // No key => launch minimal UI to claim license
    serveLocalUI();
    return null;
  }

  function saveTokenAtRest(token){
    const atRestKey = scryptSync(Buffer.from(String(cfg.clientKeyHash+permanentHWID)), Buffer.from('at-rest-v1'), 32);
    const sealed = aesGcmEnc(atRestKey, Buffer.from(token));
    fsC.writeFileSync(TOK_PATH, sealed, { mode:0o600 });
  }
  function loadTokenAtRest(){
    if (!fsC.existsSync(TOK_PATH)) return null;
    try { const atRestKey = scryptSync(Buffer.from(String(cfg.clientKeyHash+permanentHWID)), Buffer.from('at-rest-v1'), 32); const sealed=fsC.readFileSync(TOK_PATH); return aesGcmDec(atRestKey, sealed).toString('utf8'); } catch { try{fsC.unlinkSync(TOK_PATH);}catch{} return null; }
  }

  function wrapInCreateEncryptedExpression(str){
    // After encrypting token, we also wrap the string with createEncryptedExpression per spec
    return createEncryptedExpression(str); // returns callable; we store the callable under AES wrap
  }

  function logMem(type, data){ logsMem.push({ type, ts: nowSecC(), data }); }

  // Hybrid enc for logs to server's provided clientLogsPublicPem
  function encryptForServerLogs(plaintext){
    const pub = cfg.clientLogsPubPem; if(!pub) return Buffer.from(plaintext);
    const aes = randomBytes(32); const sealed = aesGcmEnc(aes, Buffer.from(plaintext));
    const encKey = publicEncrypt({ key: pub, oaepHash:'sha256' }, aes); aes.fill(0);
    return Buffer.from(JSON.stringify({ k:b64u(encKey), d:b64u(sealed) }));
  }

  function startSchedulers(){
    stopSchedulers();
    heartbeatTimer = setInterval(()=> heartbeat().catch(()=>{}), 120_000);
    integrityTimer = setInterval(()=> integrity().catch(()=>{}), 300_000);
    heartbeat(); integrity();
  }
  function stopSchedulers(){ if(heartbeatTimer) clearInterval(heartbeatTimer); if(integrityTimer) clearInterval(integrityTimer); }

  async function heartbeat(){
    const now = nowSecC();
    if (!sealedToken || !sessionID || now >= jwtExp){
      // upload logs and exit
      await uploadAndClearLogs();
      process.exit(1);
    }
    ws.send(JSON.stringify({ op:'heartbeat', token:'', data:'' }));
  }

  async function integrity(){
    // Hash this file only for brevity; expand to your app files
    const f = process.argv[1];
    let buf; try{ buf=fsC.readFileSync(f);}catch{buf=Buffer.alloc(0);} const h = sha256hexC(buf);
    ws.send(JSON.stringify({ op:'integrity', hashes: { [f]: h } }));
  }

  async function uploadAndClearLogs(){
    if (!logsMem.length) return;
    const blob = Buffer.from(JSON.stringify(logsMem));
    const sealed = encryptForServerLogs(blob);
    ws.send(JSON.stringify({ op:'upload_logs', blobB64: Buffer.from(sealed).toString('base64') }));
    logsMem.length=0;
  }

  ws.on('open', ()=>{
    ws.send(JSON.stringify({ op: 'hello' }));
  });

  ws.on('message', async (raw) => {
    const msg = JSON.parse(raw.toString());
    if (msg.op === 'hello_ok'){
      cfg.serverPubPem = msg.serverPublicPem; cfg.clientLogsPubPem = msg.clientLogsPublicPem; saveCfg(cfg);
      const kh = ensureClientKeyHash();
      if (!kh) return; // UI launched
      // runtime key
      runtimeKey = kdfRuntime(kh, processEntropySalt());
      // Try token from disk, else require claim flow
      const diskTok = loadTokenAtRest();
      if (diskTok){ await authenticateWithToken(diskTok); }
      else { serveLocalUI(); }
    }
    if (msg.op === 'claim_ok'){
      const { token, sessionID: sid } = msg; await authenticateWithToken(token, sid);
    }
    if (msg.op === 'auth_ok'){
      // ready; start schedulers
      startSchedulers();
    }
    if (msg.op === 'auth_err'){
      logMem('auth_err', msg); await uploadAndClearLogs(); process.exit(1);
    }
    if (msg.op === 'challenge'){
      const sol = msg.challenge.solution; // local solve already provided in server; in real flow recompute
      ws.send(JSON.stringify({ op:'challenge_answer', solution: sol }));
      logMem('challenge', msg.challenge);
    }
    if (msg.op === 'challenge_ok'){
      // ok
    }
    if (msg.op === 'integrity_ok'){
      // ok
    }
    if (msg.op === 'upload_ok'){
      // logs uploaded
    }
  });

  ws.on('close', async ()=>{
    stopSchedulers();
    // allow 1 reconnect attempt after 15s else exit
    await new Promise(r=>setTimeout(r,15000));
    try { await runClient({ serverUrl }); } catch { process.exit(1); }
  });

  async function authenticateWithToken(token, preSid){
    // parse exp (best-effort) and derive sessionID
    const payloadB64 = token.split('.')[1]||''; const payload=JSON.parse(Buffer.from(payloadB64,'base64url').toString('utf8'));
    jwtExp = payload.exp || 0;
    const sid = preSid || b64u(createHash('sha256').update(Buffer.from(`sid:v3|${token.split('.')[2]}|${payload.sub||''}|${payload.exp||0}`)).digest());
    sessionID = sid;

    // Save token at rest, and protect in memory: seal+wrap with createEncryptedExpression
    const callWrapped = wrapInCreateEncryptedExpression(token); // returns callable
    const sealed = new Sealed(runtimeKey, Buffer.from(String(callWrapped)));
    sealedToken = sealed; // store callable-as-string sealed; we don't persist runtime key
    saveTokenAtRest(token);

    ws.send(JSON.stringify({ op:'auth', token, temp_hwid: await getTempHWID() }));
  }

  // -------------- Minimal local UI (only when no key present) --------------
  function serveLocalUI(){
    const ui = express(); ui.use(express.urlencoded({extended:true}));
    ui.get('/',(req,res)=>{
      res.send(`<!doctype html><meta charset='utf-8'><title>Enter License</title>
      <style>body{font-family:system-ui;display:grid;place-items:center;height:100vh;background:#0b1220;color:#e6edf3} form{background:#0f172a;padding:24px;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)} input{padding:10px 12px;border-radius:10px;border:1px solid #334155;background:#111827;color:#e6edf3;width:300px} button{margin-top:12px;padding:10px 14px;border-radius:10px;border:0;background:#2563eb;color:#fff;font-weight:600;width:100%}</style>
      <form method='POST' action='/claim'><h2>Activate</h2><p>Enter License Key</p>
      <input name='key' placeholder='XXXX-XXXX-XXXX-XXXX' required>
      <button type='submit'>Claim</button></form>`);
    });
    ui.post('/claim', (req,res)=>{
      const key = String(req.body.key||'');
      const kh = sha256hexC(Buffer.from(key)); cfg.clientKeyHash = kh; cfg.tempKey = null; saveCfg(cfg);
      ws.send(JSON.stringify({ op:'claim_license', licenseKeyHash: kh, hwid: permanentHWID }));
      res.send('<p>Claiming… you can close this tab.</p>');
      setTimeout(()=>{ try { opener && opener.close && opener.close(); } catch{} }, 500);
    });
    const port = 7777; ui.listen(port, ()=>{ open(`http://localhost:${port}/`); });
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) { runClient().catch(err=>{ console.error(err); process.exit(1); }); }
