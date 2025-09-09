
/**
 * Server Version 2.0.0 (secure envelopes)
 * - ECDH handshake first (x25519)
 * - ALL subsequent frames are encrypted "env" messages using rotating AES-GCM
 * - Module responses are additionally sealed inside the envelope with a module-specific AES-GCM key
 * - Chunking preserved at transport level for large JSON frames
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import selfsigned from 'selfsigned';
import https from 'node:https';
import bytenode from 'bytenode';
import { WebSocketServer } from 'ws';
import dotenv from 'dotenv';
import ModuleRegistry from './server/lib/moduleRegistry.js';
import * as Audit from './server/lib/audit.js';
import * as RateLimiter from './server/lib/rateLimiter.js';
import * as TokenService from './server/lib/tokenService.js';
import * as LicenseStore from './server/lib/licenseStore.js';
import * as CircuitBreaker from './server/lib/CircuitBreaker.js';
import * as KeyManager from './server/lib/KeyManager.js';
ModuleRegistry.ensureCompiled()
//const { checkPassword, listUserLicenses, checkLicenseForUser, isRevoked, revokeLicense, createUser, claimLicense, createKey, getKey, claimKey, getScopesForKey, db } = await LicenseStore.init();
dotenv.config();
Audit.log('[SYS::DEBUG::MODULES]',JSON.stringify([ModuleRegistry, RateLimiter, TokenService, LicenseStore, CircuitBreaker, KeyManager, Audit]))
/*
class Audit{
	Log = ([...a])=>Audit.log(`[${a.length > 0 && a.splice(a.length) || 'LOG'}] ${a} `);
	Warn = (...a)=>self.Log(...a, 'Warn');
	Error = (...a)=>self.Log(...a, 'Error');
}
*/
// ---- Config ----
const ROOT = path.resolve(process.cwd(), 'server');
const MANIFEST_PATH = process.env.MODULE_MANIFEST || path.join(ROOT, 'modules.manifest.json');
const WORKER_PATH = process.env.WORKER_PATH || path.join(ROOT, '..', 'client.worker.js');
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const TLS_KEY = process.env.TLS_KEY || path.join('certs','server.key');
const TLS_CERT = process.env.TLS_CERT || path.join('certs','server.crt');
const TOKEN_REQUIRED = process.env.TOKEN_REQUIRED === '1';
const MAX_CHUNK = 64 * 1024;

// Ensure certs folder exists
fs.mkdirSync(path.dirname(TLS_KEY), { recursive: true });
// Generate self-signed key + cert if missing
if (!fs.existsSync(TLS_KEY) || !fs.existsSync(TLS_CERT)) {
  //Audit.Log('TLS key/cert not found, generating self-signed certificate...', 'WARN');

  const attrs = [{ name: 'commonName', value: '127.0.0.1' }];
  const pems = selfsigned.generate(attrs, { days: 365*2,
		keySize: 2048,
		extensions: [{ name: 'basicConstraints', cA: true }],
		altNames: [
		  { type: 2, value: 'localhost' },   // DNS
		  { type: 7, ip: '127.0.0.1' }       // IP
		]  
	});

  fs.writeFileSync(TLS_KEY, pems.private);
  fs.writeFileSync(TLS_CERT, pems.cert);

  //Audit.Log('TLS key and cert generated.', "SUCC");
}

// ---- Utils ----FV
const now = ()=>Date.now();
const canonical = (obj)=>{
  const sort=(x)=>Array.isArray(x)?x.map(sort):(x&&typeof x==='object')?Object.keys(x).sort().reduce((o,k)=>(o[k]=sort(x[k]),o),{}):x;
  return JSON.stringify(sort(obj));
};
const sha256hex = (buf)=>crypto.createHash('sha256').update(buf).digest('hex');
let PUBLIC_KEY_PEM, PRIVATE_KEY_PEM;
try {
  if (process.env.LOADER_SIGN_PRIV && process.env.LOADER_SIGN_PUB) {
    PRIVATE_KEY_PEM = process.env.LOADER_SIGN_PRIV;
    PUBLIC_KEY_PEM = process.env.LOADER_SIGN_PUB;
  } else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    PUBLIC_KEY_PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    PRIVATE_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  }
} catch {}
function signObject(obj) {
  const { sig, ...bare } = obj || {};
  const data = Buffer.from(JSON.stringify(bare));
  const key = crypto.createPrivateKey(PRIVATE_KEY_PEM);
  const sigBuf = crypto.sign(null, data, key);
  return sigBuf.toString('base64');
}
// ---- Manifest ----
class ManifestService{
  static computeSha256ForModule(name){
    try { const p = path.join('server','modules', name+'.jsc'); if (!fs.existsSync(p)) return null;
      const buf = fs.readFileSync(p); return crypto.createHash('sha256').update(buf).digest('hex'); } catch { return null; } }
  static toMap(modulesArr){
    const out = {}; for (const m of modulesArr){
      out[m.name] = { description: m.description||'', permissions: m.permissions||[], context: m.context||{}, version: m.version||1 };
    } return out; }
  static filterByScopes(mf, scopes){
    const arr = mf.modules || mf;
    const filtered = (Array.isArray(arr)?arr:Object.keys(arr).map(k=>({ name:k, ...(arr[k]||{}) })))
      .filter(m=>!(m.permissions&&m.permissions.length) || m.permissions.some(p=>scopes.includes(p)))
      .map(m=>({ ...m, sha256: ManifestService.computeSha256ForModule(m.name) }));
    const asMap = {}; for (const m of filtered){ asMap[m.name] = { description:m.description||'', permissions:m.permissions||[], context:m.context||{}, version:m.version||1, sha256:m.sha256 }; }
    return { version: mf.version || '1', modules: asMap }; }
  static get(){
	const dir = path.join(ROOT, 'modules');
	const files = fs.readdirSync(dir).filter(f => f.endsWith('.jsc') || f.endsWith('.js'));

	const modules = files.map(f=>{
	const name = path.basename(f, path.extname(f));
	const filePath = path.join(dir, f);
	const buf = fs.readFileSync(filePath);

	// Default description
	let description = '';

	// Try to extract "description: '...'" from source text (only if it’s text, not bytecode)
	try {
	  const text = buf.toString('utf8');
	  const m = text.match(/description:\s*'([^']*)'/);
	  if (m) description = m[1];
	} catch {
	  /* if it’s bytecode, .toString() may fail — ignore */
	}

	return {
	  name,
	  description,
	  permissions: ['user'],      // default or extend later
	  context: { version: '1.7.0' },
	  sha256: sha256hex(buf)
	};
	});

	const mf = { version: '1.7.0', modules };

	// Optional: write it out for reference
	try { fs.writeFileSync(MANIFEST_PATH, JSON.stringify(mf,null,2)); } catch {}

	return mf;
  };

  static module(id){
	  //Audit.Log("Manifest being delivered");
    const mf = this.get();
    return mf.modules?.[id] || mf[id] || null;
  }
}

// ---- Logging ----
class RpcLogger{
  static last='0'.repeat(64);
  static file=process.env.RPC_LOG || path.join(ROOT,'logs','rpc.log');
  static append(obj){
    const line = JSON.stringify({ ...obj, prev:this.last, ts: now() });
    this.last = sha256hex(Buffer.from(line));
    fs.mkdirSync(path.dirname(this.file),{recursive:true});
    fs.appendFileSync(this.file, line+'\n', 'utf8');
  }
}

// ---- Chunked send (plaintext or encrypted frames) ----
function sendJSON(ws, obj){
  const str = JSON.stringify(obj);
  const buf = Buffer.from(str);
  if (buf.length <= MAX_CHUNK) return ws.send(str);
  const id = crypto.randomUUID();
  const total = Math.ceil(buf.length / MAX_CHUNK);
  for (let i=0;i<total;i++){
    const part = buf.subarray(i*MAX_CHUNK,(i+1)*MAX_CHUNK);
    ws.send(JSON.stringify({ typ:'chunk', id, i, total, b64: part.toString('base64') }));
  }
}

// Helper to get raw public key bytes (32 bytes for X25519) without export
function getRawPublic(keyObject) {
  if (keyObject.asymmetricKeyType !== 'x25519') throw new Error('Only for x25519');
  const tempEcdh = crypto.createECDH('x25519');
  tempEcdh.setPrivateKey(keyObject.export({ type: 'pkcs8', format: 'der' }));  // Valid DER export for private
  return tempEcdh.getPublicKey();  // Returns raw 32-byte Buffer for X25519
}
// ---- Sessions (ECDH + rotating envelopes) ----
function hkdf(keyMaterial, salt, info, length){
  return crypto.hkdfSync('sha256', keyMaterial, salt, info, length);
}
function u64(n){
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b;
}
class Session {
  constructor(){
    // ephemeral ECDH with X25519 (modern KeyObjects)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    // Extract raw 32-byte pubkey: SPKI DER is fixed 44 bytes (12 header + 32 raw)
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    this.serverPub = spkiDer;//.slice(12);  // Raw 32 bytes
    this.serverPriv = privateKey;  // Full KeyObject for diffieHellman
    this.serverNonce = crypto.randomBytes(16);
    this.established = false;
    // derived keys
    this.prk = null;
    this.k_c2s = null; this.k_s2c = null;
    this.ivsalt_c2s = null; this.ivsalt_s2c = null;
    // rotation
    this.sendSeq = 0; this.recvSeq = 0;
  }
  derive(shared, clientNonce){
    const salt = Buffer.concat([clientNonce, this.serverNonce]);
    this.prk = hkdf(shared, salt, Buffer.from('session-prk'), 32);
    this.k_c2s = hkdf(this.prk, Buffer.from('c2s-key'), Buffer.from('env'), 32);
    this.k_s2c = hkdf(this.prk, Buffer.from('s2c-key'), Buffer.from('env'), 32);
    this.ivsalt_c2s = hkdf(this.prk, Buffer.from('c2s-iv'), Buffer.from('env'), 12);
    this.ivsalt_s2c = hkdf(this.prk, Buffer.from('s2c-iv'), Buffer.from('env'), 12);
    this.established = true;
    Audit.log('[Server Session] Derived keys successfully');
  }
  oneTime(dir, seq){
    const keyBase = dir==='s2c'? this.k_s2c : this.k_c2s;
    const ivSalt = dir==='s2c'? this.ivsalt_s2c : this.ivsalt_c2s;
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
    return { typ:'env', seq, dir, iv: iv.toString('hex'), ct: ct.toString('base64'), tag: tag.toString('hex') };
  }
  decrypt(dir, envMsg){
    const { seq, iv, ct, tag } = envMsg;
    if (typeof seq!=='number') throw new Error('missing seq');
    const { oneKey, iv: expectIv } = this.oneTime(dir, seq);
    const ivBuf = Buffer.from(iv, 'hex');
    if (!ivBuf.equals(expectIv)) throw new Error('iv mismatch');
    const decipher = crypto.createDecipheriv('aes-256-gcm', oneKey, ivBuf);
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    const pt = Buffer.concat([decipher.update(Buffer.from(ct,'base64')), decipher.final()]).toString('utf8');
    return JSON.parse(pt);
  }
  moduleKey(moduleId, nonceBuf){
    return hkdf(this.prk, Buffer.concat([Buffer.from(String(moduleId)), nonceBuf]), Buffer.from('module-key'), 32);
  }
}
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
// ---- HTTPS + WSS ----
const httpsServer = https.createServer({
  key: fs.readFileSync(TLS_KEY),
  cert: fs.readFileSync(TLS_CERT),
  minVersion: 'TLSv1.3',
  allowHTTP1: true, rejectUnauthorized: false 
}, (req, res)=>{ res.writeHead(200); res.end('ok'); });
httpsServer.on('connection', (socket) => {
	  // Read raw bytes from the socket
  // set client.ip to socket.remoteAddress here.;
  Audit.log('New TCP connection from', socket.remoteAddress);
});
const wss = new WebSocketServer({ server: httpsServer, rejectUnauthorized: false  });

// --- Strict Envelope Handling (v1) ---
import Ajv from 'ajv';
const ajvSrv = new Ajv({allErrors:true, strict:true});
const srvEnvelopeSchema = { $schema:'http://json-schema.org/draft-07/schema#', type:'object', additionalProperties:false,
  required:['v','t','op','nonce','data'],
  properties:{ v:{type:'integer', enum:[1]},
    t:{type:'string', enum:['auth.register','auth.login','auth.resume','module.list','module.select','telemetry','ack','error']},
    op:{type:'string', enum:['REQ','RES','EVT']},
    nonce:{type:'string', minLength:1},
    data:{type:'object'} } };
const validateSrvEnvelope = ajvSrv.compile(srvEnvelopeSchema);

async function handleEnvelope(ws, payload, session, envHandlers){
  if (!validateSrvEnvelope(payload)) return sendEnc(ws, { typ:'error', error:'bad_envelope' });
  const { t, nonce, data } = payload;
  const res = await (envHandlers[t] ? envHandlers[t](ws, data, session) : null);
  const out = { v:1, t, op:'RES', nonce, data: res || {} };
  sendEnc(ws, out);
}


// ---- Helpers ----
function clientIp(req) {
  // prefer X-Forwarded-For if behind proxy
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
} // return (req.socket.remoteAddress || req.headers['x-forwarded-for']||'').split(',')[0].trim() || 'unknown'; }
function requireAuthOrReject(ws){
  if (!TOKEN_REQUIRED) return true;
  if (ws.__authed) return true;
  sendJSON(ws, ws.__session.encrypt('s2c', { typ:'error', error:'unauthorized' }));
  return false;
}
function sendEnc(ws, payload) {
  if (!ws.__session?.established) throw new Error('Session not established');
  const frame = ws.__session.encrypt('s2c', payload);
  ws.send(JSON.stringify(frame));
}
// ---- Handlers (operate on *decrypted* payloads) ----
const handlers = {
  register(ws, _req, msg){
    try {
      const key = String(msg.key || '');
      const password = String(msg.password || '');
      if (!key || !password) throw new Error('invalid');
      const token = TokenService?.mint ? TokenService.mint({ sub:key, scope:['basic'] }) : `demo.${crypto.randomUUID()}`;
      sendEnc(ws, { typ:'ok', token });
    } catch {
      sendEnc(ws, { typ:'error', error:'register_failed' });
    }
  },
  login(ws, _req, msg){
    try {
      const key = String(msg.key || '');
      const password = String(msg.password || '');
      if (!key || !password) throw new Error('invalid');
      const token = TokenService?.mint ? TokenService.mint({ sub:key, scope:['basic'] }) : `demo.${crypto.randomUUID()}`;
      sendEnc(ws, { typ:'ok', token });
    } catch {
      sendEnc(ws, { typ:'error', error:'login_failed' });
    }
  },
  auth(ws, _req, msg){
    try {
      const token = String(msg.token || '');
      const claims = TokenService?.verify ? TokenService.verify(token) : { sub:'anon', scope:[] };
      const ok = LicenseStore?.check ? LicenseStore.check(claims.sub || claims.uid || 'anon') : true;
      if (!ok) throw new Error('license_invalid');
      ws.__authed = true;
      ws.__claims = claims;
      sendEnc(ws, { typ:'ok', sub: claims.sub });
    } catch {
      sendEnc(ws, { typ:'error', error:'auth_failed' });
    }
  },
  get_manifest(ws){
	if (!requireAuthOrReject(ws)) return;
	const raw = ManifestService.get();
	const scopes = ws.__scopes || [];
	const mf = ManifestService.filterByScopes(raw, scopes);

	// compute manifest-wide hash
	const manifestHash = sha256hex(Buffer.from(canonical(mf.modules)));

	sendEnc(ws, { typ:'manifest', manifestHash, ...mf });
  },
  get_module(ws, req, msg){
    if (!requireAuthOrReject(ws)) return;
    try {
      const raw = ManifestService.get();
      const scopes = ws.__scopes || [];
      const mf = ManifestService.filterByScopes(raw, scopes);
      const meta = mf.modules?.[msg.moduleId];
      if (!meta) return sendEnc(ws, { typ:'error', error:'forbidden' });
      const bytes = ModuleRegistry?.loadCompiled ? ModuleRegistry.loadCompiled(msg.moduleId)
        : fs.readFileSync(path.join(ROOT, 'modules', meta.file));
		// Build signed module context (permissions + integrity)
	  const context = {
	    name: msg.moduleId,
	    issued: Date.now(),
	    exp: Date.now() + 15 * 60 * 1000,
	    permissions: (meta.runtime ? meta.runtime : { fs:false, env:false, child_process:false, allowModules:[], network:[] }),
	    hash: sha256hex(bytes),
	    pub: PUBLIC_KEY_PEM
	  };
	  context.sig = signObject(context);
	  // log
	  Audit.log('module.load', { user: ws.__username, module: moduleId });
      // inner module sealing
      const nonce = crypto.randomBytes(16);
      const mKey = ws.__session.moduleKey(msg.moduleId, nonce);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', mKey, iv);
      const enc = Buffer.concat([cipher.update(bytes), cipher.final()]);
      const tag = cipher.getAuthTag();
      const payload = {
	    typ: 'module',
	    moduleId: msg.moduleId,
	    inner: {
	  	encB64: enc.toString('base64'),
	  	iv: iv.toString('hex'),
	  	tag: tag.toString('hex'),
	  	nonce: nonce.toString('hex')
	    },
	    sha256: sha256hex(bytes),
	    rpc_chunks: meta.rpc_chunks || [],
	    exp: meta.exp || undefined,
	    context
	  };
	  
      sendEnc(ws, payload);
    } catch (e){
	  Audit.log('error', { message: e.message, stack: e.stack, ip: clientIp(ws) });
  
      sendEnc(ws, { typ:'error', error:'module_failed' });
    }
  },
  getWorker(ws){
    if (!requireAuthOrReject(ws)) return;
    try {
      const code = fs.readFileSync(WORKER_PATH);
      sendEnc(ws, { typ:'client_worker', codeB64: code.toString('base64'), sha256: sha256hex(code) });
    } catch {
      sendEnc(ws, { typ:'error', error:'no_worker' });
    }
  },
  rpc(ws, _req, msg){
    if (!requireAuthOrReject(ws)) return;
    RpcLogger.append({ dir:'rpc', msg });
    sendEnc(ws, { typ:'ok' });
  }
};

// ---- Connection lifecycle ----
wss.on('connection', (ws, req)=>{
  const ip = clientIp(req);
  Audit.log('ws.connect', { ip: ip, time: Date.now() });
  RpcLogger.append({ dir:'event', ev:'open', ip: ip });
  ws.__session = new Session();
  ws.__authed = !TOKEN_REQUIRED;
  ws.__ip = ip;
  // Expect initial plaintext hello from client
  ws.on('message', (raw)=>{
    // handle chunk reassembly if needed
    let obj;
    try { obj = JSON.parse(raw.toString()); } catch (err){ 
		Audit.log('message.noObject', { message: err.message, stack: err.stack, ip: clientIp(ws) });
		return; 
	}

    // Chunk passthrough (plaintext, before session established)
    if (obj?.typ === 'chunk' && obj?.b64) {
      // In this minimal implementation, handshake messages are small; ignore chunking here.
      return;
    }

    // Handshake phase: client -> hello
    if (!ws.__session) ws.__session = new Session();  // Ensure session exists
	if (obj?.typ === 'hello' && obj.clientPub && obj.clientNonce) {
	  Audit.log('[Hello_Handshake::Debug] Received hello, computing shared secret...');
	  try {
		const clientPubRaw = Buffer.from(obj.clientPub, 'hex');
		if (clientPubRaw.length !== 44) throw new Error(`Invalid client pubkey length: ${clientPubRaw.length} (expected 32)`);
		
		// Modern diffieHellman: Create temp KeyObject for client's public key
		const clientPubKey = crypto.createPublicKey({
		  key: clientPubRaw,
		  format: 'der',
		  type: 'spki'
		});
		
		// Compute shared secret using server's private KeyObject and client's public KeyObject
		const shared = crypto.diffieHellman({
		  privateKey: ws.__session.serverPriv,
		  publicKey: clientPubKey
		});
		Audit.log('[Hello_Handshake::Debug] Shared secret computed, length:', shared.length);
		
		ws.__session.derive(shared, Buffer.from(obj.clientNonce, 'hex'));
		
		// Send hello_ack (plaintext, raw pub as hex)
		sendJSON(ws, {
		  typ: 'hello_ack',
		  serverPub: ws.__session.serverPub.toString('hex'),  // 64 hex chars
		  serverNonce: ws.__session.serverNonce.toString('hex')
		});
		Audit.log('[Hello_Handshake::Debug]', 'Sent hello_ack');
	  } catch (e) {
		Audit.log('[Hello_Handshake::Error]','ECDH failed:', e.message);
		ws.close(1002, 'Handshake error');
	  }
	  return;
}
Audit.log(JSON.stringify(obj))
    // Encrypted phase: expect env frames
    if (obj?.typ !== 'env') return;
    try {
		Audit.log('[Auth2_enc::Debug]')
		const inner = ws.__session.decrypt('c2s', obj);
		const t = inner.typ || inner.action;
		const h = handlers[t];
		if (h) Audit.log('[Auth2_t::Debug]', t)
		if (h) return h(ws, req, inner);
		
        const envHandlers = {
		  'auth.register': async (_ws, data, session, req) => {
				const { username, password, licenseKey, hwid } = data || {};
				const ip = _ws.__ip;//clientIp(_ws.__req||{});
				const { createUser, getKey, claimKey, setHWIDIfEmpty, logUser } = await LicenseStore.init();
				if (!licenseKey) return { ok:false, error:'missing_license' };
				try {
					const row = getKey(licenseKey);
					if (!row || row.status !== 'unused') return { ok:false, error:'invalid_or_claimed' };
					const user = createUser(username, password, hwid);
					claimKey(licenseKey, user.id);
					setHWIDIfEmpty(user.id, hwid);
					_ws.__userId = user.id;
					_ws.__username = username;
					_ws.__scopes = [];
					_ws.__authed = true;
					logUser(user.id, username, 'register', ip, { claimedKey: licenseKey });
					Audit.log('[user.register.debug]', { username, ip });
					return { ok:true, userId: user.id };
				} catch (e) {
					Audit.log('auth.error', { stage:'register', username, error:String(e.message||e) });
					return { ok:false, error:String(e.message||e) };
				}
		  },
		  'auth.login': async (_ws, data, session) => {
				const { username, password, hwid } = data || {};
				const ip = _ws.__ip;//clientIp(_ws.__req||{});
				const { checkPassword, getUserByUsername, getScopesForClaimedLicense, verifyHWID, updateUserIPs, createSession, logUser } = await LicenseStore.init();
				const ok = checkPassword(username, password);
				if (!ok) { Audit.log('auth.error', { stage:'login', username, ip, reason:'bad_password' }); return { ok:false, error:'bad_credentials' }; }
				const user = getUserByUsername(username);
				if (!user) { Audit.log('auth.error', { stage:'login', username, ip, reason:'unknown_user' }); return { ok:false, error:'unknown_user' }; }
				if (user.isBanned && (!user.bannedUntil || user.bannedUntil> Date.now())) {
					Audit.log('auth.error', { stage:'login', username, ip, reason:'banned' });
					return { ok:false, error:'banned', bannedUntil:user.bannedUntil||null };
				}
				if (user.hwid && user.hwid !== hwid) {
					Audit.log('auth.error', { stage:'login', username, ip, reason:'hwid_mismatch' });
					return { ok:false, error:'hwid_mismatch' };
				}
				if (!user.hwid && hwid){
					
					const { setHWIDIfEmpty } = await LicenseStore.init(); setHWIDIfEmpty(user.id, hwid);
				}
				const licScopes = getScopesForClaimedLicense(user.id);
				const userScopes = JSON.parse(user.scopes||'[]');
				const scopes = Array.from(new Set([ ...userScopes, ...licScopes ]));
				updateUserIPs(user.id, ip);
				const sess = createSession({ userId: user.id, username, ip, permissions: scopes });
				_ws.__userId = user.id;
				_ws.__username = username;
				_ws.__scopes = scopes;
				_ws.__authed = true;
				_ws.__sessionId = sess.id;
				logUser(user.id, username, 'login', ip, { sessionId: sess.id });
				Audit.log('user.login', { username, ip, sessionId: sess.id });
				return { ok:true, userId: user.id, scopes, sessionId: sess.id };
		  },
		  'auth.resume': async ()=>({ ok:true }),
		  'module.list': async (_ws) => {
				const manifest = JSON.parse(fs.readFileSync('server/modules.manifest.json','utf8'));
				const scopes = _ws.__scopes || [];
				const list = manifest.modules || (manifest.modulesList||[]);
				const allowed = list.filter(m => !m.permissions || m.permissions.some(p=>scopes.includes(p)));
				return { modules: allowed.map(({name,description,permissions})=>({name,description,permissions})) };
		  },

		  // ---- Admin: Users ----
		  'admin.users.list': async (_ws) => {
				if (!(_ws.__scopes||[]).includes('admin')) return { ok:false, error:'forbidden' };
				const { db } = await LicenseStore.init();
				const rows = db.prepare(`SELECT u.*, (SELECT secret FROM license_keys WHERE claimedByUserId=u.id) AS licenseSecret FROM users u`).all();
				return { ok:true, users: rows.map(r=>({ id:r.id, username:r.username, hwid:r.hwid, scopes:JSON.parse(r.scopes||'[]'), isBanned:!!r.isBanned, bannedUntil:r.bannedUntil||null, lastIPs: JSON.parse(r.lastIPs||'[]'), licenseSecret:r.licenseSecret||null })) };
		  },
		  'admin.users.view': async (_ws, data) => {
				if (!(_ws.__scopes||[]).includes('admin')) return { ok:false, error:'forbidden' };
				const { userId } = data||{};
				const { db, getUserLogs } = await LicenseStore.init();
				const u = db.prepare(`SELECT u.*, (SELECT secret FROM license_keys WHERE claimedByUserId=u.id) AS licenseSecret FROM users u WHERE id=?`).get(userId);
				if (!u) return { ok:false, error:'not_found' };
				const logs = getUserLogs(userId);
				const diffIPs = Array.from(new Set((logs||[]).map(l=>l.ip).filter(Boolean)));
				return { ok:true, user: { id:u.id, username:u.username, hwid:u.hwid, scopes:JSON.parse(u.scopes||'[]'), isBanned:!!u.isBanned, bannedUntil:u.bannedUntil||null, lastIPs: JSON.parse(u.lastIPs||'[]'), diffIPs, key:u.licenseSecret }, logs };
		  },
		  'admin.users.ban': async (_ws, data) => { const { banUser } = await LicenseStore.init(); banUser(data.userId, data.until||null); Audit.log('admin.ban', { by:_ws.__username, userId:data.userId, until:data.until||null }); return { ok:true }; },
		  'admin.users.unban': async (_ws, data) => { const { unbanUser } = await LicenseStore.init(); unbanUser(data.userId); Audit.log('admin.unban',{by:_ws.__username, userId:data.userId}); return { ok:true }; },
		  'admin.users.resetPassword': async (_ws, data) => { const { setUserPassword } = await LicenseStore.init(); setUserPassword(data.userId, data.newPassword); Audit.log('admin.resetPassword',{ by:_ws.__username, userId:data.userId }); return { ok:true }; },
		  'admin.users.forceLogout': async (_ws, data) => { const { endSession } = await LicenseStore.init(); endSession(data.sessionId); Audit.log('admin.forceLogout',{ by:_ws.__username, sessionId:data.sessionId }); return { ok:true }; },
		  'admin.users.scopes.add': async (_ws, data)=>{ const { addUserScope } = await LicenseStore.init(); addUserScope(data.userId, data.scope); Audit.log('admin.user.scope.add',{by:_ws.__username, userId:data.userId, scope:data.scope}); return { ok:true }; },
		  'admin.users.scopes.remove': async (_ws, data)=>{ const { removeUserScope } = await LicenseStore.init(); removeUserScope(data.userId, data.scope); Audit.log('admin.user.scope.remove',{by:_ws.__username, userId:data.userId, scope:data.scope}); return { ok:true }; },
		  'admin.users.hwid.view': async (_ws, data)=>{ const { getUserById } = await LicenseStore.init(); const u=getUserById(data.userId); return { ok:true, hwid:u?.hwid||null }; },
		  'admin.users.hwid.reset': async (_ws, data)=>{ const { resetUserHWID } = await LicenseStore.init(); resetUserHWID(data.userId); Audit.log('admin.user.hwid.reset',{ by:_ws.__username, userId:data.userId }); return { ok:true }; },
		  'admin.users.export': async (_ws, data)=>{ const { db } = await LicenseStore.init(); const u=db.prepare('SELECT * FROM users WHERE id=?').get(data.userId); const logs=db.prepare('SELECT * FROM user_logs WHERE userId=?').all(data.userId); return { ok:true, export:{ user:u, logs } }; },

		  // ---- Admin: Keys ----
		  'admin.keys.list': async (_ws, data)=>{ const { listKeys } = await LicenseStore.init(); return { ok:true, keys:listKeys(data||{}) }; },
		  'admin.keys.view': async (_ws, data)=>{ const { getKey } = await LicenseStore.init(); const k=getKey(data.secret); return { ok:!!k, key:k||null }; },
		  'admin.keys.add': async (_ws, data)=>{ const { createKey } = await LicenseStore.init(); const k=createKey(data.secret, data.plan, data.scopes, data.role, data.expiresAt||null); Audit.log('admin.key.add',{ by:_ws.__username, secret:k.secret }); return { ok:true, key:k }; },
		  'admin.keys.scope.add': async (_ws, data)=>{ const { addKeyScope } = await LicenseStore.init(); addKeyScope(data.secret, data.scope); Audit.log('admin.key.scope.add',{ by:_ws.__username, secret:data.secret, scope:data.scope }); return { ok:true }; },
		  'admin.keys.scope.remove': async (_ws, data)=>{ const { removeKeyScope } = await LicenseStore.init(); removeKeyScope(data.secret, data.scope); Audit.log('admin.key.scope.remove',{ by:_ws.__username, secret:data.secret, scope:data.scope }); return { ok:true }; },
		  'admin.keys.scope.reset': async (_ws, data)=>{ const { resetKeyScopes } = await LicenseStore.init(); resetKeyScopes(data.secret); Audit.log('admin.key.scope.reset',{ by:_ws.__username, secret:data.secret }); return { ok:true }; },
		  'admin.keys.role.set': async (_ws, data)=>{ const { setKeyRole } = await LicenseStore.init(); setKeyRole(data.secret, data.role); Audit.log('admin.key.role.set',{ by:_ws.__username, secret:data.secret, role:data.role }); return { ok:true }; },
		  'admin.keys.remove': async (_ws, data)=>{ const { removeKey } = await LicenseStore.init(); removeKey(data.secret); Audit.log('admin.key.remove',{ by:_ws.__username, secret:data.secret }); return { ok:true }; },
		  'admin.keys.expire': async (_ws, data)=>{ const { expireKey } = await LicenseStore.init(); expireKey(data.secret, data.expiresAt); Audit.log('admin.key.expire',{ by:_ws.__username, secret:data.secret, expiresAt:data.expiresAt }); return { ok:true }; },
		  'admin.keys.clone': async (_ws, data)=>{ const { cloneKey } = await LicenseStore.init(); const k=cloneKey(data.secret, data.newSecret); Audit.log('admin.key.clone',{ by:_ws.__username, from:data.secret, to:k.secret }); return { ok:true, key:k }; },
		  'admin.keys.reclaim': async (_ws, data)=>{ const { reclaimKey } = await LicenseStore.init(); reclaimKey(data.secret); Audit.log('admin.key.reclaim',{ by:_ws.__username, secret:data.secret }); return { ok:true }; },
		  'admin.keys.analytics': async (_ws)=>{ const { db } = await LicenseStore.init(); const rows=db.prepare('SELECT secret, status, claimedByUserId FROM license_keys').all(); return { ok:true, analytics: rows }; },

		  // ---- Admin: Sessions ----
		  'admin.sessions.list': async ()=>{ const { listActiveSessions } = await LicenseStore.init(); return { ok:true, sessions:listActiveSessions() }; },
		  'admin.sessions.disconnect': async (_ws, data)=>{ const { endSession } = await LicenseStore.init(); endSession(data.sessionId); Audit.log('admin.session.disconnect',{ by:_ws.__username, sessionId:data.sessionId }); return { ok:true }; },
		  'admin.sessions.killswitch': async (_ws)=>{ const { listActiveSessions, endSession } = await LicenseStore.init(); for (const s of listActiveSessions()) endSession(s.id); Audit.log('admin.killswitch', { by:_ws.__username }); return { ok:true }; },
		  'admin.sessions.send': async (_ws, data)=>{ Audit.log('admin.session.send',{ by:_ws.__username, sessionId:data.sessionId, message:data.message }); return { ok:true }; },
		  'admin.sessions.inspect': async (_ws, data)=>{ const { getSession } = await LicenseStore.init(); return { ok:true, session:getSession(data.sessionId) }; },
		  'admin.sessions.promote': async (_ws, data)=>{ const { setSessionPerm, getSession } = await LicenseStore.init(); const sess=getSession(data.sessionId); const perms=new Set(JSON.parse(sess.permissions||'[]')); perms.add(data.permission); setSessionPerm(data.sessionId, Array.from(perms)); Audit.log('admin.session.promote',{ by:_ws.__username, sessionId:data.sessionId, permission:data.permission }); return { ok:true }; },
		  'admin.sessions.demote': async (_ws, data)=>{ const { setSessionPerm, getSession } = await LicenseStore.init(); const sess=getSession(data.sessionId); const perms=new Set(JSON.parse(sess.permissions||'[]')); perms.delete(data.permission); setSessionPerm(data.sessionId, Array.from(perms)); Audit.log('admin.session.demote',{ by:_ws.__username, sessionId:data.sessionId, permission:data.permission }); return { ok:true }; },
		  'admin.sessions.annotate': async (_ws, data)=>{ const { annotateSession } = await LicenseStore.init(); annotateSession(data.sessionId, data.notes||''); Audit.log('admin.session.annotate',{ by:_ws.__username, sessionId:data.sessionId }); return { ok:true }; },

		  // ---- Admin: Server ----
		  'admin.server.status': async ()=>({ ok:true, status:{ uptime: process.uptime(), memory: process.memoryUsage(), cpu: (process.cpuUsage&&process.cpuUsage())||{}, connectedClients: (wss?.clients?.size)||0 }}),
		  'admin.server.restart': async ()=>({ ok:true }),
		  'admin.server.shutdown': async ()=>({ ok:true }),
		  'admin.server.toggle.connections': async ()=>({ ok:true }),
		  'admin.server.toggle.server': async ()=>({ ok:true }),
		  'admin.server.backup': async ()=>({ ok:true }),
		  'admin.server.restore': async ()=>({ ok:true }),
		  'admin.server.rotateLogs': async (_ws)=>{ Audit.log('admin.rotateLogs',{ by:_ws.__username }); return { ok:true }; },
		  'admin.server.reloadModules': async ()=>({ ok:true }),
		  'admin.server.maintenance.on': async (_ws, data)=>{ Audit.log('admin.maintenance.on',{ by:_ws.__username, message:data?.message||'' }); return { ok:true }; },
		  'admin.server.maintenance.off': async (_ws)=>{ Audit.log('admin.maintenance.off',{ by:_ws.__username }); return { ok:true }; },

		  // ---- Audit ----
		  'admin.audit.view': async (_ws, data)=>{ 
				const { timeframe='all', tail=null, type=null } = data||{};
				let sinceMs=0;
				if (timeframe==='1h') sinceMs=60*60*1000;
				else if (timeframe==='24h') sinceMs=24*60*60*1000;
				else if (timeframe==='7d') sinceMs=7*24*60*60*1000;
				const entries = Audit.read({ sinceMs }).filter(e=>!type || e.type===type || (e.type||'').startsWith(type));
				return { ok:true, entries: tail ? entries.slice(-tail) : entries };
		  },
		  //'admin.audit.clear': async (_ws)=>{ Audit.clear(); Audit.log('admin.audit.clear',{ by:_ws.__username }); return { ok:true }; }
};;
        if (msg && msg.v===1 && msg.t){ return handleEnvelope(ws, msg, ws.__session, envHandlers); }

        sendEnc(ws, { typ:'error', error:'unknown_request' });
    } catch (e){
	  Audit.log('auth.error', { stage:'register', user: ws.__username, error:String(e.message||e) });
      sendJSON(ws, { typ:'error', error:'bad_env' });
    }
  });

  ws.on('close', ()=>{
    RpcLogger.append({ dir:'event', ev:'close', ip: ws.__ip });
  });
});

httpsServer.listen(PORT, HOST, ()=>{
  Audit.log('server.start', { HOST, PORT, time: Date.now() });
  Audit.log(`WSS listening on wss://${HOST}:${PORT} (proto 2.0 envelopes)`);
});
