
'use strict';

const os = require('os');
const crypto = require('crypto');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

// ====== Provided obfuscation funcs (as requested) ======
function createEncryptedExpression( str){
	function obfuscateText(txt) {
	  function obNum(n) {
		const variants = [
		  `(${n>>1}<<1|${n&1})`,
		  `(~${~n})`,
		  `((1<<${Math.floor(Math.log2(n))})+${n-(1<<Math.floor(Math.log2(n)))})`,
		  `(${n}^0)`
		];
		return variants[Math.floor(Math.random() * variants.length)];
	  }
	  const codes = Array.from(txt).map(ch => obNum(ch.charCodeAt(0)));
	  return new Function(`
		return ((x * x + 1) % 2) === 1 ? 1<<1<<1<<1<<1<<1<<1<<1<<1<<1>>4 : String.fromCharCode.apply(null,[${codes.join(',')}]);
	  `.trim());
	}
	return obfuscateText( str);
}

// Provided server IP obfuscator (as requested)
const SERVER_IP_PROVIDER = new Function("return ((x * x + 1) % 2) === 1 ? 0>>1 : String.fromCharCode.apply(null,[((1<<5)+17),(28<<1|1),((1<<5)+18),((1<<5)+14),(~-50),(54^0),(~-57),(~-47),(~-50),(23<<1|0),((1<<5)+17),(~-59),(28<<1|0),(~-49),(56^0),(49^0)]);");


// ====== Minimal string protector (runtime XOR) ======
const _obKey = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest();
function protectString(s){ const b = Buffer.from(String(s),'utf8'); const o = Buffer.alloc(b.length); for(let i=0;i<b.length;i++) o[i]=b[i]^_obKey[i%_obKey.length]; return o; }
function revealString(b){ const o = Buffer.alloc(b.length); for(let i=0;i<b.length;i++) o[i]=b[i]^_obKey[i%_obKey.length]; const s=o.toString('utf8'); o.fill(0); return s; }

// ====== Crypto helpers ======
function hkdf(keyMaterial, salt, info, len=32){
  return crypto.hkdfSync('sha256', keyMaterial, salt, Buffer.from(info), len);
}
function aesgcmEncrypt(key, plaintext, aad=null){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if(aad) cipher.setAAD(Buffer.from(aad));
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function aesgcmDecrypt(key, b64, aad=null){
  const buf = Buffer.from(b64, 'base64');
  const iv = buf.slice(0,12);
  const tag = buf.slice(12,28);
  const enc = buf.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if(aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec;
}

// ====== Challenge system (exact code requested) ======
class ChallengeKit {
  _randInt(min, max){ return Math.floor(Math.random()*(max-min+1))+min; }
  _pickChallenge(){
    const t = ['algebra','arith','factor'][Math.floor(Math.random()*3)];
    if(t==='algebra'){
      const a = this._randInt(2,19);
      const x = this._randInt(-20,20);
      const b = this._randInt(-50,50);
      const c = a*x + b;
      return { type:'algebra', data:{a,b,c} };
    }
    if(t==='arith'){
      const a = this._randInt(-1000,1000);
      const b = this._randInt(-1000,1000);
      const op = Math.random()<0.5?'+':'-';
      return { type:'arith', data:{a,b,op} };
    }
    const P=[2,3,5,7,11,13,17,19,23][this._randInt(0,8)];
    const Q=[29,31,37,41,43,47,53,59][this._randInt(0,7)];
    return { type:'factor', data:{ n:P*Q } };
  }
  _solve(ch){
    if(ch.type==='algebra'){
      const {a,b,c} = ch.data; if(a===0) return null; const x=(c-b)/a; return Number.isInteger(x)? x : null;
    }
    if(ch.type==='arith'){
      const {a,b,op} = ch.data; return op==='+'? (a+b):(a-b);
    }
    if(ch.type==='factor'){
      const {n} = ch.data; for(let i=2;i*i<=n;i++){ if(n%i===0) return [i, n/i]; } return null;
    }
    return null;
  }
}

// ====== Integrity utilities (timing + native checks) ======
function isNative(fn){ return /\[native code\]/.test(Function.prototype.toString.call(fn)); }
function timingProbe(iter=5e4){
  const t0 = process.hrtime.bigint();
  let s = 0;
  for(let i=0;i<iter;i++){ s += Math.sqrt(i)%5; }
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0);
}

// ====== Client class ======
class LiveClient {
  constructor(configPath){
    this._cfgPath = configPath || path.join(__dirname,'config.json.enc');
    this._state = {}; // transient
    this._ck = new ChallengeKit();
    this._hr0 = process.hrtime.bigint();
    this._analytics = { connected_time:0n, challenges_failed:0, challenges_solved:0, login_time:0n };
    this._logQueue = [];
    this._manifest = {};
  }

  _nowHR(){ return process.hrtime.bigint(); }

  _readConfig(){
    const enc = fs.readFileSync(this._cfgPath);
    const key = crypto.createHash('sha256').update(Buffer.concat([_obKey, Buffer.from('cfg')])).digest();
    const dec = aesgcmDecrypt(key, enc.toString('utf8'));
    const cfg = JSON.parse(dec.toString('utf8'));
    return cfg;
  }

  _getHWIDs(){
    const ifs = os.networkInterfaces();
    const list = [];
    for(const [name, arr] of Object.entries(ifs)){
      if(!arr) continue;
      for(const i of arr){
        if(i && i.mac && i.mac !== '00:00:00:00:00:00'){
          list.push({ iface: name, hwid: i.mac });
        }
      }
    }
    return list;
  }

  _pack(obj){
    const p = Buffer.from(JSON.stringify(obj));
    return { data: aesgcmEncrypt(this._sessionKey, p) };
  }

  _unpack(payload){
    try{
      const dec = aesgcmDecrypt(this._sessionKey, payload.data);
      return JSON.parse(dec.toString('utf8'));
    }catch(e){ return null; }
  }

  async start(){
    const cfg = this._readConfig();
    const serverHost = (typeof SERVER_IP_PROVIDER==='function') ? SERVER_IP_PROVIDER() : SERVER_IP_PROVIDER;
    const url = `ws://${serverHost}/ws`;
    const ecdh = crypto.generateKeyPairSync('x25519');
    this._clientPriv = ecdh.privateKey;
    const clientPub = ecdh.publicKey.export({type:'spki', format:'der'});

    const ws = new WebSocket(url);
    this._ws = ws;
    const self = this;

    ws.on('open', ()=>{});

    ws.on('message', (msg)=>{
      try{
        const o = JSON.parse(msg.toString());
        const inner = JSON.parse(Buffer.from(o.data,'base64').toString('utf8'));

        if(inner.step==='hello'){
          // Derive session key
          const server_pub = Buffer.from(inner.server_pub, 'base64');
          const shared = crypto.diffieHellman({ privateKey: this._clientPriv, publicKey: crypto.createPublicKey({key:server_pub, format:'der', type:'spki'}) });
          this._sessionKey = hkdf(shared, Buffer.alloc(0), 'ws-session', 32);

          // Send keyhash + client pub + hwids
          const keyhash = crypto.createHash('sha256').update(cfg.client_key).digest('hex');
          const hwids = this._getHWIDs();
          const payload = { client_pub: clientPub.toString('base64'), keyhash, hwids, ip_hint: cfg.allowed_ips||[] };
          ws.send(JSON.stringify({ token:'', data: Buffer.from(JSON.stringify(payload)).toString('base64') }));
          this._analytics.login_time = this._nowHR();
          return;
        }

        // From here on, decrypt using session key
        const obj = this._unpack(o);
        if(!obj){ process.exit(1); }

        if(obj.step==='challenge' && obj.ch){
          const ans = this._ck._solve(obj.ch);
          if(ans===null || typeof ans==='undefined'){ process.exit(1); }
          ws.send(JSON.stringify(this._pack({ ans })));
          this._analytics.challenges_solved++;
        }

        if(obj.ch){ // bidirectional: if server sends new challenge within any message
          const ans2 = this._ck._solve(obj.ch);
          if(ans2===null || typeof ans2==='undefined'){ process.exit(1); }
          ws.send(JSON.stringify(this._pack({ ans: ans2 })));
          this._analytics.challenges_solved++;
        }

        if(obj.ch_ans){ /* server answered our challenge; verify not null */ if(obj.ch_ans.ans===null){ process.exit(1); } }

        if(obj.issued_jwt){
          this._jwtReceivedAt = this._nowHR();
        }

        if(obj.hb_ack){
          // ok
        }

        if(obj.integrity_request){
          this._sendIntegrity();
        }

      }catch(e){
        process.exit(1);
      }
    });

    ws.on('close', ()=>{
      // Save analytics and clear sensitive memory
      this._analytics.connected_time = (this._nowHR() - this._hr0);
      try{
        fs.writeFileSync(path.join(__dirname,'analytics.json'), JSON.stringify(this._analytics, null, 2));
      }catch(_){}
      this._sessionKey?.fill?.(0);
      process.exit(0);
    });

    // Heartbeats + bidirectional challenges
    const hbTimer = setInterval(()=>{
      if(!this._sessionKey){ return; }
      const ch = this._ck._pickChallenge();
      ws.send(JSON.stringify(this._pack({ heartbeat: Number(process.hrtime.bigint()), ch })));
    }, 2*60*1000);

    // Integrity every 5 minutes
    const intTimer = setInterval(()=>{
      if(!this._sessionKey){ return; }
      this._sendIntegrity();
    }, 5*60*1000);

    // Initial proactive integrity after 5s
    setTimeout(()=>{ if(this._sessionKey) this._sendIntegrity(); }, 5000);
  }

  _sendIntegrity(){
    const natives = {
      setTimeout: isNative(setTimeout),
      clearTimeout: isNative(clearTimeout),
      Math_sqrt: isNative(Math.sqrt),
      Function_toString: /\[native code\]/.test(Function.toString())
    };
    const timing = timingProbe();
    const customDigests = this._digestCustomFunctions();
    const payload = { natives, timing, manifest: customDigests };
    this._ws.send(JSON.stringify(this._pack({ integrity: payload })));
  }

  _digestCustomFunctions(){
    // Hash source code of custom functions
    const map = {};
    for(const [k,v] of Object.entries(this)){
      if(typeof v === 'function'){
        map[k] = crypto.createHash('sha256').update(k+Function.prototype.toString.call(v)).digest('hex');
      }
    }
    return map;
  }
}

// Entry
if (require.main === module){
  const lc = new LiveClient(process.argv[2]);
  lc.start();
}

module.exports = { LiveClient };
