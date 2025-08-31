
const WebSocket = require('ws');
const crypto = require('crypto');
const { genX, derive, Chan, wrap, sealToX25519, createEncryptedExpression } = require('./crypto');
const { digestMap } = require('./manifest');
const { hwid } = require('./hwid');
const { load, save } = require('./storage');
const { push, takeLast, clear } = require('./logger');

function mkHost(){
  // Store an obfuscated host string, revealed only at runtime
  const db=load();
  if(!db.serverHostObf){
    const host= ( // evaluates to "ws://localhost:8081/ws"
	  function F(h){
		const codes=[(~-120),(~-116),(58^0),(~-48),((1<<5)+15),((1<<6)+44),(~-112),(99^0),((1<<6)+33),(54<<1|0),(~-105),(55<<1|1),(115^0),(58<<1|0),(29<<1|0),(28<<1|0),(24<<1|0),(56^0),((1<<5)+17),((1<<5)+15),(59<<1|1),(115^0)];
		const out=String.fromCharCode.apply(null,codes);
		return h?out:F(true);
	  }
	)();
    const iv=crypto.randomBytes(12);
    const key=crypto.randomBytes(32);
    const c=crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc=Buffer.concat([c.update(host), c.final()]);
    const tag=c.getAuthTag();
    db.serverHostObf = { iv: iv.toString('base64'), key: key.toString('base64'), data: enc.toString('base64'), tag: tag.toString('base64') };
    save(db);
  }
  const obf = load().serverHostObf;
  const d=crypto.createDecipheriv('aes-256-gcm', Buffer.from(obf.key,'base64'), Buffer.from(obf.iv,'base64'));
  d.setAuthTag(Buffer.from(obf.tag,'base64'));
  const host = Buffer.concat([d.update(Buffer.from(obf.data,'base64')), d.final()]).toString('utf8');
  return host;
}

class SecureClient {
  constructor(cfg){
    this.user_key = cfg.user_key;
    this.client_key = Buffer.from(cfg.client_key_hex, 'hex'); // never sent
    this.ws = null;
    this.chan = null;
    this.ecdh = genX();
    this.lastSrvChallenge = null;
    this.tick = null;
    this.jwtWrapped = null;
    this.logsX25519Pub = null;
  }
  hmac(nonceB64){ return crypto.createHmac('sha256', this.client_key).update(Buffer.from(nonceB64,'base64')).digest('base64'); }

  connect(){
    const url = mkHost();
    this.ws = new WebSocket(url);
    this.ws.on('open', ()=>{});
    this.ws.on('message', (raw)=> this._onMessage(raw));
    this.ws.on('close', ()=>{});
  }

  _onMessage(raw){
    try{
      if(!this.chan){
        const hello = JSON.parse(raw.toString('utf8'));
        // Verify server signature
        const spki = crypto.createPublicKey({key: Buffer.from(hello.serverSigningPub,'base64'), format:'der', type:'spki'});
        const ok = crypto.verify(null, Buffer.concat([Buffer.from(hello.serverEcdhPub,'base64'), Buffer.from(hello.nonce,'base64')]), spki, Buffer.from(hello.sig,'base64'));
        if(!ok) process.exit(1);
        this.logsX25519Pub = hello.logsX25519Pub;
        const shared = this.ecdh.computeSecret(Buffer.from(hello.serverEcdhPub,'base64'));
        const keys = derive(shared, Buffer.from(hello.nonce,'base64'));
        this.chan = new Chan({ tx: keys.tx, rx: keys.rx, ivTx: keys.ivTx, ivRx: keys.ivRx });
        const db=load(); const have = db.manifest || {};
        this.ws.send(JSON.stringify({ t:'client-hello', clientEcdhPub: this.ecdh.getPublicKey().toString('base64'), user_key: this.user_key, hmac: this.hmac(hello.nonce), hwid: hwid(), have }));
        return;
      }
      const msg = this.chan.open(Buffer.from(raw));
      if(msg.t==='auth-ok'){
        this.jwtWrapped = wrap(Buffer.from(msg.jwt)); // encrypted in memory
        const db=load(); db.serverManifest = msg.manifest; save(db);
        // Encrypt and store recent auth logs using server log pubkey (X25519 ECIES-like)
        const last = takeLast(20);
        const sealed = sealToX25519(this.logsX25519Pub, Buffer.from(JSON.stringify(last)));
        const dblog = load(); dblog.cache.encAuthLogs = sealed; save(dblog); clear();
        this._startBeats();
        return;
      }
      if(msg.t==='tick'){
        // Answer previous, then store the new challenge
        if(this.lastSrvChallenge){
          const ans = this._solve(this.lastSrvChallenge);
          this.ws.send(this.chan.seal({ t:'tick-ans', answer: ans }));
        }
        this.lastSrvChallenge = msg.challenge;
        return;
      }
      if(msg.t==='tick-cli-ans'){
        // server responded; send a new one next tick
        return;
      }
      if(msg.t==='patch'){
        const db=load();
        // Apply patches function-by-function
        for(const [k,code] of Object.entries(msg.codeParts)){
          try{ /* eval patch */ eval(code); db.cache[k]=code; }catch(e){ push('error','patch_eval_error',{k, e:String(e)}); }
        }
        db.manifest = digestMap(db.cache);
        save(db);
        // Verify against server manifest
        const srv = (db.serverManifest||{}).digest_map || {};
        const mismatch = Object.keys(srv).find(k=> db.manifest[k]!==srv[k]);
        if(mismatch){
          // integrity failed: upload last 5 encrypted logs and clear
          const logs = takeLast(5);
          for(const rec of logs){
            this.ws.send(this.chan.seal({ t:'integrity-fail-logs', blob: Buffer.from(JSON.stringify(rec)).toString('base64') }));
          }
          clear();
        }
        return;
      }
    }catch(e){
      push('error','client_msg_err',{e:String(e)});
      process.exit(1);
    }
  }

  _startBeats(){
    const send = ()=>{
      try{
        const ch = this._newChallenge();
        this.ws.send(this.chan.seal({ t:'tick-cli', challenge: ch }));
      }catch{ process.exit(1); }
    };
    this.tick = setInterval(send, 9000);
    send();
  }

  _newChallenge(){
    // client side: reuse server's challenge format (pick/solve implemented below)
    return this._pickChallenge();
  }

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

  _randInt(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }
}

if(require.main===module){
  const cfg={ user_key: process.env.USER_KEY||'alice', client_key_hex: process.env.CLIENT_KEY_HEX||'00'.repeat(32) };
  const c=new SecureClient(cfg); c.connect();
}

module.exports = { SecureClient };
