
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { get, set, run, one, all } = require('./db');
const { pickChallenge, solveChallenge } = require('./challenges');
const { makeECDH, sign, exportPublicKey, deriveSessionKey, aesgcmEncrypt, aesgcmDecrypt, sha256 } = require('./crypto');
const { log } = require('./logger');

// Settings
const HEARTBEAT_NS = BigInt(2*60*1e9); // 2 minutes
const INTEGRITY_NS = BigInt(5*60*1e9); // 5 minutes
const JWT_TTL_SEC = 3*24*60*60; // 3 days

function nowHR(){ return process.hrtime.bigint(); }

// Active sessions
const sessions = new Map();

function packResponse(token, key, obj){
  const payload = Buffer.from(JSON.stringify(obj));
  return JSON.stringify({ token, data: aesgcmEncrypt(key, payload) });
}

function unpackRequest(key, b64){
  try {
    const payload = JSON.parse(b64);
    const dec = aesgcmDecrypt(key, payload.data);
    return JSON.parse(dec.toString('utf8'));
  } catch(e){
    return null;
  }
}

async function issueJWT(keyhash){
  // NOTE: Using hrtime for iat-ish metrics internally; JWT needs epoch seconds for exp
  const token = jwt.sign({ kh: keyhash }, await getOrGenJWTSecret(), { expiresIn: JWT_TTL_SEC });
  const nowSec = Math.floor(Date.now()/1000);
  await run('INSERT INTO tokens(keyhash,token,issued_at,expires_at) VALUES(?,?,?,?)',[keyhash, token, nowSec, nowSec+JWT_TTL_SEC]);
  return token;
}

async function getOrGenJWTSecret(){
  let s = await one('SELECT v FROM settings WHERE k=?',['jwt_secret']);
  if(!s){
    const secret = crypto.randomBytes(32).toString('hex');
    await run('INSERT INTO settings(k,v) VALUES(?,?)',['jwt_secret', secret]);
    return secret;
  }
  return s.v;
}

async function addOrUpdateIP(keyhash, ip){
  const row = await one('SELECT * FROM ips WHERE keyhash=? AND ip=?',[keyhash, ip]);
  const now = Math.floor(Date.now()/1000);
  if(!row){
    const ips = await all('SELECT * FROM ips WHERE keyhash=?',[keyhash]);
    // discard unused > 30 days
    for(const e of ips){
      if(now - e.last_seen > 30*24*3600) await run('DELETE FROM ips WHERE id=?',[e.id]);
    }
    const ips2 = await all('SELECT * FROM ips WHERE keyhash=?',[keyhash]);
    if(ips2.length >= 3){
      // remove the oldest
      const oldest = ips2.sort((a,b)=>a.last_seen-b.last_seen)[0];
      await run('DELETE FROM ips WHERE id=?',[oldest.id]);
    }
    await run('INSERT INTO ips(keyhash,ip,first_seen,last_seen) VALUES(?,?,?,?)',[keyhash, ip, now, now]);
  }else{
    await run('UPDATE ips SET last_seen=? WHERE id=?',[now, row.id]);
  }
}

async function verifyKeyAndIP(keyhash, ip){
  const k = await one('SELECT * FROM keys WHERE keyhash=?',[keyhash]);
  if(!k || k.blacklisted) return false;
  await addOrUpdateIP(keyhash, ip);
  const row = await one('SELECT * FROM users WHERE keyhash=?',[keyhash]);
  if(row && row.banned_until && row.banned_until > Math.floor(Date.now()/1000)) return false;
  return true;
}

async function onWSConnection(ws, req){
  const ip = req.socket.remoteAddress;
  const sid = uuidv4();
  let sessionKey = null;
  let jwtToken = null;
  let lastBeat = nowHR();
  let lastIntegrity = nowHR();
  let keyhash = null;

  // ECDH
  const ecdh = makeECDH();
  const serverPub = ecdh.publicKey.export ? ecdh.publicKey.export({type:'spki', format:'der'}) : ecdh.publicKey; // fallback
  ws.send(JSON.stringify({
    token: '',
    data: Buffer.from(JSON.stringify({
      step:'hello',
      server_pub: serverPub.toString('base64'),
      server_sig: sign(serverPub.toString('base64')),
      server_sign_pub: exportPublicKey()
    })).toString('base64')
  }));

  ws.on('message', async (msg)=>{
    try{
      // First message from client expected to contain client_pub and keyhash; after that, use sessionKey encryption
      if(!sessionKey){
        const first = JSON.parse(msg.toString());
        const payload = JSON.parse(Buffer.from(first.data,'base64').toString('utf8'));
        const clientPubRaw = Buffer.from(payload.client_pub,'base64');
        keyhash = payload.keyhash;
        const ok = await verifyKeyAndIP(keyhash, ip);
        if(!ok){ try{ ws.close(); }catch(e){} return; }

        sessionKey = deriveSessionKey(ecdh.privateKey, clientPubRaw);
        // issue a challenge immediately
        const ch = pickChallenge();
        ws.send(packResponse('', sessionKey, { step:'challenge', ch }));
        await run('INSERT INTO sessions(id,keyhash,ip,started_hr,last_heartbeat_hr,login_time) VALUES(?,?,?,?,?,?)',[
          sid, keyhash, ip, nowHR().toString(), nowHR().toString(), nowHR().toString()
        ]);
        return;
      }

      const reqObj = JSON.parse(msg.toString());
      const obj = unpackRequest(sessionKey, JSON.stringify(reqObj));
      if(!obj){ ws.close(); return; }

      // Solve incoming challenge from client as well
      if(obj.ch){
        const ans = { ans: solveChallenge(obj.ch) };
        ws.send(packResponse(jwtToken||'', sessionKey, { ch_ans: ans }));
      }

      // Handle answers, heartbeat and integrity
      if(obj.ans !== undefined){
        const ok = obj.ans !== null && typeof obj.ans !== 'undefined';
        if(!ok){ await run('UPDATE sessions SET challenges_failed=challenges_failed+1 WHERE id=?',[sid]); ws.close(); return; }
        else await run('UPDATE sessions SET challenges_solved=challenges_solved+1 WHERE id=?',[sid]);
        // On first successful answer, issue JWT
        if(!jwtToken){
          jwtToken = await issueJWT(keyhash);
          ws.send(packResponse(jwtToken, sessionKey, { issued_jwt: true }));
        }
      }

      if(obj.heartbeat){
        lastBeat = nowHR();
        await run('UPDATE sessions SET last_heartbeat_hr=? WHERE id=?',[lastBeat.toString(), sid]);
        // send a new challenge on every heartbeat and request integrity check occasionally
        const ch = pickChallenge();
        ws.send(packResponse(jwtToken||'', sessionKey, { hb_ack: true, ch }));
        if(nowHR()-lastIntegrity > BigInt(5*60*1e9)){
          lastIntegrity = nowHR();
          ws.send(packResponse(jwtToken||'', sessionKey, { integrity_request: true }));
        }
      }

      if(obj.integrity){
        // server-side: record digests and compare with manifest when provided
        await log(keyhash, sid, 'integrity', obj.integrity);
      }

      if(obj.manifest){
        await log(keyhash, sid, 'manifest', obj.manifest);
      }

      if(obj.request_code){
        // Return known code blob by entry name, along with digest
        // For demo, just echo
        const entry = obj.request_code;
        ws.send(packResponse(jwtToken||'', sessionKey, { code: { entry, source: '', digest: '' } }));
      }

    }catch(e){
      try{ ws.close(); }catch(_){}
    }
  });

  const beatTimer = setInterval(async ()=>{
    if(!sessionKey){ return; }
    if(nowHR()-lastBeat > BigInt(3*60*1e9)){ // grace 3 minutes
      await log(keyhash, sid, 'disconnect', { reason:'heartbeat-timeout' });
      sessions.delete(sid);
      try{ ws.close(); }catch(_){}
      clearInterval(beatTimer);
      return;
    }
    // proactive ping
    ws.ping();
  }, 30_000);

  ws.on('close', async ()=>{
    clearInterval(beatTimer);
    sessions.delete(sid);
    // finalize analytics
    const s = await one('SELECT * FROM sessions WHERE id=?',[sid]);
    if(s){
      const connected_time = nowHR() - BigInt(s.started_hr);
      await run('UPDATE sessions SET connected_time=? WHERE id=?',[connected_time.toString(), sid]);
      const a = await one('SELECT * FROM analytics WHERE keyhash=?',[s.keyhash]);
      if(!a){
        await run('INSERT INTO analytics(keyhash,total_connected_time,total_challenges_failed,total_challenges_solved,session_count) VALUES(?,?,?,?,?)',[
          s.keyhash, connected_time.toString(), s.challenges_failed, s.challenges_solved, 1
        ]);
      }else{
        await run('UPDATE analytics SET total_connected_time=total_connected_time+?, total_challenges_failed=total_challenges_failed+?, total_challenges_solved=total_challenges_solved+?, session_count=session_count+1 WHERE keyhash=?',[
          connected_time.toString(), s.challenges_failed, s.challenges_solved, s.keyhash
        ]);
      }
    }
  });

  sessions.set(sid, { ws, sid, ip });
}

function startWSServer(server){
  const wss = new WebSocket.Server({ server, path:'/ws' });
  wss.on('connection', onWSConnection);
  return wss;
}

module.exports = { startWSServer };
