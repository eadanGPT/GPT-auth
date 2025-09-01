import crypto from 'crypto';
import { WebSocketServer } from 'ws';
import db from './db.js';
import { hkdf, aesgcmEncrypt, aesgcmDecrypt, KSTORE, issueJWT } from './crypto.js';
import { ChallengeKit } from '../shared/challenges.js';
const ACTIVE=new Map();
function setupWS(server){
  const wss=new WebSocketServer({server,path:'/ws'});
  const CH=new ChallengeKit();
  wss.on('connection',(ws,req)=>{
    const ip=req.socket.remoteAddress; const sid=crypto.randomBytes(16).toString('hex');
    let ecdh=crypto.generateKeyPairSync('x25519'); let shared=null; let authed=false; let keyhash=null;
    let hb=null, integ=null; db.createSession(sid,'',ip); db.log('info','connect','',sid,{ip});
    const hello={ ts:Date.now(), server_sign_pub: KSTORE.signPub.export({type:'spki',format:'der'}).toString('hex'), ecdh_pub: ecdh.publicKey.export({type:'spki',format:'der'}).toString('hex'), nonce: crypto.randomBytes(16).toString('hex') };
    ws.send(JSON.stringify({token:'', data: aesgcmEncrypt(Buffer.alloc(32,1), Buffer.from(JSON.stringify(hello)))}));
    ws.on('message',(raw)=>{
      try{
        const m=JSON.parse(raw.toString()); const b64=m.data;
        const payload=JSON.parse(aesgcmDecrypt(shared||Buffer.alloc(32,1), b64).toString('utf8'));
        if(payload.type==='ecdh'){
          const clientPub=crypto.createPublicKey({key:Buffer.from(payload.ecdh_pub,'hex'),format:'der',type:'spki'});
          const secret=crypto.diffieHellman({privateKey: ecdh.privateKey, publicKey: clientPub});
          shared=hkdf(secret, Buffer.from(payload.nonce,'hex'), 'ws-session', 32);
          keyhash=payload.keyhash; const plainKey=db.getKeyPlain(keyhash); if(!plainKey){ db.log('warn','auth-fail',keyhash,sid,{reason:'unknown key'}); ws.close(); return; }
          const hmac=crypto.createHmac('sha256', Buffer.from(plainKey,'utf8')).update(payload.proof).digest('hex'); if(hmac!==payload.proofH){ db.log('warn','auth-fail',keyhash,sid,{reason:'bad proof'}); ws.close(); return; }
          db.upsertIP(keyhash, ip); db.upsertHWID(keyhash,'perm',payload.permHWID); db.upsertHWID(keyhash,'temp',payload.tempHWID);
          authed=true; db.finalizeSession(sid,{keyhash,login_time:Date.now()}); db.log('info','auth-ok',keyhash,sid,{ip});
          const jwt=issueJWT({sid,keyhash});
          hb=setInterval(()=>{ const {id,ch}=CH.next(); const msg={type:'hb',id,ch}; ws.send(JSON.stringify({token:jwt, data:aesgcmEncrypt(shared, Buffer.from(JSON.stringify(msg)))})); }, 120000);
          integ=setInterval(()=>{ const msg={type:'integrity-digest', q:crypto.randomBytes(8).toString('hex')}; ws.send(JSON.stringify({token:jwt, data:aesgcmEncrypt(shared, Buffer.from(JSON.stringify(msg)))})); }, 300000);
          ws.send(JSON.stringify({token:jwt, data:aesgcmEncrypt(shared, Buffer.from(JSON.stringify({type:'auth-ack',jwt,serverTime:Date.now()})))}));
          ACTIVE.set(sid,{ws,keyhash,ip,since:Date.now(),solved:0,failed:0});
          return;
        }
        if(!authed){ ws.close(); return; }
        if(payload.type==='hb-reply'){ ACTIVE.get(sid).solved++; db.log('info','challenge',keyhash,sid,{id:payload.id,ok:true}); return; }
        if(payload.type==='integrity'){ db.log('info','integrity',keyhash,sid,payload); return; }
      }catch(e){ db.log('error','ws-err',keyhash||'',sid,{error:String(e)}); try{ws.close();}catch{} }
    });
    ws.on('close',()=>{ clearInterval(hb); clearInterval(integ); const s=ACTIVE.get(sid); if(s){ const connected=Date.now()-s.since; db.finalizeSession(sid,{disconnected_at:Date.now(),challenges_solved:s.solved,challenges_failed:s.failed}); db.bumpAnalytics(keyhash||'',{connected,sessions:1,solved:s.solved,failed:s.failed}); ACTIVE.delete(sid);} db.log('info','disconnect',keyhash||'',sid,{ip}); });
  });
  setupWS.active=ACTIVE;
}
export { setupWS };
