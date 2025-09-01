import express from 'express';
import path from 'path';
import crypto from 'crypto';
import db from './db.js';
import { setupWS } from './wsServer.js';
function auth(req,res,next){ const token=req.cookies.admintoken||''; const expect=db.getSetting('admin_password')||'change-me'; if(token===crypto.createHash('sha256').update(expect).digest('hex')) return next(); res.status(401).send('unauthorized'); }
async function initAdmin(app){
  app.post('/admin/login',(req,res)=>{ const {password}=req.body||{}; const expect=db.getSetting('admin_password')||'change-me'; if(password===expect){ const token=crypto.createHash('sha256').update(expect).digest('hex'); res.cookie('admintoken',token,{httpOnly:true,maxAge:7*24*60*60*1000}); return res.json({ok:true}); } return res.status(401).json({ok:false}); });
  app.get('/admin', auth, (req,res)=>{ res.sendFile(path.join(process.cwd(),'server','public','index.html')); });
  app.get('/admin/active', auth, (req,res)=>{ const list=Array.from(setupWS.active.entries()).map(([sid,s])=>({sid,keyhash:s.keyhash,ip:s.ip,since:s.since,solved:s.solved,failed:s.failed})); res.json({list}); });
  app.get('/clients/:keyhash', auth, (req,res)=>{ const k=req.params.keyhash; const sessions=db.db.prepare('SELECT * FROM sessions WHERE keyhash=? ORDER BY connected_at DESC').all(k); const global=db.db.prepare('SELECT * FROM analytics_global WHERE keyhash=?').get(k); res.json({keyhash:k,global:global||{},sessions}); });
}
const adminRouter=express.Router();
export { adminRouter, initAdmin };
