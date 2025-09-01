
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const { get, set, all, one, run } = require('./db');

const ADMIN_COOKIE = 'adminToken';
const ADMIN_JWT_TTL = 7*24*3600; // 1 week

function makeAdmin(app){
  app.use(cookieParser());
  app.use(express.json());
  app.use('/admin', express.static(path.join(__dirname,'public')));

  app.post('/admin/login', async (req,res)=>{
    const { password } = req.body;
    const actual = await get('admin_password') || 'change-me';
    if(password !== actual) return res.status(403).json({ ok:false });
    const token = jwt.sign({ role:'admin' }, await getJWTSecret(), { expiresIn: ADMIN_JWT_TTL });
    res.cookie(ADMIN_COOKIE, token, { httpOnly: true, maxAge: ADMIN_JWT_TTL*1000 });
    res.json({ ok:true });
  });

  app.get('/admin/api/active', async (req,res)=>{
    if(!await isAdmin(req)) return res.status(403).end();
    const rows = await all('SELECT * FROM sessions');
    res.json(rows);
  });

  app.get('/clients/:key', async (req,res)=>{
    const key = req.params.key;
    const a = await one('SELECT * FROM analytics WHERE keyhash=?',[key]);
    const sessions = await all('SELECT * FROM sessions WHERE keyhash=?',[key]);
    res.json({ analytics:a||{}, sessions });
  });
}

async function getJWTSecret(){
  let s = await one('SELECT v FROM settings WHERE k=?',['admin_jwt']);
  if(!s){
    const secret = require('crypto').randomBytes(32).toString('hex');
    await run('INSERT INTO settings(k,v) VALUES(?,?)',['admin_jwt', secret]);
    return secret;
  }
  return s.v;
}

async function isAdmin(req){
  const token = req.cookies[ADMIN_COOKIE];
  if(!token) return false;
  try{
    jwt.verify(token, await getJWTSecret());
    return true;
  }catch(e){ return false; }
}

module.exports = { makeAdmin };
