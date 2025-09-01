
// server/admin.js
import express from 'express';
import basicAuth from 'basic-auth';
import jwt from 'jsonwebtoken';
import { db } from './db.js';
import { adminState } from './admin_state.js';

export const ADMIN_USER = 'Admin';

const router = express.Router();

function auth(req,res,next){
  const creds = basicAuth(req);
  if (!creds || creds.name!==ADMIN_USER || creds.pass!==adminState.getPassword()) {
    res.set('WWW-Authenticate','Basic realm="Admin"');
    return res.status(401).send('Auth required');
  }
  next();
}

router.use('/admin', auth);

// issue 1-week browser token
router.get('/admin/login', (req,res)=>{
  const now = Math.floor(Date.now()/1000);
  const tok = jwt.sign({ sub:'admin', scope:'admin', iat:now, exp: now+7*24*60*60 }, adminState.getPassword());
  res.cookie?.('admintoken', tok, { httpOnly:true, sameSite:'strict', maxAge: 7*24*60*60*1000 });
  res.json({ ok:true });
});

router.get('/admin', (_req,res)=>{
  res.set('Content-Type','text/html');
  res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Admin</title>
  <style>
    body{font-family:system-ui;margin:0;padding:0;background:#0b0c10;color:#eee}
    header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:#111;border-bottom:1px solid #222}
    nav a{color:#9ad; margin-right:12px; text-decoration:none}
    .wrap{padding:16px}
    table{width:100%;border-collapse:collapse}
    th,td{border:1px solid #333;padding:6px}
    th{background:#151515}
    .card{border:1px solid #333;border-radius:10px;padding:12px;margin-bottom:12px;background:#111}
  </style></head>
  <body>
    <header><div>Secure Admin</div><nav>
      <a href="/admin/sessions">Sessions</a>
      <a href="/admin/keys">Keys</a>
      <a href="/admin/users">Users</a>
      <a href="/admin/logs">Logs</a>
      <a href="/admin/settings">Settings</a>
    </nav></header>
    <div class="wrap">
      <div class="card"><h3>Welcome</h3><p>Use the endpoints to manage the system. (Password is <strong>never</strong> shown here.)</p></div>
    </div>
  </body></html>`);
});

function rows(sql, ...args){ return db.prepare(sql).all(...args); }
function run(sql, ...args){ return db.prepare(sql).run(...args); }

router.use(express.urlencoded({ extended: true }));
router.use(express.json());

router.get('/admin/sessions', (_req,res)=> res.json(rows('SELECT * FROM sessions WHERE active=1')));
router.post('/admin/sessions/disconnect', (req,res)=>{
  const { id } = req.body; if(!id) return res.status(400).json({ok:false});
  run('UPDATE sessions SET active=0 WHERE id=?', id);
  res.json({ ok:true });
});
router.get('/admin/keys', (_req,res)=> res.json(rows('SELECT * FROM keys')));
router.post('/admin/keys/add', (req,res)=>{
  const { license, owner } = req.body;
  if (!license || !owner) return res.status(400).json({ok:false});
  run('INSERT OR REPLACE INTO keys(license_key, owner, created_at) VALUES (?,?,?)', license, owner, Date.now());
  res.json({ ok:true });
});
router.post('/admin/keys/blacklist', (req,res)=>{
  const { license } = req.body; if(!license) return res.status(400).json({ok:false});
  run('UPDATE keys SET blacklisted=1 WHERE license_key=?', license);
  res.json({ ok:true });
});
router.post('/admin/keys/remove', (req,res)=>{
  const { license } = req.body; if(!license) return res.status(400).json({ok:false});
  run('DELETE FROM keys WHERE license_key=?', license);
  res.json({ ok:true });
});
router.get('/admin/logs', (_req,res)=> res.json(rows('SELECT * FROM logs ORDER BY created_at DESC LIMIT 200')));
router.get('/admin/settings', (_req,res)=> res.json(rows('SELECT * FROM settings')));
router.post('/admin/settings', (req,res)=>{
  const { key, value } = req.body; if(!key) return res.status(400).json({ok:false});
  run('INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)', key, value ?? '');
  res.json({ ok:true });
});

export default router;
