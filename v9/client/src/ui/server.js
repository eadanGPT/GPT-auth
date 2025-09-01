
import express from 'express';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { attachLiveView } from '../bot/liveView.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function startClientUI(bot, port=9090){
  const app = express();
  app.use(express.json());
  app.use('/', express.static(path.join(__dirname, '..', '..', 'public')));

  app.get('/api/inventory', (_req,res)=> res.json({ items: bot.inventory.items().map(i=>({name:i.name,count:i.count,slot:i.slot})) }));
  app.post('/api/equip', async (req,res)=>{
    const name = req.body?.name; 
    const item = bot.inventory.items().find(i=>i.name===name);
    if (!item) return res.status(404).json({ error:'item_not_found' });
    try { await bot.equip(item, 'hand'); res.json({ ok:true }); } catch (e) { res.status(500).json({ error:e.message }); }
  });
  app.post('/api/drop', async (req,res)=>{
    const name = req.body?.name; 
    const item = bot.inventory.items().find(i=>i.name===name);
    if (!item) return res.status(404).json({ error:'item_not_found' });
    try { await bot.tossStack(item); res.json({ ok:true }); } catch (e) { res.status(500).json({ error:e.message }); }
  });

  const server = http.createServer(app);
  attachLiveView(server, bot);
  server.listen(port, ()=> console.log(`[ui] http://localhost:${port}`));
  return server;
}
