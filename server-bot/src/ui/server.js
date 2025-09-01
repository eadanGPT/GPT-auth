
import express from 'express';
import http from 'node:http';
import { WebSocketServer } from 'ws';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function startBotUI(bot, port){
  const app = express();
  app.use('/', express.static(path.join(__dirname, '..', '..', 'public')));
  app.get('/api/inventory', (_req,res)=> res.json({ items: bot.inventory.items().map(i=>({name:i.name,count:i.count,slot:i.slot})) }));
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/live' });
  function snapshot(){
    return JSON.stringify({
      pos: bot.entity?.position,
      health: bot.health, food: bot.food,
      time: Date.now()
    });
  }
  setInterval(()=>{
    const frame = snapshot();
    for (const ws of wss.clients) { try { ws.send(frame); } catch {} }
  }, 1000);
  server.listen(port, ()=> console.log(`[server-bot ui] http://localhost:${port}/`));
  return server;
}
