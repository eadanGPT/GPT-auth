
import chalk from 'chalk';
import readline from 'node:readline';
import express from 'express';
import { config } from './config.js';
import { connectAndAuth } from './ws.js';
import { createBot } from './bot/createBot.js';
import { installInventoryAPI } from './bot/inventory.js';
import { startClientUI } from './ui/server.js';

async function menu(){
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  function ask(q){ return new Promise(r=> rl.question(q, r)); }
  console.clear();
  console.log(chalk.cyanBright('Secure Client CLI'));
  const server = await ask(chalk.gray('Server WS URL [ws://localhost:8080/ws]: ')) || 'ws://localhost:8080/ws';
  const mcHost = await ask(chalk.gray('Minecraft host [localhost]: ')) || 'localhost';
  const mcPort = Number(await ask(chalk.gray('Minecraft port [25565]: ')) || '25565');
  const username = await ask(chalk.gray('Bot username [SecureBot]: ')) || 'SecureBot';
  rl.close();
  return { server, mcHost, mcPort, username };
}

async function main(){
  const sel = await menu();
  process.env.SERVER_URL = sel.server;
  const key = process.env.CLIENT_KEY || '';
  const { ws } = await connectAndAuth(key);
  console.log(chalk.green('[client] authenticated'));

  const bot = createBot({ host: sel.mcHost, port: sel.mcPort, username: sel.username });
  const invApi = installInventoryAPI(bot);

  const app = express();
  app.use(express.json());
  app.use('/', express.static(new URL('../public', import.meta.url).pathname));
  app.get('/api/inventory', (_req,res)=> res.json({ items: invApi.list() }));
  startClientUI(bot, config.clientHTTPPort);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.setPrompt(chalk.gray('client> ')); rl.prompt();
  rl.on('line', async (line)=>{
    const [cmd, ...args] = line.trim().split(/\s+/);
    try {
      if (cmd === 'equip') { await invApi.equip(args[0]); console.log('equipped'); }
      else if (cmd === 'drop') { await invApi.drop(args[0]); console.log('dropped'); }
      else if (cmd === 'exit') process.exit(0);
      else console.log('commands: equip <name>, drop <name>, exit');
    } catch (e) { console.log('err:', e.message); }
    rl.prompt();
  });
}
main().catch((e)=>{ console.error(e); process.exit(1); });
