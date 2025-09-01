
import { config } from './config.js';
import { connectAndAuth } from './wsAuth.js';
import { createServerSideBot } from './bot.js';
import { startBotUI } from './ui/server.js';

(async function(){
  await connectAndAuth(); // authenticate this service with the WS auth system
  const bot = createServerSideBot();
  startBotUI(bot, config.botHTTPPort);
})().catch((e)=>{ console.error(e); process.exit(1); });
