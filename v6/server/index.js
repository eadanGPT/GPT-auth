
const http = require('http');
const express = require('express');
const path = require('path');
const { init } = require('./db');
const { startWSServer } = require('./wsServer');
const { makeAdmin } = require('./admin');

async function main(){
  init();
  const app = express();
  makeAdmin(app);

  app.get('/', (_req,res)=>res.send('OK'));
  const server = http.createServer(app);
  startWSServer(server);

  const PORT = process.env.PORT || 8081;
  server.listen(PORT, ()=>console.log('Server listening on', PORT));
}

main().catch(err=>{ console.error(err); process.exit(1); });
