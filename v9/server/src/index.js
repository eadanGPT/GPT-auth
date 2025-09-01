
import http from 'node:http';
import express from 'express';
import { env } from './config.js';
import { startWSServer } from './websocket.js';
import { startAdminServer } from './admin.js';

const app = express();
app.get('/', (_req,res)=> res.send('Secure WS Server running'));
const httpServer = http.createServer(app);

startWSServer(httpServer);
const adminApp = startAdminServer();
httpServer.on('request', adminApp);

httpServer.listen(env.PORT, ()=> {
  console.log(`HTTP/WS server on :${env.PORT}`);
});
