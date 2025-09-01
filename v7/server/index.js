import express from 'express';
import http from 'http';
import cookieParser from 'cookie-parser';
import { setupWS } from './wsServer.js';
import { adminRouter, initAdmin } from './admin.js';
import db from './db.js';

const app = express();
app.use(express.json());
app.use(cookieParser());

await db.init();

const server = http.createServer(app);
setupWS(server);
await initAdmin(app);

const PORT = process.env.PORT || 8081;
server.listen(PORT, () => console.log('[server] listening', PORT));
