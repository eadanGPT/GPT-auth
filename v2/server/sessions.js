// server/sessions.js
// Active sessions manager class: create, lookup, expire, offline cleanup, and heartbeat stats.

import crypto from 'crypto';
import { monoNowMs } from '../common/util.js';

export class SessionManager {
  constructor(db, logger) {
    this.db = db;
    this.logger = logger;
    this.map = new Map(); // session_id -> session data (in-RAM light state only)
  }

  createSession({ clientId, token, ip, expiresAt }) {
    // Create a new session and persist it
    const sessionId = crypto.randomUUID();
    const now = Date.now();
    const stats = { heartbeats: 0, answered: 0, challenges: 0, last5ServerResponses: [] };
    this.db.stmts.saveSession.run(sessionId, clientId, token, now, expiresAt, ip, now, JSON.stringify(stats));
    const state = { sessionId, clientId, token, ip, expiresAt, stats };
    this.map.set(sessionId, state);
    this.logger.user(clientId, 'auth', `New session ${sessionId} from ${ip}`);
    return state;
  }

  updateHeartbeat(sessionId, responded, serverResponded) {
    // Update session statistics on heartbeat
    const s = this.map.get(sessionId);
    if (!s) return;
    s.stats.heartbeats++;
    if (responded) s.stats.answered++;
    if (serverResponded) {
      s.stats.last5ServerResponses.push(Date.now());
      if (s.stats.last5ServerResponses.length > 5) s.stats.last5ServerResponses.shift();
    }
    this.db.stmts.saveSession.run(
      s.sessionId, s.clientId, s.token,
      s.expiresAt - 259200000 + 1, // dummy issued_at derivation to keep schema; not displayed
      s.expiresAt, s.ip, Date.now(), JSON.stringify(s.stats)
    );
  }

  deactivate(sessionId) {
    // Mark session inactive in DB and remove from RAM
    this.db.stmts.deactivateSession.run(sessionId);
    const s = this.map.get(sessionId);
    if (s) {
      this.logger.user(s.clientId, 'log', `Session ${sessionId} deactivated`);
      this.map.delete(sessionId);
    }
  }

  offlineCleanup(sessionId) {
    // Save minimal info and remove heavy in-RAM state
    this.deactivate(sessionId);
  }

  listActive() {
    // Return array of active sessions (lightweight view)
    return Array.from(this.map.values()).map(({ sessionId, clientId, ip, expiresAt }) => ({ sessionId, clientId, ip, expiresAt }));
  }
}
