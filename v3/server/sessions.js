// server/sessions.js
// Tracks active sessions in RAM with stats.

class Sessions {
  constructor() {
    this.sessions = new Map();
  }

  add({ connId, clientId, ip }) {
    this.sessions.set(connId, {
      connId,
      clientId,
      ip,
      stats: { heartbeats: 0, challengesIssued: 0, challengesSolved: 0 },
      lastSeen: Date.now()
    });
  }

  get(connId) {
    return this.sessions.get(connId);
  }

  list() {
    return Array.from(this.sessions.values());
  }

  getWS(connId) {
    return this.sessions.get(connId)?.ws || null;
  }

  onHeartbeat(connId) {
    const s = this.sessions.get(connId);
    if (s) {
      s.stats.heartbeats++;
      s.lastSeen = Date.now();
    }
  }

  onChallengeIssued(connId) {
    const s = this.sessions.get(connId);
    if (s) s.stats.challengesIssued++;
  }

  onChallengeSolved(connId) {
    const s = this.sessions.get(connId);
    if (s) s.stats.challengesSolved++;
  }

  remove(connId) {
    this.sessions.delete(connId);
  }
}

module.exports = Sessions;
