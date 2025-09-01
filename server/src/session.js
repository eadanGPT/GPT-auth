
import { v4 as uuidv4 } from 'uuid';
export const sessions = new Map();
export function createSession({ user_id, key_hash, hwid_perm, temp_hwid, ip }) {
  const session_id = uuidv4();
  const s = { session_id, user_id, key_hash, hwid_perm, temp_hwid, ip, started_at: Date.now(), last_seen: Date.now(), heartbeats: 0, challenges_ok: 0, challenges_fail: 0 };
  sessions.set(session_id, s);
  return s;
}
export function endSession(session_id) { sessions.delete(session_id); }
