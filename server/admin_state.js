
// server/admin_state.js
import crypto from 'crypto';
import EventEmitter from 'events';
import { logEvent } from './db.js';

class AdminState extends EventEmitter {
  constructor(){
    super();
    this.password = null;
    this.issuedAt = 0;
    this.nextRotationAt = 0;
    this.rotate(true);
    const TWELVE_HOURS = 12*60*60*1000;
    setInterval(()=> this.rotate(true), TWELVE_HOURS).unref();
  }
  generatePassword(){
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let s=''; for(let i=0;i<16;i++) s += chars[Math.floor(Math.random()*chars.length)];
    return s;
  }
  rotate(log=true){
    const now = Date.now();
    this.password = this.generatePassword();
    this.issuedAt = now;
    this.nextRotationAt = now + 12*60*60*1000;
    if (log) {
      console.log(`[ADMIN] Password generated/rotated at ${new Date(now).toISOString()}: ${this.password}`);
      logEvent({ kind:'admin_password', level:'info', message:`Admin password rotated`, payload: Buffer.from(JSON.stringify({ issuedAt: now })) });
    }
    this.emit('rotated', { password: this.password, issuedAt: this.issuedAt, nextRotationAt: this.nextRotationAt });
  }
  getPassword(){ return this.password; }
  getMeta(){ return { password:this.password, issuedAt:this.issuedAt, nextRotationAt:this.nextRotationAt }; }
}

export const adminState = new AdminState();
