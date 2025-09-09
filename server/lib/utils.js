'use strict';
function delay(ms){ return new Promise(r => setTimeout(r, ms)); }
function randInt(n){ return Math.floor(Math.random() * n); }
function safeStringify(x){ try { return JSON.stringify(x); } catch { return '[unserializable]'; } }
module.exports = { delay, randInt, safeStringify };
