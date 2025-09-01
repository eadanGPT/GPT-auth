
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, 'server.db');
const db = new sqlite3.Database(dbPath);

function init(){
  const schema = fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8');
  db.exec(schema);
  set('allowConnections','true');
  set('maxConnections','500');
}

function get(k){
  return new Promise((resolve,reject)=>{
    db.get('SELECT v FROM settings WHERE k=?',[k], (err,row)=>{
      if(err) reject(err); else resolve(row?row.v:null);
    });
  });
}

function set(k,v){
  db.run('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',[k,v]);
}

function run(sql, params=[]){
  return new Promise((resolve,reject)=>{
    db.run(sql, params, function(err){ if(err) reject(err); else resolve(this); });
  });
}

function all(sql, params=[]){
  return new Promise((resolve,reject)=>{
    db.all(sql, params, function(err,rows){ if(err) reject(err); else resolve(rows); });
  });
}

function one(sql, params=[]){
  return new Promise((resolve,reject)=>{
    db.get(sql, params, function(err,row){ if(err) reject(err); else resolve(row); });
  });
}

module.exports = { db, init, get, set, run, all, one };
