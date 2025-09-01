
// server/manifests.js
import fs from 'fs';
import crypto from 'crypto';

export function buildFileManifest(root){
  // compute simple manifest for server files
  const files = [];
  function walk(dir){
    for (const name of fs.readdirSync(dir)){
      const p = `${dir}/${name}`;
      const st = fs.statSync(p);
      if (st.isDirectory()) walk(p);
      else {
        const h = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
        files.push({ path: p.replace(root+'/',''), hash: h });
      }
    }
  }
  walk(root);
  return files;
}
