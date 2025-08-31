// server/integrity.js
// Computes and stores file digests for integrity checks.

const fs = require('fs');
const path = require('path');
const { sha256File } = require('../shared/crypto');

async function computeDigests(dir) {
  const files = fs.readdirSync(dir);
  const digests = {};
  for (const f of files) {
    const full = path.join(dir, f);
    if (fs.statSync(full).isFile()) {
      digests[f] = await sha256File(fs, full);
    }
  }
  return digests;
}

module.exports = { computeDigests };
