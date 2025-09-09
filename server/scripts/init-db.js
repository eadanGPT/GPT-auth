import '../lib/licenseStore.js'; console.log('DB initialized/seeded on first run.');

import { LicenseStore } from '../lib/licenseStore.js';
const { createKey } = await LicenseStore.init();
try { createKey('LIC-TRIAL-123', 'trial', ['user']); } catch {}
try { createKey('LIC-ANALYTICS-999', 'pro', ['user','module:get:analytics']); } catch {}
console.log('Seeded default license keys');
