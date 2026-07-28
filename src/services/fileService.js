/**
 * fileService.js
 *
 * WARNING: SEC-004 HIGH - Path Traversal (line 16)
 * filename from req.query joined to __dirname without path guard.
 * Attacker: ?filename=../../.env reads secrets.
 * Fix: resolve path and assert it starts with REPORTS_DIR.
 *
 * WARNING: SEC-005 HIGH - Prototype Pollution (line 21)
 * deepMerge iterates keys without blocking __proto__.
 * Attacker: {"__proto__":{"isAdmin":true}} poisons Object.prototype.
 * Fix: skip __proto__, constructor, prototype keys.
 */

const fs   = require('fs');
const path = require('path');

const getReport = (filename) => {
  const filePath = path.join(__dirname, '../../reports', filename);
  return fs.readFileSync(filePath, 'utf8');
};

function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { getReport, deepMerge };
