/**
 * fileService.js - SECURE baseline
 * Path-guard prevents traversal. Key-guard prevents prototype pollution.
 */

const fs   = require('fs');
const path = require('path');

const REPORTS_DIR = path.resolve(__dirname, '../../reports');

const getReport = (filename) => {
  const resolved = path.resolve(REPORTS_DIR, filename);
  if (!resolved.startsWith(REPORTS_DIR + path.sep)) {
    throw new Error('Access denied');
  }
  return fs.readFileSync(resolved, 'utf8');
};

function deepMerge(target, source) {
  const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
  for (const key of Object.keys(source)) {
    if (BLOCKED.has(key)) continue;
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
