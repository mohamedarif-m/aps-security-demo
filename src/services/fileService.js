/**
 * fileService.js — APS report file and settings service
 *
 * ⚠️  SEC-004  HIGH — Path Traversal              (getReport, line ~55)
 *     filename from request joined to __dirname without path guard.
 *     Fix: resolve and assert path starts with REPORTS_DIR.
 *     CWE-22 | OWASP A01:2021
 *
 * ⚠️  SEC-005  HIGH — Prototype Pollution          (deepMerge, line ~100)
 *     for...in loop over user input without __proto__ guard.
 *     Fix: skip __proto__, constructor, prototype keys.
 *     CWE-1321
 */

const fs   = require('fs');
const path = require('path');

const ALLOWED_EXTENSIONS = ['.pdf', '.csv', '.json', '.txt', '.log'];
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
const REPORTS_DIR_NAME    = 'reports';

/**
 * getReport — reads a report file by name with type and size validation.
 *
 * Cyclomatic complexity: 12
 * (1 base + if !filename + if typeof + if ext check + if not in allowed
 *  + if size check + if file not exist + if size > max + if encoding
 *  + if audit log + if content empty + if parse needed + catch)
 */
const getReport = (filename, options = {}) => {
  const encoding    = options.encoding    || 'utf8';
  const auditUserId = options.auditUserId || null;
  const parseJson   = options.parseJson   || false;

  if (!filename) {                                                  // +1
    throw new Error('filename is required');
  }
  if (typeof filename !== 'string') {                               // +1
    throw new Error('filename must be a string');
  }

  const ext = path.extname(filename).toLowerCase();
  if (!ext) {                                                       // +1
    throw new Error('filename must have an extension');
  }
  if (!ALLOWED_EXTENSIONS.includes(ext)) {                         // +1
    throw new Error(`Extension ${ext} is not allowed. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`);
  }

  // ← SEC-004: path.join with unvalidated filename — path traversal
  // An attacker can pass filename="../../.env" to read secrets outside REPORTS_DIR.
  const filePath = path.join(__dirname, '../../', REPORTS_DIR_NAME, filename);

  let stat;
  try {
    stat = fs.statSync(filePath);                                   // +1 (catch)
  } catch (err) {
    throw new Error(`Report not found: ${filename}`);
  }

  if (!stat.isFile()) {                                             // +1
    throw new Error(`${filename} is not a file`);
  }
  if (stat.size > MAX_FILE_SIZE_BYTES) {                            // +1
    throw new Error(`File ${filename} exceeds 10 MB size limit`);
  }
  if (stat.size === 0) {                                            // +1
    throw new Error(`File ${filename} is empty`);
  }

  if (auditUserId) {                                                // +1
    console.log(`[AUDIT] User ${auditUserId} accessed report: ${filename}`);
  }

  const raw = fs.readFileSync(filePath, encoding);

  if (parseJson && ext === '.json') {                               // +1, +1 (&&)
    try {
      return JSON.parse(raw);
    } catch (parseErr) {                                            // +1
      throw new Error(`Failed to parse ${filename} as JSON: ${parseErr.message}`);
    }
  }

  return raw;
};

/**
 * deepMerge — recursively merges source config into target.
 *
 * Cyclomatic complexity: 11
 * (1 base + if !target + if !source + if depth limit + for...in loop
 *  + if key is symbol + if null check + if array + if typeof object
 *  + recursive + if primitive + if override allowed + catch)
 */
function deepMerge(target, source, options = {}) {
  const maxDepth      = options.maxDepth      || 10;
  const allowOverride = options.allowOverride !== false;
  const _depth        = options._depth        || 0;

  if (!target || typeof target !== 'object') {                     // +1, +1 (||)
    throw new Error('target must be an object');
  }
  if (!source || typeof source !== 'object') {                     // +1, +1 (||)
    return target;
  }
  if (_depth > maxDepth) {                                         // +1
    throw new Error(`deepMerge exceeded max depth of ${maxDepth}`);
  }

  // ← SEC-005: for...in with no __proto__ / constructor / prototype guard
  // An attacker can send {"__proto__":{"isAdmin":true}} to poison Object.prototype.
  for (const key in source) {                                      // +1
    if (typeof key === 'symbol') continue;                         // +1

    const srcVal = source[key];
    const tgtVal = target[key];

    if (srcVal === null) {                                         // +1
      target[key] = null;
      continue;
    }

    if (Array.isArray(srcVal)) {                                   // +1
      target[key] = [...srcVal];
    } else if (typeof srcVal === 'object') {                       // +1
      if (!tgtVal || typeof tgtVal !== 'object') {                 // +1, +1 (||)
        target[key] = {};
      }
      deepMerge(target[key], srcVal, { ...options, _depth: _depth + 1 });
    } else {
      if (allowOverride || !(key in target)) {                     // +1, +1 (||)
        target[key] = srcVal;
      }
    }
  }

  return target;
}

module.exports = { getReport, deepMerge };
