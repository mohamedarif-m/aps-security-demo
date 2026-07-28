# Security Rules - APS Security Demo

These rules apply to every Bob interaction in this project.
When reading, writing, or reviewing any file, Bob MUST flag the following patterns.

---

## SEC-001 - No Hardcoded Credentials (CRITICAL)

Flag any string literal assigned to a variable named `api_key`, `apiKey`,
`password`, `secret`, `token`, or `auth_token`.

Violation example:
```js
const SCADA_API_KEY = "APS-SCADA-k7mN3xQ9vR2pL8wT";
```
Fix: `const SCADA_API_KEY = process.env.SCADA_API_KEY;`
CWE-798 | OWASP A07:2021

---

## SEC-002 - SQL Injection (HIGH)

Flag SQL template literals that interpolate user input without parameterisation.

Violation example:
```js
const sql = `SELECT * FROM users WHERE id = ${userId}`;
```
Fix: `db.query('SELECT * FROM users WHERE id = ?', [userId])`
CWE-89 | OWASP A03:2021

---

## SEC-003 - Eval / Remote Code Execution (CRITICAL)

Flag `eval(x)` or `new Function(x)` where x is not a string literal.

Violation example:
```js
return eval(formula);
```
Fix: replace with safe allow-list of operations.
CWE-95 | OWASP A03:2021

---

## SEC-004 - Path Traversal (HIGH)

Flag `path.join` / `fs.readFileSync` using user-supplied input without a path guard.

Violation example:
```js
const filePath = path.join(__dirname, '../../reports', filename);
```
Fix: resolve and assert path starts with REPORTS_DIR.
CWE-22 | OWASP A01:2021

---

## SEC-005 - Prototype Pollution (HIGH)

Flag `for...in` loops over user objects without `__proto__` guard.

Violation example:
```js
for (const key in source) { target[key] = source[key]; }
```
Fix: skip `__proto__`, `constructor`, `prototype` keys.
CWE-1321

---

## SEC-008 - Sensitive Data in Logs (MEDIUM)

Flag `console.log` calls printing `password`, `token`, or `apiKey` values.

Violation example:
```js
console.log(`username=${username} password=${password}`);
```
Fix: log only opaque identifiers (userId, requestId).
CWE-532

---

## CVE-2022-25883 - semver ReDoS (HIGH)

Flag `"semver": "7.3.4"` or any version below 7.5.2 in package.json.
Fix: bump to `"semver": "^7.5.2"`
Advisory: https://github.com/advisories/GHSA-c2qf-rxjj-qqgw
