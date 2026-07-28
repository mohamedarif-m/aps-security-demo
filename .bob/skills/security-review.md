---
name: security-review
description: Review code for CVE vulnerabilities, OWASP Top 10 violations, and hardcoded secrets.
---

Perform a security-focused code review. For every issue found, report:

```
[SEVERITY] RULE-ID - Short title
File: <filename>, Line: <line number>
Issue: <one sentence>
Fix: <one sentence>
Reference: <CWE or CVE>
```

Severity: CRITICAL | HIGH | MEDIUM | LOW

## What to check

### SEC-001 - Hardcoded Credentials (CRITICAL)
Flag: `const SCADA_API_KEY = "APS-SCADA-k7mN3xQ9vR2pL8wT";`

### SEC-002 - SQL Injection (HIGH)
Flag: template literal interpolating userId into SQL string

### SEC-003 - Eval / RCE (CRITICAL)
Flag: `return eval(formula);`

### SEC-004 - Path Traversal (HIGH)
Flag: `path.join(__dirname, '../../reports', filename)` without path guard

### SEC-005 - Prototype Pollution (HIGH)
Flag: `for (const key in source)` without `__proto__` guard

### SEC-008 - Password in Logs (MEDIUM)
Flag: `console.log(... password=${password} ...)`

### CVE-2022-25883 - semver ReDoS (HIGH)
Flag: `"semver": "7.3.4"` in package.json
