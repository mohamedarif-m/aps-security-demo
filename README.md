# APS Security Demo

**Bob AI Developer — Shift-Left Security Demo**

This repo has two branches:

| Branch | Purpose |
|--------|---------|
| `main` | Clean, secure baseline |
| `demo/security` | Introduces 7 security vulnerabilities for Bob to find |

## How to trigger Bob Findings

1. Open this repo in VS Code with the Bob extension
2. Check out `demo/security` branch
3. In the Bob chat panel, type:

```
/review main
```

Bob compares `demo/security` against `main` and posts findings in the **Bob Findings** panel.

## Vulnerabilities on `demo/security`

| ID | File | Severity | Description |
|----|------|----------|-------------|
| CVE-2022-25883 | `package.json` | HIGH | semver@7.3.4 ReDoS |
| SEC-001 | `scadaService.js` | CRITICAL | Hardcoded SCADA API key |
| SEC-002 | `userService.js` | HIGH | SQL injection |
| SEC-003 | `userService.js` | CRITICAL | eval() Remote Code Execution |
| SEC-004 | `fileService.js` | HIGH | Path traversal |
| SEC-005 | `fileService.js` | HIGH | Prototype pollution |
| SEC-008 | `userService.js` | MEDIUM | Password written to logs |
