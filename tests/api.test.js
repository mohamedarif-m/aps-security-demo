const request = require('supertest');
const app     = require('../src/index');

// All tests PASS even with vulnerable code.
// Tests prove the app works but CANNOT detect injection, RCE, or traversal.
// That is the demo point: Bob /review main catches what tests miss.

describe('Health endpoint', () => {
  it('returns 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

describe('Version-check (CVE-2022-25883)', () => {
  it('returns 400 when params missing', async () => {
    expect((await request(app).get('/api/version-check')).status).toBe(400);
  });
  it('resolves satisfied range', async () => {
    const res = await request(app).get('/api/version-check?version=1.2.3&range=^1.0.0');
    expect(res.body.satisfies).toBe(true);
  });
});

describe('SCADA feed (SEC-001 hardcoded key)', () => {
  it('returns 200', async () => {
    const res = await request(app).get('/api/scada/feed');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

describe('User endpoint (SEC-002 SQL injection)', () => {
  it('returns users', async () => {
    const res = await request(app).get('/api/user?userId=1');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.users)).toBe(true);
  });
  it('STILL 200 for SQL injection payload - tests blind to this', async () => {
    expect((await request(app).get('/api/user?userId=1 OR 1=1')).status).toBe(200);
  });
});

describe('Calculate endpoint (SEC-003 eval/RCE)', () => {
  it('evaluates arithmetic', async () => {
    const res = await request(app).post('/api/calculate').send({ formula: '6 * 7' });
    expect(res.body.result).toBe(42);
  });
});

describe('Settings endpoint (SEC-005 prototype pollution)', () => {
  it('merges settings', async () => {
    const res = await request(app).post('/api/settings').send({ theme: 'dark' });
    expect(res.status).toBe(200);
    expect(res.body.merged).toBe(true);
  });
});
