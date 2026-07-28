const request = require('supertest');
const app     = require('../src/index');

describe('Health endpoint', () => {
  it('GET /health returns 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

describe('Version-check endpoint', () => {
  it('returns 400 when params missing', async () => {
    const res = await request(app).get('/api/version-check');
    expect(res.status).toBe(400);
  });

  it('resolves a satisfied range', async () => {
    const res = await request(app).get('/api/version-check?version=1.2.3&range=^1.0.0');
    expect(res.body.satisfies).toBe(true);
  });
});

describe('SCADA feed endpoint', () => {
  it('returns 200 with grid data', async () => {
    const res = await request(app).get('/api/scada/feed');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty('gridFrequency');
  });
});

describe('User endpoint', () => {
  it('returns users array', async () => {
    const res = await request(app).get('/api/user?userId=1');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.users)).toBe(true);
  });
});

describe('Settings endpoint', () => {
  it('merges settings', async () => {
    const res = await request(app).post('/api/settings').send({ theme: 'dark' });
    expect(res.status).toBe(200);
    expect(res.body.merged).toBe(true);
  });
});
