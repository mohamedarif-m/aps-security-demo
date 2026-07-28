require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const semver  = require('semver');

const app  = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/version-check', (req, res) => {
  const { version, range } = req.query;
  if (!version || !range) {
    return res.status(400).json({ error: 'Pass ?version=x.y.z&range=^x.y.z' });
  }
  const satisfies = semver.satisfies(version, range);
  res.json({ version, range, satisfies, semverVersion: semver.SEMVER_SPEC_VERSION });
});

app.get('/api/scada/feed', async (req, res) => {
  try {
    const { getScadaFeed } = require('./services/scadaService');
    res.json(await getScadaFeed());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/user', async (req, res) => {
  try {
    const { getUserById } = require('./services/userService');
    res.json({ users: await getUserById(req.query.userId) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/calculate', (req, res) => {
  try {
    const { calculateFormula } = require('./services/userService');
    res.json({ result: calculateFormula(req.body.formula) });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.get('/api/report', (req, res) => {
  try {
    const { getReport } = require('./services/fileService');
    res.send(getReport(req.query.filename));
  } catch (err) { res.status(404).json({ error: err.message }); }
});

app.post('/api/settings', (req, res) => {
  try {
    const { deepMerge } = require('./services/fileService');
    const settings = {};
    deepMerge(settings, req.body);
    res.json({ settings, merged: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`APS Security Demo API on port ${PORT}`));
}

module.exports = app;
