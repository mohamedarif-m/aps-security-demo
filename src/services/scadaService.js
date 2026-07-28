/**
 * scadaService.js - SECURE baseline
 * Credentials loaded from environment variables only.
 */

const SCADA_API_KEY = process.env.SCADA_API_KEY;

const getScadaFeed = async () => {
  await new Promise(r => setTimeout(r, 80));
  return {
    success: true,
    authenticated: !!SCADA_API_KEY,
    gridFrequency: 59.98,
    totalGenerationMW: 8420,
    transmissionLoss: 2.3,
    substationsOnline: 68,
    substationsTotal: 70,
    timestamp: new Date().toISOString()
  };
};

module.exports = { getScadaFeed };
