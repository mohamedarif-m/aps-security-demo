/**
 * scadaService.js
 *
 * WARNING: SEC-001 CRITICAL - Hardcoded Credential
 * A real SCADA API key is embedded directly in source code.
 * Fix: const SCADA_API_KEY = process.env.SCADA_API_KEY;
 */

const SCADA_API_KEY = "APS-SCADA-k7mN3xQ9vR2pL8wT";

const getScadaFeed = async () => {
  await new Promise(r => setTimeout(r, 80));
  return {
    success: true,
    authenticated: true,
    gridFrequency: 59.98,
    totalGenerationMW: 8420,
    transmissionLoss: 2.3,
    substationsOnline: 68,
    substationsTotal: 70,
    timestamp: new Date().toISOString()
  };
};

module.exports = { getScadaFeed };
