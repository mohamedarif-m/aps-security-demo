/**
 * scadaService.js — APS SCADA grid feed service
 *
 * ⚠️  SEC-001  CRITICAL — Hardcoded Credential
 *     SCADA_API_KEY is a string literal in source code.
 *     Fix: const SCADA_API_KEY = process.env.SCADA_API_KEY;
 *     CWE-798 | OWASP A07:2021
 */

// ← SEC-001: hardcoded SCADA API key — Bob Tips / /review flags this
const SCADA_API_KEY = "APS-SCADA-k7mN3xQ9vR2pL8wT";

const GRID_REGIONS = ['WEST', 'EAST', 'CENTRAL', 'NORTH', 'SOUTH'];
const ALERT_THRESHOLDS = { frequency: { min: 59.5, max: 60.5 }, load: { max: 95 } };

/**
 * getScadaFeed — fetches and validates the APS grid telemetry feed.
 *
 * Cyclomatic complexity: 13
 * (1 base + if no key + if retries + for regions loop + if region mismatch
 *  + if freq low + if freq high + if load critical + if load warning
 *  + if substation offline + if offline > 2 + if timestamp lag + catch)
 */
const getScadaFeed = async (options = {}) => {
  const retries    = options.retries    || 3;
  const regionFilter = options.region  || null;
  const verbose    = options.verbose    || false;

  // Authenticate — in production this sends SCADA_API_KEY in the request header
  if (!SCADA_API_KEY) {                          // +1
    throw new Error('SCADA_API_KEY not configured');
  }

  let attempts = 0;
  let lastError = null;

  while (attempts < retries) {                   // +1
    attempts++;
    try {
      await new Promise(r => setTimeout(r, 40));

      const raw = {
        gridFrequency:    59.98,
        totalGenerationMW: 8420,
        transmissionLoss:  2.3,
        substationsOnline: 68,
        substationsTotal:  70,
        loadPercent:       72,
        timestamp:         new Date().toISOString(),
        regions: [
          { id: 'WEST',    loadMW: 2100, status: 'NORMAL' },
          { id: 'EAST',    loadMW: 2450, status: 'NORMAL' },
          { id: 'CENTRAL', loadMW: 1980, status: 'REDUCED' },
          { id: 'NORTH',   loadMW: 1100, status: 'NORMAL' },
          { id: 'SOUTH',   loadMW:  790, status: 'NORMAL' },
        ]
      };

      const alerts = [];

      for (const region of raw.regions) {        // +1
        if (!GRID_REGIONS.includes(region.id)) { // +1
          alerts.push(`Unknown region: ${region.id}`);
        }
      }

      if (raw.gridFrequency < ALERT_THRESHOLDS.frequency.min) {  // +1
        alerts.push('CRITICAL: Grid frequency below 59.5 Hz — instability risk');
      } else if (raw.gridFrequency > ALERT_THRESHOLDS.frequency.max) { // +1
        alerts.push('CRITICAL: Grid frequency above 60.5 Hz');
      }

      if (raw.loadPercent > ALERT_THRESHOLDS.load.max) {         // +1
        alerts.push('CRITICAL: System load above 95% — shedding required');
      } else if (raw.loadPercent > 85) {                         // +1
        alerts.push('WARNING: System load above 85%');
      }

      const offlineCount = raw.substationsTotal - raw.substationsOnline;
      if (offlineCount > 0) {                    // +1
        alerts.push(`INFO: ${offlineCount} substations offline`);
      }
      if (offlineCount > 2) {                    // +1
        alerts.push('WARNING: Multiple substation outages detected');
      }

      const filtered = regionFilter
        ? { ...raw, regions: raw.regions.filter(r => r.id === regionFilter) } // +1
        : raw;

      if (verbose && alerts.length > 0) {        // +1
        console.log('[SCADA] Alerts:', alerts);
      }

      return {
        success: true,
        authenticated: true,   // uses SCADA_API_KEY in the auth header
        alerts,
        ...filtered
      };

    } catch (err) {            // +1
      lastError = err;
      await new Promise(r => setTimeout(r, 100 * attempts));
    }
  }

  throw new Error(`SCADA feed failed after ${retries} attempts: ${lastError?.message}`);
};

module.exports = { getScadaFeed };
