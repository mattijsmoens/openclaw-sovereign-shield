/**
 * SovereignShield Plugin for OpenClaw
 * 
 * Intercepts tool executions and deterministically blocks prompt injections and RCE.
 * Supports both Local Daemon (fast/private) and Cloud SaaS API (no setup).
 */

import http from 'http';
import https from 'https';

// Tools that provide system access and thus require strict security oversight
const defaultTools = ['bash', 'system.run', 'fs_write', 'fs_read', 'python', 'exec'];
const HIGH_RISK_TOOLS = process.env.SS_PROTECTED_TOOLS 
  ? process.env.SS_PROTECTED_TOOLS.split(',').map(t => t.trim()) 
  : defaultTools;

// Configuration
const API_KEY = process.env.SOVEREIGN_SHIELD_API_KEY;
const SAAS_URL = 'https://sovereign-shield-467902938909.us-central1.run.app/api/v1/scan/input';
// Default to 'local' unless an API key is provided and mode isn't explicitly set to local
const MODE = process.env.SOVEREIGN_SHIELD_MODE || (API_KEY ? 'remote' : 'local');

export default async function sovereignShieldPlugin(api) {
  console.log(`[SovereignShield] Initializing OpenClaw security layer (Mode: ${MODE.toUpperCase()})...`);

  api.on('before_tool_call', async (event) => {
    const { toolName, args } = event;

    if (!HIGH_RISK_TOOLS.includes(toolName)) {
      return {}; // Allow normal execution
    }

    try {
      let response;
      if (MODE === 'remote' && API_KEY) {
        response = await scanWithSaaS(toolName, args);
      } else {
        response = await scanWithDaemon(toolName, args);
      }

      // The API returns { "status": "safe" | "blocked", "reason": "..." }
      // The daemon returns { "allowed": true | false, "reason": "..." }
      const isAllowed = response.allowed !== undefined ? response.allowed : (response.status === 'safe');
      const blockReason = response.reason || 'Malicious payload detected.';

      if (!isAllowed) {
        console.warn(`[SovereignShield] 🛡️ BLOCKED malicious tool call (${toolName}). Reason: ${blockReason}`);
        return { 
          block: true, 
          reason: `SovereignShield blocked this action. Reason: ${blockReason}`
        };
      }
      
      return {}; // Passed security check
    } catch (error) {
      console.error(`[SovereignShield] Scan error: ${error.message}`);
      return { 
        block: true, 
        reason: `SovereignShield unreachable (${MODE} mode). Cannot verify safety of ${toolName}.` 
      };
    }
  });

  console.log('[SovereignShield] Protection active. Monitoring tool executions.');
}

/** Local Daemon Scanner (127.0.0.1:8765) */
function scanWithDaemon(toolName, inputData) {
  return new Promise((resolve, reject) => {
    const rawInput = typeof inputData === 'string' ? inputData : JSON.stringify(inputData);
    const payload = JSON.stringify({ tool_name: toolName, input: rawInput });

    const options = {
      hostname: '127.0.0.1',
      port: 8765,
      path: '/scan',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Daemon response parse error: ${e.message} / Data: ${data.substring(0, 50)}`));
        }
      });
    });

    req.on('error', (e) => reject(e));
    req.write(payload);
    req.end();
  });
}

/** Remote SaaS API Scanner */
function scanWithSaaS(toolName, inputData) {
  return new Promise((resolve, reject) => {
    const rawInput = typeof inputData === 'string' ? inputData : JSON.stringify(inputData);
    const payload = JSON.stringify({ input: rawInput });
    
    // Parse URL
    const url = new URL(SAAS_URL);
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`,
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`SaaS API response parse error: ${e.message} / Status: ${res.statusCode}`));
        }
      });
    });

    req.on('error', (e) => reject(e));
    req.write(payload);
    req.end();
  });
}
