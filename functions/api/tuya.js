// Tuya Cloud API client for Cloudflare Workers
// Docs: https://developer.tuya.com/en/docs/cloud/api-reference

import { verifyToken, corsHeaders, json } from './_shared.js';
const JWT_SECRET = 'dripsolve-jwt-secret-2026';

// ─── HMAC-SHA256 signing ───
async function sign(secret, str) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(str));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ─── Get Tuya cloud token ───
async function getTuyaToken(clientId, secret) {
  const t = Date.now().toString();
  const msg = clientId + t;
  const signStr = await sign(secret, msg);
  const res = await fetch('https://openapi.tuyaus.com/v1.0/token?grant_type=1', {
    method: 'GET',
    headers: { client_id: clientId, sign: signStr, t, sign_method: 'HMAC-SHA256', lang: 'en' }
  });
  const data = await res.json();
  if (!data.success) throw new Error('Tuya token error: ' + (data.msg || JSON.stringify(data)));
  return { token: data.result.access_token, expire: data.result.expire_time };
}

// ─── Signed Tuya API request ───
async function tuyaRequest(clientId, secret, token, method, path, body) {
  const t = Date.now().toString();
  const bodyHash = body ? await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(body))).then(b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase()) : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const msg = clientId + token + t + method + '\n' + bodyHash + '\n\n' + path;
  const signStr = await sign(secret, msg);
  const opts = {
    method,
    headers: { client_id: clientId, access_token: token, sign: signStr, t, sign_method: 'HMAC-SHA256', lang: 'en', 'Content-Type': 'application/json' }
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('https://openapi.tuyaus.com' + path, opts);
  const data = await res.json();
  if (!data.success && data.code === 1010) { // Token expired, refresh
    const { token: newToken } = await getTuyaToken(clientId, secret);
    return tuyaRequest(clientId, secret, newToken, method, path, body);
  }
  return data;
}

// ─── Get user's Tuya tokens from DB ───
async function getUserTuya(db, userId) {
  const row = await db.prepare('SELECT * FROM tuya_tokens WHERE user_id = ?').bind(userId).first();
  if (!row) return null;
  if (row.expires_at && Date.parse(row.expires_at) < Date.now()) return null;
  return row;
}

function makeTuyaClient(env) {
  const clientId = env.TUYA_CLIENT_ID;
  const secret = env.TUYA_CLIENT_SECRET;
  if (!clientId || !secret) throw new Error('Tuya credentials not configured');
  return {
    getToken: () => getTuyaToken(clientId, secret),
    request: (token, method, path, body) => tuyaRequest(clientId, secret, token, method, path, body),
    clientId, secret
  };
}

// ─── OAuth authorization URL ───
function getAuthUrl(clientId, redirectUri, state) {
  return `https://images.tuyaus.com/smart_home/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
}

// ─── Exchange OAuth code for token ───
async function exchangeCode(tuya, code) {
  const res = await tuya.request(null, 'GET', `/v1.0/token?grant_type=authorization_code&code=${code}`);
  if (!res.success) throw new Error('OAuth code exchange failed: ' + JSON.stringify(res));
  return {
    access_token: res.result.access_token,
    refresh_token: res.result.refresh_token,
    expire: res.result.expire_time,
    uid: res.result.uid
  };
}

// ─── Refresh Tuya token from refresh_token ───
async function refreshTuyaToken(tuya, refreshToken) {
  const res = await tuya.request(null, 'GET', `/v1.0/token/${refreshToken}`);
  if (!res.success) throw new Error('Token refresh failed: ' + JSON.stringify(res));
  return {
    access_token: res.result.access_token,
    refresh_token: res.result.refresh_token,
    expire: res.result.expire_time
  };
}

// ─── List user's Tuya devices ───
async function listDevices(tuya, token) {
  const res = await tuya.request(token, 'GET', '/v1.0/devices');
  if (!res.success) throw new Error('List devices failed: ' + JSON.stringify(res));
  return res.result || [];
}

// ─── Get single device status ───
async function getDeviceStatus(tuya, token, deviceId) {
  const res = await tuya.request(token, 'GET', `/v1.0/devices/${deviceId}/status`);
  if (!res.success) throw new Error('Device status failed: ' + JSON.stringify(res));
  return res.result || [];
}

// ─── Parse water leak status from device status codes ───
// Common Tuya leak sensor DP codes:
//  101 = water_sensor_state (0=normal, 1=leaking, 2=alarm)
//  102 = battery_percentage (0-100)
//  104 = alarm_volume
function parseWaterLeakStatus(statusArray) {
  let leaking = false;
  let battery = 100;
  for (const s of statusArray) {
    if (s.code === 'water_sensor_state' || s.code === '101') {
      leaking = s.value === '1' || s.value === 'leaking' || s.value === true || s.value === 1;
    }
    if (s.code === 'battery_percentage' || s.code === '102') {
      battery = parseInt(s.value) || 100;
    }
  }
  return { leaking, battery };
}

export {
  makeTuyaClient, getAuthUrl, exchangeCode, refreshTuyaToken,
  listDevices, getDeviceStatus, parseWaterLeakStatus, getUserTuya
};
