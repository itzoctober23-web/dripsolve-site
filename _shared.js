// Shared utilities for auth
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateId() { return crypto.randomUUID(); }

// base64url helpers (JWT-safe, no +/= chars)
function b64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64url(String.fromCharCode(...new Uint8Array(sig)));
}

async function makeToken(userId, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + 86400 * 30 }));
  const sig = await hmacSign(header + '.' + payload, secret);
  return header + '.' + payload + '.' + sig;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const expected = await hmacSign(parts[0] + '.' + parts[1], secret);
    // constant-time comparison to avoid timing leaks
    if (expected.length !== parts[2].length) return null;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ parts[2].charCodeAt(i);
    if (diff !== 0) return null;
    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (payload.exp * 1000 < Date.now()) return null;
    return payload.sub;
  } catch { return null; }
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders() } });
}

// ─── Tuya Cloud API utilities ───
async function tuyaSign(secret, method, path, token) {
  const t = Date.now().toString();
  const bodyHashBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(''));
  const bodyHash = Array.from(new Uint8Array(bodyHashBytes)).map(b => b.toString(16).padStart(2, '0')).join('');
  const stringToSign = method + '\n' + bodyHash + '\n\n' + path;
  const str = secret.client_id + (token || '') + t + stringToSign;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret.client_secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(str));
  const sign = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return { sign, t };
}

async function tuyaGetToken(tuyaCreds) {
  const { sign, t } = await tuyaSign(tuyaCreds, 'GET', '/v1.0/token?grant_type=1');
  const res = await fetch('https://openapi.tuyaus.com/v1.0/token?grant_type=1', {
    headers: { client_id: tuyaCreds.client_id, sign, t, sign_method: 'HMAC-SHA256' }
  });
  const data = await res.json();
  if (!data.success) throw new Error('Tuya token: ' + data.msg);
  return data.result.access_token;
}

async function tuyaApi(tuyaCreds, method, path) {
  const token = await tuyaGetToken(tuyaCreds);
  return tuyaApiWithToken(tuyaCreds, token, method, path);
}

// Same as tuyaApi but reuses a pre-fetched access token (avoids one token round-trip
// per call — important when polling many devices, e.g. the scheduled cron).
async function tuyaApiWithToken(tuyaCreds, token, method, path) {
  const { sign, t } = await tuyaSign(tuyaCreds, method, path, token);
  const res = await fetch('https://openapi.tuyaus.com' + path, {
    method,
    headers: { client_id: tuyaCreds.client_id, access_token: token, sign, t, sign_method: 'HMAC-SHA256' }
  });
  return res.json();
}

function makeTuyaCreds(env) {
  return { client_id: env.TUYA_CLIENT_ID, client_secret: env.TUYA_CLIENT_SECRET };
}

// App Authorization credentials (used for the OAuth "Link App Account" flow)
function makeTuyaAppCreds(env) {
  return {
    client_id: env.TUYA_APP_CLIENT_ID || env.TUYA_CLIENT_ID,
    client_secret: env.TUYA_APP_CLIENT_SECRET || env.TUYA_CLIENT_SECRET,
  };
}

// Exchange an OAuth authorization code for a user access token (grant_type=2).
// NOTE: the code is bound to the client_id that requested authorization, so this
// must use the SAME creds the authorize URL used (the app creds). Query params are
// sorted alphabetically (code before grant_type) per Tuya's signing rules.
async function tuyaExchangeCode(creds, code, base = 'https://openapi.tuyaus.com') {
  const path = '/v1.0/token?code=' + encodeURIComponent(code) + '&grant_type=2';
  const { sign, t } = await tuyaSign(creds, 'GET', path);
  const res = await fetch(base + path, {
    headers: { client_id: creds.client_id, sign, t, sign_method: 'HMAC-SHA256' },
  });
  const data = await res.json();
  if (!data.success) throw new Error('code-exchange [' + (data.code || '?') + ']: ' + (data.msg || JSON.stringify(data)));
  return data.result; // { access_token, refresh_token, uid, expire_time }
}

// Refresh an expired user access token. Path: GET /v1.0/token/{refresh_token}
async function tuyaRefreshUserToken(creds, refreshToken, base = 'https://openapi.tuyaus.com') {
  const path = '/v1.0/token/' + encodeURIComponent(refreshToken);
  const { sign, t } = await tuyaSign(creds, 'GET', path);
  const res = await fetch(base + path, {
    headers: { client_id: creds.client_id, sign, t, sign_method: 'HMAC-SHA256' },
  });
  const data = await res.json();
  if (!data.success) throw new Error('token-refresh [' + (data.code || '?') + ']: ' + (data.msg || JSON.stringify(data)));
  return data.result; // { access_token, refresh_token, uid, expire_time }
}

export { hashPassword, generateId, makeToken, verifyToken, corsHeaders, json, tuyaSign, tuyaGetToken, tuyaApi, tuyaApiWithToken, makeTuyaCreds, makeTuyaAppCreds, tuyaExchangeCode, tuyaRefreshUserToken };
