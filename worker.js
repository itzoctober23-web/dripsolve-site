// DripSolve Worker — serves static assets + API routes
import { hashPassword, generateId, makeToken, verifyToken, tuyaApi, tuyaApiWithToken, tuyaGetToken, makeTuyaCreds, makeTuyaAppCreds, tuyaExchangeCode } from './_shared.js';

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path.startsWith('/api/')) {
    return handleApi(request, env, path, method, url);
  }

  // Let the assets serve static files
  return new Response('Not found', { status: 404 });
}

async function handleApi(request, env, path, method, url) {
  const JWT_SECRET = env.JWT_SECRET;
  if (!JWT_SECRET) return json({ error: 'Server auth not configured (JWT_SECRET missing)' }, 500);
  const body = method === 'POST' || method === 'PUT' ? await request.json().catch(() => ({})) : {};

  // Auth endpoints
  if (path === '/api/auth') {
    const action = url.searchParams.get('action') || '';

    if (action === 'signup') {
      const { email, password, name } = body;
      if (!email || !password) return json({ error: 'Email and password required' }, 400);
      if (password.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);
      const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
      if (existing) return json({ error: 'Email already registered' }, 409);
      const id = generateId();
      const password_hash = await hashPassword(password, email.toLowerCase());
      await env.DB.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
        .bind(id, email.toLowerCase(), name || '', password_hash).run();
      await env.DB.prepare('INSERT INTO user_data (user_id, data) VALUES (?, ?)').bind(id, '{}').run();
      const token = await makeToken(id, JWT_SECRET);
      return json({ token, user: { id, email: email.toLowerCase(), name: name || '', plan: 'starter' } }, 201);
    }

    if (action === 'login') {
      const { email, password } = body;
      if (!email || !password) return json({ error: 'Email and password required' }, 400);
      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
      if (!user) return json({ error: 'Invalid email or password' }, 401);
      const hash = await hashPassword(password, email.toLowerCase());
      if (hash !== user.password_hash) return json({ error: 'Invalid email or password' }, 401);
      const token = await makeToken(user.id, JWT_SECRET);
      return json({ token, user: { id: user.id, email: user.email, name: user.name, plan: user.plan } });
    }

    if (action === 'verify' || action === 'status') {
      const auth = request.headers.get('Authorization');
      if (!auth) return json({ error: 'No token' }, 401);
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);
      const user = await env.DB.prepare('SELECT id, email, name, plan FROM users WHERE id = ?').bind(userId).first();
      if (!user) return json({ error: 'User not found' }, 404);
      return json({ user });
    }

    if (action === 'change-password') {
      const { currentPassword, newPassword } = body;
      if (!currentPassword || !newPassword) return json({ error: 'Current and new password required' }, 400);
      if (newPassword.length < 6) return json({ error: 'New password must be at least 6 characters' }, 400);
      const auth = request.headers.get('Authorization');
      if (!auth) return json({ error: 'No token' }, 401);
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);
      const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
      if (!user) return json({ error: 'User not found' }, 404);
      const hash = await hashPassword(currentPassword, user.email);
      if (hash !== user.password_hash) return json({ error: 'Current password is incorrect' }, 401);
      const newHash = await hashPassword(newPassword, user.email);
      await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, userId).run();
      return json({ ok: true });
    }

    return json({ error: 'Unknown action' }, 400);
  }

  // Data endpoints
  if (path === '/api/data') {
    const auth = request.headers.get('Authorization');
    if (!auth) return json({ error: 'No token' }, 401);
    const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
    if (!userId) return json({ error: 'Invalid token' }, 401);

    if (method === 'GET') {
      const row = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      const data = row ? JSON.parse(row.data || '{}') : {};
      return json(data);
    }

    if (method === 'PUT') {
      // Server-managed monitoring fields are owned by the cron / device endpoints.
      // Preserve them so a client save (which doesn't know about them) can't wipe them.
      const SERVER_OWNED = ['deviceStates', 'tuyaDevices', 'tuyaSyncedAt', 'tuyaDeviceIds', 'alerts'];
      const existingRow = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      const existing = existingRow ? JSON.parse(existingRow.data || '{}') : {};
      const merged = { ...body };
      for (const k of SERVER_OWNED) if (k in existing) merged[k] = existing[k];
      const raw = JSON.stringify(merged);
      await env.DB.prepare("INSERT INTO user_data (user_id, data, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(user_id) DO UPDATE SET data = ?, updated_at = datetime('now')")
        .bind(userId, raw, raw).run();
      return json({ ok: true });
    }

    return json({ error: 'Method not allowed' }, 405);
  }

  // Sensor endpoint
  if (path === '/api/sensor') {
    const auth = request.headers.get('Authorization');
    if (!auth) return json({ error: 'No token' }, 401);
    const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
    if (!userId) return json({ error: 'Invalid token' }, 401);

    if (method === 'POST') {
      const { sensor_id, value, battery } = body;
      if (!sensor_id) return json({ error: 'sensor_id required' }, 400);
      await env.DB.prepare('INSERT INTO sensor_readings (sensor_id, user_id, value, battery) VALUES (?, ?, ?, ?)')
        .bind(sensor_id, userId, value || 0, battery ?? 100).run();
      return json({ ok: true }, 201);
    }
    return json({ error: 'Method not allowed' }, 405);
  }

  // Tuya auth
  if (path === '/api/tuya-auth') {
    const action = url.searchParams.get('action') || '';
    // Use App Authorization credentials for OAuth flow
    const tuyaClientId = env.TUYA_APP_CLIENT_ID || env.TUYA_CLIENT_ID;
    const tuyaSecret = env.TUYA_APP_CLIENT_SECRET || env.TUYA_CLIENT_SECRET;
    if (!tuyaClientId || !tuyaSecret) return json({ error: 'Tuya not configured' }, 503);

    const auth = request.headers.get('Authorization');
    if (!auth && action !== 'callback') return json({ error: 'No token' }, 401);

    if (action === 'authorize') {
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);
      const callbackUrl = url.origin + '/api/tuya-auth?action=callback';
      const state = userId + ':' + Date.now().toString(36);
      const authUrl = `https://images.tuyaus.com/smart_home/auth?client_id=${tuyaClientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&state=${state}`;
      return json({ url: authUrl, state });
    }

    if (action === 'callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code) return json({ error: 'No code' }, 400);
      const userId = state ? state.split(':')[0] : null;
      if (!userId) return json({ error: 'Invalid state' }, 400);
      // Exchange the authorization code for a user token and persist it.
      // Never throw out of the callback — always land the user back on the dashboard.
      try {
        const appCreds = makeTuyaAppCreds(env);
        const tok = await tuyaExchangeCode(appCreds, code);
        const expiresAt = new Date(Date.now() + (tok.expire_time || 7200) * 1000).toISOString();
        await env.DB.prepare(
          "INSERT INTO tuya_tokens (user_id, access_token, refresh_token, uid, expires_at) VALUES (?, ?, ?, ?, ?) " +
          "ON CONFLICT(user_id) DO UPDATE SET access_token = excluded.access_token, refresh_token = excluded.refresh_token, uid = excluded.uid, expires_at = excluded.expires_at"
        ).bind(userId, tok.access_token, tok.refresh_token, tok.uid, expiresAt).run();
        return Response.redirect(url.origin + '/dashboard.html?tuya=connected', 302);
      } catch (e) {
        // Surface a short reason in the URL so we can debug the live flow.
        return Response.redirect(url.origin + '/dashboard.html?tuya=error&reason=' + encodeURIComponent(e.message || 'exchange_failed'), 302);
      }
    }

    if (action === 'status') {
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);
      const row = await env.DB.prepare('SELECT * FROM tuya_tokens WHERE user_id = ?').bind(userId).first();
      const userRow = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      const userData = userRow ? JSON.parse(userRow.data || '{}') : {};
      return json({ connected: !!row, devices: userData.tuyaDevices || [], syncedAt: userData.tuyaSyncedAt });
    }

    if (action === 'disconnect') {
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);
      await env.DB.prepare('DELETE FROM tuya_tokens WHERE user_id = ?').bind(userId).run();
      return json({ ok: true });
    }

    return json({ error: 'Unknown action' }, 400);
  }

  // Add device IDs for Tuya monitoring
  if (path === '/api/tuya-devices') {
    const auth = request.headers.get('Authorization');
    if (!auth) return json({ error: 'No token' }, 401);
    const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
    if (!userId) return json({ error: 'Invalid token' }, 401);

    if (method === 'POST') {
      const { device_ids } = body;
      if (!device_ids || !Array.isArray(device_ids)) return json({ error: 'device_ids array required' }, 400);
      const row = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      const userData = row ? JSON.parse(row.data || '{}') : {};
      userData.tuyaDeviceIds = device_ids;
      await env.DB.prepare("INSERT INTO user_data (user_id, data, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(user_id) DO UPDATE SET data = ?, updated_at = datetime('now')")
        .bind(userId, JSON.stringify(userData), JSON.stringify(userData)).run();
      return json({ ok: true, device_ids: device_ids });
    }

    if (method === 'GET') {
      const row = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      const userData = row ? JSON.parse(row.data || '{}') : {};
      return json({ device_ids: userData.tuyaDeviceIds || [] });
    }

    return json({ error: 'Method not allowed' }, 405);
  }

  // Tuya sync - list devices and detect leaks
  if (path === '/api/tuya-sync') {
    const auth = request.headers.get('Authorization');
    if (!auth) return json({ error: 'No token' }, 401);
    const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
    if (!userId) return json({ error: 'Invalid token' }, 401);

    try {
      const result = await syncUserData(env, userId);
      return json({ synced: true, devices: result.devices, alerts: result.newAlerts });
    } catch (e) {
      return json({ error: e.message }, 502);
    }
  }

  return json({ error: 'Not found' }, 404);
}

// Poll Tuya for one user's devices, update live state + raise alerts. Shared by the
// manual /api/tuya-sync endpoint and the scheduled cron. Pass a pre-fetched
// {creds, token} (e.g. from the cron) to avoid re-fetching a token per user.
async function syncUserData(env, userId, opts = {}) {
  const creds = opts.creds || makeTuyaCreds(env);
  const token = opts.token || await tuyaGetToken(creds);

  const row = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
  const userData = row ? JSON.parse(row.data || '{}') : {};

  // Devices to poll: each sensor's deviceId (real model) + legacy flat list.
  const fromSensors = (userData.sensors || []).map(s => s.deviceId).filter(Boolean);
  const legacy = userData.tuyaDeviceIds || [];
  const deviceIds = [...new Set([...fromSensors, ...legacy])];

  const nowIso = new Date().toISOString();
  const deviceStates = {};
  for (const deviceId of deviceIds) {
    try {
      const devRes = await tuyaApiWithToken(creds, token, 'GET', '/v1.0/iot-03/devices?device_ids=' + deviceId);
      if (!devRes.success) continue;
      for (const d of (devRes.result?.list || [])) {
        const st = { id: d.id, name: d.name, online: d.online, category: d.category_name || d.category, lastSeen: nowIso };
        if (d.category === 'sj' || d.category_name === 'Flooding Detector') {
          const statusRes = await tuyaApiWithToken(creds, token, 'GET', '/v1.0/iot-03/devices/' + d.id + '/status');
          if (statusRes.success) {
            for (const s of (statusRes.result || [])) {
              if (s.code === 'watersensor_state') st.waterState = s.value;
              if (s.code === 'battery_percentage') st.battery = s.value;
            }
          }
        }
        deviceStates[d.id] = st;
      }
    } catch (e) { continue; }
  }

  // Build alert candidates (leak = critical, offline = warning), dedup vs. recent.
  const existing = userData.alerts || [];
  const RECENT_MS = 12 * 60 * 60 * 1000;
  const now = Date.now();
  const candidates = [];
  for (const st of Object.values(deviceStates)) {
    if (st.waterState === 'alarm') candidates.push({ id: st.id, name: st.name, type: 'water_leak', severity: 'critical', time: nowIso });
    else if (st.online === false) candidates.push({ id: st.id, name: st.name, type: 'offline', severity: 'warning', time: nowIso });
  }
  const newAlerts = candidates.filter(a =>
    !existing.some(e => e.id === a.id && e.type === a.type && (now - Date.parse(e.time || 0)) < RECENT_MS)
  );

  userData.deviceStates = deviceStates;
  userData.tuyaDevices = Object.values(deviceStates); // back-compat for the status endpoint
  userData.tuyaSyncedAt = nowIso;
  if (newAlerts.length) userData.alerts = [...existing, ...newAlerts];

  const raw = JSON.stringify(userData);
  await env.DB.prepare("INSERT INTO user_data (user_id, data, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(user_id) DO UPDATE SET data = ?, updated_at = datetime('now')")
    .bind(userId, raw, raw).run();

  return { devices: Object.values(deviceStates), deviceStates, newAlerts };
}

// Scheduled cron: poll every user's devices on a fixed interval. One Tuya token is
// fetched and reused across all users/devices for the whole run.
async function runScheduledSync(env) {
  const creds = makeTuyaCreds(env);
  let token;
  try { token = await tuyaGetToken(creds); } catch (e) { return { ok: false, error: e.message }; }
  const { results } = await env.DB.prepare('SELECT id FROM users').all();
  let users = 0, alerts = 0;
  for (const u of (results || [])) {
    try {
      const r = await syncUserData(env, u.id, { creds, token });
      users++; alerts += r.newAlerts.length;
    } catch (e) { /* skip this user, continue */ }
  }
  return { ok: true, users, alerts };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' }
  });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
    }
    try {
      return await handleRequest(request, env);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },

  // Cloudflare Cron Trigger — automatic background monitoring of all users' sensors.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduledSync(env));
  }
};
