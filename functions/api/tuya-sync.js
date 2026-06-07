import { verifyToken, corsHeaders, json } from './_shared.js';
import { makeTuyaClient, listDevices, getDeviceStatus, parseWaterLeakStatus, refreshTuyaToken } from './tuya.js';
const JWT_SECRET = 'dripsolve-jwt-secret-2026';

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

  try {
    const tuya = makeTuyaClient(env);

    // Can be called by a cron job (no auth) or by a user manually
    const auth = request.headers.get('Authorization');
    let userId = null;
    if (auth) {
      userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
    }

    // For cron: sync ALL connected Tuya accounts
    // For user: sync just their account
    if (request.method === 'POST') {
      return await syncAllUsers(env, tuya, userId);
    }

    // GET: sync a specific user's devices (called from dashboard)
    if (request.method === 'GET') {
      if (!userId) return json({ error: 'No token' }, 401);
      return await syncUser(env, tuya, userId);
    }

    return json({ error: 'Method not allowed' }, 405);
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

async function syncUser(env, tuya, userId) {
  const row = await env.DB.prepare('SELECT * FROM tuya_tokens WHERE user_id = ?').bind(userId).first();
  if (!row) return json({ connected: false });

  // Refresh token if needed
  let token = row.access_token;
  if (row.expires_at && Date.parse(row.expires_at) < Date.now() + 300000) {
    try {
      const fresh = await refreshTuyaToken(tuya, row.refresh_token);
      token = fresh.access_token;
      await env.DB.prepare('UPDATE tuya_tokens SET access_token=?, refresh_token=?, expires_at=? WHERE user_id=?')
        .bind(fresh.access_token, fresh.refresh_token,
          new Date(Date.now() + fresh.expire * 1000).toISOString(), userId).run();
    } catch { return json({ error: 'Token refresh failed. Reconnect Tuya.' }); }
  }

  // Get devices
  const devices = await listDevices(tuya, token);
  const waterDevices = devices.filter(d =>
    d.category === 'wsdl' || d.category === 'ws' ||
    (d.name || '').toLowerCase().includes('leak') ||
    (d.name || '').toLowerCase().includes('water') ||
    (d.name || '').toLowerCase().includes('moisture')
  );

  const alerts = [];
  for (const d of waterDevices) {
    const status = await getDeviceStatus(tuya, token, d.id);
    const { leaking, battery } = parseWaterLeakStatus(status);
    if (leaking) {
      alerts.push({
        tuyaDeviceId: d.id,
        name: d.name,
        battery,
        time: new Date().toISOString()
      });
    }
  }

  // Update user data
  const userRow = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
  if (userRow) {
    const data = JSON.parse(userRow.data || '{}');
    data.tuyaDevices = devices.map(d => ({
      id: d.id, name: d.name, category: d.category, online: d.online, product_name: d.product_name,
      is_water: waterDevices.some(wd => wd.id === d.id)
    }));
    data.tuyaSyncedAt = new Date().toISOString();

    // Add alerts for leaking devices
    if (!data.tuyaAlerted) data.tuyaAlerted = [];
    for (const a of alerts) {
      if (!data.tuyaAlerted.includes(a.tuyaDeviceId)) {
        data.tuyaAlerted.push(a.tuyaDeviceId);
        if (!data.alerts) data.alerts = [];
        data.alerts.unshift({
          id: 'ta_' + Date.now(),
          tuyaDeviceId: a.tuyaDeviceId,
          event: 'Water detected by ' + a.name,
          type: 'Critical', status: 'Active', time: 'just now',
          battery: a.battery
        });
      }
    }

    await env.DB.prepare('UPDATE user_data SET data = ?, updated_at = datetime(\'now\') WHERE user_id = ?')
      .bind(JSON.stringify(data), userId).run();

    // Trigger sync to dashboard (write to localStorage on next load)
  }

  return json({ synced: true, devices: devices.length, waterDevices: waterDevices.length, alerts: alerts.length });
}

async function syncAllUsers(env, tuya, specificUserId) {
  if (specificUserId) {
    return await syncUser(env, tuya, specificUserId);
  }

  // Get all connected users
  const rows = await env.DB.prepare('SELECT user_id FROM tuya_tokens').all();
  const results = [];
  for (const row of rows.results || []) {
    try {
      const r = await syncUser(env, tuya, row.user_id);
      results.push({ user_id: row.user_id, status: 'ok', synced: r.synced });
    } catch (e) {
      results.push({ user_id: row.user_id, status: 'error', error: e.message });
    }
  }
  return json({ synced: results.length, results });
}
