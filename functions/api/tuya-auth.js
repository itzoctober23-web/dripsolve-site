import { verifyToken, corsHeaders, json } from './_shared.js';
import { makeTuyaClient, getAuthUrl, exchangeCode, refreshTuyaToken, listDevices, getDeviceStatus, parseWaterLeakStatus } from './tuya.js';
const JWT_SECRET = 'dripsolve-jwt-secret-2026';

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

  const url = new URL(request.url);
  const action = url.searchParams.get('action') || '';

  try {
    const tuya = makeTuyaClient(env);

    // Step 1: Get authorization URL to redirect user to Tuya
    if (action === 'authorize' || request.url.endsWith('/authorize')) {
      const auth = request.headers.get('Authorization');
      if (!auth) return json({ error: 'No token' }, 401);
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);

      const callbackUrl = url.origin + '/api/tuya-auth?action=callback';
      const state = userId + ':' + Date.now().toString(36);
      const authUrl = getAuthUrl(tuya.clientId, callbackUrl, state);
      return json({ url: authUrl, state });
    }

    // Step 2: OAuth callback — Tuya redirects here after user authorizes
    if (action === 'callback' || request.url.endsWith('/callback')) {
      const { code, state } = url.searchParams;
      if (!code) return json({ error: 'No code received' }, 400);

      const userId = state ? state.split(':')[0] : null;
      if (!userId) return json({ error: 'Invalid state' }, 400);

      const tokenData = await exchangeCode(tuya, code);
      const expiresAt = new Date(Date.now() + (tokenData.expire || 7200) * 1000).toISOString();

      // Store tokens in DB
      await env.DB.prepare(
        `INSERT INTO tuya_tokens (user_id, access_token, refresh_token, tuya_uid, expires_at, updated_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(user_id) DO UPDATE SET access_token=?, refresh_token=?, tuya_uid=?, expires_at=?, updated_at=datetime('now')`
      ).bind(userId, tokenData.access_token, tokenData.refresh_token, tokenData.uid || '', expiresAt,
             tokenData.access_token, tokenData.refresh_token, tokenData.uid || '', expiresAt).run();

      // Fetch devices on first connect
      try {
        const devices = await listDevices(tuya, tokenData.access_token);
        const leakSensors = devices.filter(d =>
          d.category === 'wsdl' || // water sensor
          d.category === 'ws' ||   // water sensor (alt)
          d.device_type === 'leak_sensor' ||
          (d.name || '').toLowerCase().includes('water') ||
          (d.name || '').toLowerCase().includes('leak') ||
          (d.name || '').toLowerCase().includes('moisture')
        );
        // Store device list in user_data
        const row = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
        if (row) {
          const data = JSON.parse(row.data || '{}');
          data.tuyaDevices = devices.map(d => ({
            id: d.id, name: d.name, category: d.category, online: d.online,
            product_name: d.product_name, is_water: leakSensors.some(ls => ls.id === d.id)
          }));
          data.tuyaSyncedAt = new Date().toISOString();
          await env.DB.prepare('UPDATE user_data SET data = ?, updated_at = datetime(\'now\') WHERE user_id = ?')
            .bind(JSON.stringify(data), userId).run();
        }
      } catch {}

      // Redirect user back to dashboard (no way to show token in redirect, so just redirect)
      return Response.redirect(url.origin + '/dashboard.html', 302);
    }

    // Step 3: Get user's Tuya connection status and devices
    if (action === 'status' || request.url.endsWith('/status')) {
      const auth = request.headers.get('Authorization');
      if (!auth) return json({ error: 'No token' }, 401);
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);

      const row = await env.DB.prepare('SELECT * FROM tuya_tokens WHERE user_id = ?').bind(userId).first();
      if (!row) return json({ connected: false, devices: [] });

      const userRow = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      const userData = userRow ? JSON.parse(userRow.data || '{}') : {};
      return json({
        connected: true,
        connectedAt: row.created_at,
        devices: userData.tuyaDevices || [],
        syncedAt: userData.tuyaSyncedAt
      });
    }

    // Step 4: Disconnect Tuya account
    if (action === 'disconnect' || request.url.endsWith('/disconnect')) {
      const auth = request.headers.get('Authorization');
      if (!auth) return json({ error: 'No token' }, 401);
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);

      await env.DB.prepare('DELETE FROM tuya_tokens WHERE user_id = ?').bind(userId).run();
      const row = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      if (row) {
        const data = JSON.parse(row.data || '{}');
        delete data.tuyaDevices;
        delete data.tuyaSyncedAt;
        await env.DB.prepare('UPDATE user_data SET data = ?, updated_at = datetime(\'now\') WHERE user_id = ?')
          .bind(JSON.stringify(data), userId).run();
      }
      return json({ ok: true });
    }

    return json({ error: 'Unknown action' }, 400);
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}
