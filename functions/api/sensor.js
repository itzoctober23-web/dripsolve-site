import { verifyToken, corsHeaders, json } from './_shared.js';
const JWT_SECRET = 'dripsolve-jwt-secret-2026';

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  // Can be auth'd by user token OR by sensor token in URL
  let userId = null;
  const auth = request.headers.get('Authorization');
  if (auth) {
    userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
  }

  try {
    const body = await request.json();
    const { sensor_id, value, battery, token } = body;

    // If no auth header, check body for user/sensor token
    if (!userId) {
      // Allow reading with a sensor-level API key in the future
      return json({ error: 'Authentication required' }, 401);
    }

    if (!sensor_id) return json({ error: 'sensor_id required' }, 400);

    await env.DB.prepare('INSERT INTO sensor_readings (sensor_id, user_id, value, battery) VALUES (?, ?, ?, ?)')
      .bind(sensor_id, userId, value || 0, battery ?? 100).run();

    return json({ ok: true }, 201);
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}
