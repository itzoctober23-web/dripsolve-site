import { verifyToken, corsHeaders, json } from './_shared.js';
const JWT_SECRET = 'dripsolve-jwt-secret-2026';

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

  const auth = request.headers.get('Authorization');
  if (!auth) return json({ error: 'No token' }, 401);
  const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
  if (!userId) return json({ error: 'Invalid token' }, 401);

  try {
    if (request.method === 'GET') {
      const row = await env.DB.prepare('SELECT data FROM user_data WHERE user_id = ?').bind(userId).first();
      const data = row ? JSON.parse(row.data) : {};
      return json(data);
    }

    if (request.method === 'PUT') {
      const body = await request.json();
      const raw = JSON.stringify(body);
      await env.DB.prepare('INSERT INTO user_data (user_id, data, updated_at) VALUES (?, ?, datetime(\'now\')) ON CONFLICT(user_id) DO UPDATE SET data = ?, updated_at = datetime(\'now\')')
        .bind(userId, raw, raw).run();
      return json({ ok: true });
    }

    return json({ error: 'Method not allowed' }, 405);
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}
