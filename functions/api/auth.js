import { hashPassword, generateId, makeToken, verifyToken, corsHeaders, json } from './_shared.js';

const JWT_SECRET = 'dripsolve-jwt-secret-2026';

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

  const url = new URL(request.url);
  const action = url.searchParams.get('action') || url.pathname.split('/').pop();

  try {
    const body = await request.json();

    if (action === 'login' || request.url.endsWith('/login')) {
      const { email, password } = body;
      if (!email || !password) return json({ error: 'Email and password required' }, 400);

      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
      if (!user) return json({ error: 'Invalid email or password' }, 401);

      const hash = await hashPassword(password, email.toLowerCase());
      if (hash !== user.password_hash) return json({ error: 'Invalid email or password' }, 401);

      const token = makeToken(user.id);
      return json({ token, user: { id: user.id, email: user.email, name: user.name, plan: user.plan } });
    }

    if (action === 'signup' || request.url.endsWith('/signup')) {
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

      const token = makeToken(id);
      return json({ token, user: { id, email: email.toLowerCase(), name: name || '', plan: 'starter' } }, 201);
    }

    if (action === 'change-password' || request.url.endsWith('/change-password')) {
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

    if (action === 'verify' || request.url.endsWith('/verify')) {
      const auth = request.headers.get('Authorization');
      if (!auth) return json({ error: 'No token' }, 401);
      const userId = await verifyToken(auth.replace('Bearer ', ''), JWT_SECRET);
      if (!userId) return json({ error: 'Invalid token' }, 401);

      const user = await env.DB.prepare('SELECT id, email, name, plan FROM users WHERE id = ?').bind(userId).first();
      if (!user) return json({ error: 'User not found' }, 404);
      return json({ user });
    }

    return json({ error: 'Unknown action' }, 400);
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}
