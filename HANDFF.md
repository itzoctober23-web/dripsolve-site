# DripSolve — Handoff Document

## Project Overview

DripSolve is a SaaS water leak detection dashboard platform. Users buy Tuya-compatible WiFi water leak sensors (~$10-18 on Amazon), register them in the SmartLife/Tuya Smart app, and grant DripSolve access via OAuth. DripSolve polls the Tuya Cloud API to detect leaks and sends alerts through the dashboard.

## Architecture

- **Hosting**: Cloudflare Workers (single `worker.js` with static assets from `dist/`)
- **Database**: Cloudflare D1 (SQLite-compatible), database name `dripsolve-db`
- **Auth**: Custom JWT tokens — PBKDF2 password hashing, real HMAC-SHA256 signed tokens (`header.payload.signature`), 30-day expiry. `JWT_SECRET` is a Cloudflare secret (NOT in source/wrangler.toml); the Worker fails closed with a 500 if it is unset.
- **Payments**: Stripe Payment Links (redirect-based, no Stripe SDK needed)
- **Tuya API**: Direct REST calls to `openapi.tuyaus.com` with HMAC-SHA256 signing
- **Static files**: `index.html` (landing page), `dashboard.html` (SaaS dashboard) served from `dist/`
- **Domain**: `https://dripsolve.com` → Worker at `https://dripsolve-site.itzoctober23.workers.dev`

## Files and Purposes

| File | Purpose |
|------|---------|
| `worker.js` | Main Worker — handles all API routes + static asset serving |
| `_shared.js` | Shared utilities: auth, Tuya signing, CORS, JSON helpers |
| `wrangler.toml` | Wrangler config: D1 binding, env vars, assets dir |
| `index.html` | Landing page with Stripe links, FAQ, signup modal |
| `dashboard.html` | Full SaaS dashboard: login, devices, alerts, settings, Stripe subscribe |
| `functions/` | (DEPRECATED) Old Pages Functions — not used anymore |
| `src/worker.js` | (ARCHIVE) Copy used during development |
| `dist/` | Static assets served by Worker (index.html, dashboard.html) |
| `.gitignore` | Ignores `.wrangler/`, `.env`, `node_modules/`, `dist/` |

## Deployment

```bash
cd C:\Users\SATURN\Desktop\DripSolve-site
wrangler deploy   # builds assets from dist/ and deploys worker + static files
```

No build step needed — `dist/` contains pre-copied HTML files. After editing `worker.js`, `_shared.js`, or `dist/*.html`, re-deploy.

## Secrets (Cloudflare secrets — NOT in wrangler.toml)

Set each with `wrangler secret put <NAME>`. For local `wrangler dev`, copy `.dev.vars.example` to `.dev.vars` (gitignored) and fill in values.

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | Signs auth tokens (HMAC-SHA256). Worker 500s if unset. |
| `TUYA_CLIENT_ID` | Cloud Authorization Access ID |
| `TUYA_CLIENT_SECRET` | Cloud Authorization Secret |
| `TUYA_APP_CLIENT_ID` | App Authorization Access ID (for OAuth) |
| `TUYA_APP_CLIENT_SECRET` | App Authorization Secret |

> ⚠️ The old Tuya secret values were committed to git history (in `wrangler.toml`). Rotate them in the Tuya console and set the new values as secrets.

The Worker also has D1 binding `DB` → `dripsolve-db` (ID: `a2bae2de-21c3-482f-8026-951a10096be7`).

## D1 Database Schema

```sql
-- Users table
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT DEFAULT '',
  password_hash TEXT NOT NULL,
  plan TEXT DEFAULT 'starter',
  created_at TEXT DEFAULT (datetime('now'))
);

-- Per-user JSON data blob (alerts, devices, settings, preferences)
CREATE TABLE user_data (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  data TEXT DEFAULT '{}',
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Physical sensor readings (for future use)
CREATE TABLE sensor_readings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sensor_id TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),
  value REAL DEFAULT 0,
  battery INTEGER DEFAULT 100,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Tuya OAuth tokens (for user-linked devices via SmartLife app)
CREATE TABLE tuya_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT UNIQUE REFERENCES users(id),
  access_token TEXT,
  refresh_token TEXT,
  uid TEXT,
  expires_at TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
```

## API Endpoints (all prefixed with `/api`)

### Auth — `/api/auth?action=<action>`
- `signup` (POST): `{email, password, name}` → `{token, user}`
- `login` (POST): `{email, password}` → `{token, user}`
- `verify`/`status` (GET): Header `Authorization: Bearer <token>` → `{user}`
- `change-password` (POST): `{currentPassword, newPassword}` + Auth → `{ok}`

### Data — `/api/data`
- GET (Auth) → user's JSON data blob
- PUT (Auth, body is the JSON blob) → `{ok}`

### Tuya Devices — `/api/tuya-devices`
- GET (Auth) → `{device_ids: [...]}`
- POST (Auth, body: `{device_ids: [...]}`) → `{ok, device_ids}`

### Tuya Sync — `/api/tuya-sync`
- GET (Auth) → polls Tuya API for each saved device ID, updates alerts

### Tuya Auth — `/api/tuya-auth?action=<action>`
- `authorize` (GET, Auth) → `{url: <OAuth URL>, state}`
- `callback` (GET, no auth, `?code=&state=`) → redirects to dashboard
- `status` (GET, Auth) → `{connected, devices, syncedAt}`
- `disconnect` (GET, Auth) → `{ok}`

### Stripe Subscription
- Dashboard uses `subscribeToPlan(planId)` which saves pending plan to localStorage and opens the Stripe Payment Link URL
- `openCheckout()` redirects to Stripe with `prefilled_email` + `return_url`
- `confirmSubscription()` is a fallback button for when redirect doesn't complete
- Stripe sends user back to dashboard after payment — dashboard checks localStorage for pending plan and updates

### Stripe Payment Links (all Active)
- Starter ($9.99/mo): `https://buy.stripe.com/6oUeVc6W3c1j5Fb23fasg00`
- Pro ($24.99/mo): `https://buy.stripe.com/3cI5kCcgne9rdD7J6vasg01`
- Portfolio ($99.99/mo): `https://buy.stripe.com/9B65kC0xFfdv7NjeQ1asg02`

## Tuya Cloud API Signing

The correct HMAC-SHA256 signing process (used in `_shared.js`):

```javascript
function signRequest(method, path, token) {
  const t = Date.now().toString();
  const bodyHash = SHA256('').hex(); // empty body
  const stringToSign = method + '\n' + bodyHash + '\n\n' + path;
  const str = client_id + (token || '') + t + stringToSign;
  const sign = HMAC-SHA256(str, client_secret).toUpperCase();
  return { sign, t };
}
```

For token endpoint: `GET /v1.0/token?grant_type=1` (no access_token in str)
For business endpoints: `GET /v1.0/iot-03/devices/{id}` (include access_token in str)

## Credentials Summary

| Service | Credential |
|---------|-----------|
| Cloudflare API | Token in wrangler OAuth config (logged in as `itzoctober23@gmail.com`) |
| Stripe | Account dashboard at dashboard.stripe.com |
| Tuya Cloud | Stored as Cloudflare secrets `TUYA_CLIENT_ID` / `TUYA_CLIENT_SECRET` (rotate — old values leaked in git history) |
| Tuya App OAuth | Stored as Cloudflare secrets `TUYA_APP_CLIENT_ID` / `TUYA_APP_CLIENT_SECRET` (rotate — old values leaked in git history) |
| GitHub | Repo: `itzoctober23-web/dripsolve-site` (auto-deploy from main branch not active) |
| D1 Database | Name: `dripsolve-db`, ID: `a2bae2de-21c3-482f-8026-951a10096be7` |
| Custom domain | `dripsolve.com` on Cloudflare, proxied to Worker |
| JWT Secret | Cloudflare secret `JWT_SECRET` — set via `wrangler secret put JWT_SECRET`. NOT in source. (Old hardcoded `dripsolve-jwt-secret-2026` is retired.) |

## Current Status (deployed to prod: June 7, 2026)

### Done
- Worker deployed serving static site + API at `dripsolve.com`
- D1 database with users, user_data, sensor_readings, tuya_tokens tables
- **Auth hardened: real HMAC-SHA256 signed tokens; forged/tampered tokens rejected (verified live). `JWT_SECRET` + all 4 Tuya creds are Cloudflare secrets (no longer in source).**
- Full auth API (signup, login, verify, change-password) with password-length validation
- User data API (GET/PUT JSON blob)
- Tuya Cloud API integration (HMAC-SHA256 signing, token management) — verified working through secrets
- **Tuya OAuth code→token exchange implemented in `/api/tuya-auth?action=callback` (grant_type=2), stores token in `tuya_tokens`, redirects with `?tuya=connected|error&reason=...`. Best-effort: Cloud-style signature + app client_id; signature scheme NOT yet confirmed against live Tuya.**
- Dashboard shows a toast for the OAuth connect result.
- Tuya sync endpoint queries devices by IDs and generates leak alerts
- Stripe Payment Links created and integrated in dashboard
- GitHub repo pushed; changes on branch `claude/affectionate-chatterjee-eb2aaa` (PR #2)

### Remaining
1. **Finish Tuya OAuth (live test in progress).** In Tuya Console → `Devices` → `Link App Account`: enable login authorization, set data center to **Western America (us)**, set callback `https://dripsolve.com/api/tuya-auth?action=callback`, and copy the generated **authorization page URL** (the `authorize` action currently hardcodes a guessed `images.tuyaus.com/smart_home/auth` URL — replace with the real one). Then click Connect, log in, and read the `?tuya=` result. If `reason=sign invalid` → switch the exchange to the App-Authorization signature (adds `nonce` + `identifier`).
2. Decide sync model: keep manual device IDs (current) vs. per-user OAuth auto-discovery (rewrites `/api/tuya-sync` to use the stored per-user token + refresh).
3. Re-create / refresh the virtual sensor `vdevo178080038144948` (returns empty now — Tuya virtual devices expire when the debug session ends).
4. Rotate the 4 Tuya secret values (old ones are in git history) in the Tuya console, then `wrangler secret put` the new values.
5. Update dashboard Settings to let users add/edit Tuya device IDs in the UI.
6. Test full Stripe → return-to-dashboard flow end-to-end.
7. Resolve Gmail SMTP for `hello@dripsolve.com` (optional — email sending).

### Deploy note
`wrangler` serves UI from `dist/` (gitignored). Before `wrangler deploy`, copy HTML in: `Copy-Item index.html, dashboard.html dist\ -Force`.

## How to Continue

Share this file with Claude and say: "Continue helping me with DripSolve. Read HANDFF.md first for full context."

Or for specific tasks:

- **Dashboard UI updates**: Edit `dashboard.html` (the main SaaS interface with login, alerts, devices, settings)
- **Worker API changes**: Edit `worker.js` (route handlers) and `_shared.js` (utilities)
- **New deployment**: Run `wrangler deploy` from repo root
- **Database queries**: Run `wrangler d1 execute dripsolve-db --remote --command "SQL"`
- **View logs**: Go to Cloudflare Dashboard → Workers & Pages → dripsolve-site → Observability
