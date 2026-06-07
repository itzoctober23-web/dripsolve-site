# DripSolve — Project Context for Claude

I am a SaaS water leak detection dashboard. Users buy Tuya-compatible WiFi sensors (~$10-18 on Amazon), and I poll the Tuya Cloud API to detect leaks and alert them.

## Quick Start

- **Code**: `C:\Users\SATURN\Desktop\DripSolve-site\`
- **Deploy**: `cd C:\Users\SATURN\Desktop\DripSolve-site && wrangler deploy`
- **Live**: https://dripsolve.com (Worker at https://dripsolve-site.itzoctober23.workers.dev)
- **D1 queries**: `wrangler d1 execute dripsolve-db --remote --command "SQL"`
- **Git push**: `git add -A && git commit -m "msg" && git push`

## Architecture

- `worker.js` — Main Worker (API routes + static assets from `dist/`)
- `_shared.js` — Auth, Tuya signing, CORS utilities
- `dashboard.html` — SaaS dashboard (login, devices, alerts, settings)
- `index.html` — Landing page
- `wrangler.toml` — D1 binding + env vars

## Key Credentials

| What | Value |
|------|-------|
| Tuya Cloud ID | `s537yq45fx3nf7dvttnq` |
| Tuya Cloud Secret | `e14bab9a2865422eaa3bce97e4a5d6f4` |
| Tuya App OAuth ID | `sp8emhrsknday9c93gy8` |
| Tuya App OAuth Secret | `ffea7590c71948a1965a67b470d74689` |
| D1 Database ID | `a2bae2de-21c3-482f-8026-951a10096be7` |
| JWT Secret | `dripsolve-jwt-secret-2026` (hardcoded in worker.js) |

## Stripe Payment Links (all Active)
- Starter ($9.99): https://buy.stripe.com/6oUeVc6W3c1j5Fb23fasg00
- Pro ($24.99): https://buy.stripe.com/3cI5kCcgne9rdD7J6vasg01
- Portfolio ($99.99): https://buy.stripe.com/9B65kC0xFfdv7NjeQ1asg02

## Virtual Test Device
- ID: `vdevo178080038144948` — Water Leak Sensor (currently reporting `alarm` state)
- Add to dashboard via: `POST /api/tuya-devices` with body `{"device_ids":["vdevo178080038144948"]}`

## Tuya API Signing (important!)
HMAC-SHA256 with this string format:
```
str = client_id + (access_token or '') + t + HTTP_METHOD + '\n' + SHA256(body).hex() + '\n\n' + /path?query
sign = HMAC-SHA256(str, client_secret).toUpperCase()
```
Token endpoint: `GET /v1.0/token?grant_type=1`, no access_token in str.
Device list: `GET /v1.0/iot-03/devices?device_ids=id1,id2`, with access_token.

## Remaining Steps
1. Set Tuya OAuth callback URL in Tuya Console (Devices → Link App Account → DripSolveWeb → `https://dripsolve.com/api/tuya-auth?action=callback`)
2. Update dashboard Settings to let users add/edit Tuya device IDs
3. Test Stripe → return-to-dashboard flow
4. Run DripSolve.bat for lead gen
