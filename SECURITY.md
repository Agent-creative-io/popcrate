# POPCRATE — security model

Zero-dependency hardening, all in `security.js` + wired through `server.js`.

## Request layer
- **Headers**: CSP (`default-src 'self'`, fonts allow-listed, `frame-ancestors 'none'`),
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP,
  Permissions-Policy, HSTS in production.
- **CSRF**: cookies are `SameSite=Strict`, and every state-changing `/api` request must show
  ONE of two independent proofs: the custom `X-PC: 1` header (cross-site pages can't attach
  custom headers without a CORS preflight, which is never granted) **or** a verified
  same-origin `Origin`/`Referer` (browsers stamp `Origin` on all cross-site POSTs, so forged
  requests identify themselves). The dual check keeps privacy extensions that strip custom
  headers from locking real users out.
- **Rate limits**: per-IP buckets per route, plus a per-account **40 opens/min velocity cap**
  that IP rotation can't dodge.

## Accounts & sessions
- Passwords: `scrypt` with per-user salt.
- **Login lockout**: 8 failures in 15 minutes locks the username *and* the source IP;
  attempts are logged and surfaced in the admin Security tab.
- Sessions: 192-bit random tokens, HMAC-signed, `httpOnly`, `Secure` in production,
  30-day absolute + 3-day idle expiry, server-side revocation on logout.

## Money paths
- **Idempotency keys** on purchases — a replayed/double-clicked/retried request can never
  credit twice (`purchases.idem_key` primary key).
- Every balance change is a SQLite **transaction** with a ledger row; battles debit both
  players and pay the winner atomically.
- Production rule: tokens are credited **only** from verified Stripe webhooks, never from
  client-initiated endpoints.

## Admin
- Timing-safe admin-key comparison.
- **TOTP two-factor (RFC 6238, hand-rolled, no deps)** — enable in the Security tab; every
  admin request then requires a fresh 6-digit code (`X-Admin-OTP`).
- Append-only audit log for every odds change, CMS edit, payout and security event.

## Content & injection
- 100% parameterized SQL (better-sqlite3 prepared statements) — no string-built queries.
- All user/CMS strings length-clamped and HTML-escaped at render time; strict CSP as backstop.
- **Uploads**: 3 MB cap, MIME allow-list, and magic-byte sniffing — a script renamed `.png`
  is rejected because its bytes don't match the format.
- Fairness endpoints expose only hashes until seeds are rotated; server seeds never leave
  the DB while active.

## Battles fairness
Each battle round uses the *player's own* provably-fair chain
(`HMAC(serverSeed, clientSeed:nonce:battle:id:crate:round)`), so battle rolls are verifiable
exactly like solo opens. Ties resolve by an HMAC coin flip whose seed is stored in the
battle record.
