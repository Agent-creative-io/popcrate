// POPCRATE — security layer
// Zero-dependency hardening: strict headers + CSP, CSRF guard, login backoff,
// session expiry, and hand-rolled RFC-6238 TOTP for admin two-factor.
'use strict';
const crypto = require('crypto');
const { db, getSetting, setSetting } = require('./db');

const PROD = process.env.NODE_ENV === 'production';

/* ---------- hardened response headers ---------- */
function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",              // inline app script; move to a file+nonce if you prefer
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; '));
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
}

/* ---------- CSRF guard ----------
   Two independent proofs; EITHER passes:
   1. The custom header X-PC: 1 (cross-site pages can't attach custom headers
      without a CORS preflight, and we never grant CORS).
   2. A same-origin Origin/Referer header (browsers attach Origin to all
      cross-site POSTs, so a forged request identifies itself and is blocked).
   Cookies are additionally SameSite=Strict. The dual check means privacy
   extensions that strip custom headers can't lock legitimate users out. */
function csrfGuard(req, res, next) {
  if (!/^(POST|PUT|PATCH|DELETE)$/.test(req.method)) return next();
  if (!req.path.startsWith('/api/')) return next();
  if (req.headers['x-pc'] === '1') return next();
  const src = req.headers.origin || req.headers.referer;
  if (src) { try { if (new URL(src).host === req.headers.host) return next(); } catch {} }
  return res.status(403).json({ error: 'Request blocked by cross-site protection — refresh the page and try again.' });
}

/* ---------- login backoff (per username + per IP) ---------- */
const LOCK_AFTER = 8, WINDOW_MS = 15 * 60 * 1000;
function recordAttempt(key, ok) {
  db.prepare('INSERT INTO login_attempts(key, ok, at) VALUES (?,?,?)').run(key, ok ? 1 : 0, Date.now());
  if (Math.random() < 0.02) db.prepare('DELETE FROM login_attempts WHERE at < ?').run(Date.now() - 24 * 3600 * 1000);
}
function isLocked(key) {
  const fails = db.prepare('SELECT COUNT(*) c FROM login_attempts WHERE key=? AND ok=0 AND at > ?')
    .get(key, Date.now() - WINDOW_MS).c;
  return fails >= LOCK_AFTER;
}

/* ---------- session expiry ---------- */
const SESSION_ABS_MS = 30 * 24 * 3600 * 1000;  // 30 days absolute
const SESSION_IDLE_MS = 3 * 24 * 3600 * 1000;  // 3 days idle
function sessionValid(s) {
  const created = new Date(s.created_at + 'Z').getTime();
  if (Date.now() - created > SESSION_ABS_MS) return false;
  if (s.last_seen && Date.now() - s.last_seen > SESSION_IDLE_MS) return false;
  return true;
}
function touchSession(token) {
  db.prepare('UPDATE sessions SET last_seen=? WHERE token=?').run(Date.now(), token);
}

/* ---------- TOTP (RFC 6238), no dependencies ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) { val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  let bits = 0, val = 0; const out = [];
  for (const ch of str.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(ch); if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function totpCode(secretB32, step = Math.floor(Date.now() / 30000)) {
  const key = base32Decode(secretB32);
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const code = ((h[off] & 0x7f) << 24 | h[off + 1] << 16 | h[off + 2] << 8 | h[off + 3]) % 1e6;
  return String(code).padStart(6, '0');
}
function totpVerify(secretB32, code) {
  const step = Math.floor(Date.now() / 30000);
  const c = String(code || '').trim();
  for (const s of [step, step - 1, step + 1]) {  // ±30s clock drift
    const expect = totpCode(secretB32, s);
    try { if (crypto.timingSafeEqual(Buffer.from(c), Buffer.from(expect))) return true; } catch {}
  }
  return false;
}
function totpSetupBegin() {
  const secret = base32Encode(crypto.randomBytes(20));
  setSetting('admin_totp_pending', secret);
  return { secret, otpauth: `otpauth://totp/POPCRATE%20Admin?secret=${secret}&issuer=POPCRATE` };
}
function totpSetupConfirm(code) {
  const pending = getSetting('admin_totp_pending');
  if (!pending || !totpVerify(pending, code)) return false;
  setSetting('admin_totp_secret', pending);
  setSetting('admin_totp_pending', '');
  return true;
}

/* ---------- admin auth with optional TOTP ---------- */
function makeAdminAuth() {
  return (req, res, next) => {
    const key = String(req.headers['x-admin-key'] || '');
    const expect = getSetting('admin_key');
    let ok = false;
    try { ok = key.length === expect.length && crypto.timingSafeEqual(Buffer.from(key), Buffer.from(expect)); } catch {}
    if (!ok) return res.status(403).json({ error: 'Invalid admin key.' });
    const secret = getSetting('admin_totp_secret');
    if (secret) {
      if (!totpVerify(secret, req.headers['x-admin-otp'])) {
        return res.status(403).json({ error: 'Two-factor code required or invalid.', need_otp: true });
      }
    }
    next();
  };
}

module.exports = {
  securityHeaders, csrfGuard,
  recordAttempt, isLocked,
  sessionValid, touchSession,
  totpSetupBegin, totpSetupConfirm, totpVerify, totpCode,
  makeAdminAuth, PROD,
};
