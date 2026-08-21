// POPCRATE — server
// Node/Express. All outcomes are decided server-side with a provably-fair
// HMAC-SHA256 roll (server seed + client seed + nonce). The client only animates.
'use strict';
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { db, getSetting, setSetting, caseStats, tuneCase, levelFromXp } = require('./db');
const sec = require('./security');
const mountCms = require('./cms');
const mountBattles = require('./battles');

const app = express();
app.use(sec.securityHeaders);
app.use(express.json({ limit: '4mb' }));   // 4mb: allows base64 image uploads to the CMS media library
app.use(sec.csrfGuard);
app.use(express.static(path.join(__dirname, 'public')));
app.disable('x-powered-by');

const PORT = process.env.PORT || 3000;
const COOKIE_SECRET = getSetting('cookie_secret');

// ---------- helpers ----------
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const hmac = (key, msg) => crypto.createHmac('sha256', key).update(msg).digest('hex');
const now = () => new Date().toISOString();

function hashPassword(pw, salt) {
  return crypto.scryptSync(pw, salt, 32).toString('hex');
}

function sign(v) { return v + '.' + hmac(COOKIE_SECRET, v); }
function unsign(v) {
  if (!v) return null;
  const i = v.lastIndexOf('.');
  if (i < 0) return null;
  const raw = v.slice(0, i), sig = v.slice(i + 1);
  const expect = hmac(COOKIE_SECRET, raw);
  try { if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return raw; } catch {}
  return null;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

// naive per-IP rate limiter (swap for redis-backed in production)
const buckets = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const key = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'ip') + ':' + req.path;
    const b = buckets.get(key) || { n: 0, t: Date.now() };
    if (Date.now() - b.t > windowMs) { b.n = 0; b.t = Date.now(); }
    if (++b.n > max) return res.status(429).json({ error: 'Slow down — too many requests.' });
    buckets.set(key, b);
    next();
  };
}

function audit(actor, action, meta) {
  db.prepare('INSERT INTO audit_log(actor,action,meta) VALUES (?,?,?)').run(actor, action, JSON.stringify(meta || {}));
}

// ---------- auth middleware ----------
function auth(req, res, next) {
  const token = unsign(parseCookies(req).pc_session);
  if (!token) return res.status(401).json({ error: 'Sign in first.' });
  const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
  if (!s || !sec.sessionValid(s)) {
    if (s) db.prepare('DELETE FROM sessions WHERE token=?').run(token);
    return res.status(401).json({ error: 'Session expired — sign in again.' });
  }
  sec.touchSession(token);
  req.user = db.prepare('SELECT * FROM users WHERE id=?').get(s.user_id);
  next();
}
const adminAuth = sec.makeAdminAuth();   // admin key + optional TOTP two-factor

// ---------- provably fair core ----------
function activeSeed(userId) {
  let s = db.prepare('SELECT * FROM seeds WHERE user_id=? AND active=1').get(userId);
  if (!s) {
    const seed = crypto.randomBytes(32).toString('hex');
    const info = db.prepare('INSERT INTO seeds(user_id,seed,seed_hash) VALUES (?,?,?)').run(userId, seed, sha256(seed));
    s = db.prepare('SELECT * FROM seeds WHERE id=?').get(info.lastInsertRowid);
  }
  return s;
}
function rollFor(user, seed, nonce, salt) {
  const digest = hmac(seed.seed, `${user.client_seed}:${nonce}:${salt}`);
  return parseInt(digest.slice(0, 8), 16) / 0x100000000; // [0,1)
}
function pickItem(items, roll) {
  const total = items.reduce((s, i) => s + i.weight, 0);
  let acc = 0;
  for (const i of items) { acc += i.weight; if (roll < acc / total) return i; }
  return items[items.length - 1];
}

const publicUser = u => {
  const tier = db.prepare('SELECT * FROM membership_tiers WHERE slug=?').get(effectiveTier(u)) || {};
  return { id: u.id, username: u.username, balance: u.balance, client_seed: u.client_seed, nonce: u.nonce,
           tier: effectiveTier(u), tier_until: u.tier_until, tier_emoji: tier.emoji, tier_color: tier.color,
           xp: u.xp, level: levelFromXp(u.xp) };
};
// membership expires automatically — expired paid tiers read as 'free'
function effectiveTier(u) {
  if (u.tier && u.tier !== 'free' && u.tier_until && new Date(u.tier_until) < new Date()) return 'free';
  return u.tier || 'free';
}
function tierOf(u) { return db.prepare('SELECT * FROM membership_tiers WHERE slug=?').get(effectiveTier(u)); }
function awardXp(userId, base) {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(userId);
  if (!u) return { gained: 0 };
  const t = tierOf(u) || { xp_boost_bps: 0 };
  const gained = Math.max(1, Math.round(base * (1 + (t.xp_boost_bps || 0) / 10000)));
  const before = levelFromXp(u.xp);
  db.prepare('UPDATE users SET xp=xp+? WHERE id=?').run(gained, userId);
  const after = levelFromXp(u.xp + gained);
  return { gained, level: after, leveled_up: after > before };
}
const cookieOpts = `HttpOnly; Path=/; SameSite=Strict${sec.PROD ? '; Secure' : ''}`;

// ================= AUTH =================
app.post('/api/register', rateLimit(10, 60000), (req, res) => {
  const { username, password } = req.body || {};
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) return res.status(400).json({ error: 'Username: 3–20 letters, numbers, underscores.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password needs at least 6 characters.' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(username)) return res.status(400).json({ error: 'That name is taken.' });
  const salt = crypto.randomBytes(16).toString('hex');
  const info = db.prepare('INSERT INTO users(username,pass_hash,salt,balance,client_seed) VALUES (?,?,?,?,?)')
    .run(username, hashPassword(password, salt), salt, 1000, crypto.randomBytes(8).toString('hex')); // 1000 welcome tokens (demo)
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions(token,user_id) VALUES (?,?)').run(token, info.lastInsertRowid);
  res.setHeader('Set-Cookie', `pc_session=${sign(token)}; ${cookieOpts}; Max-Age=2592000`);
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  activeSeed(u.id);
  audit(username, 'register', {});
  res.json({ user: publicUser(u) });
});

app.post('/api/login', rateLimit(15, 60000), (req, res) => {
  const { username, password } = req.body || {};
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'ip');
  const keys = ['u:' + (username || ''), 'ip:' + ip];
  if (keys.some(sec.isLocked)) return res.status(429).json({ error: 'Too many failed attempts — locked for 15 minutes.' });
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username || '');
  const ok = u && hashPassword(password || '', u.salt) === u.pass_hash;
  keys.forEach(k => sec.recordAttempt(k, ok));
  if (!ok) return res.status(400).json({ error: 'Wrong username or password.' });
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions(token,user_id) VALUES (?,?)').run(token, u.id);
  res.setHeader('Set-Cookie', `pc_session=${sign(token)}; ${cookieOpts}; Max-Age=2592000`);
  res.json({ user: publicUser(u) });
});

app.post('/api/logout', auth, (req, res) => {
  const token = unsign(parseCookies(req).pc_session);
  db.prepare('DELETE FROM sessions WHERE token=?').run(token);
  res.setHeader('Set-Cookie', `pc_session=; ${cookieOpts}; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const seed = activeSeed(req.user.id);
  res.json({ user: publicUser(req.user), seed_hash: seed.seed_hash });
});

// ================= CATALOG =================
app.get('/api/categories', (req, res) => {
  res.json({ categories: db.prepare('SELECT id,slug,name,emoji,blurb FROM categories WHERE active=1 ORDER BY sort').all() });
});
app.get('/api/site', (req, res) => {
  res.json({ hero_title: getSetting('hero_title'), hero_sub: getSetting('hero_sub'), announcement: getSetting('announcement') });
});
app.get('/api/pages', (req, res) => {
  res.json({ pages: db.prepare('SELECT slug,title FROM pages WHERE published=1 ORDER BY slug').all() });
});
app.get('/api/pages/:slug', (req, res) => {
  const p = db.prepare('SELECT slug,title,body,updated_at FROM pages WHERE slug=? AND published=1').get(req.params.slug);
  if (!p) return res.status(404).json({ error: 'page not found' });
  res.json(p);
});
app.get('/api/cases', (req, res) => {
  const cases = db.prepare('SELECT * FROM cases WHERE active=1 ORDER BY featured DESC, sort').all();
  res.json({
    cases: cases.map(c => {
      const st = caseStats(c.id);
      return { ...c, items: st.items.map(i => ({ id: i.id, name: i.name, emoji: i.emoji, image: i.image, value: i.value, rarity: i.rarity, probability: Math.round(i.probability * 100000) / 100000 })) };
    })
  });
});

// ================= WALLET =================
// Demo checkout. Production: create a Stripe Checkout Session here and credit
// tokens only inside the checkout.session.completed webhook handler.
const PACKAGES = {
  scoop:  { usd: 5,   tokens: 500 },
  bundle: { usd: 10,  tokens: 1050 },
  stack:  { usd: 25,  tokens: 2750 },
  vault:  { usd: 50,  tokens: 5750 },
  whale:  { usd: 100, tokens: 12000 },
};
app.get('/api/wallet/packages', (req, res) => res.json({ packages: PACKAGES }));
app.post('/api/wallet/purchase', auth, rateLimit(20, 60000), (req, res) => {
  const p = PACKAGES[req.body?.package];
  if (!p) return res.status(400).json({ error: 'Unknown package.' });
  // Idempotency: a retried/replayed request can never double-credit.
  const idem = String(req.body?.idempotency_key || crypto.randomBytes(12).toString('hex')).slice(0, 64);
  const prior = db.prepare('SELECT * FROM purchases WHERE idem_key=?').get(idem);
  if (prior) {
    const u0 = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    return res.json({ user: publicUser(u0), credited: 0, duplicate: true });
  }
  // --- STRIPE INTEGRATION POINT ------------------------------------------
  // const session = await stripe.checkout.sessions.create({...});
  // return res.json({ checkout_url: session.url });
  // Credit tokens ONLY in the webhook after payment confirmation.
  // ------------------------------------------------------------------------
  const tx = db.transaction(() => {
    db.prepare('INSERT INTO purchases(idem_key,user_id,package,tokens) VALUES (?,?,?,?)').run(idem, req.user.id, req.body.package, p.tokens);
    db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(p.tokens, req.user.id);
    db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
      .run(req.user.id, 'purchase', p.tokens, JSON.stringify({ usd: p.usd, demo: true }));
  });
  tx();
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  res.json({ user: publicUser(u), credited: p.tokens, demo: true });
});

// ================= OPEN A CRATE =================
app.post('/api/open/:slug', auth, rateLimit(60, 60000), (req, res) => {
  const c = db.prepare('SELECT * FROM cases WHERE slug=? AND active=1').get(req.params.slug);
  if (!c) return res.status(404).json({ error: 'Crate not found.' });
  // per-account velocity cap (anti-bot, independent of the IP limiter)
  const recent = db.prepare("SELECT COUNT(*) n FROM opens WHERE user_id=? AND created_at > datetime('now','-60 seconds')").get(req.user.id).n;
  if (recent >= 40) return res.status(429).json({ error: 'Whoa, speed demon — take a breath (40 opens/min cap).' });
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (user.balance < c.price) return res.status(400).json({ error: 'Not enough tokens — top up your wallet.' });

  const items = db.prepare('SELECT * FROM items WHERE case_id=?').all(c.id);
  const seed = activeSeed(user.id);
  const results = [];
  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(c.price, user.id);
    db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
      .run(user.id, 'open', -c.price, JSON.stringify({ case: c.slug }));
    for (let d = 0; d < c.draws; d++) {
      const nonce = db.prepare('SELECT nonce FROM users WHERE id=?').get(user.id).nonce + 1;
      db.prepare('UPDATE users SET nonce=? WHERE id=?').run(nonce, user.id);
      const roll = rollFor(user, seed, nonce, `${c.slug}:${d}`);
      const item = pickItem(items, roll);
      db.prepare('INSERT INTO opens(user_id,case_id,item_id,roll,nonce,client_seed,seed_id,cost,value) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(user.id, c.id, item.id, roll, nonce, user.client_seed, seed.id, d === 0 ? c.price : 0, item.value);
      const inv = db.prepare('INSERT INTO inventory(user_id,item_name,item_emoji,rarity,value) VALUES (?,?,?,?,?)')
        .run(user.id, item.name, item.emoji, item.rarity, item.value);
      results.push({ inventory_id: inv.lastInsertRowid, item_id: item.id, name: item.name, emoji: item.emoji, image: item.image, value: item.value, rarity: item.rarity, roll: Math.round(roll * 1e8) / 1e8, nonce });
    }
  });
  tx();
  // membership rakeback: tokens back on every open
  const t = tierOf(user);
  let rakeback = 0;
  if (t && t.rakeback_bps > 0) {
    rakeback = Math.floor(c.price * t.rakeback_bps / 10000);
    if (rakeback > 0) {
      db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(rakeback, user.id);
      db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
        .run(user.id, 'rakeback', rakeback, JSON.stringify({ case: c.slug }));
    }
  }
  const xp = awardXp(user.id, Math.round(c.price / 10));
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(user.id);
  res.json({ results, balance: u.balance, seed_hash: seed.seed_hash, rakeback, xp });
});

// sell an inventory item back for tokens
app.post('/api/inventory/:id/sell', auth, (req, res) => {
  const row = db.prepare('SELECT * FROM inventory WHERE id=? AND user_id=? AND status=?').get(req.params.id, req.user.id, 'held');
  if (!row) return res.status(404).json({ error: 'Item not found or already handled.' });
  const tx = db.transaction(() => {
    db.prepare('UPDATE inventory SET status=? WHERE id=?').run('sold', row.id);
    db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(row.value, req.user.id);
    db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
      .run(req.user.id, 'sell', row.value, JSON.stringify({ item: row.item_name }));
  });
  tx();
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  res.json({ balance: u.balance });
});

app.get('/api/inventory', auth, (req, res) => {
  res.json({ items: db.prepare('SELECT * FROM inventory WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.user.id) });
});

// live win feed (recent notable pulls, anonymised)
app.get('/api/feed', (req, res) => {
  const rows = db.prepare(`
    SELECT o.value, o.created_at, i.name, i.emoji, i.rarity, u.username, c.name AS case_name
    FROM opens o JOIN items i ON i.id=o.item_id JOIN users u ON u.id=o.user_id JOIN cases c ON c.id=o.case_id
    ORDER BY o.id DESC LIMIT 24`).all();
  res.json({ feed: rows.map(r => ({ ...r, username: r.username.slice(0, 2) + '***' })) });
});

// ================= PROVABLY FAIR =================
app.post('/api/fair/client-seed', auth, (req, res) => {
  const cs = String(req.body?.client_seed || '').slice(0, 64);
  if (!/^[a-zA-Z0-9_-]{4,64}$/.test(cs)) return res.status(400).json({ error: 'Seed: 4–64 letters, numbers, - or _.' });
  db.prepare('UPDATE users SET client_seed=? WHERE id=?').run(cs, req.user.id);
  res.json({ client_seed: cs });
});
app.post('/api/fair/rotate', auth, (req, res) => {
  const old = activeSeed(req.user.id);
  db.prepare('UPDATE seeds SET active=0, revealed=1 WHERE id=?').run(old.id);
  const fresh = activeSeed(req.user.id);
  res.json({ revealed_seed: old.seed, revealed_hash: old.seed_hash, new_hash: fresh.seed_hash });
});
app.get('/api/fair/verify', (req, res) => {
  const { seed, client_seed, nonce, salt } = req.query;
  if (!seed || !client_seed || !nonce) return res.status(400).json({ error: 'seed, client_seed, nonce required' });
  const digest = hmac(String(seed), `${client_seed}:${nonce}:${salt || ''}`);
  res.json({ roll: parseInt(digest.slice(0, 8), 16) / 0x100000000, hash_of_seed: sha256(String(seed)) });
});

// ================= RAFFLES =================
app.get('/api/raffles', (req, res) => {
  const raffles = db.prepare("SELECT * FROM raffles ORDER BY status='open' DESC, ends_at").all();
  const counts = db.prepare('SELECT raffle_id, COUNT(*) c FROM raffle_tickets GROUP BY raffle_id').all();
  const map = Object.fromEntries(counts.map(r => [r.raffle_id, r.c]));
  res.json({ raffles: raffles.map(r => ({ ...r, sold: map[r.id] || 0 })) });
});
app.post('/api/raffles/:id/buy', auth, rateLimit(30, 60000), (req, res) => {
  const qty = Math.max(1, Math.min(50, parseInt(req.body?.qty || 1)));
  const r = db.prepare("SELECT * FROM raffles WHERE id=? AND status='open'").get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Raffle closed or not found.' });
  const sold = db.prepare('SELECT COUNT(*) c FROM raffle_tickets WHERE raffle_id=?').get(r.id).c;
  if (sold + qty > r.max_tickets) return res.status(400).json({ error: 'Not enough tickets left.' });
  const cost = qty * r.ticket_price;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (user.balance < cost) return res.status(400).json({ error: 'Not enough tokens.' });
  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(cost, user.id);
    db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
      .run(user.id, 'raffle_ticket', -cost, JSON.stringify({ raffle: r.id, qty }));
    const ins = db.prepare('INSERT INTO raffle_tickets(raffle_id,user_id) VALUES (?,?)');
    for (let i = 0; i < qty; i++) ins.run(r.id, user.id);
  });
  tx();
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(user.id);
  res.json({ balance: u.balance, bought: qty });
});

function drawRaffle(raffleId, actor) {
  const r = db.prepare("SELECT * FROM raffles WHERE id=? AND status='open'").get(raffleId);
  if (!r) throw new Error('raffle not open');
  const tickets = db.prepare('SELECT * FROM raffle_tickets WHERE raffle_id=? ORDER BY id').all(r.id);
  if (!tickets.length) { db.prepare("UPDATE raffles SET status='cancelled' WHERE id=?").run(r.id); return { cancelled: true }; }
  const seed = crypto.randomBytes(32).toString('hex');
  const idx = parseInt(hmac(seed, `raffle:${r.id}`).slice(0, 8), 16) % tickets.length;
  const win = tickets[idx];
  const tx = db.transaction(() => {
    db.prepare("UPDATE raffles SET status='drawn', winner_user_id=?, winning_ticket=?, proof=? WHERE id=?")
      .run(win.user_id, win.id, JSON.stringify({ seed, seed_hash: sha256(seed), index: idx, total: tickets.length }), r.id);
    db.prepare('INSERT INTO inventory(user_id,item_name,item_emoji,rarity,value) VALUES (?,?,?,?,?)')
      .run(win.user_id, r.name + ' (Raffle Prize)', r.emoji, 'legendary', r.prize_value);
    db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
      .run(win.user_id, 'raffle_win', 0, JSON.stringify({ raffle: r.id }));
  });
  tx();
  audit(actor, 'raffle_draw', { raffle: r.id, winner: win.user_id });
  return { winner_user_id: win.user_id, winning_ticket: win.id };
}
// auto-draw expired raffles every 30s
setInterval(() => {
  const due = db.prepare("SELECT id FROM raffles WHERE status='open' AND ends_at <= datetime('now')").all();
  for (const r of due) { try { drawRaffle(r.id, 'scheduler'); } catch {} }
}, 30000);

// ================= ADMIN =================
app.get('/api/admin/overview', adminAuth, (req, res) => {
  const cases = db.prepare('SELECT id FROM cases').all().map(c => caseStats(c.id));
  const totals = db.prepare(`SELECT
    (SELECT COUNT(*) FROM users) users,
    (SELECT COUNT(*) FROM opens) opens,
    (SELECT COALESCE(SUM(-amount),0) FROM transactions WHERE type='open') wagered,
    (SELECT COALESCE(SUM(value),0) FROM opens) paid_out,
    (SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='purchase') tokens_sold`).get();
  totals.realized_rtp = totals.wagered ? Math.round(totals.paid_out / totals.wagered * 10000) / 10000 : null;
  res.json({ cases, totals });
});
app.post('/api/admin/cases/:id/tune', adminAuth, (req, res) => {
  try {
    const out = tuneCase(req.params.id, req.body?.target_rtp);
    audit('admin', 'tune_rtp', { case: req.params.id, target: req.body?.target_rtp });
    res.json(out);
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/admin/items/:id', adminAuth, (req, res) => {
  const { weight, value, name, image } = req.body || {};
  const item = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!item) return res.status(404).json({ error: 'item not found' });
  db.prepare('UPDATE items SET weight=?, value=?, name=?, image=? WHERE id=?')
    .run(weight ?? item.weight, value ?? item.value, name ?? item.name, image ?? item.image, item.id);
  audit('admin', 'edit_item', { item: item.id, weight, value });
  res.json(caseStats(item.case_id));
});
// (crate create/edit/delete now live in cms.js — see /api/admin/cases/create, /:id/edit, /:id/delete)
app.get('/api/admin/users', adminAuth, (req, res) => {
  res.json({ users: db.prepare('SELECT id,username,balance,nonce,created_at FROM users ORDER BY id DESC LIMIT 200').all() });
});
app.post('/api/admin/users/:id/balance', adminAuth, (req, res) => {
  const delta = parseInt(req.body?.delta || 0);
  db.prepare('UPDATE users SET balance=MAX(0,balance+?) WHERE id=?').run(delta, req.params.id);
  db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
    .run(req.params.id, 'admin_adjust', delta, '{}');
  audit('admin', 'adjust_balance', { user: req.params.id, delta });
  res.json({ ok: true });
});
app.post('/api/admin/raffles', adminAuth, (req, res) => {
  const { name, emoji, prize_value, ticket_price, max_tickets, hours } = req.body || {};
  if (!name || !prize_value || !ticket_price || !max_tickets) return res.status(400).json({ error: 'name, prize_value, ticket_price, max_tickets required' });
  const info = db.prepare(`INSERT INTO raffles(name,emoji,prize_value,ticket_price,max_tickets,ends_at)
    VALUES (?,?,?,?,?,datetime('now', ?))`).run(name, emoji || '🎁', prize_value, ticket_price, max_tickets, `+${Math.max(1, hours || 24)} hours`);
  audit('admin', 'create_raffle', { id: info.lastInsertRowid });
  res.json({ id: info.lastInsertRowid });
});
app.post('/api/admin/raffles/:id/draw', adminAuth, (req, res) => {
  try { res.json(drawRaffle(req.params.id, 'admin')); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/admin/audit', adminAuth, (req, res) => {
  res.json({ log: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all() });
});

// ================= MEMBERSHIPS =================
app.get('/api/tiers', (req, res) => {
  res.json({ tiers: db.prepare('SELECT slug,name,emoji,price_usd,rakeback_bps,daily_bonus,xp_boost_bps,color,perks,sort FROM membership_tiers ORDER BY sort').all()
    .map(t => ({ ...t, perks: JSON.parse(t.perks || '[]') })) });
});
// Demo subscribe. Production: create a Stripe *subscription* Checkout Session
// here and set the tier ONLY in the invoice.paid / checkout webhook.
app.post('/api/tiers/subscribe', auth, rateLimit(10, 60000), (req, res) => {
  const t = db.prepare('SELECT * FROM membership_tiers WHERE slug=?').get(req.body?.tier);
  if (!t || t.slug === 'free') return res.status(400).json({ error: 'Pick a paid tier.' });
  const until = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
  db.prepare('UPDATE users SET tier=?, tier_until=? WHERE id=?').run(t.slug, until, req.user.id);
  db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
    .run(req.user.id, 'membership', 0, JSON.stringify({ tier: t.slug, usd: t.price_usd, demo: true }));
  audit(req.user.username, 'subscribe', { tier: t.slug });
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  res.json({ user: publicUser(u), demo: true });
});
app.post('/api/tiers/daily-claim', auth, rateLimit(10, 60000), (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  const t = tierOf(u);
  if (!t || !t.daily_bonus) return res.status(400).json({ error: 'Your tier has no daily bonus. Upgrade!' });
  const day = new Date().toISOString().slice(0, 10);
  try {
    db.prepare('INSERT INTO daily_claims(user_id,day,amount) VALUES (?,?,?)').run(u.id, day, t.daily_bonus);
  } catch { return res.status(400).json({ error: 'Already claimed today — come back tomorrow!' }); }
  db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(t.daily_bonus, u.id);
  db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
    .run(u.id, 'daily_bonus', t.daily_bonus, JSON.stringify({ tier: t.slug }));
  const fresh = db.prepare('SELECT * FROM users WHERE id=?').get(u.id);
  res.json({ claimed: t.daily_bonus, balance: fresh.balance });
});

// ================= ADMIN: SECURITY =================
app.get('/api/admin/security', adminAuth, (req, res) => {
  res.json({
    totp_enabled: !!getSetting('admin_totp_secret'),
    recent_lockouts: db.prepare('SELECT key, COUNT(*) fails FROM login_attempts WHERE ok=0 AND at > ? GROUP BY key HAVING fails >= 4 ORDER BY fails DESC LIMIT 20')
      .all(Date.now() - 15 * 60 * 1000),
  });
});
app.post('/api/admin/security/totp/setup', adminAuth, (req, res) => {
  if (getSetting('admin_totp_secret')) return res.status(400).json({ error: '2FA already enabled.' });
  res.json(sec.totpSetupBegin());
});
app.post('/api/admin/security/totp/confirm', adminAuth, (req, res) => {
  if (!sec.totpSetupConfirm(req.body?.code)) return res.status(400).json({ error: 'Code did not match — scan the secret and try again.' });
  audit('admin', 'totp_enabled', {});
  res.json({ ok: true });
});
app.post('/api/admin/security/totp/disable', adminAuth, (req, res) => {
  setSetting('admin_totp_secret', '');
  audit('admin', 'totp_disabled', {});
  res.json({ ok: true });
});

// ================= MOUNT: CMS + BATTLES =================
mountCms(app, adminAuth, audit);
mountBattles(app, { auth, rateLimit, audit, activeSeed, rollFor, pickItem, awardXp });

app.listen(PORT, () => {
  console.log(`\n  🎁 POPCRATE running →  http://localhost:${PORT}`);
  console.log(`  🔐 Admin panel      →  http://localhost:${PORT}/admin.html`);
  console.log(`  🔑 Admin key        →  ${getSetting('admin_key')}\n`);
});
