// POPCRATE — database layer (better-sqlite3)
// Schema, seed data, and the RTP tuning engine that lets admins dial
// exact win/loss percentages per crate.
'use strict';
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const db = new Database(path.join(__dirname, 'popcrate.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 0,
  client_seed TEXT NOT NULL,
  nonce INTEGER NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS seeds (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  seed TEXT NOT NULL,
  seed_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  revealed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  emoji TEXT NOT NULL,
  price INTEGER NOT NULL,
  draws INTEGER NOT NULL DEFAULT 1,
  open_style TEXT NOT NULL DEFAULT 'spinner', -- spinner | chest | pack | wheel
  color TEXT NOT NULL DEFAULT '#FF4FA3',
  description TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id),
  name TEXT NOT NULL,
  emoji TEXT NOT NULL,
  image TEXT,                 -- optional URL; swap in licensed product photos here
  value INTEGER NOT NULL,     -- token sell-back value
  weight REAL NOT NULL,       -- relative odds weight (admin adjustable)
  rarity TEXT NOT NULL        -- common|uncommon|rare|epic|legendary|mythic
);
CREATE TABLE IF NOT EXISTS opens (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  case_id INTEGER NOT NULL REFERENCES cases(id),
  item_id INTEGER NOT NULL REFERENCES items(id),
  roll REAL NOT NULL,
  nonce INTEGER NOT NULL,
  client_seed TEXT NOT NULL,
  seed_id INTEGER NOT NULL REFERENCES seeds(id),
  cost INTEGER NOT NULL,
  value INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS inventory (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  item_name TEXT NOT NULL,
  item_emoji TEXT NOT NULL,
  rarity TEXT NOT NULL,
  value INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'held', -- held | sold | redeemed
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS raffles (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  emoji TEXT NOT NULL,
  prize_value INTEGER NOT NULL,
  ticket_price INTEGER NOT NULL,
  max_tickets INTEGER NOT NULL,
  ends_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', -- open | drawn | cancelled
  winner_user_id INTEGER,
  winning_ticket INTEGER,
  proof TEXT
);
CREATE TABLE IF NOT EXISTS raffle_tickets (
  id INTEGER PRIMARY KEY,
  raffle_id INTEGER NOT NULL REFERENCES raffles(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,       -- purchase | open | sell | raffle_ticket | raffle_win | admin_adjust
  amount INTEGER NOT NULL,  -- signed token delta
  meta TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  meta TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  emoji TEXT NOT NULL DEFAULT '📦',
  blurb TEXT NOT NULL DEFAULT '',
  sort INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS membership_tiers (
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  emoji TEXT NOT NULL DEFAULT '⭐',
  price_usd REAL NOT NULL DEFAULT 0,
  rakeback_bps INTEGER NOT NULL DEFAULT 0,   -- tokens back on every open, basis points
  daily_bonus INTEGER NOT NULL DEFAULT 0,    -- free tokens claimable once/day
  xp_boost_bps INTEGER NOT NULL DEFAULT 0,   -- extra XP, basis points
  color TEXT NOT NULL DEFAULT '#B45CFF',
  perks TEXT NOT NULL DEFAULT '[]',          -- extra display lines (JSON array)
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pages (
  slug TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  published INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS battles (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id),
  rounds INTEGER NOT NULL,
  creator_id INTEGER NOT NULL REFERENCES users(id),
  opponent_id INTEGER,
  status TEXT NOT NULL DEFAULT 'open',      -- open | done | cancelled
  creator_total INTEGER,
  opponent_total INTEGER,
  winner_id INTEGER,
  tiebreak TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS battle_rounds (
  id INTEGER PRIMARY KEY,
  battle_id INTEGER NOT NULL REFERENCES battles(id),
  round INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  item_id INTEGER NOT NULL,
  roll REAL NOT NULL,
  nonce INTEGER NOT NULL,
  value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY,
  key TEXT NOT NULL,          -- username or ip bucket
  ok INTEGER NOT NULL,
  at INTEGER NOT NULL         -- epoch ms
);
CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts(key, at);
CREATE TABLE IF NOT EXISTS daily_claims (
  user_id INTEGER NOT NULL,
  day TEXT NOT NULL,
  amount INTEGER NOT NULL,
  PRIMARY KEY (user_id, day)
);
CREATE TABLE IF NOT EXISTS purchases (
  idem_key TEXT PRIMARY KEY,  -- idempotency: same key can never credit twice
  user_id INTEGER NOT NULL,
  package TEXT NOT NULL,
  tokens INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_opens_user ON opens(user_id);
CREATE INDEX IF NOT EXISTS idx_items_case ON items(case_id);
`);

// ---------- settings ----------
const getSetting = k => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : null; };
const setSetting = (k, v) => db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, String(v));

if (!getSetting('admin_key')) setSetting('admin_key', crypto.randomBytes(18).toString('hex'));
if (!getSetting('cookie_secret')) setSetting('cookie_secret', crypto.randomBytes(32).toString('hex'));
if (!getSetting('token_rate_usd')) setSetting('token_rate_usd', '0.01'); // 1 token ≈ $0.01
if (!getSetting('hero_title')) setSetting('hero_title', 'POP a crate. RIP a pack. WIN the grail.');
if (!getSetting('hero_sub')) setSetting('hero_sub', 'Cartoon-grade openings, provably-fair rolls, real prizes — from flagship phones to graded holo grails.');
if (!getSetting('announcement')) setSetting('announcement', '🎉 Grand opening — every new account starts with 1,000 free tokens. Crate Battles are LIVE!');

// ---------- column migrations (safe to re-run on existing databases) ----------
function addCol(table, def) { try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${def}`); } catch {} }
addCol('cases', "category_id INTEGER");
addCol('cases', "featured INTEGER NOT NULL DEFAULT 0");
addCol('users', "tier TEXT NOT NULL DEFAULT 'free'");
addCol('users', 'tier_until TEXT');
addCol('users', 'xp INTEGER NOT NULL DEFAULT 0');
addCol('sessions', 'last_seen INTEGER');

// XP → level curve: level n needs n²·100 xp (lvl 5 = 2,500xp, lvl 10 = 10,000xp)
const levelFromXp = xp => Math.floor(Math.sqrt(Math.max(0, xp) / 100));

// ---------- RTP math & tuning ----------
function caseStats(caseId) {
  const c = db.prepare('SELECT * FROM cases WHERE id=?').get(caseId);
  const items = db.prepare('SELECT * FROM items WHERE case_id=? ORDER BY value DESC').all(caseId);
  const totalW = items.reduce((s, i) => s + i.weight, 0) || 1;
  const evPerDraw = items.reduce((s, i) => s + (i.weight / totalW) * i.value, 0);
  const ev = evPerDraw * c.draws;
  return {
    case: c,
    items: items.map(i => ({ ...i, probability: i.weight / totalW })),
    ev: Math.round(ev * 100) / 100,
    rtp: Math.round((ev / c.price) * 10000) / 10000,
    houseEdge: Math.round((1 - ev / c.price) * 10000) / 10000
  };
}

// Rescale weights so the crate hits an exact target RTP.
// Splits items into a "win pool" (value above the per-draw break-even target)
// and a "loss pool", then solves the probability mass between them.
function tuneCase(caseId, targetRtp) {
  const c = db.prepare('SELECT * FROM cases WHERE id=?').get(caseId);
  if (!c) throw new Error('case not found');
  targetRtp = Math.min(0.99, Math.max(0.05, Number(targetRtp)));
  const T = (targetRtp * c.price) / c.draws; // per-draw EV target
  const items = db.prepare('SELECT * FROM items WHERE case_id=?').all(caseId);
  const W = items.filter(i => i.value > T);
  const L = items.filter(i => i.value <= T);
  if (!W.length || !L.length) throw new Error('need items both above and below the target value to tune');
  const wSum = W.reduce((s, i) => s + i.weight, 0);
  const lSum = L.reduce((s, i) => s + i.weight, 0);
  const Ew = W.reduce((s, i) => s + (i.weight / wSum) * i.value, 0);
  const El = L.reduce((s, i) => s + (i.weight / lSum) * i.value, 0);
  let a = (T - El) / (Ew - El);          // required probability mass on win pool
  a = Math.min(0.999, Math.max(0.0001, a));
  const upd = db.prepare('UPDATE items SET weight=? WHERE id=?');
  const tx = db.transaction(() => {
    for (const i of W) upd.run((i.weight / wSum) * a * 100000, i.id);
    for (const i of L) upd.run((i.weight / lSum) * (1 - a) * 100000, i.id);
  });
  tx();
  return caseStats(caseId);
}

// ---------- seed data ----------
function seedIfEmpty() {
  const n = db.prepare('SELECT COUNT(*) c FROM cases').get().c;
  if (n > 0) return;

  const insCase = db.prepare(`INSERT INTO cases(slug,name,emoji,price,draws,open_style,color,description,sort)
    VALUES (@slug,@name,@emoji,@price,@draws,@open_style,@color,@description,@sort)`);
  const insItem = db.prepare(`INSERT INTO items(case_id,name,emoji,value,weight,rarity)
    VALUES (?,?,?,?,?,?)`);

  const mk = (c, items, targetRtp) => {
    const info = insCase.run(c);
    const id = info.lastInsertRowid;
    for (const [name, emoji, value, weight, rarity] of items) insItem.run(id, name, emoji, value, weight, rarity);
    tuneCase(id, targetRtp);
  };

  mk({ slug: 'starter-pop', name: 'Starter Pop', emoji: '🎁', price: 150, draws: 1, open_style: 'spinner',
       color: '#35E0FF', description: 'The warm-up crate. Candy-tier tech and small treats.', sort: 1 }, [
    ['Sticker Sheet', '🌈', 15, 40, 'common'],
    ['Phone Grip', '📎', 30, 30, 'common'],
    ['LED String Lights', '💡', 60, 20, 'uncommon'],
    ['Enamel Pin Set', '📌', 90, 14, 'uncommon'],
    ['Portable Charger', '🔋', 180, 9, 'rare'],
    ['Bluetooth Speaker Mini', '🔊', 350, 5, 'rare'],
    ['Wireless Earbuds', '🎧', 700, 2, 'epic'],
    ['Retro Handheld Console', '🕹️', 1500, 0.8, 'legendary'],
    ['Smartwatch', '⌚', 3000, 0.2, 'mythic'],
  ], 0.92);

  mk({ slug: 'tech-vault', name: 'Tech Vault', emoji: '💾', price: 900, draws: 1, open_style: 'spinner',
       color: '#7CFF6B', description: 'Flagship electronics behind a very shiny door.', sort: 2 }, [
    ['USB-C Cable Pack', '🔌', 60, 34, 'common'],
    ['Mechanical Keyboard', '⌨️', 250, 24, 'common'],
    ['Gaming Mouse Pro', '🖱️', 400, 16, 'uncommon'],
    ['Smart Speaker', '🔊', 650, 11, 'uncommon'],
    ['Noise-Cancel Headphones', '🎧', 1500, 7, 'rare'],
    ['4K Camera Drone', '🛸', 4000, 3.5, 'epic'],
    ['Gaming Console (Current Gen)', '🎮', 5000, 2.4, 'epic'],
    ['Flagship Smartphone 256GB', '📱', 11000, 1.1, 'legendary'],
    ['RTX-Class Graphics Card', '🖥️', 18000, 0.5, 'legendary'],
    ['Ultralight Pro Laptop', '💻', 25000, 0.2, 'mythic'],
  ], 0.90);

  mk({ slug: 'collectors-chest', name: "Collector's Chest", emoji: '🧰', price: 1500, draws: 1, open_style: 'chest',
       color: '#FFB13F', description: 'Graded cards, comics and shiny grails. Lid pops, jaw drops.', sort: 3 }, [
    ['Common Card Bundle', '🃏', 120, 34, 'common'],
    ['Vintage Comic (Reader Grade)', '📖', 300, 22, 'common'],
    ['Vinyl Figure (Boxed)', '🧸', 550, 16, 'uncommon'],
    ['Silver Collector Coin', '🪙', 900, 12, 'uncommon'],
    ['Graded Holo Card (9)', '✨', 2200, 8, 'rare'],
    ['Signed Art Print', '🖼️', 4500, 4, 'epic'],
    ['Graded Holo Card (PSA 10)', '💎', 9000, 2.4, 'legendary'],
    ['Key-Issue Comic (Slabbed)', '📚', 16000, 1, 'legendary'],
    ['1st Edition Booster Box (Sealed)', '🏆', 40000, 0.25, 'mythic'],
  ], 0.89);

  mk({ slug: 'creature-pack', name: 'Creature Pack', emoji: '🐲', price: 600, draws: 3, open_style: 'pack',
       color: '#B45CFF', description: 'Rip the foil. Three creatures per pack — chase the Solar Phoenix.', sort: 4 }, [
    ['Mossling', '🌱', 20, 34, 'common'],
    ['Bubbletox', '🫧', 35, 26, 'common'],
    ['Emberling', '🔥', 70, 18, 'uncommon'],
    ['Glacierpuff', '❄️', 120, 11, 'uncommon'],
    ['Voltifang', '⚡', 300, 6.5, 'rare'],
    ['Shadowmaw', '🌑', 700, 3, 'epic'],
    ['Prism Drake', '🌈', 1800, 1.2, 'legendary'],
    ['Solar Phoenix', '☀️', 6000, 0.3, 'mythic'],
  ], 0.90);

  mk({ slug: 'court-and-field', name: 'Court & Field', emoji: '🏆', price: 1200, draws: 1, open_style: 'spinner',
       color: '#FF6B4F', description: 'Sports grails: sneakers, jerseys and signed heat.', sort: 5 }, [
    ['Team Wristband Set', '🎽', 90, 34, 'common'],
    ['Rookie Card Pack', '🃏', 260, 24, 'common'],
    ['Replica Team Cap', '🧢', 450, 16, 'uncommon'],
    ['Limited Sneakers (DS)', '👟', 1600, 11, 'rare'],
    ['Authentic Team Jersey', '👕', 2600, 7, 'rare'],
    ['Signed Ball (COA)', '🏀', 6000, 4, 'epic'],
    ['Signed Jersey (Framed, COA)', '🖼️', 12000, 2, 'legendary'],
    ['Graded Rookie Card (Gem Mint)', '💎', 30000, 0.5, 'mythic'],
  ], 0.90);

  mk({ slug: 'mythic-reactor', name: 'Mythic Reactor', emoji: '☢️', price: 5000, draws: 1, open_style: 'chest',
       color: '#FF4FA3', description: 'High-roller chamber. Volatile odds, colossal ceiling.', sort: 6 }, [
    ['Reactor Scrap', '🔩', 400, 42, 'common'],
    ['Plasma Cell', '🧪', 1200, 24, 'uncommon'],
    ['Gold Bar (1oz)', '🪙', 3500, 14, 'rare'],
    ['Luxury Mechanical Watch', '⌚', 9000, 9, 'epic'],
    ['Ultralight Pro Laptop', '💻', 25000, 5, 'legendary'],
    ['Full Battlestation Build', '🖥️', 60000, 2, 'legendary'],
    ['Grail Watch (Swiss, Boxed)', '🏆', 150000, 0.5, 'mythic'],
  ], 0.85);

  mk({ slug: 'lucky-wheel', name: 'Lucky Wheel', emoji: '🎡', price: 300, draws: 1, open_style: 'wheel',
       color: '#FFD23F', description: 'Ten wedges. One spin. Physics with confetti.', sort: 7 }, [
    ['5 Tokens', '🪙', 5, 20, 'common'],
    ['50 Tokens', '🪙', 50, 20, 'common'],
    ['120 Tokens', '💰', 120, 18, 'uncommon'],
    ['200 Tokens', '💰', 200, 14, 'uncommon'],
    ['300 Tokens', '💰', 300, 10, 'rare'],
    ['500 Tokens', '🤑', 500, 8, 'rare'],
    ['Wireless Earbuds', '🎧', 700, 5, 'epic'],
    ['1,500 Tokens', '💎', 1500, 3, 'epic'],
    ['Retro Handheld Console', '🕹️', 2500, 1.5, 'legendary'],
    ['10,000 Token Jackpot', '🎰', 10000, 0.5, 'mythic'],
  ], 0.90);

  // demo raffles
  const insR = db.prepare(`INSERT INTO raffles(name,emoji,prize_value,ticket_price,max_tickets,ends_at)
    VALUES (?,?,?,?,?,datetime('now', ?))`);
  insR.run('Flagship Smartphone Giveaway', '📱', 11000, 100, 500, '+2 days');
  insR.run('Graded Holo Grail Raffle', '💎', 9000, 75, 400, '+1 day');
  insR.run('RTX Battlestation Mega Raffle', '🖥️', 60000, 250, 1000, '+5 days');

  db.prepare('INSERT INTO audit_log(actor,action,meta) VALUES (?,?,?)')
    .run('system', 'seed', 'initial cases, items, raffles created and RTP-tuned');
}
seedIfEmpty();

// ---------- CMS / membership / category seeds (each self-checks, safe on old DBs) ----------
function seedCms() {
  if (!db.prepare('SELECT COUNT(*) c FROM categories').get().c) {
    const ins = db.prepare('INSERT INTO categories(slug,name,emoji,blurb,sort) VALUES (?,?,?,?,?)');
    ins.run('tech',    'Tech & Electronics', '📱', 'Flagship phones, GPUs, drones and daily-driver gear.', 1);
    ins.run('cards',   'Cards & TCG',        '🃏', 'Graded holos, sealed boosters and chase pulls.', 2);
    ins.run('retro',   'Retro & Vintage',    '👾', 'Old-school consoles, sealed classics and nostalgia grails.', 3);
    ins.run('sports',  'Sports Grails',      '🏆', 'Signed heat, gem-mint rookies and deadstock kicks.', 4);
    ins.run('luxury',  'Watches & Luxury',   '⌚', 'Swiss steel, gold bars and grail-tier horology.', 5);
    ins.run('jackpot', 'Wheels & Jackpots',  '🎡', 'Pure token action. Spin it and grin.', 6);
  }
  const cat = s => db.prepare('SELECT id FROM categories WHERE slug=?').get(s)?.id;
  const assign = db.prepare('UPDATE cases SET category_id=? WHERE slug=? AND category_id IS NULL');
  assign.run(cat('tech'), 'starter-pop');       assign.run(cat('tech'), 'tech-vault');
  assign.run(cat('cards'), 'collectors-chest'); assign.run(cat('cards'), 'creature-pack');
  assign.run(cat('sports'), 'court-and-field'); assign.run(cat('luxury'), 'mythic-reactor');
  assign.run(cat('jackpot'), 'lucky-wheel');
  db.prepare("UPDATE cases SET featured=1 WHERE slug IN ('tech-vault','mythic-reactor')").run();

  // three new crates so every audience walks in the door
  const insCase = db.prepare(`INSERT INTO cases(slug,name,emoji,price,draws,open_style,color,description,sort,category_id,featured)
    VALUES (@slug,@name,@emoji,@price,@draws,@open_style,@color,@description,@sort,@category_id,@featured)`);
  const insItem = db.prepare('INSERT INTO items(case_id,name,emoji,value,weight,rarity) VALUES (?,?,?,?,?,?)');
  const mk = (c, items, rtp) => {
    if (db.prepare('SELECT id FROM cases WHERE slug=?').get(c.slug)) return;
    const id = insCase.run(c).lastInsertRowid;
    for (const [name, emoji, value, weight, rarity] of items) insItem.run(id, name, emoji, value, weight, rarity);
    tuneCase(id, rtp);
  };

  mk({ slug: 'holo-hunt', name: 'Holo Hunt', emoji: '🃏', price: 800, draws: 1, open_style: 'spinner',
       color: '#35A7FF', description: 'TCG singles ladder — climb from bulk to a slabbed alt-art chase.', sort: 8,
       category_id: cat('cards'), featured: 1 }, [
    ['Bulk Commons Stack', '🂠', 40, 36, 'common'],
    ['Reverse Holo Set', '🌀', 140, 24, 'common'],
    ['Full-Art Trainer', '🖌️', 350, 16, 'uncommon'],
    ['Vintage Holo (Played)', '🕰️', 700, 10, 'rare'],
    ['Modern Alt-Art Chase', '🎨', 1800, 7, 'rare'],
    ['Graded Vintage Holo (8.5)', '🔷', 4200, 4, 'epic'],
    ['Sealed Vintage Booster Pack', '📦', 9500, 2.2, 'legendary'],
    ['Slabbed Alt-Art (Gem 10)', '💎', 22000, 0.8, 'mythic'],
  ], 0.90);

  mk({ slug: 'retro-rewind', name: 'Retro Rewind', emoji: '👾', price: 700, draws: 1, open_style: 'chest',
       color: '#7CFF6B', description: 'Blow on the cartridge. Vintage toys, sealed classics, CIB grails.', sort: 9,
       category_id: cat('retro'), featured: 0 }, [
    ['Mystery Retro Sticker Pack', '🌟', 35, 34, 'common'],
    ['Loose Cartridge (Classic)', '🕹️', 150, 25, 'common'],
    ['80s Action Figure (Carded)', '🤖', 380, 16, 'uncommon'],
    ['Vintage Handheld (Working)', '📟', 800, 11, 'uncommon'],
    ['Boxed Console (CIB)', '📺', 2000, 7.5, 'rare'],
    ['Sealed VHS Classic (Graded)', '📼', 5000, 4, 'epic'],
    ['Holy-Grail Cartridge (CIB)', '🏰', 12000, 1.8, 'legendary'],
    ['Sealed Launch Console (VGA)', '🏆', 35000, 0.5, 'mythic'],
  ], 0.90);

  mk({ slug: 'horology-vault', name: 'Horology Vault', emoji: '⌚', price: 3000, draws: 1, open_style: 'chest',
       color: '#FFD23F', description: 'For the wrist game. Micro-brands to Swiss grails, boxed and papered.', sort: 10,
       category_id: cat('luxury'), featured: 1 }, [
    ['Leather Strap Set', '🟤', 220, 34, 'common'],
    ['Watch Roll (3-slot)', '🧵', 500, 24, 'common'],
    ['Micro-Brand Diver', '🌊', 1400, 16, 'uncommon'],
    ['Automatic Field Watch', '🧭', 2600, 11, 'rare'],
    ['Swiss Chronograph', '⏱️', 6500, 7.5, 'epic'],
    ['Luxury Diver (Boxed)', '🐋', 15000, 4, 'legendary'],
    ['Vintage Grail (Papered)', '📜', 40000, 1.6, 'legendary'],
    ['Icon Sports Watch (Full Set)', '👑', 120000, 0.4, 'mythic'],
  ], 0.88);

  if (!db.prepare('SELECT COUNT(*) c FROM membership_tiers').get().c) {
    const t = db.prepare(`INSERT INTO membership_tiers(slug,name,emoji,price_usd,rakeback_bps,daily_bonus,xp_boost_bps,color,perks,sort)
      VALUES (?,?,?,?,?,?,?,?,?,?)`);
    t.run('free', 'Free',      '🎈', 0,     0,   0,    0,    '#9AA3B2', JSON.stringify(['Provably-fair openings', 'Live raffles', 'Crate battles']), 1);
    t.run('plus', 'Plus Club', '🚀', 9.99,  300, 150,  2500, '#35E0FF', JSON.stringify(['3% token rakeback on every open', '150 free tokens daily', '+25% XP', 'Plus badge']), 2);
    t.run('vip',  'VIP Whale', '🐳', 24.99, 700, 500, 10000, '#FFD23F', JSON.stringify(['7% token rakeback on every open', '500 free tokens daily', 'Double XP', 'VIP badge + priority raffle entries']), 3);
  }

  if (!db.prepare('SELECT COUNT(*) c FROM pages').get().c) {
    const p = db.prepare('INSERT INTO pages(slug,title,body) VALUES (?,?,?)');
    p.run('how-it-works', 'How POPCRATE works', `## Tokens in, prizes out
Buy tokens, open crates, and every pull lands in your inventory. Sell items back for tokens instantly or keep them.

## Four ways to open
- **Reels** — the classic case spinner
- **Chests** — rumble, pop, beam of glory
- **Packs** — rip the foil, flip three cards
- **Wheel** — ten wedges of pure chaos

## Battles
Pick a crate, set the rounds, and go head-to-head. **Winner takes every item from both sides.**`);
    p.run('fairness', 'Provably fair, explained', `## You can check our math
Before you ever open a crate we commit to a secret server seed by publishing its **SHA-256 hash**. Your rolls combine that seed, **your own client seed** (which you can change any time), and an increasing nonce.

## Verify anything
Rotate your seed in the Fairness panel and we reveal the old one. Recompute any past roll with the public verifier — if the hash matches the commitment, the roll was locked in before you clicked.

- Roll = HMAC-SHA256(serverSeed, clientSeed:nonce:crate:draw)
- Every crate publishes its exact item probabilities
- Admin odds changes are audit-logged`);
    p.run('faq', 'FAQ', `## Are the odds real?
Yes — the odds shown on every crate are the same weights the server rolls against, and the fairness system lets you verify past rolls yourself.

## How do memberships work?
Plus and VIP are monthly plans that pay you back: rakeback tokens on every open, daily bonus tokens, and faster XP.

## Can I get real items shipped?
Inventory items marked shippable can be redeemed at checkout (production feature). Everything can always be instantly sold back for tokens.

## What's the minimum age?
You must be **18 or older** to use POPCRATE.`);
    p.run('terms', 'Terms of Service', `## The short version
- 18+ only. One account per person.
- Tokens are a virtual currency for use on POPCRATE and have no cash value.
- Abuse, automation, or exploit attempts result in account closure.
- Prize availability may vary; equivalent-value substitutions can apply.
- This is a demonstration build — consult local regulations before operating a paid prize platform.`);
  }
}
seedCms();

module.exports = { db, getSetting, setSetting, caseStats, tuneCase, levelFromXp };
