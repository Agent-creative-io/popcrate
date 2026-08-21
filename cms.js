// POPCRATE — custom CMS
// Everything an admin can publish or edit lives here: crates, items,
// categories, site copy, content pages, membership tiers and media uploads.
// Mounted behind adminAuth (admin key + optional TOTP). Every write is audited.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db, getSetting, setSetting, caseStats, tuneCase } = require('./db');

const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const slugify = s => String(s || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
const clampInt = (v, lo, hi, dflt) => { const n = parseInt(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt; };

module.exports = function mountCms(app, adminAuth, audit) {

  /* ============ CATEGORIES ============ */
  app.get('/api/admin/categories', adminAuth, (req, res) => {
    res.json({ categories: db.prepare('SELECT * FROM categories ORDER BY sort').all() });
  });
  app.post('/api/admin/categories', adminAuth, (req, res) => {
    const { name, emoji, blurb, sort } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const slug = slugify(name);
    if (db.prepare('SELECT id FROM categories WHERE slug=?').get(slug)) return res.status(400).json({ error: 'category exists' });
    const info = db.prepare('INSERT INTO categories(slug,name,emoji,blurb,sort) VALUES (?,?,?,?,?)')
      .run(slug, String(name).slice(0, 40), String(emoji || '📦').slice(0, 8), String(blurb || '').slice(0, 160), clampInt(sort, 0, 999, 99));
    audit('admin', 'cms_category_create', { id: info.lastInsertRowid, slug });
    res.json({ id: info.lastInsertRowid, slug });
  });
  app.post('/api/admin/categories/:id', adminAuth, (req, res) => {
    const c = db.prepare('SELECT * FROM categories WHERE id=?').get(req.params.id);
    if (!c) return res.status(404).json({ error: 'not found' });
    const { name, emoji, blurb, sort, active } = req.body || {};
    db.prepare('UPDATE categories SET name=?, emoji=?, blurb=?, sort=?, active=? WHERE id=?')
      .run(String(name ?? c.name).slice(0, 40), String(emoji ?? c.emoji).slice(0, 8),
           String(blurb ?? c.blurb).slice(0, 160), clampInt(sort, 0, 999, c.sort),
           active === undefined ? c.active : (active ? 1 : 0), c.id);
    audit('admin', 'cms_category_edit', { id: c.id });
    res.json({ ok: true });
  });

  /* ============ CRATES (create / edit / delete) ============ */
  app.post('/api/admin/cases/create', adminAuth, (req, res) => {
    const { name, emoji, price, draws, open_style, color, description, category_id, featured } = req.body || {};
    if (!name || !price) return res.status(400).json({ error: 'name and price required' });
    if (!['spinner', 'chest', 'pack', 'wheel'].includes(open_style)) return res.status(400).json({ error: 'open_style must be spinner|chest|pack|wheel' });
    const slug = slugify(name);
    if (db.prepare('SELECT id FROM cases WHERE slug=?').get(slug)) return res.status(400).json({ error: 'a crate with that name exists' });
    const info = db.prepare(`INSERT INTO cases(slug,name,emoji,price,draws,open_style,color,description,sort,category_id,featured,active)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,0)`)  // starts INACTIVE until items are added + it's published
      .run(slug, String(name).slice(0, 48), String(emoji || '🎁').slice(0, 8), clampInt(price, 10, 10_000_000, 500),
           clampInt(draws, 1, 5, 1), open_style, String(color || '#FF4FA3').slice(0, 16), String(description || '').slice(0, 200),
           clampInt(req.body?.sort, 0, 999, 99), category_id || null, featured ? 1 : 0);
    audit('admin', 'cms_case_create', { id: info.lastInsertRowid, slug });
    res.json({ id: info.lastInsertRowid, slug });
  });
  app.post('/api/admin/cases/:id/edit', adminAuth, (req, res) => {
    const c = db.prepare('SELECT * FROM cases WHERE id=?').get(req.params.id);
    if (!c) return res.status(404).json({ error: 'not found' });
    const b = req.body || {};
    if (b.open_style && !['spinner', 'chest', 'pack', 'wheel'].includes(b.open_style)) return res.status(400).json({ error: 'bad open_style' });
    db.prepare(`UPDATE cases SET name=?, emoji=?, price=?, draws=?, open_style=?, color=?, description=?, sort=?, category_id=?, featured=?, active=? WHERE id=?`)
      .run(String(b.name ?? c.name).slice(0, 48), String(b.emoji ?? c.emoji).slice(0, 8),
           clampInt(b.price, 10, 10_000_000, c.price), clampInt(b.draws, 1, 5, c.draws),
           b.open_style ?? c.open_style, String(b.color ?? c.color).slice(0, 16),
           String(b.description ?? c.description).slice(0, 200), clampInt(b.sort, 0, 999, c.sort),
           b.category_id === undefined ? c.category_id : (b.category_id || null),
           b.featured === undefined ? c.featured : (b.featured ? 1 : 0),
           b.active === undefined ? c.active : (b.active ? 1 : 0), c.id);
    audit('admin', 'cms_case_edit', { id: c.id });
    res.json(caseStats(c.id));
  });
  app.post('/api/admin/cases/:id/delete', adminAuth, (req, res) => {
    const c = db.prepare('SELECT * FROM cases WHERE id=?').get(req.params.id);
    if (!c) return res.status(404).json({ error: 'not found' });
    const opened = db.prepare('SELECT COUNT(*) c FROM opens WHERE case_id=?').get(c.id).c;
    if (opened) {   // keep history intact — retire instead of hard delete
      db.prepare('UPDATE cases SET active=0 WHERE id=?').run(c.id);
      audit('admin', 'cms_case_retire', { id: c.id });
      return res.json({ retired: true, note: 'Crate has open history — retired (hidden) instead of deleted.' });
    }
    db.prepare('DELETE FROM items WHERE case_id=?').run(c.id);
    db.prepare('DELETE FROM cases WHERE id=?').run(c.id);
    audit('admin', 'cms_case_delete', { id: c.id });
    res.json({ deleted: true });
  });

  /* ============ ITEMS (add / delete; edit lives in server.js) ============ */
  app.post('/api/admin/cases/:id/items', adminAuth, (req, res) => {
    const c = db.prepare('SELECT * FROM cases WHERE id=?').get(req.params.id);
    if (!c) return res.status(404).json({ error: 'crate not found' });
    const { name, emoji, value, weight, rarity, image } = req.body || {};
    if (!name || !value) return res.status(400).json({ error: 'name and value required' });
    if (!['common', 'uncommon', 'rare', 'epic', 'legendary', 'mythic'].includes(rarity)) return res.status(400).json({ error: 'bad rarity' });
    const info = db.prepare('INSERT INTO items(case_id,name,emoji,image,value,weight,rarity) VALUES (?,?,?,?,?,?,?)')
      .run(c.id, String(name).slice(0, 64), String(emoji || '🎁').slice(0, 8), image || null,
           clampInt(value, 1, 100_000_000, 100), Math.max(0.0001, Number(weight) || 1), rarity);
    audit('admin', 'cms_item_add', { case: c.id, item: info.lastInsertRowid });
    res.json({ id: info.lastInsertRowid, stats: caseStats(c.id) });
  });
  app.post('/api/admin/items/:id/delete', adminAuth, (req, res) => {
    const item = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
    if (!item) return res.status(404).json({ error: 'not found' });
    const used = db.prepare('SELECT COUNT(*) c FROM opens WHERE item_id=?').get(item.id).c;
    if (used) return res.status(400).json({ error: 'Item has pull history — set its weight to ~0 instead of deleting.' });
    db.prepare('DELETE FROM items WHERE id=?').run(item.id);
    audit('admin', 'cms_item_delete', { item: item.id });
    res.json({ stats: caseStats(item.case_id) });
  });

  /* ============ MEDIA LIBRARY (base64 upload → /uploads) ============ */
  const MIME = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif' };
  app.post('/api/admin/media', adminAuth, (req, res) => {
    const { data, mime } = req.body || {};
    const ext = MIME[mime];
    if (!ext) return res.status(400).json({ error: 'mime must be png/jpeg/webp/gif' });
    let buf;
    try { buf = Buffer.from(String(data || ''), 'base64'); } catch { return res.status(400).json({ error: 'bad base64' }); }
    if (!buf.length || buf.length > 3 * 1024 * 1024) return res.status(400).json({ error: 'file must be 1B–3MB' });
    // magic-byte sniff so a renamed .html can't sneak in
    const magicOk =
      (ext === 'png'  && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) ||
      (ext === 'jpg'  && buf[0] === 0xFF && buf[1] === 0xD8) ||
      (ext === 'webp' && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') ||
      (ext === 'gif'  && ['GIF87a', 'GIF89a'].includes(buf.slice(0, 6).toString()));
    if (!magicOk) return res.status(400).json({ error: 'file content does not match its type' });
    const fname = crypto.randomBytes(10).toString('hex') + '.' + ext;
    fs.writeFileSync(path.join(UPLOAD_DIR, fname), buf);
    audit('admin', 'cms_media_upload', { file: fname, bytes: buf.length });
    res.json({ url: '/uploads/' + fname });
  });
  app.get('/api/admin/media', adminAuth, (req, res) => {
    const files = fs.readdirSync(UPLOAD_DIR).map(f => ({ url: '/uploads/' + f, bytes: fs.statSync(path.join(UPLOAD_DIR, f)).size }));
    res.json({ files });
  });

  /* ============ PAGES ============ */
  app.get('/api/admin/pages', adminAuth, (req, res) => {
    res.json({ pages: db.prepare('SELECT * FROM pages ORDER BY slug').all() });
  });
  app.post('/api/admin/pages/:slug', adminAuth, (req, res) => {
    const slug = slugify(req.params.slug);
    const { title, body, published } = req.body || {};
    db.prepare(`INSERT INTO pages(slug,title,body,published,updated_at) VALUES (?,?,?,?,datetime('now'))
      ON CONFLICT(slug) DO UPDATE SET title=excluded.title, body=excluded.body, published=excluded.published, updated_at=datetime('now')`)
      .run(slug, String(title || slug).slice(0, 80), String(body || '').slice(0, 20000), published === false ? 0 : 1);
    audit('admin', 'cms_page_save', { slug });
    res.json({ ok: true, slug });
  });
  app.post('/api/admin/pages/:slug/delete', adminAuth, (req, res) => {
    db.prepare('DELETE FROM pages WHERE slug=?').run(slugify(req.params.slug));
    audit('admin', 'cms_page_delete', { slug: req.params.slug });
    res.json({ ok: true });
  });

  /* ============ SITE SETTINGS (hero copy, announcement) ============ */
  app.get('/api/admin/site', adminAuth, (req, res) => {
    res.json({
      hero_title: getSetting('hero_title'), hero_sub: getSetting('hero_sub'),
      announcement: getSetting('announcement'),
    });
  });
  app.post('/api/admin/site', adminAuth, (req, res) => {
    const { hero_title, hero_sub, announcement } = req.body || {};
    if (hero_title !== undefined) setSetting('hero_title', String(hero_title).slice(0, 120));
    if (hero_sub !== undefined) setSetting('hero_sub', String(hero_sub).slice(0, 220));
    if (announcement !== undefined) setSetting('announcement', String(announcement).slice(0, 200));
    audit('admin', 'cms_site_edit', {});
    res.json({ ok: true });
  });

  /* ============ MEMBERSHIP TIERS ============ */
  app.get('/api/admin/tiers', adminAuth, (req, res) => {
    res.json({ tiers: db.prepare('SELECT * FROM membership_tiers ORDER BY sort').all() });
  });
  app.post('/api/admin/tiers/:id', adminAuth, (req, res) => {
    const t = db.prepare('SELECT * FROM membership_tiers WHERE id=?').get(req.params.id);
    if (!t) return res.status(404).json({ error: 'not found' });
    const b = req.body || {};
    db.prepare('UPDATE membership_tiers SET name=?, price_usd=?, rakeback_bps=?, daily_bonus=?, xp_boost_bps=?, perks=? WHERE id=?')
      .run(String(b.name ?? t.name).slice(0, 40), Number(b.price_usd ?? t.price_usd),
           clampInt(b.rakeback_bps, 0, 5000, t.rakeback_bps), clampInt(b.daily_bonus, 0, 100000, t.daily_bonus),
           clampInt(b.xp_boost_bps, 0, 50000, t.xp_boost_bps),
           b.perks ? JSON.stringify(b.perks).slice(0, 2000) : t.perks, t.id);
    audit('admin', 'cms_tier_edit', { tier: t.id });
    res.json({ ok: true });
  });
};
