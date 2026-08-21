// POPCRATE — Crate Battles
// Head-to-head crate opening. Both players pay the crate price × rounds.
// Every round uses each player's OWN provably-fair seed chain (server seed
// commitment + their client seed + their nonce), so battle rolls are just as
// verifiable as solo opens. Winner takes every item from both sides.
'use strict';
const crypto = require('crypto');
const { db, levelFromXp } = require('./db');

module.exports = function mountBattles(app, deps) {
  const { auth, rateLimit, audit, activeSeed, rollFor, pickItem, awardXp } = deps;

  const publicBattle = b => {
    const c = db.prepare('SELECT id,slug,name,emoji,price,color,open_style FROM cases WHERE id=?').get(b.case_id);
    const uname = id => id ? db.prepare('SELECT username FROM users WHERE id=?').get(id)?.username : null;
    return {
      id: b.id, status: b.status, rounds: b.rounds, created_at: b.created_at,
      case: c, cost: c.price * b.rounds,
      creator: { id: b.creator_id, username: uname(b.creator_id) },
      opponent: b.opponent_id ? { id: b.opponent_id, username: uname(b.opponent_id) } : null,
      creator_total: b.creator_total, opponent_total: b.opponent_total,
      winner_id: b.winner_id, tiebreak: b.tiebreak ? JSON.parse(b.tiebreak) : null,
    };
  };

  /* ---------- lobby ---------- */
  app.get('/api/battles', (req, res) => {
    const open = db.prepare("SELECT * FROM battles WHERE status='open' ORDER BY id DESC LIMIT 30").all();
    const done = db.prepare("SELECT * FROM battles WHERE status='done' ORDER BY id DESC LIMIT 8").all();
    res.json({ battles: [...open, ...done].map(publicBattle) });
  });

  app.get('/api/battles/:id', (req, res) => {
    const b = db.prepare('SELECT * FROM battles WHERE id=?').get(req.params.id);
    if (!b) return res.status(404).json({ error: 'battle not found' });
    const out = publicBattle(b);
    if (b.status === 'done') {
      out.rounds_detail = db.prepare(`
        SELECT br.round, br.user_id, br.value, br.roll, br.nonce, i.name, i.emoji, i.rarity, i.image
        FROM battle_rounds br JOIN items i ON i.id = br.item_id
        WHERE br.battle_id=? ORDER BY br.round, br.user_id`).all(b.id);
    }
    res.json(out);
  });

  /* ---------- create ---------- */
  app.post('/api/battles', auth, rateLimit(20, 60000), (req, res) => {
    const rounds = Math.max(1, Math.min(5, parseInt(req.body?.rounds || 1)));
    const c = db.prepare('SELECT * FROM cases WHERE id=? AND active=1').get(req.body?.case_id);
    if (!c) return res.status(404).json({ error: 'Crate not found.' });
    if (c.draws !== 1) return res.status(400).json({ error: 'Multi-draw packs cannot battle (yet).' });
    const cost = c.price * rounds;
    const openCount = db.prepare("SELECT COUNT(*) c FROM battles WHERE creator_id=? AND status='open'").get(req.user.id).c;
    if (openCount >= 3) return res.status(400).json({ error: 'You already have 3 open battles.' });
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (user.balance < cost) return res.status(400).json({ error: 'Not enough tokens for the buy-in.' });
    let id;
    const tx = db.transaction(() => {
      db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(cost, user.id);
      db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
        .run(user.id, 'battle_stake', -cost, JSON.stringify({ case: c.slug, rounds }));
      id = db.prepare('INSERT INTO battles(case_id,rounds,creator_id) VALUES (?,?,?)').run(c.id, rounds, user.id).lastInsertRowid;
    });
    tx();
    audit(user.username, 'battle_create', { battle: id, case: c.slug, rounds });
    const u = db.prepare('SELECT balance FROM users WHERE id=?').get(user.id);
    res.json({ id, balance: u.balance });
  });

  /* ---------- cancel (creator only, while open) ---------- */
  app.post('/api/battles/:id/cancel', auth, (req, res) => {
    const b = db.prepare("SELECT * FROM battles WHERE id=? AND status='open' AND creator_id=?").get(req.params.id, req.user.id);
    if (!b) return res.status(404).json({ error: 'Battle not found or not yours.' });
    const c = db.prepare('SELECT * FROM cases WHERE id=?').get(b.case_id);
    const refund = c.price * b.rounds;
    const tx = db.transaction(() => {
      db.prepare("UPDATE battles SET status='cancelled' WHERE id=?").run(b.id);
      db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(refund, req.user.id);
      db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
        .run(req.user.id, 'battle_refund', refund, JSON.stringify({ battle: b.id }));
    });
    tx();
    res.json({ ok: true, refunded: refund });
  });

  /* ---------- join → instant server-side resolution ---------- */
  app.post('/api/battles/:id/join', auth, rateLimit(20, 60000), (req, res) => {
    const b = db.prepare("SELECT * FROM battles WHERE id=? AND status='open'").get(req.params.id);
    if (!b) return res.status(404).json({ error: 'Battle already taken or gone.' });
    if (b.creator_id === req.user.id) return res.status(400).json({ error: "You can't battle yourself." });
    const c = db.prepare('SELECT * FROM cases WHERE id=?').get(b.case_id);
    const cost = c.price * b.rounds;
    const joiner = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (joiner.balance < cost) return res.status(400).json({ error: 'Not enough tokens for the buy-in.' });

    const creator = db.prepare('SELECT * FROM users WHERE id=?').get(b.creator_id);
    const items = db.prepare('SELECT * FROM items WHERE case_id=?').all(c.id);
    const seeds = { [creator.id]: activeSeed(creator.id), [joiner.id]: activeSeed(joiner.id) };
    let totals = { [creator.id]: 0, [joiner.id]: 0 };
    let winner, tiebreak = null;

    const tx = db.transaction(() => {
      // joiner pays in (creator already staked at creation)
      db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(cost, joiner.id);
      db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
        .run(joiner.id, 'battle_stake', -cost, JSON.stringify({ battle: b.id }));
      db.prepare('UPDATE battles SET opponent_id=? WHERE id=?').run(joiner.id, b.id);

      const insRound = db.prepare('INSERT INTO battle_rounds(battle_id,round,user_id,item_id,roll,nonce,value) VALUES (?,?,?,?,?,?,?)');
      const bumpNonce = db.prepare('UPDATE users SET nonce=nonce+1 WHERE id=?');
      const getNonce = db.prepare('SELECT nonce, client_seed FROM users WHERE id=?');

      for (let r = 0; r < b.rounds; r++) {
        for (const player of [creator, joiner]) {
          bumpNonce.run(player.id);
          const row = getNonce.get(player.id);
          const roll = rollFor({ client_seed: row.client_seed }, seeds[player.id], row.nonce, `battle:${b.id}:${c.slug}:${r}`);
          const item = pickItem(items, roll);
          insRound.run(b.id, r, player.id, item.id, roll, row.nonce, item.value);
          totals[player.id] += item.value;
        }
      }

      if (totals[creator.id] === totals[joiner.id]) {
        // provably-logged coin flip
        const seed = crypto.randomBytes(16).toString('hex');
        const flip = parseInt(crypto.createHmac('sha256', seed).update('tiebreak:' + b.id).digest('hex').slice(0, 8), 16) % 2;
        winner = flip === 0 ? creator : joiner;
        tiebreak = { seed, flip };
      } else {
        winner = totals[creator.id] > totals[joiner.id] ? creator : joiner;
      }

      // winner takes ALL items from both sides
      const rows = db.prepare('SELECT br.*, i.name, i.emoji, i.rarity FROM battle_rounds br JOIN items i ON i.id=br.item_id WHERE br.battle_id=?').all(b.id);
      const insInv = db.prepare('INSERT INTO inventory(user_id,item_name,item_emoji,rarity,value) VALUES (?,?,?,?,?)');
      for (const row of rows) insInv.run(winner.id, row.name, row.emoji, row.rarity, row.value);
      db.prepare('INSERT INTO transactions(user_id,type,amount,meta) VALUES (?,?,?,?)')
        .run(winner.id, 'battle_win', 0, JSON.stringify({ battle: b.id, pot_value: totals[creator.id] + totals[joiner.id] }));

      db.prepare(`UPDATE battles SET status='done', creator_total=?, opponent_total=?, winner_id=?, tiebreak=?, resolved_at=datetime('now') WHERE id=?`)
        .run(totals[creator.id], totals[joiner.id], winner.id, tiebreak ? JSON.stringify(tiebreak) : null, b.id);
    });
    tx();

    awardXp(creator.id, Math.round(cost / 8));
    awardXp(joiner.id, Math.round(cost / 8));
    audit(joiner.username, 'battle_resolve', { battle: b.id, winner: winner.id });

    const detail = db.prepare(`
      SELECT br.round, br.user_id, br.value, br.roll, br.nonce, i.name, i.emoji, i.rarity, i.image
      FROM battle_rounds br JOIN items i ON i.id=br.item_id WHERE br.battle_id=? ORDER BY br.round, br.user_id`).all(b.id);
    const u = db.prepare('SELECT balance FROM users WHERE id=?').get(joiner.id);
    res.json({
      battle: publicBattle(db.prepare('SELECT * FROM battles WHERE id=?').get(b.id)),
      rounds_detail: detail, balance: u.balance,
    });
  });
};
