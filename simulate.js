// POPCRATE — Monte Carlo odds verification
// Opens every crate N times through the same math the server uses and
// compares empirical RTP against the configured theoretical RTP.
// Run:  node simulate.js [opens_per_case]
'use strict';
const crypto = require('crypto');
const { db, caseStats } = require('./db');

const N = parseInt(process.argv[2] || '100000');
const hmac = (k, m) => crypto.createHmac('sha256', k).update(m).digest('hex');

console.log(`\nPOPCRATE odds audit — ${N.toLocaleString()} opens per crate\n`);
console.log('CRATE                    PRICE   THEO RTP   EMPIRICAL   DRIFT');
console.log('─'.repeat(66));

for (const c of db.prepare('SELECT * FROM cases ORDER BY sort').all()) {
  const st = caseStats(c.id);
  const items = st.items;
  const seed = crypto.randomBytes(32).toString('hex');
  let paid = 0;
  for (let n = 0; n < N; n++) {
    for (let d = 0; d < c.draws; d++) {
      const roll = parseInt(hmac(seed, `audit:${n}:${d}`).slice(0, 8), 16) / 0x100000000;
      let acc = 0;
      for (const i of items) { acc += i.probability; if (roll < acc) { paid += i.value; break; } }
    }
  }
  const emp = paid / (N * c.price);
  const drift = ((emp - st.rtp) * 100).toFixed(3);
  console.log(
    `${(c.emoji + ' ' + c.name).padEnd(24)} ${String(c.price).padStart(6)}   ${(st.rtp * 100).toFixed(2).padStart(6)}%   ${(emp * 100).toFixed(2).padStart(7)}%   ${drift.padStart(6)}pp`
  );
}
console.log('─'.repeat(66));
console.log('Drift within ±0.5pp at 100k opens = configured odds are exact.\n');
