# 🎁 POPCRATE! — mystery-box platform with a built-in CMS

A complete, self-contained prize-crate platform: provably-fair openings, crate battles,
raffles, memberships, a token wallet — and a **custom CMS control room** so you run the
whole site without touching code.

```bash
npm install
node server.js          # → http://localhost:3000   (admin key prints in the console)
```

Admin panel: `http://localhost:3000/admin.html`

---

## What's in the box

| Area | Details |
|---|---|
| **Crates** | 10 seeded crates across 6 categories (Tech, Cards & TCG, Retro, Sports, Watches & Luxury, Jackpots). 4 opening animations: reel · chest · pack rip · wheel |
| **⚔️ Crate Battles** | Head-to-head, same crate × 1–5 rounds, both stake the buy-in, **winner takes every item from both sides**. Animated VS arena with per-round reveals |
| **👑 Memberships** | Free / Plus / VIP tiers: token **rakeback on every open**, daily bonus claims, XP boosts. Tiers fully editable from the CMS |
| **🎟️ Raffles** | Ticketed giveaways with auto-draw + published draw proof |
| **🛡️ Provably fair** | HMAC-SHA256 rolls, hashed server-seed commitments, player client seeds, rotate-and-reveal, public verifier endpoint |
| **XP / levels** | Every open and battle grants XP (level = √(xp/100)); level chip in the nav |

## The CMS (admin.html)

Ten tabs, every change audit-logged:

- **📊 Overview** — house stats, realized RTP, and the **win-rate dial**: drag a slider and item
  weights re-solve to that exact RTP.
- **🎁 Catalog** — create/edit/retire crates, add/remove items, upload images to the media
  library (paste the URL onto an item to replace its emoji with product photography).
  New crates start hidden until you flip them live.
- **🏷️ Categories** — the tabs players filter by on the homepage.
- **👑 Memberships** — price, rakeback bps, daily bonus, XP boost, perk lines.
- **📄 Pages** — FAQ / fairness / terms / anything, in mini-markdown (`##`, `**bold**`, `- lists`).
- **🎨 Site** — hero title/subtitle and the announcement bar (ALL-CAPS words auto-colorize).
- **👥 Users / 🎟️ Raffles / 🧾 Audit** — operations.
- **🔐 Security** — one-click TOTP two-factor for the admin key + live lockout monitor.

### Why a custom CMS instead of WordPress
The wallet, odds engine and battle resolution are transactional systems; bolting a separate
PHP/MySQL WordPress install onto them would double the stack and import the most-attacked
plugin surface on the internet into a site that holds balances. Everything WordPress would
give you here (edit copy, pages, catalog, media) is built in — one hardened Node process,
one database, one audit log. Keep WordPress for marketing sites; keep the money engine custom.

## Security model (see SECURITY.md for details)

CSRF double-lock (SameSite=Strict + custom header) · CSP + full hardening headers ·
scrypt passwords · login lockouts · signed httpOnly sessions with absolute+idle expiry ·
purchase **idempotency keys** · per-account open velocity caps · magic-byte-sniffed uploads ·
100% parameterized SQL · admin TOTP 2FA · append-only audit log.

## Files

```
server.js     core API: auth, wallet, opens, raffles, fairness, memberships
db.js         schema, migrations, seeds, RTP auto-solver
security.js   headers, CSRF, lockouts, session expiry, TOTP (zero deps)
cms.js        the CMS: crates/items/categories/pages/media/tiers/site copy
battles.js    crate battles engine
public/       index.html (site) · admin.html (control room) · vendor/gsap
simulate.js   Monte Carlo RTP verification
uitest*.js    headless Playwright UI test suites
```

## Going to production

1. **Payments** — the demo credits tokens instantly. Wire Stripe Checkout and credit **only**
   inside the `checkout.session.completed` webhook (the integration points are marked in
   `server.js`); memberships likewise via subscription webhooks. Keep the idempotency keys.
2. **TLS + proxy** — run behind Caddy/nginx with HTTPS; set `NODE_ENV=production`
   (enables `Secure` cookies + HSTS).
3. **Enable admin 2FA** on day one (Security tab).
4. **Prize imagery** — the emoji art ships clean; license real product photos before using them.
5. **Compliance** — paid mystery boxes sit near gambling law. 18+ gate, published odds and the
   fairness verifier are built in, but get jurisdiction-specific counsel before charging real money.
