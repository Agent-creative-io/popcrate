// POPCRATE — headless UI test v2 (CMS + battles + memberships build)
'use strict';
const { chromium } = require('playwright');
const { getSetting } = require('./db');

const EXE = '/opt/pw-browsers/chromium_headless_shell-1228/chrome-headless-shell-linux64/chrome-headless-shell';
const BASE = 'http://localhost:3000';
const ok = (name, cond) => { console.log((cond ? '  ✅ ' : '  ❌ ') + name); if (!cond) process.exitCode = 1; };

(async () => {
  const browser = await chromium.launch({ executablePath: EXE, args: ['--no-sandbox'] });

  /* ============ 1) HOME: CMS-driven sections ============ */
  const A = await browser.newContext({ viewport: { width: 1360, height: 900 } });
  const pa = await A.newPage();
  pa.on('pageerror', e => console.log('  ⚠️ pageerror(A):', e.message));
  await pa.goto(BASE, { waitUntil: 'networkidle' });
  await pa.waitForTimeout(1200);

  ok('announcement bar visible', await pa.locator('#announceBar').isVisible());
  const tabs = await pa.locator('.cat-tab').count();
  ok(`category tabs rendered (${tabs})`, tabs === 7); // All + 6 categories
  const crates = await pa.locator('#caseGrid .card').count();
  ok(`10 crates on the wall (${crates})`, crates === 10);
  ok('featured ⭐ stars present', await pa.locator('.feat-star').count() >= 3);
  ok('battles section rendered', (await pa.locator('#battleGrid .battle-card').count()) >= 1 || (await pa.locator('#battleGrid').textContent()).includes('be the first'));
  ok('club shows 3 tiers', await pa.locator('#tierGrid .tier').count() === 3);
  ok('footer CMS page links (4)', await pa.locator('#pageLinks button').count() === 4);
  await pa.screenshot({ path: '/tmp/shot-home.png' });

  /* category filter: click Cards & TCG */
  await pa.locator('.cat-tab', { hasText: 'Cards & TCG' }).click();
  await pa.waitForTimeout(900);
  const visible = await pa.locator('#caseGrid .card:visible').count();
  ok(`cards filter shows 3 crates (${visible})`, visible === 3);
  await pa.screenshot({ path: '/tmp/shot-filter.png' });
  await pa.locator('.cat-tab', { hasText: 'All crates' }).click();
  await pa.waitForTimeout(700);

  /* page modal */
  await pa.locator('#pageLinks button', { hasText: 'FAQ' }).click();
  await pa.waitForTimeout(400);
  ok('FAQ page modal opens with rendered markdown', await pa.locator('#pageBody h2').count() >= 3);
  await pa.locator('#pageModal .close').click();

  /* ============ 2) MEMBERSHIP: register → join Plus → daily claim ============ */
  const uA = 'ui_' + Date.now().toString(36);
  await pa.locator('#authBtn').click();
  await pa.fill('#authUser', uA); await pa.fill('#authPass', 'secret1');
  await pa.locator('button', { hasText: 'Create account' }).click();
  await pa.waitForTimeout(900);
  ok('registered + wallet visible', await pa.locator('#walletChip').isVisible());
  ok('level chip shows LV 0', (await pa.locator('#lvlChip').textContent()) === 'LV 0');

  await pa.locator('#club').scrollIntoViewIfNeeded();
  await pa.locator('.tier button', { hasText: 'Join Plus Club' }).click();
  await pa.waitForTimeout(900);
  ok('tier badge shows PLUS', (await pa.locator('#tierBadge').textContent()).includes('PLUS'));
  ok('YOUR TIER marker on Plus card', await pa.locator('.tier .cur').count() === 1);
  const balBefore = (await pa.locator('#balance').textContent()).replace(/,/g, '');
  await pa.locator('.tier button', { hasText: 'Claim' }).click();
  await pa.waitForTimeout(700);
  const balAfter = (await pa.locator('#balance').textContent()).replace(/,/g, '');
  ok(`daily claim credited (+${+balAfter - +balBefore})`, +balAfter - +balBefore === 150);
  await pa.screenshot({ path: '/tmp/shot-club.png' });

  /* ============ 3) BATTLE: A creates, B joins, arena plays ============ */
  await pa.locator('#battles').scrollIntoViewIfNeeded();
  await pa.locator('button', { hasText: 'Start a battle' }).click();
  await pa.waitForTimeout(400);
  await pa.selectOption('#cbCase', { label: /Starter Pop/ }).catch(async () => {
    // fallback: pick by value containing starter price
    const val = await pa.locator('#cbCase option', { hasText: 'Starter Pop' }).getAttribute('value');
    await pa.selectOption('#cbCase', val);
  });
  await pa.selectOption('#cbRounds', '2');
  ok('cost preview shows 300', (await pa.locator('#cbCost').textContent()) === '300');
  await pa.locator('#createBattleModal button', { hasText: 'Create battle' }).click();
  await pa.waitForTimeout(900);
  ok('battle posted (waiting card visible)', await pa.locator('.battle-card', { hasText: 'Waiting for a challenger' }).count() === 1);

  const B = await browser.newContext({ viewport: { width: 1360, height: 900 } });
  const pb = await B.newPage();
  pb.on('pageerror', e => console.log('  ⚠️ pageerror(B):', e.message));
  await pb.goto(BASE, { waitUntil: 'networkidle' });
  const uB = 'uj_' + Date.now().toString(36);
  await pb.locator('#authBtn').click();
  await pb.fill('#authUser', uB); await pb.fill('#authPass', 'secret1');
  await pb.locator('button', { hasText: 'Create account' }).click();
  await pb.waitForTimeout(900);
  await pb.locator('#battles').scrollIntoViewIfNeeded();
  await pb.locator('.battle-card button', { hasText: 'Accept for' }).first().click();
  await pb.waitForTimeout(1400); // arena open + first round
  ok('arena overlay opened', await pb.locator('#battleOverlay').isVisible());
  ok('fighters named', (await pb.locator('#fAname').textContent()) === uA && (await pb.locator('#fBname').textContent()) === uB);
  await pb.screenshot({ path: '/tmp/shot-arena-mid.png' });
  await pb.waitForTimeout(2600); // 2 rounds * 1150 + finale
  ok('winner banner shown', await pb.locator('#winBanner').isVisible());
  const pulls = await pb.locator('.fighter .pull').count();
  ok(`4 pulls rendered across both sides (${pulls})`, pulls === 4);
  ok('win/lose styling applied', await pb.locator('.fighter.win').count() === 1 && await pb.locator('.fighter.lose').count() === 1);
  await pb.screenshot({ path: '/tmp/shot-arena-final.png' });

  /* lobby now shows the finished battle with replay */
  await pa.waitForTimeout(8500); // wait for poll
  ok('lobby shows replay for finished battle', await pa.locator('.battle-card button', { hasText: 'Watch replay' }).count() >= 1);

  /* ============ 4) ADMIN: unlock + CMS tabs ============ */
  const AD = await browser.newContext({ viewport: { width: 1360, height: 950 } });
  const pd = await AD.newPage();
  pd.on('pageerror', e => console.log('  ⚠️ pageerror(admin):', e.message));
  await pd.goto(BASE + '/admin.html', { waitUntil: 'networkidle' });
  await pd.fill('#keyInput', getSetting('admin_key'));
  await pd.locator('button', { hasText: 'Enter' }).click();
  await pd.waitForTimeout(900);
  ok('admin unlocked (tabs visible)', await pd.locator('.tab').count() === 10);
  await pd.locator('.tab', { hasText: 'Catalog' }).click(); await pd.waitForTimeout(900);
  ok('catalog lists all crates with item editors', await pd.locator('#catalogCases .panel').count() >= 10);
  await pd.screenshot({ path: '/tmp/shot-admin-catalog.png' });
  await pd.locator('.tab', { hasText: 'Pages' }).click(); await pd.waitForTimeout(600);
  ok('pages editor lists 4 CMS pages', await pd.locator('#pageSelect option').count() === 5); // + "new page"
  await pd.locator('.tab', { hasText: 'Security' }).click(); await pd.waitForTimeout(600);
  ok('security tab: 2FA setup offered', await pd.locator('#totpOff button', { hasText: 'Enable 2FA' }).isVisible());
  await pd.screenshot({ path: '/tmp/shot-admin-security.png' });

  await browser.close();
  console.log(process.exitCode ? '\nSOME CHECKS FAILED' : '\nALL UI CHECKS PASSED 🎉');
})().catch(e => { console.error('FATAL', e); process.exit(1); });
