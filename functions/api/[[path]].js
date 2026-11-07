/* Tambak Nila Sim: API akun dan data pemain.
   Cloudflare Pages Functions + D1. Letak file: functions/api/[[path]].js
   Binding D1 harus bernama DB. Tabel dibuat dari schema.sql. */
const enc = new TextEncoder();
const ITER = 100000;                       // batas PBKDF2 di Cloudflare Workers
const SESSION_MS = 30 * 24 * 3600 * 1000;   // "Simpan akun" dicentang
const SHORT_MS = 24 * 3600 * 1000;           // tidak dicentang: cookie sesi, maksimal 1 hari
const REC_LOCK_MS = 15 * 60 * 1000;
const REC_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const MAX_BODY = 600 * 1024;
const MAX_SAVE = 500 * 1024;
const LOCK_AFTER = 5, LOCK_MS = 5 * 60 * 1000;
const EMAIL_RE = /^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$/;

class HttpError extends Error { constructor(status, code, msg) { super(msg); this.status = status; this.code = code; } }
const json = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin', 'Referrer-Policy': 'no-referrer', ...h } });
const fail = (s, error, message, extra = {}) => json({ error, message, ...extra }, s);

const b64 = (buf) => { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const sha256 = async (str) => b64url(await crypto.subtle.digest('SHA-256', enc.encode(str)));
async function hashPassword(pw, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, key, 256);
}
function safeEqual(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

function getCookie(req, name) {
  const c = req.headers.get('Cookie') || '';
  for (const p of c.split(';')) { const i = p.indexOf('='); if (i > 0 && p.slice(0, i).trim() === name) return p.slice(i + 1).trim(); }
  return null;
}
const sessionCookie = (val, maxAge, secure) => `tns_sid=${val}; Path=/; HttpOnly; SameSite=Lax${maxAge == null ? '' : '; Max-Age=' + maxAge}${secure ? '; Secure' : ''}`;

async function readJson(req) {
  const len = +(req.headers.get('Content-Length') || 0);
  if (len > MAX_BODY) throw new HttpError(413, 'too_large', 'Data terlalu besar.');
  const text = await req.text();
  if (text.length > MAX_BODY) throw new HttpError(413, 'too_large', 'Data terlalu besar.');
  try { return JSON.parse(text || '{}'); } catch (e) { throw new HttpError(400, 'bad_json', 'Format data salah.'); }
}

async function currentUser(env, req) {
  const t = getCookie(req, 'tns_sid');
  if (!t || t.length < 20 || t.length > 100) return null;
  const h = await sha256(t);
  return (await env.DB.prepare('SELECT u.id AS id, u.email AS email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?').bind(h, Date.now()).first()) || null;
}

async function openSession(env, user, url, status, remember = true, extra = {}) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = b64url(raw);
  const now = Date.now();
  const ttl = remember ? SESSION_MS : SHORT_MS;
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
  await env.DB.prepare('INSERT INTO sessions(user_id, token_hash, created_at, expires_at) VALUES(?,?,?,?)').bind(user.id, await sha256(token), now, now + ttl).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id NOT IN (SELECT id FROM sessions WHERE user_id = ? ORDER BY id DESC LIMIT 10)').bind(user.id, user.id).run();
  return json({ ok: true, user: { id: user.id, email: user.email }, ...extra }, status, { 'Set-Cookie': sessionCookie(token, remember ? ttl / 1000 : null, url.protocol === 'https:') });
}

// ---- kode pemulihan (pengganti email untuk "lupa kata sandi") ----
function newRecoveryCode() {
  const b = crypto.getRandomValues(new Uint8Array(12));
  let s = '';
  for (let i = 0; i < 12; i++) { s += REC_ALPHA[b[i] & 31]; if (i % 4 === 3 && i < 11) s += '-'; }
  return s;
}
const normCode = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const codeHash = (salt, code) => sha256(salt + ':' + code);
async function storeRecovery(env, userId) {
  const code = newRecoveryCode();
  const salt = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const h = await codeHash(salt, normCode(code));
  await env.DB.prepare('INSERT INTO recovery(user_id, salt, code_hash, fail_count, locked_until) VALUES(?,?,?,0,0) ON CONFLICT(user_id) DO UPDATE SET salt = excluded.salt, code_hash = excluded.code_hash, fail_count = 0, locked_until = 0').bind(userId, salt, h).run();
  return code;
}

async function register(env, req, url) {
  const b = await readJson(req);
  const email = String(b.email || '').trim().toLowerCase();
  const pw = String(b.password || '');
  const remember = b.remember !== false;
  if (!EMAIL_RE.test(email) || email.length > 120) return fail(400, 'bad_email', 'Email tidak valid.');
  if (pw.length < 8) return fail(400, 'weak_password', 'Kata sandi minimal 8 karakter.');
  if (pw.length > 200) return fail(400, 'bad_password', 'Kata sandi terlalu panjang.');
  if (await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()) return fail(409, 'exists', 'Email sudah terdaftar. Silakan masuk.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = b64(await hashPassword(pw, salt));
  try {
    await env.DB.prepare('INSERT INTO users(email, pass_hash, salt, created_at) VALUES(?,?,?,?)').bind(email, hash, b64(salt), Date.now()).run();
  } catch (e) { return fail(409, 'exists', 'Email sudah terdaftar. Silakan masuk.'); }
  const u = await env.DB.prepare('SELECT id, email FROM users WHERE email = ?').bind(email).first();
  const recovery = await storeRecovery(env, u.id);
  return openSession(env, u, url, 201, remember, { recovery });
}

async function login(env, req, url) {
  const b = await readJson(req);
  const email = String(b.email || '').trim().toLowerCase();
  const pw = String(b.password || '');
  const remember = b.remember !== false;
  const wrong = () => fail(401, 'bad_login', 'Email atau kata sandi salah.');
  if (!EMAIL_RE.test(email) || !pw || pw.length > 200) { await hashPassword('x', new Uint8Array(16)); return wrong(); }
  const row = await env.DB.prepare('SELECT id, email, pass_hash, salt, locked_until FROM users WHERE email = ?').bind(email).first();
  if (!row) { await hashPassword(pw, new Uint8Array(16)); return wrong(); }   // samakan waktu proses
  const now = Date.now();
  if (row.locked_until > now) return fail(429, 'locked', `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((row.locked_until - now) / 60000)} menit.`);
  const calc = new Uint8Array(await hashPassword(pw, unb64(row.salt)));
  if (!safeEqual(calc, unb64(row.pass_hash))) {
    const r = await env.DB.prepare('UPDATE users SET fail_count = fail_count + 1 WHERE id = ?').bind(row.id).run();
    const cur = await env.DB.prepare('SELECT fail_count FROM users WHERE id = ?').bind(row.id).first();
    if (cur && cur.fail_count >= LOCK_AFTER) await env.DB.prepare('UPDATE users SET fail_count = 0, locked_until = ? WHERE id = ?').bind(now + LOCK_MS, row.id).run();
    return wrong();
  }
  await env.DB.prepare('UPDATE users SET fail_count = 0, locked_until = 0 WHERE id = ?').bind(row.id).run();
  return openSession(env, { id: row.id, email: row.email }, url, 200, remember);
}

async function logout(env, req, url) {
  const t = getCookie(req, 'tns_sid');
  if (t) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(t)).run();
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0, url.protocol === 'https:') });
}

async function getSave(env, user) {
  const row = await env.DB.prepare('SELECT data, rev, updated_at FROM saves WHERE user_id = ?').bind(user.id).first();
  if (!row) return json({ data: null, rev: 0 });
  return json({ data: JSON.parse(row.data), rev: row.rev, updated_at: row.updated_at });
}

async function putSave(env, req, user) {
  const b = await readJson(req);
  const d = b.data, rev = b.rev;
  if (!d || typeof d !== 'object' || d.v !== 2 || !Array.isArray(d.objs)) return fail(400, 'bad_data', 'Data tambak tidak valid.');
  if (!Number.isInteger(rev) || rev < 0) return fail(400, 'bad_rev', 'Versi data tidak valid.');
  const text = JSON.stringify(d);
  if (text.length > MAX_SAVE) return fail(413, 'too_large', 'Data tambak terlalu besar.');
  const now = Date.now();
  if (rev === 0) {
    try { await env.DB.prepare('INSERT INTO saves(user_id, data, rev, updated_at) VALUES(?,?,1,?)').bind(user.id, text, now).run(); return json({ ok: true, rev: 1 }); }
    catch (e) { const c = await env.DB.prepare('SELECT rev FROM saves WHERE user_id = ?').bind(user.id).first(); return fail(409, 'conflict', 'Data akun lebih baru.', { rev: c ? c.rev : 0 }); }
  }
  const r = await env.DB.prepare('UPDATE saves SET data = ?, rev = rev + 1, updated_at = ? WHERE user_id = ? AND rev = ?').bind(text, now, user.id, rev).run();
  if (!r.meta || r.meta.changes !== 1) { const c = await env.DB.prepare('SELECT rev FROM saves WHERE user_id = ?').bind(user.id).first(); return fail(409, 'conflict', 'Data akun lebih baru.', { rev: c ? c.rev : 0 }); }
  return json({ ok: true, rev: rev + 1 });
}

async function resetPassword(env, req, url) {
  const b = await readJson(req);
  const email = String(b.email || '').trim().toLowerCase();
  const code = normCode(b.code);
  const pw = String(b.password || '');
  const bad = () => fail(400, 'bad_reset', 'Email atau kode pemulihan salah.');
  if (pw.length < 8) return fail(400, 'weak_password', 'Kata sandi baru minimal 8 karakter.');
  if (pw.length > 200) return fail(400, 'bad_password', 'Kata sandi terlalu panjang.');
  if (!EMAIL_RE.test(email) || email.length > 120 || code.length !== 12) return bad();
  const row = await env.DB.prepare('SELECT u.id AS id, u.email AS email, r.salt AS salt, r.code_hash AS code_hash, r.locked_until AS locked_until FROM users u JOIN recovery r ON r.user_id = u.id WHERE u.email = ?').bind(email).first();
  if (!row) { await sha256('dummy'); return bad(); }
  const now = Date.now();
  if (row.locked_until > now) return fail(429, 'locked', `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((row.locked_until - now) / 60000)} menit.`);
  const h = await codeHash(row.salt, code);
  if (!safeEqual(enc.encode(h), enc.encode(row.code_hash))) {
    await env.DB.prepare('UPDATE recovery SET fail_count = fail_count + 1 WHERE user_id = ?').bind(row.id).run();
    const cur = await env.DB.prepare('SELECT fail_count FROM recovery WHERE user_id = ?').bind(row.id).first();
    if (cur && cur.fail_count >= LOCK_AFTER) await env.DB.prepare('UPDATE recovery SET fail_count = 0, locked_until = ? WHERE user_id = ?').bind(now + REC_LOCK_MS, row.id).run();
    return bad();
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = b64(await hashPassword(pw, salt));
  await env.DB.prepare('UPDATE users SET pass_hash = ?, salt = ?, fail_count = 0, locked_until = 0 WHERE id = ?').bind(hash, b64(salt), row.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(row.id).run();
  const recovery = await storeRecovery(env, row.id);
  return openSession(env, { id: row.id, email: row.email }, url, 200, true, { recovery });
}

async function newRecovery(env, req) {
  const u = await currentUser(env, req);
  if (!u) return fail(401, 'unauth', 'Belum masuk.');
  const b = await readJson(req);
  const pw = String(b.password || '');
  const row = await env.DB.prepare('SELECT pass_hash, salt, locked_until FROM users WHERE id = ?').bind(u.id).first();
  const now = Date.now();
  if (row.locked_until > now) return fail(429, 'locked', `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((row.locked_until - now) / 60000)} menit.`);
  const ok = pw && pw.length <= 200 && safeEqual(new Uint8Array(await hashPassword(pw, unb64(row.salt))), unb64(row.pass_hash));
  if (!ok) {
    await env.DB.prepare('UPDATE users SET fail_count = fail_count + 1 WHERE id = ?').bind(u.id).run();
    const cur = await env.DB.prepare('SELECT fail_count FROM users WHERE id = ?').bind(u.id).first();
    if (cur && cur.fail_count >= LOCK_AFTER) await env.DB.prepare('UPDATE users SET fail_count = 0, locked_until = ? WHERE id = ?').bind(now + LOCK_MS, u.id).run();
    return fail(401, 'bad_login', 'Kata sandi salah.');
  }
  await env.DB.prepare('UPDATE users SET fail_count = 0 WHERE id = ?').bind(u.id).run();
  return json({ ok: true, recovery: await storeRecovery(env, u.id) });
}

export async function onRequest({ request, env, params }) {
  const url = new URL(request.url);
  const route = [].concat(params && params.path || []).join('/');
  const method = request.method;
  try {
    if (route === 'health') return json({ ok: true, db: !!env.DB });
    if (!env.DB) return fail(503, 'db_missing', 'Database belum terpasang.');
    if (method !== 'GET' && method !== 'HEAD') {
      const origin = request.headers.get('Origin');
      if (origin && new URL(origin).host !== url.host) return fail(403, 'forbidden', 'Asal permintaan tidak sah.');
      if (request.headers.get('X-Requested-With') !== 'tns') return fail(403, 'forbidden', 'Permintaan tidak sah.');
    }
    const only = (m, fn) => (method === m ? fn() : fail(405, 'method', 'Metode tidak diizinkan.'));
    switch (route) {
      case 'register': return await only('POST', () => register(env, request, url));
      case 'login': return await only('POST', () => login(env, request, url));
      case 'logout': return await only('POST', () => logout(env, request, url));
      case 'reset': return await only('POST', () => resetPassword(env, request, url));
      case 'recovery': return await only('POST', () => newRecovery(env, request));
      case 'me': return await only('GET', async () => { const u = await currentUser(env, request); return u ? json({ user: { id: u.id, email: u.email } }) : fail(401, 'unauth', 'Belum masuk.'); });
      case 'save': {
        const u = await currentUser(env, request);
        if (!u) return fail(401, 'unauth', 'Belum masuk.');
        if (method === 'GET') return await getSave(env, u);
        if (method === 'PUT') return await putSave(env, request, u);
        if (method === 'DELETE') { await env.DB.prepare('DELETE FROM saves WHERE user_id = ?').bind(u.id).run(); return json({ ok: true }); }
        return fail(405, 'method', 'Metode tidak diizinkan.');
      }
      default: return fail(404, 'not_found', 'Tidak ditemukan.');
    }
  } catch (e) {
    if (e instanceof HttpError) return fail(e.status, e.code, e.message);
    return fail(500, 'server', 'Terjadi kesalahan di server.');
  }
}
