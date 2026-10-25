'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_PATH = process.env.ADMIN_PATH || '/admin';
const SECURE = process.env.COOKIE_SECURE === '1';
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
fs.mkdirSync(DATA, { recursive: true });

const file = n => path.join(DATA, n);
const load = (n, d) => { try { return JSON.parse(fs.readFileSync(file(n), 'utf8')); } catch { return d; } };
const save = (n, v) => { const t = file(n) + '.tmp'; fs.writeFileSync(t, JSON.stringify(v, null, 1)); fs.renameSync(t, file(n)); };

/* ---------- public page template + site content ---------- */
const tpl = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
const adminHtml = fs.readFileSync(path.join(__dirname, 'public', 'admin.html'), 'utf8');
const re = /(<script type="application\/json" id="site-data">)([\s\S]*?)(<\/script>)/;
const m = tpl.match(re);
let site = load('site.json', null);
if (!site) { site = JSON.parse(m[2]); save('site.json', site); }
let enquiries = load('enquiries.json', []);

/* ---------- admin credentials (scrypt) ---------- */
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
let admin = load('admin.json', null);
if (!admin) {
  const user = process.env.ADMIN_USER || 'admin';
  let pw = process.env.ADMIN_PASSWORD;
  if (!pw || pw.length < 8) { pw = crypto.randomBytes(9).toString('base64url'); console.log('\n  First start. Admin login created:\n    username: ' + user + '\n    password: ' + pw + '\n  Change it after logging in.\n'); }
  const salt = crypto.randomBytes(16).toString('hex');
  admin = { user, salt, hash: hash(pw, salt) };
  save('admin.json', admin);
}
const checkPw = (pw) => {
  const a = Buffer.from(hash(String(pw), admin.salt), 'hex'), b = Buffer.from(admin.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

/* ---------- sessions, rate limits, live stream ---------- */
const sessions = new Map();           // token -> expiry
const hits = new Map();               // key -> [timestamps]
const streams = new Set();
function limited(key, max, ms) {
  const now = Date.now(), arr = (hits.get(key) || []).filter(t => now - t < ms);
  arr.push(now); hits.set(key, arr); return arr.length > max;
}
setInterval(() => { const n = Date.now(); for (const [k, e] of sessions) if (e < n) sessions.delete(k); for (const [k, a] of hits) if (!a.some(t => n - t < 3600e3)) hits.delete(k); }, 600e3).unref();
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(p => [p[0], p.slice(1).join('=')]));
const isAdmin = req => { const t = cookie(req).sc_sid; return !!t && (sessions.get(t) || 0) > Date.now(); };

const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' });
  next();
});
app.use(express.json({ limit: '100kb' }));
// basic CSRF guard: state-changing requests must come from this site
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ error: 'forbidden' });
  next();
});
const need = (req, res, next) => isAdmin(req) ? next() : res.status(401).json({ error: 'login required' });
const str = (v, n) => String(v == null ? '' : v).trim().slice(0, n);

/* ---------- pages ---------- */
app.get('/', (req, res) => res.type('html').send(tpl.replace(re, (_, a, __, c) => a + JSON.stringify(site).replace(/</g, '\\u003c') + c)));
app.get(ADMIN_PATH, (req, res) => { res.set({ 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' }); res.type('html').send(adminHtml); });

/* ---------- public API ---------- */
app.post('/api/enquiry', (req, res) => {
  if (limited('enq:' + req.ip, 10, 3600e3)) return res.status(429).json({ error: 'too many requests' });
  const b = req.body || {};
  const names = Object.values(site.services).flat().map(s => s.name);
  const service = str(b.service, 100);
  if (!names.includes(service) || !str(b.name, 120) || !str(b.phone, 40)) return res.status(400).json({ error: 'invalid' });
  const item = {
    id: Date.now().toString(36) + crypto.randomBytes(3).toString('hex'), ts: Date.now(), status: 'new', service,
    name: str(b.name, 120), phone: str(b.phone, 40), email: str(b.email, 160), org: str(b.org, 160), pref: str(b.pref, 40),
    fields: (Array.isArray(b.fields) ? b.fields : []).slice(0, 30).map(f => ({ l: str(f && f.l, 200), v: str(f && f.v, 2000) }))
  };
  enquiries.unshift(item); enquiries = enquiries.slice(0, 5000); save('enquiries.json', enquiries);
  for (const r of streams) r.write('event: enquiry\ndata: ' + JSON.stringify(item) + '\n\n');
  res.json({ ok: true });
});

/* ---------- admin API ---------- */
app.post('/api/login', (req, res) => {
  if (limited('login:' + req.ip, 8, 15 * 60e3)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { username, password } = req.body || {};
  const okUser = String(username || '').toLowerCase() === String(admin.user).toLowerCase();
  if (!(checkPw(password || '') && okUser)) return res.status(401).json({ error: 'Wrong username or password.' });
  const t = crypto.randomBytes(32).toString('hex'); sessions.set(t, Date.now() + 12 * 3600e3);
  res.set('Set-Cookie', `sc_sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${12 * 3600}${SECURE ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => { sessions.delete(cookie(req).sc_sid); res.set('Set-Cookie', 'sc_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/admin/me', need, (req, res) => res.json({ ok: true, user: admin.user }));
app.get('/api/admin/enquiries', need, (req, res) => res.json(enquiries));
app.post('/api/admin/status', need, (req, res) => {
  const { id, status } = req.body || {};
  const it = enquiries.find(e => e.id === id);
  if (!it || !['new', 'read', 'progress', 'done', 'archived'].includes(status)) return res.status(400).json({ error: 'invalid' });
  it.status = status; save('enquiries.json', enquiries); res.json({ ok: true });
});
app.put('/api/admin/site', need, (req, res) => {
  const b = req.body || {};
  if (!b.hero || !Array.isArray(b.faqs) || !Array.isArray(b.tags) || !b.services || typeof b.services !== 'object') return res.status(400).json({ error: 'invalid site data' });
  site = b; save('site.json', site); res.json({ ok: true });
});
app.post('/api/admin/password', need, (req, res) => {
  const { current, next } = req.body || {};
  if (!checkPw(current || '') ) return res.status(401).json({ error: 'Current password is wrong.' });
  if (String(next || '').length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  admin.salt = crypto.randomBytes(16).toString('hex'); admin.hash = hash(String(next), admin.salt); save('admin.json', admin);
  sessions.clear(); res.json({ ok: true });
});
app.get('/api/admin/stream', need, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.write('retry: 4000\n\n'); streams.add(res);
  const hb = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(hb); streams.delete(res); });
});

app.listen(PORT, () => console.log(`Secure-Connect running on http://localhost:${PORT}  (admin: ${ADMIN_PATH})`));
