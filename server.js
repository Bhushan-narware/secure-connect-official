'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/* ===================================================================
   🔒 SECRET HIDDEN ADMIN CONFIGURATION (Full Lockdown)
   =================================================================== */
const PORT = process.env.PORT || 3000;

// 1. Secret Hidden Path (Kisi ko pata nahi chalega, /admin par 404 aayega)
const ADMIN_PATH = process.env.ADMIN_PATH || '/sc-private-access';

// 2. Personal Private Credentials
const HARDCODED_USER = process.env.ADMIN_USER || 'bhushan';
const HARDCODED_PASSWORD = process.env.ADMIN_PASSWORD || 'Bhushan@Secure2026';

// Storage paths
const defaultData = process.env.VERCEL ? '/tmp/data' : path.join(__dirname, 'data');
const DATA = path.resolve(process.env.DATA_DIR || defaultData);
try { fs.mkdirSync(DATA, { recursive: true }); } catch (e) {}

const file = n => path.join(DATA, n);
const load = (n, d) => { 
  try { 
    return JSON.parse(fs.readFileSync(file(n), 'utf8')); 
  } catch { 
    return d; 
  } 
};
const save = (n, v) => { 
  try { 
    const t = file(n) + '.tmp'; 
    fs.writeFileSync(t, JSON.stringify(v, null, 1)); 
    fs.renameSync(t, file(n)); 
  } catch (e) {
    // Fail-safe for read-only serverless filesystems
  } 
};

/* ---------- public page template + site content ---------- */
let tpl = '';
let adminHtml = '';
try {
  tpl = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
} catch (e) {
  console.error('Could not load index.html:', e.message);
}
try {
  adminHtml = fs.readFileSync(path.join(__dirname, 'public', 'admin.html'), 'utf8');
} catch (e) {
  console.error('Could not load admin.html:', e.message);
}

const re = /(<script type="application\/json" id="site-data">)([\s\S]*?)(<\/script>)/;
const m = tpl.match(re);
const defaultSite = m ? JSON.parse(m[2]) : {};
let site = load('site.json', defaultSite);
if (!site) site = defaultSite;

// Default Wallpapers, Feedbacks, and Reel if not present
site.wallpapers = site.wallpapers || { hero: '', about: '', services: '', process: '', feedback: '', faq: '', cta: '', contact: '' };
site.wallpaperOpacity = site.wallpaperOpacity || { hero: 80, about: 80, services: 80, process: 80, feedback: 80, faq: 80, cta: 80, contact: 80 };
site.ads = site.ads || {
  enabled: true,
  badge: 'SPONSORED',
  title: 'Enterprise Cyber Security & Cloud Protection',
  text: 'Get 20% off on comprehensive Penetration Testing & VAPT audit assessments this month.',
  btnText: 'Claim Offer',
  link: '#contact',
  image: '',
  html: ''
};
site.feedbacks = Array.isArray(site.feedbacks) ? site.feedbacks : [
  { name: 'Aman Singhal', role: 'Head of IT, SecureFin', rating: 5, text: 'Secure-Connect conducted our annual VAPT audit. They identified critical security flaws and guided us through remediations seamlessly. Exceptional reporting!', avatar: '' },
  { name: 'Pooja Kulkarni', role: 'Co-Founder, DataStream', rating: 5, text: 'We consulted Secure-Connect for ISO 27001 readiness. The clarity in documentation and security audits made our compliance 100% stress-free.', avatar: '' },
  { name: 'Vikram Mehta', role: 'Corporate Legal Counsel', rating: 5, text: 'Handled our digital forensics case with strict chain-of-custody. The technical report was rock-solid in legal proceedings. Highly discreet.', avatar: '' }
];
site.reel = site.reel || {
  title: 'Client Experience & Security Review',
  subtitle: 'Watch how Secure-Connect helped prevent a major enterprise cyber intrusion.',
  author: 'Rohit Bansal · Director of IT Infrastructure',
  videoUrl: '',
  posterUrl: 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=700&q=80',
  stats: '4.9 ★ Rating · 100+ Audits Completed'
};

let enquiries = load('enquiries.json', []);

/* ---------- admin credentials (scrypt + hardcoded fallback) ---------- */
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
let admin = load('admin.json', null);
if (!admin) {
  const salt = crypto.randomBytes(16).toString('hex');
  admin = { user: HARDCODED_USER, salt, hash: hash(HARDCODED_PASSWORD, salt) };
  save('admin.json', admin);
}

const checkPw = (pw) => {
  if (String(pw) === HARDCODED_PASSWORD) return true;
  if (admin && admin.salt && admin.hash) {
    try {
      const a = Buffer.from(hash(String(pw), admin.salt), 'hex');
      const b = Buffer.from(admin.hash, 'hex');
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
    } catch (e) {}
  }
  return false;
};

/* ---------- sessions, rate limits, live stream ---------- */
const sessions = new Map();           // token -> expiry
const hits = new Map();               // key -> [timestamps]
const streams = new Set();

function limited(key, max, ms) {
  const now = Date.now(), arr = (hits.get(key) || []).filter(t => now - t < ms);
  arr.push(now); hits.set(key, arr); return arr.length > max;
}

setInterval(() => { 
  const n = Date.now(); 
  for (const [k, e] of sessions) if (e < n) sessions.delete(k); 
  for (const [k, a] of hits) if (!a.some(t => n - t < 3600e3)) hits.delete(k); 
}, 600e3).unref();

const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(p => [p[0], p.slice(1).join('=')]));
const isAdmin = req => { const t = cookie(req).sc_sid; return !!t && (sessions.get(t) || 0) > Date.now(); };

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' });
  next();
});
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// CSRF guard
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.headers.origin) {
    try {
      if (new URL(req.headers.origin).host !== req.headers.host) {
        return res.status(403).json({ error: 'forbidden' });
      }
    } catch (e) {}
  }
  next();
});

const need = (req, res, next) => isAdmin(req) ? next() : res.status(401).json({ error: 'login required' });
const str = (v, n) => String(v == null ? '' : v).trim().slice(0, n);

/* ---------- pages ---------- */
app.get('/', (req, res) => {
  res.type('html').send(tpl.replace(re, (_, a, __, c) => a + JSON.stringify(site).replace(/</g, '\\u003c') + c));
});

// ❌ /admin route is BLOCKED completely (Shows standard 404 Not Found)
app.get('/admin', (req, res) => {
  res.status(404).type('text/plain').send('Cannot GET /admin');
});

// ✅ Secret Hidden Admin URL (Sirf aapko pata hai)
app.get(ADMIN_PATH, (req, res) => { 
  res.set({ 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' }); 
  res.type('html').send(adminHtml); 
});

/* ---------- public API ---------- */
app.post('/api/enquiry', (req, res) => {
  if (limited('enq:' + req.ip, 20, 3600e3)) return res.status(429).json({ error: 'too many requests' });
  const b = req.body || {};
  const names = Object.values(site.services || {}).flat().map(s => s.name);
  const service = str(b.service, 100);
  if (!names.includes(service) || !str(b.name, 120) || !str(b.phone, 40)) return res.status(400).json({ error: 'invalid' });
  
  const item = {
    id: Date.now().toString(36) + crypto.randomBytes(3).toString('hex'), 
    ts: Date.now(), 
    status: 'new', 
    service,
    name: str(b.name, 120), 
    phone: str(b.phone, 40), 
    email: str(b.email, 160), 
    org: str(b.org, 160), 
    pref: str(b.pref, 40),
    fields: (Array.isArray(b.fields) ? b.fields : []).slice(0, 30).map(f => ({ l: str(f && f.l, 200), v: str(f && f.v, 2000) }))
  };
  
  enquiries.unshift(item); 
  enquiries = enquiries.slice(0, 5000); 
  save('enquiries.json', enquiries);
  
  for (const r of streams) {
    try { r.write('event: enquiry\ndata: ' + JSON.stringify(item) + '\n\n'); } catch (e) {}
  }
  res.json({ ok: true });
});

app.post('/api/feedback', (req, res) => {
  if (limited('fb:' + req.ip, 12, 3600e3)) return res.status(429).json({ error: 'Too many requests. Please try later.' });
  const b = req.body || {};
  const name = str(b.name, 120);
  const text = str(b.text, 2000);
  if (!name || !text) return res.status(400).json({ error: 'Name and review text are required.' });
  
  const rating = Math.max(1, Math.min(5, parseInt(b.rating, 10) || 5));
  const role = str(b.role, 140) || 'Verified Client';
  
  const item = {
    id: Date.now().toString(36) + crypto.randomBytes(3).toString('hex'),
    name,
    role,
    rating,
    text,
    avatar: str(b.avatar, 300) || '',
    ts: Date.now()
  };
  
  site.feedbacks = Array.isArray(site.feedbacks) ? site.feedbacks : [];
  site.feedbacks.unshift(item);
  save('site.json', site);
  
  for (const r of streams) {
    try { r.write('event: feedback\ndata: ' + JSON.stringify(item) + '\n\n'); } catch (e) {}
  }
  
  res.json({ ok: true, item });
});

/* ---------- admin API (Strict Rate Limit: 5 attempts per 15 min) ---------- */
app.post('/api/login', (req, res) => {
  if (limited('login:' + req.ip, 5, 15 * 60e3)) {
    return res.status(429).json({ error: 'Too many attempts. Access locked for 15 minutes.' });
  }
  const { username, password } = req.body || {};
  
  const currentAdminUser = (admin && admin.user) ? admin.user : HARDCODED_USER;
  const okUser = String(username || '').trim().toLowerCase() === String(currentAdminUser).toLowerCase() ||
                 String(username || '').trim().toLowerCase() === HARDCODED_USER.toLowerCase();
                 
  if (!(okUser && checkPw(password || ''))) {
    return res.status(401).json({ error: 'Wrong username or password.' });
  }
  
  const t = crypto.randomBytes(32).toString('hex'); 
  sessions.set(t, Date.now() + 12 * 3600e3);
  
  const isSecure = (process.env.COOKIE_SECURE === '1') || (process.env.VERCEL === '1') || (req.headers['x-forwarded-proto'] === 'https');
  res.set('Set-Cookie', `sc_sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${12 * 3600}${isSecure ? '; Secure' : ''}`);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => { 
  sessions.delete(cookie(req).sc_sid); 
  res.set('Set-Cookie', 'sc_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); 
  res.json({ ok: true }); 
});

app.get('/api/admin/me', need, (req, res) => {
  res.json({ ok: true, user: admin ? admin.user : HARDCODED_USER });
});

app.get('/api/admin/enquiries', need, (req, res) => {
  res.json(enquiries);
});

app.post('/api/admin/status', need, (req, res) => {
  const { id, status } = req.body || {};
  const it = enquiries.find(e => e.id === id);
  if (!it || !['new', 'read', 'progress', 'done', 'archived'].includes(status)) return res.status(400).json({ error: 'invalid' });
  it.status = status; 
  save('enquiries.json', enquiries); 
  res.json({ ok: true });
});

app.put('/api/admin/site', need, (req, res) => {
  const b = req.body || {};
  if (!b.hero || !Array.isArray(b.faqs) || !Array.isArray(b.tags) || !b.services || typeof b.services !== 'object') {
    return res.status(400).json({ error: 'invalid site data' });
  }
  site = b; 
  save('site.json', site); 
  res.json({ ok: true });
});

app.post('/api/admin/password', need, (req, res) => {
  const { current, next } = req.body || {};
  if (!checkPw(current || '')) return res.status(401).json({ error: 'Current password is wrong.' });
  if (String(next || '').length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  
  const salt = crypto.randomBytes(16).toString('hex'); 
  admin = { user: (admin && admin.user) ? admin.user : HARDCODED_USER, salt, hash: hash(String(next), salt) }; 
  save('admin.json', admin);
  sessions.clear(); 
  res.json({ ok: true });
});

app.get('/api/admin/stream', need, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.write('retry: 4000\n\n'); 
  streams.add(res);
  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (e) {}
  }, 25000);
  req.on('close', () => { clearInterval(hb); streams.delete(res); });
});

/* ---------- start server ---------- */
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`\n==============================================`);
    console.log(`🚀 Secure-Connect running at http://localhost:${PORT}`);
    console.log(`🔒 Secret Admin: http://localhost:${PORT}${ADMIN_PATH}`);
    console.log(`👤 Username:     ${HARDCODED_USER}`);
    console.log(`🔑 Password:     ${HARDCODED_PASSWORD}`);
    console.log(`❌ Public /admin: BLOCKED (404 Not Found)`);
    console.log(`==============================================\n`);
  });
}

module.exports = app;
