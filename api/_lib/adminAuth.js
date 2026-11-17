'use strict';
// Helper auth admin untuk Sean Robux, dipakai semua endpoint /api/admin-*.
// Tanpa dependensi: hanya modul bawaan Node (crypto).
//
// Cara kerja:
// - Password TIDAK ada di file manapun. Password awal dibaca dari env var
//   ADMIN_PASSWORD. Password yang sudah diganti lewat panel tersimpan
//   sebagai HASH scrypt di Firebase (jalur seanrobux_config, field
//   adminPasswordHash), bukan plaintext.
// - Login yang berhasil menerbitkan cookie sesi yang ditandatangani HMAC
//   (rahasia dari env var ADMIN_SESSION_SECRET), httpOnly, berlaku 12 jam.
// - Semua endpoint admin memeriksa cookie itu DI SERVER sebelum
//   membaca/menulis Firebase. Browser tidak pernah memegang password
//   ataupun menulis langsung ke Firebase untuk keperluan admin.
// - URL Firebase dibaca dari env var FIREBASE_DB_URL, atau konstanta di
//   bawah (URL yang sama dengan yang sudah publik di index.html, karena
//   halaman utama memang memuat daftar harga langsung dari Firebase).

const crypto = require('crypto');

const FIREBASE_DB_URL = (process.env.FIREBASE_DB_URL || 'https://dolphinjoki-default-rtdb.asia-southeast1.firebasedatabase.app').replace(/\/+$/, '');
if (FIREBASE_DB_URL.indexOf('__FIREBASE') !== -1) {
  throw new Error('FIREBASE_DB_URL belum dikonfigurasi.');
}
const PRICES_DB_PATH = 'seanrobux_prices';
const CONFIG_DB_PATH = 'seanrobux_config';
const SESSION_COOKIE = 'sr_admin';
const SESSION_MAX_AGE = 12 * 60 * 60; // 12 jam, dalam detik
const NOMINALS = [80, 100, 200, 400, 800, 1700, 2750, 5500];
// Batas daftar harga dinamis (sejak Admin v2, admin bisa membuat list
// item sendiri): tiap metode 1-20 item, nominal 1-1.000.000 Robux,
// harga 1-100.000.000 rupiah. NOMINALS di atas hanya daftar awal.
const MAX_PRICE_ITEMS = 20;
const MAX_NOMINAL = 1000000;
const MAX_PRICE = 100000000;

// ---------- Rahasia & perbandingan aman ----------

function getSessionSecret() {
  const secret = process.env.ADMIN_SESSION_SECRET || '';
  if (secret.length < 16) {
    throw new Error('SESSION_SECRET_MISSING');
  }
  return secret;
}

// Perbandingan string yang tahan timing attack: kedua sisi di-hash dulu
// (panjang selalu sama), lalu dibandingkan dengan timingSafeEqual.
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------- Hash password (scrypt, format: scrypt$salt$hash) ----------

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return 'scrypt$' + salt.toString('hex') + '$' + derived.toString('hex');
}

function verifyHash(password, stored) {
  try {
    const parts = String(stored).split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const salt = Buffer.from(parts[1], 'hex');
    const expected = Buffer.from(parts[2], 'hex');
    if (salt.length !== 16 || expected.length !== 64) return false;
    const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
    return crypto.timingSafeEqual(derived, expected);
  } catch (e) {
    return false;
  }
}

// ---------- Firebase REST (dari server) ----------

async function fbRequest(path, method, body) {
  const res = await fetch(FIREBASE_DB_URL + '/' + path + '.json', {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error('Firebase HTTP ' + res.status);
  return res.json().catch(() => null);
}

function fbGet(path) {
  return fbRequest(path, 'GET');
}

function fbPut(path, obj) {
  return fbRequest(path, 'PUT', obj);
}

function fbPatch(path, obj) {
  return fbRequest(path, 'PATCH', obj);
}

// ---------- Password admin ----------

async function getStoredPassword() {
  const data = await fbGet(CONFIG_DB_PATH);
  if (!data || typeof data !== 'object') return { hash: null, legacy: null };
  return {
    hash: typeof data.adminPasswordHash === 'string' && data.adminPasswordHash ? data.adminPasswordHash : null,
    // Format lama: plaintext di field adminPassword. Dimigrasikan
    // otomatis menjadi hash saat login pertama yang berhasil.
    legacy: typeof data.adminPassword === 'string' && data.adminPassword ? data.adminPassword : null,
  };
}

// Mengembalikan true kalau password cocok. Melempar NO_ADMIN_PASSWORD
// kalau tidak ada password tersimpan DAN env var ADMIN_PASSWORD kosong.
async function verifyPassword(input) {
  const stored = await getStoredPassword();
  if (stored.hash) {
    return verifyHash(input, stored.hash);
  }
  if (stored.legacy) {
    const ok = safeEqual(input, stored.legacy);
    if (ok) {
      // Migrasikan simpanan lama (plaintext) menjadi hash. Kegagalan
      // migrasi tidak menggagalkan login yang sudah benar.
      try {
        await fbPatch(CONFIG_DB_PATH, {
          adminPasswordHash: hashPassword(input),
          adminPassword: null,
          updatedAt: Date.now(),
        });
      } catch (e) { /* abaikan */ }
    }
    return ok;
  }
  const envPass = process.env.ADMIN_PASSWORD || '';
  if (!envPass) {
    throw new Error('NO_ADMIN_PASSWORD');
  }
  return safeEqual(input, envPass);
}

async function setPassword(newPassword) {
  await fbPatch(CONFIG_DB_PATH, {
    adminPasswordHash: hashPassword(newPassword),
    adminPassword: null,
    updatedAt: Date.now(),
  });
}

// ---------- Sesi (token HMAC di cookie httpOnly) ----------

function createSessionToken(maxAgeSec) {
  const secret = getSessionSecret();
  const age = typeof maxAgeSec === 'number' ? maxAgeSec : SESSION_MAX_AGE;
  const exp = Math.floor(Date.now() / 1000) + age;
  const payload = 'v1.' + exp;
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return payload + '.' + sig;
}

function verifySessionToken(token) {
  try {
    const secret = getSessionSecret();
    const parts = String(token || '').split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return false;
    const exp = parseInt(parts[1], 10);
    if (!Number.isInteger(exp) || exp <= Math.floor(Date.now() / 1000)) return false;
    const payload = parts[0] + '.' + parts[1];
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    const given = Buffer.from(parts[2], 'hex');
    const want = Buffer.from(expected, 'hex');
    if (given.length !== want.length) return false;
    return crypto.timingSafeEqual(given, want);
  } catch (e) {
    return false;
  }
}

function parseCookies(req) {
  const out = {};
  const header = (req.headers && req.headers.cookie) || '';
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    try {
      out[name] = decodeURIComponent(value);
    } catch (e) {
      out[name] = value;
    }
  }
  return out;
}

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  return !!cookies[SESSION_COOKIE] && verifySessionToken(cookies[SESSION_COOKIE]);
}

function sessionCookieHeader(token) {
  return SESSION_COOKIE + '=' + token
    + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + SESSION_MAX_AGE;
}

function clearSessionCookieHeader() {
  return SESSION_COOKIE + '=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';
}

// ---------- HTTP helpers ----------

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return req.body ? JSON.parse(req.body) : {};
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

// ---------- Validasi daftar harga & nomor WA ----------
// Harga tersimpan per metode sebagai map nominal -> harga rupiah:
// { "80": 14000, "500": 75000, ... }. Sejak Admin v2, nominalnya bebas
// (tidak harus kedelapan NOMINALS): tiap metode 1-20 item, nominal
// bilangan bulat 1-1.000.000, harga bilangan bulat 1-100.000.000.
// Data lama berisi 8 nominal tetap tetap lolos validasi ini.

function validPriceMap(m) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) return false;
  const keys = Object.keys(m);
  if (keys.length < 1 || keys.length > MAX_PRICE_ITEMS) return false;
  for (const k of keys) {
    if (!/^[1-9][0-9]*$/.test(k)) return false;
    if (parseInt(k, 10) > MAX_NOMINAL) return false;
    const p = m[k];
    if (!Number.isInteger(p) || p < 1 || p > MAX_PRICE) return false;
  }
  return true;
}

// Mengambil map yang sudah divalidasi, dengan kunci diurutkan dari
// nominal terkecil. Mengembalikan null kalau tidak valid.
function pickPrices(m) {
  if (!validPriceMap(m)) return null;
  const out = {};
  const keys = Object.keys(m).map((k) => parseInt(k, 10)).sort((a, b) => a - b);
  for (const n of keys) out[String(n)] = m[String(n)];
  return out;
}

// Normalisasi nomor WA admin ke format internasional tanpa '+':
// spasi/tanda hubung dihapus, '08...' -> '62...', '812...' -> '62...'.
// Mengembalikan string ternormalisasi, atau '' kalau tidak valid.
function normalizeWa(raw) {
  let d = String(raw || '').replace(/[^0-9]/g, '');
  if (d.startsWith('0')) d = '62' + d.slice(1);
  else if (!d.startsWith('62')) d = '62' + d;
  if (!/^62[0-9]{8,13}$/.test(d)) return '';
  return d;
}

function validAdminWa(wa) {
  return typeof wa === 'string' && /^62[0-9]{8,13}$/.test(wa);
}

// ---------- Pembatas percobaan login (best-effort) ----------
// Di serverless, memori ini tidak dibagi antar instance, jadi pembatas
// ini hanya menambah gesekan, bukan jaminan. Hash scrypt + cookie HMAC
// tetap menjadi pengaman utama.
const loginAttempts = new Map(); // ip -> { count, resetAt }
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_MAX_FAILS = 10;

function clientIp(req) {
  const fwd = req.headers && req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function loginRateLimited(ip) {
  const rec = loginAttempts.get(ip);
  if (!rec) return false;
  if (Date.now() > rec.resetAt) {
    loginAttempts.delete(ip);
    return false;
  }
  return rec.count >= LOGIN_MAX_FAILS;
}

function recordFailedLogin(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec || now > rec.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  } else {
    rec.count += 1;
  }
}

function clearLoginAttempts(ip) {
  loginAttempts.delete(ip);
}

module.exports = {
  PRICES_DB_PATH,
  CONFIG_DB_PATH,
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  NOMINALS,
  MAX_PRICE_ITEMS,
  MAX_NOMINAL,
  MAX_PRICE,
  getSessionSecret,
  safeEqual,
  hashPassword,
  verifyHash,
  fbGet,
  fbPut,
  fbPatch,
  getStoredPassword,
  verifyPassword,
  setPassword,
  createSessionToken,
  verifySessionToken,
  parseCookies,
  isAuthenticated,
  sessionCookieHeader,
  clearSessionCookieHeader,
  sendJson,
  readJsonBody,
  validPriceMap,
  pickPrices,
  normalizeWa,
  validAdminWa,
  clientIp,
  loginRateLimited,
  recordFailedLogin,
  clearLoginAttempts,
};
