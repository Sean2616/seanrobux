'use strict';
// POST /api/admin-login { password }
// Memeriksa password DI SERVER. Kalau cocok, menerbitkan cookie sesi
// (httpOnly, ditandatangani HMAC, 12 jam). Password tidak pernah
// dikirim kembali ke browser dan tidak ada di file manapun.

const auth = require('./_lib/adminAuth');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return auth.sendJson(res, 405, { success: false, message: 'Method tidak diizinkan. Pakai POST.' });
  }
  const ip = auth.clientIp(req);
  if (auth.loginRateLimited(ip)) {
    return auth.sendJson(res, 429, { success: false, message: 'Terlalu banyak percobaan login. Coba lagi dalam 10 menit.' });
  }
  let body;
  try {
    body = await auth.readJsonBody(req);
  } catch (e) {
    return auth.sendJson(res, 400, { success: false, message: 'Body JSON tidak valid.' });
  }
  const password = body && typeof body.password === 'string' ? body.password : '';
  if (!password) {
    auth.recordFailedLogin(ip);
    return auth.sendJson(res, 401, { success: false, message: 'Password salah.' });
  }
  try {
    const ok = await auth.verifyPassword(password);
    if (!ok) {
      auth.recordFailedLogin(ip);
      return auth.sendJson(res, 401, { success: false, message: 'Password salah.' });
    }
    const token = auth.createSessionToken();
    auth.clearLoginAttempts(ip);
    res.setHeader('Set-Cookie', auth.sessionCookieHeader(token));
    return auth.sendJson(res, 200, { success: true });
  } catch (e) {
    if (e && e.message === 'NO_ADMIN_PASSWORD') {
      return auth.sendJson(res, 500, { success: false, message: 'Password admin belum dikonfigurasi di server.' });
    }
    if (e && e.message === 'SESSION_SECRET_MISSING') {
      return auth.sendJson(res, 500, { success: false, message: 'Konfigurasi sesi server belum lengkap.' });
    }
    return auth.sendJson(res, 500, { success: false, message: 'Login gagal. Coba lagi.' });
  }
};
