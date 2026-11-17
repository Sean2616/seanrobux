'use strict';
// POST /api/admin-password { oldPassword, newPassword }
// Mengganti password admin. Memeriksa sesi DAN password lama DI SERVER,
// lalu menyimpan password baru sebagai HASH scrypt di Firebase.
// Password lama (plaintext, format v3.2) ikut dimigrasikan saat
// pemeriksaan password lama berhasil.

const auth = require('./_lib/adminAuth');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return auth.sendJson(res, 405, { success: false, message: 'Method tidak diizinkan. Pakai POST.' });
  }
  if (!auth.isAuthenticated(req)) {
    return auth.sendJson(res, 401, { success: false, message: 'Sesi berakhir. Login lagi.' });
  }
  let body;
  try {
    body = await auth.readJsonBody(req);
  } catch (e) {
    return auth.sendJson(res, 400, { success: false, message: 'Body JSON tidak valid.' });
  }
  const oldPassword = body && typeof body.oldPassword === 'string' ? body.oldPassword : '';
  const newPassword = body && typeof body.newPassword === 'string' ? body.newPassword : '';
  if (!newPassword || newPassword.length < 6) {
    return auth.sendJson(res, 400, { success: false, message: 'Password baru minimal 6 karakter.' });
  }
  if (newPassword === oldPassword) {
    return auth.sendJson(res, 400, { success: false, message: 'Password baru sama dengan password lama.' });
  }
  try {
    const ok = await auth.verifyPassword(oldPassword);
    if (!ok) {
      return auth.sendJson(res, 400, { success: false, message: 'Password lama salah.' });
    }
    await auth.setPassword(newPassword);
    return auth.sendJson(res, 200, { success: true });
  } catch (e) {
    if (e && e.message === 'NO_ADMIN_PASSWORD') {
      return auth.sendJson(res, 500, { success: false, message: 'Password admin belum dikonfigurasi di server.' });
    }
    return auth.sendJson(res, 500, { success: false, message: 'Gagal mengubah password. Coba lagi.' });
  }
};
