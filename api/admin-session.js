'use strict';
// GET /api/admin-session
// Mengecek apakah cookie sesi yang dikirim browser masih valid.
// Dipakai admin.html saat halaman dimuat untuk memilih tampilan
// login atau editor, tanpa pernah memegang password di browser.

const auth = require('./_lib/adminAuth');

module.exports = async (req, res) => {
  if (req.method !== 'GET') {
    return auth.sendJson(res, 405, { success: false, message: 'Method tidak diizinkan. Pakai GET.' });
  }
  if (auth.isAuthenticated(req)) {
    return auth.sendJson(res, 200, { success: true, authenticated: true });
  }
  return auth.sendJson(res, 401, { success: false, authenticated: false });
};
