'use strict';
// POST /api/admin-logout
// Menghapus cookie sesi di browser.

const auth = require('./_lib/adminAuth');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return auth.sendJson(res, 405, { success: false, message: 'Method tidak diizinkan. Pakai POST.' });
  }
  res.setHeader('Set-Cookie', auth.clearSessionCookieHeader());
  return auth.sendJson(res, 200, { success: true });
};
