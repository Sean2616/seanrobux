'use strict';
// /api/admin-prices — baca/tulis daftar harga Robux lewat SERVER (butuh sesi admin).
// GET  -> { success, stored: { login, username } | null }
// PUT  -> body { login, username } (masing-masing map nominal -> harga rupiah;
//         tiap metode 1-20 item, nominal 1-1.000.000, harga 1-100.000.000)
// Browser tidak lagi membaca/menulis Firebase langsung untuk admin;
// halaman utama situs tetap memuat harga publik langsung dari Firebase.

const auth = require('./_lib/adminAuth');

module.exports = async (req, res) => {
  if (!auth.isAuthenticated(req)) {
    return auth.sendJson(res, 401, { success: false, message: 'Sesi berakhir. Login lagi.' });
  }
  if (req.method === 'GET') {
    try {
      const data = await auth.fbGet(auth.PRICES_DB_PATH);
      const login = data ? auth.pickPrices(data.login) : null;
      const username = data ? auth.pickPrices(data.username) : null;
      const stored = (login && username) ? { login, username } : null;
      return auth.sendJson(res, 200, { success: true, stored });
    } catch (e) {
      return auth.sendJson(res, 500, { success: false, message: 'Gagal memuat harga tersimpan.' });
    }
  }
  if (req.method === 'PUT') {
    let body;
    try {
      body = await auth.readJsonBody(req);
    } catch (e) {
      return auth.sendJson(res, 400, { success: false, message: 'Body JSON tidak valid.' });
    }
    const login = body ? auth.pickPrices(body.login) : null;
    const username = body ? auth.pickPrices(body.username) : null;
    if (!login || !username) {
      return auth.sendJson(res, 400, { success: false, message: 'Daftar harga tidak valid: tiap metode 1-20 item, nominal 1-1.000.000 Robux, harga angka lebih dari 0.' });
    }
    try {
      await auth.fbPut(auth.PRICES_DB_PATH, {
        login,
        username,
        updatedAt: Date.now(),
      });
      return auth.sendJson(res, 200, { success: true });
    } catch (e) {
      return auth.sendJson(res, 500, { success: false, message: 'Gagal menyimpan harga.' });
    }
  }
  return auth.sendJson(res, 405, { success: false, message: 'Method tidak diizinkan.' });
};
