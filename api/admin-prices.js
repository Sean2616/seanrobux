'use strict';
// /api/admin-prices — baca/tulis daftar harga Robux lewat SERVER (butuh sesi admin).
// GET  -> { success, stored: { login, username, plus? } | null }
// PUT  -> body { login, username, plus? } (masing-masing map nominal -> harga
//         rupiah; tiap daftar 1-20 item, nominal 1-1.000.000, harga
//         1-100.000.000). Daftar "plus" (Roblox Plus, sub-kategori di tab
//         Via Login) berisi DURASI dalam Bulan, bukan Robux, tapi
//         aturannya sama. Daftar "plus" boleh tidak ada, untuk data
//         lama yang hanya berisi login + username; kalau ada, harus
//         valid seperti daftar lain.
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
      const plus = data ? auth.pickPrices(data.plus) : null;
      const stored = (login && username) ? { login, username } : null;
      if (stored && plus) stored.plus = plus;
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
    const plus = body && body.plus !== undefined ? auth.pickPrices(body.plus) : undefined;
    if (!login || !username || plus === null) {
      return auth.sendJson(res, 400, { success: false, message: 'Daftar harga tidak valid: tiap daftar 1-20 item, nominal 1-1.000.000, harga angka lebih dari 0.' });
    }
    try {
      const toStore = { login, username, updatedAt: Date.now() };
      if (plus) toStore.plus = plus;
      await auth.fbPut(auth.PRICES_DB_PATH, toStore);
      return auth.sendJson(res, 200, { success: true });
    } catch (e) {
      return auth.sendJson(res, 500, { success: false, message: 'Gagal menyimpan harga.' });
    }
  }
  return auth.sendJson(res, 405, { success: false, message: 'Method tidak diizinkan.' });
};
