'use strict';
// /api/admin-config — baca/tulis setting situs (nomor WA Admin) lewat SERVER
// (butuh sesi admin). Disimpan di jalur seanrobux_config yang sama dengan
// hash password admin, jadi penulisan memakai PATCH agar tidak menghapus
// field lain (hash password harus tetap utuh).
// GET  -> { success, config: { adminWa } | null }
// PUT  -> body { adminWa } (dinormalisasi ke format 62..., 10-15 digit)

const auth = require('./_lib/adminAuth');

module.exports = async (req, res) => {
  if (!auth.isAuthenticated(req)) {
    return auth.sendJson(res, 401, { success: false, message: 'Sesi berakhir. Login lagi.' });
  }
  if (req.method === 'GET') {
    try {
      const data = await auth.fbGet(auth.CONFIG_DB_PATH);
      const adminWa = data && auth.validAdminWa(data.adminWa) ? data.adminWa : null;
      return auth.sendJson(res, 200, { success: true, config: adminWa ? { adminWa } : null });
    } catch (e) {
      return auth.sendJson(res, 500, { success: false, message: 'Gagal memuat setting tersimpan.' });
    }
  }
  if (req.method === 'PUT') {
    let body;
    try {
      body = await auth.readJsonBody(req);
    } catch (e) {
      return auth.sendJson(res, 400, { success: false, message: 'Body JSON tidak valid.' });
    }
    const adminWa = auth.normalizeWa(body && body.adminWa);
    if (!adminWa) {
      return auth.sendJson(res, 400, { success: false, message: 'Nomor WA tidak valid. Isi nomor Indonesia, mis. 081234567890.' });
    }
    try {
      await auth.fbPatch(auth.CONFIG_DB_PATH, {
        adminWa,
        updatedAt: Date.now(),
      });
      return auth.sendJson(res, 200, { success: true, adminWa });
    } catch (e) {
      return auth.sendJson(res, 500, { success: false, message: 'Gagal menyimpan setting.' });
    }
  }
  return auth.sendJson(res, 405, { success: false, message: 'Method tidak diizinkan.' });
};
