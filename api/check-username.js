// POST /api/check-username  { username }
// Mengecek username Roblox lewat API publik users.roblox.com.
// Jujur: mengembalikan found:false kalau tidak ada, tanpa pernah
// mengarang nama akun. Tidak butuh kredensial apa pun.
// Metode lain (GET, dst) ditolak dengan 405.

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  const username = String((body && body.username) || '').trim();

  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'Username tidak valid' });
  }

  try {
    const r = await fetch('https://users.roblox.com/v1/usernames/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernames: [username], excludeBannedUsers: false })
    });
    if (!r.ok) {
      return res.status(502).json({ error: 'Roblox API tidak bisa dijangkau' });
    }
    const data = await r.json();
    const list = Array.isArray(data && data.data) ? data.data : [];
    const hit = list.find(function (u) {
      return String(u && u.name).toLowerCase() === username.toLowerCase();
    });
    if (!hit) {
      return res.status(200).json({ found: false });
    }
    return res.status(200).json({
      found: true,
      id: hit.id,
      name: hit.name,
      displayName: hit.displayName
    });
  } catch (e) {
    return res.status(502).json({ error: 'Roblox API tidak bisa dijangkau' });
  }
};
