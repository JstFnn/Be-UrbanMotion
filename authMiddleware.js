const jwt = require("jsonwebtoken");

// Middleware untuk memverifikasi token
function authenticateToken(req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", ""); // Mengambil token dari header Authorization
  if (!token) return res.status(401).send("Akses ditolak, token tidak ada");

  try {
    const verified = jwt.verify(token, "secretKey"); // Ganti 'secretKey' dengan kunci rahasia milik kamu
    req.user = verified; // Menyimpan informasi user yang sudah diverifikasi
    next();
  } catch (error) {
    res.status(400).send("Token tidak valid");
  }
}

module.exports = authenticateToken;
