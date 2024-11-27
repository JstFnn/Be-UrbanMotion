const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json()); // Untuk parsing JSON body

// Koneksi ke Database
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "user_db", // Sesuaikan dengan nama database kamu
});

// Cek koneksi
db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    return;
  }
  console.log("Connected to database");
});

// Route Register
app.post("/register", async (req, res) => {
  const { username, email, nohp, password, role } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql =
      "INSERT INTO users (username, email, nohp, password, role) VALUES (?, ?, ?, ?, ?)";
    db.query(
      sql,
      [username, email, nohp, hashedPassword, role || "user"],
      (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "User registered successfully!" });
      }
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Route Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0)
      return res.status(404).json({ error: "User not found" });

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ error: "Invalid credentials" });

    // Buat token JWT dengan data id dan role
    const token = jwt.sign(
      { id: user.id, role: user.role },
      "your_jwt_secret", // Ganti dengan secret key yang aman
      { expiresIn: "1h" }
    );

    res.json({
      token,
      role: user.role, // Kirim role ke frontend
      message: "Login successful",
    });
  });
});


// Jalankan server
app.listen(5000, () => console.log("Server running on http://localhost:5000"));
