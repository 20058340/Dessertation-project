const express = require("express");
const cors = require("cors");
const path = require("path");
const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// 🔁 Place this route BEFORE the static middleware
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Serve static files after setting custom route
app.use(express.static(path.join(__dirname, "public")));

// Temporary user storage (in-memory)
let users = [];

// LOGIN
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  if (user.password !== password) {
    return res.status(401).json({ success: false, message: 'Incorrect password' });
  }

  res.json({ success: true, message: 'Login successful' });
});

// REGISTER
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = users.find(user => user.email === email);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists!" });
  }

  users.push({ name, email, password });
  res.json({ message: "User registered successfully!" });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
