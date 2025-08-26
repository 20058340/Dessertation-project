const express = require("express");
const cors = require("cors");
const path = require("path");
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");

const app = express();
const PORT = 4000;

// Database setup
const dbFile = path.join(__dirname, "db.json");
const adapter = new JSONFile(dbFile);
const db = new Low(adapter, { users: [] });

// Middleware
app.use(cors());
app.use(express.json());

// 👇 Place this BEFORE express.static
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Serve static files (CSS, JS, etc.)
app.use(express.static(path.join(__dirname, "public")));

async function startServer() {
  await db.read();
  db.data ||= { users: [] };
  await db.write();

  app.post("/login", (req, res) => {
    const { email, password } = req.body;
    const user = db.data.users.find(u => u.email === email);

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (user.password !== password) {
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    res.json({ success: true, message: "Login successful" });
  });

  app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    const existingUser = db.data.users.find(user => user.email === email);

    if (existingUser) {
      return res.status(400).json({ message: "User already exists!" });
    }

    db.data.users.push({ name, email, password });
    await db.write();

    res.json({ message: "User registered successfully!" });
  });

  app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
  });
}

startServer();
