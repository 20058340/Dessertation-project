const express = require("express");
const cors = require("cors");
const path = require("path");
<<<<<<< HEAD
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
=======
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
>>>>>>> 3d028248b627d12fb461cfa0d13fb73c470d5578

const app = express();
const PORT = 3000;
const saltRounds = 10;
const JWT_SECRET = "your_super_secret_key"; // Change this in real apps

// Setup lowdb
const adapter = new FileSync(path.join(__dirname, "db.json"));
const db = low(adapter);
db.defaults({ users: [] }).write();

// Database setup
const dbFile = path.join(__dirname, "db.json");
const adapter = new JSONFile(dbFile);
const db = new Low(adapter, { users: [] });

// Middleware
app.use(cors());
app.use(express.json());

<<<<<<< HEAD
// 👇 Place this BEFORE express.static
=======

// Default route → login.html
>>>>>>> 3d028248b627d12fb461cfa0d13fb73c470d5578
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

<<<<<<< HEAD
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
=======
app.use(express.static(path.join(__dirname, "public"))); // serve frontend

// Register route
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = db.get("users").find({ email }).value();
  if (existingUser) {
    return res.status(400).json({ success: false, message: "User already exists" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = { name, email, password: hashedPassword };

    db.get("users").push(newUser).write();

    res.status(201).json({ success: true, message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error registering user" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.get("users").find({ email }).value();
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }

  try {
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    // Create JWT token
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Login error" });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
>>>>>>> 3d028248b627d12fb461cfa0d13fb73c470d5578
