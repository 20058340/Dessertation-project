const express = require("express");
const cors = require("cors");
const path = require("path");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const saltRounds = 10;
const JWT_SECRET = "your_super_secret_key"; // Change this in real apps

// Setup lowdb
const adapter = new FileSync(path.join(__dirname, "db.json"));
const db = low(adapter);
db.defaults({ users: [] }).write();

// Middleware
app.use(cors());
app.use(express.json());


// Default route → login.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

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
