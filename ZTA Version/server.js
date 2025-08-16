const express = require("express");
const cors = require("cors");
const path = require("path");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

const app = express();
const PORT = 3000;
const saltRounds = 10;
const JWT_SECRET = "your_super_secret_key";

// Setup lowdb
const adapter = new FileSync(path.join(__dirname, "db.json"));
const db = low(adapter);
db.defaults({ users: [] }).write(); // store users only

// Middleware: verify token
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// Middleware: role check
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: insufficient permissions" });
    }
    next();
  };
}

app.use(cors());
app.use(express.json());

// Default route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});
app.use(express.static(path.join(__dirname, "public")));

// REGISTER
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const existingUser = db.get("users").find({ email }).value();
  if (existingUser) {
    return res.status(400).json({ success: false, message: "User already exists" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate MFA secret for Google Authenticator
    const secret = speakeasy.generateSecret({ name: `NostraApp (${email})` });

    const newUser = { 
      name, 
      email, 
      password: hashedPassword, 
      role: role || "user",
      mfa: { base32: secret.base32 } // save MFA secret
    };
    db.get("users").push(newUser).write();

    // Generate QR code for Google Authenticator
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    res.status(201).json({ 
      success: true, 
      message: "User registered successfully", 
      qrCodeUrl,  // front-end shows this QR code
      base32: secret.base32
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error registering user" });
  }
});

// LOGIN (Step 1 - password check)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.get("users").find({ email }).value();
  if (!user) return res.status(404).json({ success: false, message: "User not found" });

  try {
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    // Password is correct → ask for MFA code
    res.status(200).json({
      success: true,
      message: "Password correct. Enter MFA code.",
      mfa_required: true,
      email
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Login error" });
  }
});

// VERIFY MFA (Step 2 - final login)
app.post("/verify-mfa", (req, res) => {
  const { email, token } = req.body;
  const user = db.get("users").find({ email }).value();
  if (!user || !user.mfa) {
    return res.status(400).json({ success: false, message: "MFA not set up" });
  }

  // Verify the TOTP token
  const verified = speakeasy.totp.verify({
    secret: user.mfa.base32,
    encoding: "base32",
    token
  });

  if (!verified) {
    return res.status(401).json({ success: false, message: "Invalid MFA code" });
  }

  // Success → issue JWT
  const jwtToken = jwt.sign({ email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "1h" });

  res.status(200).json({
    success: true,
    message: "Login successful",
    token: jwtToken,
    role: user.role
  });
});

// PROFILE
app.get("/api/profile", verifyToken, (req, res) => {
  const user = db.get("users").find({ email: req.user.email }).value();
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ message: "Access granted ✅", user: { name: user.name, email: user.email, role: user.role } });
});

//  Get all users (admin only)
app.get("/api/users", verifyToken, authorizeRoles("admin"), (req, res) => {
  const users = db.get("users").map(u => ({
    name: u.name,
    email: u.email,
    role: u.role
  })).value();
  res.json(users);
});

// Delete a user by email (admin only)
app.delete("/api/users/:email", verifyToken, authorizeRoles("admin"), (req, res) => {
  const { email } = req.params;
  db.get("users").remove({ email }).write();
  res.json({ message: `User ${email} deleted successfully` });
});

// Change a user's role (admin only)
app.put("/api/users/:email", verifyToken, authorizeRoles("admin"), (req, res) => {
  const { email } = req.params;
  const { role } = req.body;
  const user = db.get("users").find({ email }).value();
  
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  db.get("users").find({ email }).assign({ role }).write();
  res.json({ message: `User ${email} role updated to ${role}` });
});

// ADMIN ONLY
app.get("/api/admin-data", verifyToken, authorizeRoles("admin"), (req, res) => {
  res.json({ message: "Welcome Admin 🚀 Here is your secret data" });
});

app.listen(PORT, () => console.log(` Server running at http://localhost:${PORT}`));
