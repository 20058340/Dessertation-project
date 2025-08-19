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
const REFRESH_SECRET = "your_refresh_secret_key"; 

// Setup lowdb
const adapter = new FileSync(path.join(__dirname, "db.json"));
const db = low(adapter);
db.defaults({ users: [], logs: [] }).write(); 

//  Helper: Log Event 
function logEvent(userEmail, action, details = "") {
  const log = {
    timestamp: new Date().toISOString(),
    user: userEmail || "SYSTEM",
    action,
    details
  };
  db.get("logs").push(log).write();
  console.log("📜 LOG:", log);
}

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
    logEvent(email, "REGISTER_FAILED", "User already exists");
    return res.status(400).json({ success: false, message: "User already exists" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const secret = speakeasy.generateSecret({ name: `NostraApp (${email})` });

    const newUser = { 
      name, 
      email, 
      password: hashedPassword, 
      role: role || "user",
      mfa: { base32: secret.base32 }
    };
    db.get("users").push(newUser).write();

    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    logEvent(email, "REGISTER_SUCCESS", `Role: ${role || "user"}`);

    res.status(201).json({ 
      success: true, 
      message: "User registered successfully", 
      qrCodeUrl,
      base32: secret.base32
    });
  } catch (err) {
    console.error(err);
    logEvent(email, "REGISTER_ERROR", err.message);
    res.status(500).json({ success: false, message: "Error registering user" });
  }
});

// LOGIN (Step 1 - password check)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.get("users").find({ email }).value();
  if (!user) {
    logEvent(email, "LOGIN_FAILED", "User not found");
    return res.status(404).json({ success: false, message: "User not found" });
  }

  try {
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      logEvent(email, "LOGIN_FAILED", "Incorrect password");
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    logEvent(email, "LOGIN_STEP1_SUCCESS", "Password correct, MFA required");

    res.status(200).json({
      success: true,
      message: "Password correct. Enter MFA code.",
      mfa_required: true,
      email
    });
  } catch (err) {
    console.error(err);
    logEvent(email, "LOGIN_ERROR", err.message);
    res.status(500).json({ success: false, message: "Login error" });
  }
});

// VERIFY MFA (Step 2 - final login)
app.post("/verify-mfa", (req, res) => {
  const { email, token } = req.body;

  if (!/^\d{6}$/.test(String(token || ""))) {
    logEvent(email, "MFA_FAILED", "Invalid format");
    return res.status(400).json({ success: false, message: "Invalid code format" });
  }

  const user = db.get("users").find({ email }).value();
  if (!user || !user.mfa?.base32) {
    logEvent(email, "MFA_FAILED", "MFA not set up");
    return res.status(400).json({ success: false, message: "MFA not set up" });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfa.base32,
    encoding: "base32",
    token,
    window: 1
  });

  if (!verified) {
    logEvent(email, "MFA_FAILED", "Invalid/expired code");
    return res.status(401).json({ success: false, message: "Invalid or expired MFA code" });
  }

  const jwtToken = jwt.sign(
    { email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "1min" }
  );

  logEvent(email, "LOGIN_SUCCESS", "MFA passed, token issued");

  res.status(200).json({
    success: true,
    message: "Login successful",
    token: jwtToken,
    role: user.role
  });
});

// REFRESH TOKEN ENDPOINT
app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ message: "Refresh token missing" });

  const user = db.get("users").find({ refreshToken }).value();
  if (!user) return res.status(403).json({ message: "Invalid refresh token" });

  jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid or expired refresh token" });

    const newAccessToken = jwt.sign(
      { email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "1m" }
    );

    logEvent(user.email, "TOKEN_REFRESHED");

    res.json({ token: newAccessToken });
  });
});

// LOGOUT (invalidate refresh token)
app.post("/logout", (req, res) => {
  const { email } = req.body;
  db.get("users").find({ email }).assign({ refreshToken: null }).write();
  logEvent(email, "LOGOUT", "Refresh token cleared");
  res.json({ message: "Logged out successfully" });
});

// PROFILE
app.get("/api/profile", verifyToken, (req, res) => {
  const user = db.get("users").find({ email: req.user.email }).value();
  if (!user) {
    logEvent(req.user.email, "PROFILE_FAILED", "User not found");
    return res.status(404).json({ message: "User not found" });
  }
  logEvent(req.user.email, "PROFILE_VIEW", "User accessed profile");
  res.json({ message: "Access granted ✅", user: { name: user.name, email: user.email, role: user.role } });
});

//  Get all users (admin only)
app.get("/api/users", verifyToken, authorizeRoles("admin"), (req, res) => {
  logEvent(req.user.email, "ADMIN_VIEW_USERS");
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
  logEvent(req.user.email, "ADMIN_DELETE_USER", `Deleted: ${email}`);
  res.json({ message: `User ${email} deleted successfully` });
});

// Change a user's role (admin only)
app.put("/api/users/:email", verifyToken, authorizeRoles("admin"), (req, res) => {
  const { email } = req.params;
  const { role } = req.body;
  const user = db.get("users").find({ email }).value();
  
  if (!user) {
    logEvent(req.user.email, "ADMIN_UPDATE_ROLE_FAILED", `User not found: ${email}`);
    return res.status(404).json({ message: "User not found" });
  }

  db.get("users").find({ email }).assign({ role }).write();
  logEvent(req.user.email, "ADMIN_UPDATE_ROLE", `Changed ${email} to ${role}`);
  res.json({ message: `User ${email} role updated to ${role}` });
});

// ADMIN ONLY - Logs
app.get("/api/logs", verifyToken, authorizeRoles("admin"), (req, res) => {
  logEvent(req.user.email, "ADMIN_VIEW_LOGS");
  const logs = db.get("logs").value();
  res.json(logs);
});

app.listen(PORT, () => console.log(` Server running at http://localhost:${PORT}`));
