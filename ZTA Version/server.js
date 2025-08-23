// server.js
// =================================================
// ✅ NEW: env + security headers + notes
// =================================================
require("dotenv").config(); // loads .env if present (JWT_SECRET, REFRESH_SECRET, etc.)
const IS_PROD = process.env.NODE_ENV === "production";

// =================================================
const express = require("express");
const cors = require("cors");
const path = require("path");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser"); // ✅ already present
const helmet = require("helmet");             // ✅ NEW

const app = express();
const PORT = 3000;
const saltRounds = 10;

// ===== SECRETS (use env vars in production) =====
// ✅ UPDATED: read from env if set, fallback to your existing strings (kept)
const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your_refresh_secret_key";

// ===== LowDB setup =====
const adapter = new FileSync(path.join(__dirname, "db.json"));
const db = low(adapter);
// ✅ UPDATED: added metrics + sessions while keeping your original keys
db.defaults({ users: [], logs: [], metrics: {}, sessions: [] }).write();

// ===== Audit Log Helper =====
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

// ✅ NEW: tiny metrics bump helper (used sparingly, safe even if key missing)
function bump(key) {
  const v = db.get("metrics").get(key).value() || 0;
  db.get("metrics").set(key, v + 1).write();
}

// ===== Client IP helper =====
function getClientIp(req) {
  return (req.headers["x-forwarded-for"]?.split(",")[0]?.trim())
      || req.socket?.remoteAddress
      || req.ip
      || "unknown";
}

/* =========================
   RATE LIMIT & LOCKOUTS
   ========================= */

// --- Global IP burst limiter (200 requests/minute/IP) ---
const ipBuckets = new Map(); // ip -> { count, resetAt }
const GLOBAL_WINDOW_MS = 60 * 1000;
const GLOBAL_MAX = 200;

function globalRateLimiter(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  let bucket = ipBuckets.get(ip);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + GLOBAL_WINDOW_MS };
    ipBuckets.set(ip, bucket);
  }
  bucket.count += 1;
  if (bucket.count > GLOBAL_MAX) {
    logEvent(null, "RATE_LIMIT_GLOBAL", `IP=${ip}`);
    bump("rate_limit_hits");
    return res.status(429).json({ message: "Too many requests. Please slow down." });
  }
  next();
}

// --- Login attempt throttle (per IP) ---
const loginIpBuckets = new Map(); // ip -> { count, resetAt }
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const LOGIN_MAX = 5;

function loginRateLimiter(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  let bucket = loginIpBuckets.get(ip);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    loginIpBuckets.set(ip, bucket);
  }
  bucket.count += 1;
  if (bucket.count > LOGIN_MAX) {
    logEvent(null, "RATE_LIMIT_LOGIN", `IP=${ip}`);
    bump("rate_limit_login_hits");
    return res.status(429).json({
      success: false,
      message: "Too many login attempts from this IP. Try again later."
    });
  }
  next();
}

// --- Password fail lockout (per email) ---
const pwdFailMap = new Map(); // email -> { fails, firstAt, lockUntil }
const PWD_FAIL_WINDOW_MS = 15 * 60 * 1000;
const PWD_MAX_FAILS = 5;
const PWD_LOCK_MS = 15 * 60 * 1000;

function checkPasswordLock(email) {
  const now = Date.now();
  const rec = pwdFailMap.get(email);
  if (!rec) return null;
  if (rec.lockUntil && now < rec.lockUntil) return rec.lockUntil;
  if (rec.firstAt && now - rec.firstAt > PWD_FAIL_WINDOW_MS) {
    pwdFailMap.delete(email);
    return null;
  }
  return null;
}
function recordPasswordFail(email) {
  const now = Date.now();
  let rec = pwdFailMap.get(email);
  if (!rec || now - rec.firstAt > PWD_FAIL_WINDOW_MS) {
    rec = { fails: 0, firstAt: now, lockUntil: null };
  }
  rec.fails += 1;
  if (rec.fails >= PWD_MAX_FAILS) {
    rec.lockUntil = now + PWD_LOCK_MS;
    logEvent(email, "ACCOUNT_LOCKED_PASSWORD", `Lock for ${Math.ceil(PWD_LOCK_MS/60000)} min`);
    bump("login_lockout");
  }
  pwdFailMap.set(email, rec);
}
function clearPasswordFails(email) { pwdFailMap.delete(email); }

// --- MFA fail lockout (per email) ---
const mfaFailMap = new Map(); // email -> { fails, firstAt, lockUntil }
const MFA_FAIL_WINDOW_MS = 10 * 60 * 1000;
const MFA_MAX_FAILS = 5;
const MFA_LOCK_MS = 10 * 60 * 1000;

function checkMFALock(email) {
  const now = Date.now();
  const rec = mfaFailMap.get(email);
  if (!rec) return null;
  if (rec.lockUntil && now < rec.lockUntil) return rec.lockUntil;
  if (rec.firstAt && now - rec.firstAt > MFA_FAIL_WINDOW_MS) {
    mfaFailMap.delete(email);
    return null;
  }
  return null;
}
function recordMFAFail(email) {
  const now = Date.now();
  let rec = mfaFailMap.get(email);
  if (!rec || now - rec.firstAt > MFA_FAIL_WINDOW_MS) {
    rec = { fails: 0, firstAt: now, lockUntil: null };
  }
  rec.fails += 1;
  if (rec.fails >= MFA_MAX_FAILS) {
    rec.lockUntil = now + MFA_LOCK_MS;
    logEvent(email, "ACCOUNT_LOCKED_MFA", `Lock for ${Math.ceil(MFA_LOCK_MS/60000)} min`);
    bump("mfa_lockout");
  }
  mfaFailMap.set(email, rec);
}
function clearMFAFails(email) { mfaFailMap.delete(email); }

/* =========================
   AUTH & RBAC
   ========================= */

// Verify access token
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    bump("auth_401");
    return res.status(401).json({ message: "Token missing" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        bump("auth_401");
        return res.status(401).json({ message: "Token expired" });
      }
      bump("auth_403");
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
}

// Role check
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      bump("rbac_403");
      return res.status(403).json({ message: "Access denied: insufficient permissions" });
    }
    next();
  };
}

// Device binding enforcement
function enforceKnownDevice(req, res, next) {
  const deviceId = req.headers["x-device-id"];
  if (!deviceId) {
    bump("device_403");
    return res.status(403).json({ message: "Missing device id" });
  }
  const user = db.get("users").find({ email: req.user.email }).value();
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  const isKnown = Array.isArray(user.devices) && user.devices.includes(deviceId);
  if (!isKnown) {
    logEvent(req.user.email, "DEVICE_BLOCKED", `Unknown device: ${deviceId}`);
    bump("device_403");
    return res.status(403).json({ message: "Device not recognized. Please login again from this device." });
  }
  next();
}

/* =========================
   ✅ NEW: Security headers + CSRF
   ========================= */

// ✅ Helmet security headers (kept minimal with CSP & referrer policy)
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "img-src": ["'self'", "data:", "https:"],
    }
  },
  referrerPolicy: { policy: "no-referrer" }
}));

// ✅ CSRF: issue cookie + verify header on state-changing requests
// === CSRF helpers ===
function issueCsrf(res) {
  const csrf = crypto.randomBytes(16).toString("hex");
  res.cookie("csrf", csrf, {
    secure: IS_PROD,
    sameSite: IS_PROD ? "Strict" : "Lax",
    path: "/",
  });
  return csrf;
}

// allow these routes pre-login / no CSRF
const CSRF_WHITELIST = new Set([
  "/login",
  "/register",
  "/verify-mfa",
  "/forgot-password",
  "/reset-password",
]);

function csrfCheck(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();

  // Skip CSRF for auth/setup routes
  if (CSRF_WHITELIST.has(req.path)) return next();

  const header = req.get("X-CSRF-Token");
  const cookieToken = req.cookies?.csrf;
  if (!cookieToken || !header || header !== cookieToken) {
    // helpful server log for debugging
    console.warn("CSRF BLOCK:", {
      path: req.path,
      method: req.method,
      hdr: !!header,
      cookie: !!cookieToken,
    });
    return res.status(403).json({ error: "CSRF check failed" });
  }
  next();
}


/* =========================
   APP
   ========================= */

// ✅ CORS + Cookies
app.use(cors({
  origin: "http://localhost:3000", // adjust if your frontend is on a different origin
  credentials: true               // allow cookies
}));
app.use(express.json());
app.use(cookieParser());
app.use(globalRateLimiter);

// ✅ Apply CSRF check after parsers (protects POST/PUT/PATCH/DELETE globally)
app.use(csrfCheck);

// Static / default route
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

    // Create TOTP secret for Google Authenticator
    const secret = speakeasy.generateSecret({ name: `NostraApp (${email})` });

    const newUser = {
      name,
      email,
      password: hashedPassword,
      role: role || "user",
      mfa: { base32: secret.base32 },
      refreshToken: null,
      devices: [],  // <- trusted device IDs
      ips: []       // <- known IPs (optional)
    };

    db.get("users").push(newUser).write();

    // QR code for enrolling the TOTP secret in an Authenticator app
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    logEvent(email, "REGISTER_SUCCESS", `Role: ${role || "user"}`);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      qrCodeUrl,
      base32: secret.base32 // optional: for manual entry
    });
  } catch (err) {
    console.error(err);
    logEvent(email, "REGISTER_ERROR", err.message);
    res.status(500).json({ success: false, message: "Error registering user" });
  }
});

// LOGIN (step 1: password)
app.post("/login", loginRateLimiter, async (req, res) => {
  const { email, password } = req.body;

  const lockUntil = checkPasswordLock(email);
  if (lockUntil) {
    const secs = Math.ceil((lockUntil - Date.now()) / 1000);
    return res.status(429).json({ success: false, message: `Account temporarily locked due to failed passwords. Try again in ${secs}s.` });
  }

  const user = db.get("users").find({ email }).value();
  if (!user) {
    logEvent(email, "LOGIN_FAILED", "User not found");
    bump("failed_login");
    return res.status(404).json({ success: false, message: "User not found" });
  }

  try {
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      recordPasswordFail(email);
      logEvent(email, "LOGIN_FAILED", "Incorrect password");
      bump("failed_login");
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    // success -> clear password fail counter
    clearPasswordFails(email);

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

// VERIFY MFA (step 2) — issue access + refresh tokens and bind device
app.post("/verify-mfa", loginRateLimiter, (req, res) => {
  const { email, token, deviceId } = req.body;
  const requestIp = getClientIp(req);

  const mfaLockUntil = checkMFALock(email);
  if (mfaLockUntil) {
    const secs = Math.ceil((mfaLockUntil - Date.now()) / 1000);
    return res.status(429).json({ success: false, message: `MFA temporarily locked. Try again in ${secs}s.` });
  }

  if (!/^\d{6}$/.test(String(token || ""))) {
    recordMFAFail(email);
    logEvent(email, "MFA_FAILED", "Invalid format");
    bump("failed_mfa");
    return res.status(400).json({ success: false, message: "Invalid code format" });
  }

  const user = db.get("users").find({ email }).value();
  if (!user || !user.mfa?.base32) {
    recordMFAFail(email);
    logEvent(email, "MFA_FAILED", "MFA not set up");
    bump("failed_mfa");
    return res.status(400).json({ success: false, message: "MFA not set up" });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfa.base32,
    encoding: "base32",
    token,
    window: 1
  });

  if (!verified) {
    recordMFAFail(email);
    logEvent(email, "MFA_FAILED", "Invalid/expired code");
    bump("failed_mfa");
    return res.status(401).json({ success: false, message: "Invalid or expired MFA code" });
  }

  // success -> clear MFA fail counter
  clearMFAFails(email);

  // Trust/bind device + record IP
  const devices = Array.isArray(user.devices) ? user.devices : [];
  const ips = Array.isArray(user.ips) ? user.ips : [];
  let newDeviceAdded = false;

  if (deviceId && !devices.includes(deviceId)) {
    devices.push(deviceId);
    newDeviceAdded = true;
  }
  if (requestIp && !ips.includes(requestIp)) {
    ips.push(requestIp);
  }

  db.get("users")
    .find({ email: user.email })
    .assign({ devices, ips })
    .write();

  // Short-lived access token + long-lived refresh token
  const accessToken = jwt.sign(
    { email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
  const refreshToken = jwt.sign(
    { email: user.email },
    REFRESH_SECRET,
    { expiresIn: "30d" }
  );

  // Persist latest refresh token (rotation anchor)
  db.get("users").find({ email: user.email }).assign({ refreshToken }).write();

  // ✅ Set refresh token as HttpOnly cookie (NOT in JSON)
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: IS_PROD,   // ✅ true in production (HTTPS). stays false in local dev
    sameSite: "Strict",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000
  });

  // ✅ NEW: issue CSRF cookie now that we have a session
  const csrf = issueCsrf(res);

  logEvent(
    email,
    "LOGIN_SUCCESS",
    `MFA passed, tokens issued. Device ${newDeviceAdded ? "added" : "recognized"}. IP: ${requestIp}`
  );
  bump("login_success");

  res.status(200).json({
    success: true,
    message: "Login successful",
    token: accessToken,
    role: user.role
  });
});

// REFRESH TOKEN (rotation) — reads cookie, rotates cookie
app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken; // ✅ read from cookie
  if (!refreshToken) {
    bump("refresh_401");
    return res.status(401).json({ message: "Refresh token missing" });
  }

  jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
    if (err) {
      bump("refresh_403");
      return res.status(403).json({ message: "Invalid or expired refresh token" });
    }

    const user = db.get("users").find({ email: decoded.email }).value();
    if (!user || user.refreshToken !== refreshToken) {
      bump("refresh_mismatch");
      return res.status(403).json({ message: "Refresh token mismatch" });
    }

    // Issue new pair (rotate)
    const newAccessToken = jwt.sign(
      { email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    const newRefreshToken = jwt.sign(
      { email: user.email },
      REFRESH_SECRET,
      { expiresIn: "30d" }
    );

    db.get("users").find({ email: user.email }).assign({ refreshToken: newRefreshToken }).write();

    // ✅ Rotate cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: "Strict",
      path: "/",
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    // ✅ Re-issue CSRF to keep it fresh
    issueCsrf(res);

    logEvent(user.email, "TOKEN_REFRESHED", "Refresh token rotated");
    bump("refresh_ok");

    res.json({ token: newAccessToken });
  });
});

// LOGOUT (invalidate refresh token) – still protected; clears cookie
app.post("/logout", verifyToken, (req, res) => {
  const email = req.user.email;
  db.get("users").find({ email }).assign({ refreshToken: null }).write();
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: "Strict",
    path: "/"
  });
  // optional: clear csrf cookie too
  res.clearCookie("csrf", { secure: IS_PROD, sameSite: "Strict", path: "/" });
  logEvent(email, "LOGOUT", "Refresh token cleared & cookie removed");
  res.json({ message: "Logged out successfully" });
});

// PROFILE (protected + device-bound)
app.get("/api/profile", verifyToken, enforceKnownDevice, (req, res) => {
  const user = db.get("users").find({ email: req.user.email }).value();
  if (!user) {
    logEvent(req.user.email, "PROFILE_FAILED", "User not found");
    return res.status(404).json({ message: "User not found" });
  }
  logEvent(req.user.email, "PROFILE_VIEW", "User accessed profile");
  res.json({
    message: "Access granted ✅",
    user: { name: user.name, email: user.email, role: user.role }
  });
});

// ADMIN: list users
app.get("/api/users", verifyToken, enforceKnownDevice, authorizeRoles("admin"), (req, res) => {
  logEvent(req.user.email, "ADMIN_VIEW_USERS");
  const users = db.get("users").map(u => ({
    name: u.name,
    email: u.email,
    role: u.role
  })).value();
  res.json(users);
});

// ADMIN: delete user
app.delete("/api/users/:email", verifyToken, enforceKnownDevice, authorizeRoles("admin"), (req, res) => {
  const { email } = req.params;
  db.get("users").remove({ email }).write();
  logEvent(req.user.email, "ADMIN_DELETE_USER", `Deleted: ${email}`);
  res.json({ message: `User ${email} deleted successfully` });
});

// ADMIN: update role
app.put("/api/users/:email", verifyToken, enforceKnownDevice, authorizeRoles("admin"), (req, res) => {
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

// ADMIN: view logs
app.get("/api/logs", verifyToken, enforceKnownDevice, authorizeRoles("admin"), (req, res) => {
  logEvent(req.user.email, "ADMIN_VIEW_LOGS");
  const logs = db.get("logs").value();
  res.json(logs);
});

// ✅ NEW: metrics readout for your dissertation figures
app.get("/metrics", verifyToken, enforceKnownDevice, authorizeRoles("admin"), (req, res) => {
  res.json(db.get("metrics").value());
});

// =================================================
// EMAIL TRANSPORTER for Forgot Password
// =================================================
// ✅ NOTE: you can move these to env vars too: MAIL_USER / MAIL_PASS
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER || "barathm0114@gmail.com",
    pass: process.env.MAIL_PASS || "ssyn wiep fwjs yuhw"
  }
});

// =================================================
// Forgot Password - Send Reset Email
// =================================================
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  const user = db.get("users").find({ email }).value();

  if (!user) {
    logEvent(email, "FORGOT_PASSWORD_FAILED", "Email not found");
    return res.status(404).json({ success: false, message: "User not found" });
  }

  const token = crypto.randomBytes(20).toString("hex");
  const expiresAt = Date.now() + 15 * 60 * 1000; // 15 min

  db.get("users").find({ email }).assign({ resetToken: token, resetExpires: expiresAt }).write();

  const resetLink = `http://localhost:3000/reset.html?token=${token}&email=${encodeURIComponent(email)}`;

  transporter.sendMail({
    from: '"Nostra Security" <yourgmail@gmail.com>',
    to: email,
    subject: "Password Reset Request",
    html: `
      <h3>Password Reset</h3>
      <p>You requested a password reset. Click the link below:</p>
      <a href="${resetLink}">${resetLink}</a>
      <p>This link will expire in 15 minutes.</p>
    `
  }, (err) => {
    if (err) {
      console.error("Email error:", err);
      return res.status(500).json({ success: false, message: "Failed to send reset email" });
    }
    logEvent(email, "FORGOT_PASSWORD_REQUEST", "Reset link sent by email");
    res.json({ success: true, message: "Reset link sent to your email" });
  });
});

// =================================================
// Reset Password
// =================================================
app.post("/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body;
  const user = db.get("users").find({ email }).value();

  if (!user || user.resetToken !== token || Date.now() > user.resetExpires) {
    logEvent(email, "RESET_PASSWORD_FAILED", "Invalid or expired token");
    return res.status(400).json({ success: false, message: "Invalid or expired token" });
    }

  const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

  db.get("users").find({ email }).assign({
    password: hashedPassword,
    resetToken: null,
    resetExpires: null
  }).write();

  logEvent(email, "RESET_PASSWORD_SUCCESS", "Password updated");
  res.json({ success: true, message: "Password updated successfully" });
});

// Start server
app.listen(PORT, () => console.log(` Server running at http://localhost:${PORT}`));
