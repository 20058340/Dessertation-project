
console.log("login.js loaded");

(function () {
  // --- Stable deviceId for device binding ---
  function getOrCreateDeviceId() {
    let id = localStorage.getItem("deviceId");
    if (!id) {
      const parts = new Uint32Array(2);
      crypto.getRandomValues(parts);
      id = "dev_" + parts[0] + "-" + parts[1];
      localStorage.setItem("deviceId", id);
    }
    return id;
  }
  const deviceId = getOrCreateDeviceId();

  // --- cookie helper ---
  function getCookie(name) {
    return document.cookie
      .split("; ")
      .find((r) => r.startsWith(name + "="))
      ?.split("=")[1];
  }

  // --- central API wrapper used here too (adds device id; CSRF on writes; auto refresh) ---
  async function api(url, { method = "GET", body, headers = {} } = {}) {
    const h = { "Content-Type": "application/json", ...headers };

    // always send device id
    h["X-Device-Id"] = deviceId;

    const token = localStorage.getItem("accessToken");
    if (token) h["Authorization"] = "Bearer " + token;

    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      const csrf = getCookie("csrf");
      if (csrf) h["X-CSRF-Token"] = csrf;
    }

    const res = await fetch(url, {
      method,
      headers: h,
      credentials: "include",
      body: body ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401) {
      const r = await fetch("http://localhost:3000/refresh", {
        method: "POST",
        credentials: "include",
        headers: {
          "X-Device-Id": deviceId,
          "X-CSRF-Token": getCookie("csrf") || "",
          "Content-Type": "application/json",
        },
      });
      if (r.ok) {
        const data = await r.json();
        if (data?.token) {
          localStorage.setItem("accessToken", data.token);
          return api(url, { method, body, headers });
        }
      }
    }

    return res;
  }

  document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("loginForm");
    const otpForm = document.getElementById("otpForm");

    let currentEmail = "";

    //  Step 1: Login with email & password 
    loginForm?.addEventListener("submit", async function (e) {
      e.preventDefault();

      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;
      currentEmail = email;

      try {
        const response = await fetch("http://localhost:3000/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include", // not required but harmless
          body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (response.ok && data.mfa_required) {
          alert("Please open your Authenticator app and enter the 6-digit code.");
          loginForm.style.display = "none";
          otpForm.style.display = "block";
        } else {
          alert("Login failed: " + (data.message || "Unknown error"));
        }
      } catch (error) {
        alert("Unable to connect to server.");
        console.error("Error:", error);
      }
    });

    //  Step 2: Verify Authenticator code 
    otpForm?.addEventListener("submit", async function (e) {
      e.preventDefault();

      const otp = document.getElementById("otp").value.trim();

      try {
        const response = await fetch("http://localhost:3000/verify-mfa", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include", // set HttpOnly refresh cookie + CSRF cookie
          body: JSON.stringify({ email: currentEmail, token: otp, deviceId }),
        });

        const data = await response.json();

        if (response.ok && data.success) {
          // Store only the short-lived access token + role
          localStorage.setItem("accessToken", data.token);
          localStorage.setItem("userRole", data.role);

          alert("Login successful! Redirecting...");
          // if the user is admin, send them to admin page directly (optional)
            window.location.href = "index.html";
        } else {
          alert("Code verification failed: " + (data.message || "Unknown error"));
        }
      } catch (error) {
        alert("Unable to connect to server.");
        console.error("Error:", error);
      }
    });
  });

  /* Helper: Token Refresh (manual) */
  window.refreshAccessToken = async function () {
    try {
      const response = await fetch("http://localhost:3000/refresh", {
        method: "POST",
        credentials: "include",
        headers: {
          "X-Device-Id": deviceId,
          "X-CSRF-Token": getCookie("csrf") || "",
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();

      if (response.ok && data.token) {
        localStorage.setItem("accessToken", data.token);
        console.log("Access token refreshed");
        return data.token;
      } else {
        console.warn("Failed to refresh token:", data.message || "Unknown error");
        return null;
      }
    } catch (error) {
      console.error("Error refreshing token:", error);
      return null;
    }
  };
})();
