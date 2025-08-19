console.log("login.js loaded");

document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  const otpForm = document.getElementById("otpForm");

  let currentEmail = "";

  // Step 1: Login with email & password
  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    currentEmail = email;

    try {
      const response = await fetch("http://localhost:3000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok && data.mfa_required) {
        alert("Please open your Authenticator app and enter the 6-digit code.");
        loginForm.style.display = "none";
        otpForm.style.display = "block";
      } else {
        alert("Login failed: " + data.message);
      }
    } catch (error) {
      alert("Unable to connect to server.");
      console.error("Error:", error);
    }
  });

  // Step 2: Verify Authenticator code
  otpForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const otp = document.getElementById("otp").value;

    try {
      const response = await fetch("http://localhost:3000/verify-mfa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: currentEmail, token: otp })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Store both tokens
        localStorage.setItem("accessToken", data.token);
        localStorage.setItem("refreshToken", data.refreshToken);
        localStorage.setItem("userRole", data.role);

        alert("Login successful! Redirecting...");
        window.location.href = "index.html";
      } else {
        alert("Code verification failed: " + data.message);
      }
    } catch (error) {
      alert("Unable to connect to server.");
      console.error("Error:", error);
    }
  });
});

/* ===== Helper: Token Refresh ===== */
async function refreshAccessToken() {
  const refreshToken = localStorage.getItem("refreshToken");
  if (!refreshToken) {
    console.warn("No refresh token found. Please log in again.");
    return null;
  }

  try {
    const response = await fetch("http://localhost:3000/refresh-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      localStorage.setItem("accessToken", data.accessToken);
      console.log("✅ Access token refreshed");
      return data.accessToken;
    } else {
      console.warn("Failed to refresh token:", data.message);
      return null;
    }
  } catch (error) {
    console.error("Error refreshing token:", error);
    return null;
  }
}
