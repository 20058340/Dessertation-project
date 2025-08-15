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

      if (response.ok && data.otp_required) {
        alert("OTP sent! (Check console for demo)");
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

  // Step 2: Verify OTP
  otpForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const otp = document.getElementById("otp").value;

    try {
      const response = await fetch("http://localhost:3000/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: currentEmail, otp })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        localStorage.setItem("jwtToken", data.token);
        localStorage.setItem("userRole", data.role);

        alert("Login successful! Redirecting...");
        window.location.href = "index.html";
      } else {
        alert("OTP failed: " + data.message);
      }
    } catch (error) {
      alert("Unable to connect to server.");
      console.error("Error:", error);
    }
  });
});
