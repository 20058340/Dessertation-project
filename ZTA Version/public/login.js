console.log("login.js loaded");

document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  const otpForm = document.getElementById("otpForm");

  let currentEmail = ""; // store email temporarily for OTP verification

  // Step 1: Email + Password
  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
      const response = await fetch("http://localhost:3000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok && data.otpSent) {
        alert("OTP sent to your email. Please enter it below.");
        currentEmail = email;

        loginForm.style.display = "none"; // hide login form
        otpForm.style.display = "block";  // show OTP form
      } else {
        alert("Login failed: " + data.message);
      }
    } catch (error) {
      alert("Unable to connect to server.");
      console.error("Error:", error);
    }
  });

  // Step 2: OTP Verification
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
        alert("OTP verification failed: " + data.message);
      }
    } catch (error) {
      alert("Unable to connect to server.");
      console.error("Error:", error);
    }
  });
});
