console.log("login.js loaded");

document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("loginForm");

  if (!form) {
    console.error("Login form not found");
    return;
  }

  form.addEventListener("submit", async function (e) {
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

      if (response.ok && data.success) {
        console.log("Token received:", data.token);

        localStorage.setItem("jwtToken", data.token);
        localStorage.setItem("userRole", data.role);

        alert("Login successful! Redirecting...");
        window.location.href = "index.html";
      } else if (data.message === "User not found") {
        alert("User not found. Redirecting to registration...");
        window.location.href = "register.html";
      } else {
        alert("Login failed: " + data.message);
      }
    } catch (error) {
      alert("Unable to connect to server.");
      console.error("Error:", error);
    }
  });
});
