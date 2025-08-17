document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("registerForm");
  const roleSelect = document.getElementById("role");
  const adminSecretInput = document.getElementById("adminSecret");

  const mfaSetupDiv = document.getElementById("mfaSetup");
  const qrCodeImg = document.getElementById("qrCodeImg");
  const manualKey = document.getElementById("manualKey");
  const goToLoginBtn = document.getElementById("goToLogin");

  const ADMIN_SECRET_CODE = "barath123"; 

  // Show/Hide secret input based on role selection
  roleSelect.addEventListener("change", () => {
    if (roleSelect.value === "admin") {
      adminSecretInput.style.display = "block";
    } else {
      adminSecretInput.style.display = "none";
      adminSecretInput.value = "";
    }
  });

  form.addEventListener("submit", async function (e) {
    e.preventDefault();

    const name = document.getElementById("name").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const role = roleSelect.value;
    const adminSecret = adminSecretInput.value;

    // Check admin secret if registering as admin
    if (role === "admin" && adminSecret !== ADMIN_SECRET_CODE) {
      alert("Invalid Admin Secret Code!");
      return;
    }

    try {
      const response = await fetch("http://localhost:3000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password, role })
      });

      const data = await response.json();
      if (response.ok && data.success) {
        // Hide form, show MFA setup
        form.style.display = "none";
        mfaSetupDiv.style.display = "block";

        // Show QR code and manual key
        qrCodeImg.src = data.qrCodeUrl;
        manualKey.textContent = data.base32;

        // Button to login page
        goToLoginBtn.addEventListener("click", () => {
          window.location.href = "login.html";
        });
      } else {
        alert("Registration failed: " + (data.message || "Please try again."));
      }
    } catch (error) {
      alert("Server error: " + error.message);
      console.error(error);
    }
  });
});
