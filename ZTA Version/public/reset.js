const params = new URLSearchParams(window.location.search);
const token = params.get("token");
const email = params.get("email");

const statusEl = document.getElementById("status");
const formEl = document.getElementById("resetForm");

if (!token || !email) {
  statusEl.textContent = "Invalid reset link.";
  formEl.style.display = "none";
}

formEl.addEventListener("submit", async (e) => {
  e.preventDefault();

  const newPassword = document.getElementById("newPassword").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  if (newPassword !== confirmPassword) {
    statusEl.textContent = "Passwords do not match.";
    return;
  }

  statusEl.textContent = "Updating password...";

  try {
    const response = await fetch("http://localhost:3000/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, token, newPassword })
    });
    const data = await response.json();

    statusEl.textContent = data.message || "Unknown response";

    if (data.success) {
      setTimeout(() => {
        window.location.href = "login.html";
      }, 1500);
    }
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Error resetting password.";
  }
});
