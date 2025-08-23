document.getElementById("forgotForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("email").value;

  const statusEl = document.getElementById("status");
  const linkBox = document.getElementById("resetLinkContainer");
  statusEl.textContent = "Sending...";
  linkBox.innerHTML = "";

  try {
    const response = await fetch("http://localhost:3000/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    });

    const data = await response.json();
    if (response.ok && data.success) {
      statusEl.textContent = "✅ Reset link sent to your email.";
      // (No inline link shown because you’re emailing it now)
    } else {
      statusEl.textContent = data.message || "Failed to send reset link.";
    }
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Error connecting to server.";
  }
});
