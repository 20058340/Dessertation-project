document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("registerForm");

  if (!form) {
    console.error("Form with id 'registerForm' not found.");
    return;
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();

    const name = document.getElementById("name").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const role = document.getElementById("role").value; // Get selected role

    try {
      const response = await fetch("http://localhost:3000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password, role })
      });

      const data = await response.json();
      if (response.ok) {
        alert(`Registration successful as ${role}. Redirecting to login...`);
        window.location.href = "login.html";
      } else {
        alert("Registration failed: " + (data.message || "Please try again."));
      }
    } catch (error) {
      alert("Server error: " + error.message);
      console.error(error);
    }
  });
});
