document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById('registerForm');

  if (!form) {
    console.error("Form with id 'registerForm' not found.");
    return;
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();

    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
      const response = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });

      const data = await response.json();

      if (response.ok) {
        alert('Registration successful. Redirecting to login...');
        window.location.href = 'login.html';
      } else {
        alert('Registration failed: ' + (data.message || 'Please try again.'));
      }

    } catch (error) {
      alert('Server error: ' + error.message);
      console.error(error);
    }
  });
});
