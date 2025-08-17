const token = localStorage.getItem("jwtToken");
const role = localStorage.getItem("userRole");

if (!token || role !== "admin") {
  alert("Access denied: Admins only");
  window.location.href = "login.html";
}

// Display admin's name
fetch("http://localhost:3000/api/profile", {
  headers: { Authorization: "Bearer " + token }
})
.then(res => res.json())
.then(data => {
  document.getElementById("adminUserInfo").innerText = `Hello, ${data.user.name} (Admin)`;
});

// ========== USERS ==========
let usersData = [];
let currentPage = 1;
const rowsPerPage = 5;
const usersTableBody = document.querySelector("#usersTable tbody");
const paginationDiv = document.getElementById("pagination");

function displayUsers(users, page) {
  usersTableBody.innerHTML = "";
  page--;
  const start = page * rowsPerPage;
  const end = start + rowsPerPage;
  const paginatedUsers = users.slice(start, end);

  paginatedUsers.forEach(user => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${user.name}</td>
      <td>${user.email}</td>
      <td>
        <select onchange="changeRole('${user.email}', this.value)">
          <option value="user" ${user.role === "user" ? "selected" : ""}>User</option>
          <option value="admin" ${user.role === "admin" ? "selected" : ""}>Admin</option>
        </select>
      </td>
      <td><button class="delete-btn" onclick="deleteUser('${user.email}')">Delete</button></td>
    `;
    usersTableBody.appendChild(row);
  });
  setupPagination(users);
}

function setupPagination(users) {
  paginationDiv.innerHTML = "";
  const pageCount = Math.ceil(users.length / rowsPerPage);
  for (let i = 1; i <= pageCount; i++) {
    const btn = document.createElement("button");
    btn.innerText = i;
    btn.classList.add(i === currentPage ? "active" : "");
    btn.addEventListener("click", () => {
      currentPage = i;
      displayUsers(users, currentPage);
    });
    paginationDiv.appendChild(btn);
  }
}

function loadUsers() {
  fetch("http://localhost:3000/api/users", {
    headers: { Authorization: "Bearer " + token }
  })
  .then(res => res.json())
  .then(users => {
    usersData = users;
    displayUsers(usersData, currentPage);
  });
}

window.deleteUser = function(email) {
  if (!confirm(`Delete user ${email}?`)) return;
  fetch(`http://localhost:3000/api/users/${email}`, {
    method: "DELETE",
    headers: { Authorization: "Bearer " + token }
  }).then(() => loadUsers());
}

window.changeRole = function(email, newRole) {
  fetch(`http://localhost:3000/api/users/${email}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    body: JSON.stringify({ role: newRole })
  }).then(() => loadUsers());
}

document.getElementById("searchInput").addEventListener("input", function() {
  const searchText = this.value.toLowerCase();
  const filtered = usersData.filter(user =>
    user.name.toLowerCase().includes(searchText) ||
    user.email.toLowerCase().includes(searchText)
  );
  displayUsers(filtered, 1);
});

// ========== LOGS ==========
let logsData = [];
const logsTableBody = document.querySelector("#logsTable tbody");

function loadLogs() {
  fetch("http://localhost:3000/api/logs", {
    headers: { Authorization: "Bearer " + token }
  })
  .then(res => res.json())
  .then(logs => {
    logsData = logs;
    displayLogs(logsData);
  });
}

function displayLogs(logs) {
  logsTableBody.innerHTML = "";
  logs.forEach(log => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${new Date(log.timestamp).toLocaleString()}</td>
      <td>${log.user}</td>
      <td>${log.action}</td>
      <td>${log.details || "-"}</td>
    `;
    logsTableBody.appendChild(row);
  });
}

document.getElementById("logSearchInput").addEventListener("input", function() {
  const searchText = this.value.toLowerCase();
  const filtered = logsData.filter(log =>
    log.user.toLowerCase().includes(searchText) ||
    log.action.toLowerCase().includes(searchText) ||
    (log.details && log.details.toLowerCase().includes(searchText))
  );
  displayLogs(filtered);
});

// ========== Tabs ==========
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "logsTab") loadLogs();
    else loadUsers();
  });
});

// ========== Logout ==========
document.getElementById("logoutBtn").addEventListener("click", () => {
  localStorage.removeItem("jwtToken");
  localStorage.removeItem("userRole");
  window.location.href = "login.html";
});

// Load default tab
loadUsers();
