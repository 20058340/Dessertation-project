// --- Normalize/migrate localStorage keys (runs once) ---
(function normalizeAuthKeys() {
  const oldJwt = localStorage.getItem("jwtToken");
  if (oldJwt && !localStorage.getItem("accessToken")) {
    localStorage.setItem("accessToken", oldJwt);
    localStorage.removeItem("jwtToken");
  }

  const oldRole = localStorage.getItem("user");
  if (oldRole && !localStorage.getItem("userRole")) {
    localStorage.setItem("userRole", oldRole);
    localStorage.removeItem("user");
  }
})();

// 📌 Ensure deviceId exists (new for binding)
if (!localStorage.getItem("deviceId")) {
  localStorage.setItem("deviceId", crypto.randomUUID());
}

// Read tokens/role
const token = localStorage.getItem("accessToken");
const role  = localStorage.getItem("userRole");
const deviceId = localStorage.getItem("deviceId");

if (!token || role !== "admin") {
  alert("Access denied: Admins only");
  window.location.href = "login.html";
}

// Display admin's name
fetch("http://localhost:3000/api/profile", {
  headers: { 
    Authorization: "Bearer " + token,
    "X-Device-Id": deviceId     // 👈 send deviceId
  }
})
  .then(res => {
    if (!res.ok) throw new Error("Unauthorized");
    return res.json();
  })
  .then(data => {
    document.getElementById("adminUserInfo").innerText = `Hello, ${data.user.name} (Admin)`;
  })
  .catch(() => {
    alert("Session expired or device mismatch, please log in again.");
    window.location.href = "login.html";
  });

// ================== USERS ==================
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
    headers: { 
      Authorization: "Bearer " + token,
      "X-Device-Id": deviceId
    }
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
    headers: { 
      Authorization: "Bearer " + token,
      "X-Device-Id": deviceId
    }
  }).then(() => loadUsers());
}

window.changeRole = function(email, newRole) {
  fetch(`http://localhost:3000/api/users/${email}`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      Authorization: "Bearer " + token,
      "X-Device-Id": deviceId
    },
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
    headers: { 
      Authorization: "Bearer " + token,
      "X-Device-Id": deviceId
    }
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

// CSV Export
document.getElementById("exportUsersBtn")?.addEventListener("click", () => {
  exportCSV(usersData, ["Name", "Email", "Role"]);
});

document.getElementById("exportLogsBtn")?.addEventListener("click", () => {
  exportCSV(logsData, ["Timestamp", "User", "Action", "Details"]);
});

function exportCSV(data, headers) {
  if (!data.length) return alert("No data to export");
  const csvRows = [];
  csvRows.push(headers.join(","));
  data.forEach(item => {
    const values = headers.map(h => {
      const key = h.toLowerCase();
      return `"${item[key] || ""}"`;
    });
    csvRows.push(values.join(","));
  });
  const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "export.csv";
  a.click();
  URL.revokeObjectURL(url);
}

// Tabs
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

// Logout
document.getElementById("logoutBtn").addEventListener("click", () => {
  localStorage.removeItem("accessToken");
  localStorage.removeItem("refreshToken");
  localStorage.removeItem("userRole");
  localStorage.removeItem("deviceId");
  window.location.href = "login.html";
});

// Initial load
loadUsers();
