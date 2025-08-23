// ===========================
// admin.js (full)
// ===========================

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

// --- Stable device id for device binding ---
function getOrCreateDeviceId() {
  let id = localStorage.getItem("deviceId");
  if (!id) {
    if (window.crypto?.randomUUID) {
      id = crypto.randomUUID();
    } else {
      const arr = new Uint32Array(2);
      crypto.getRandomValues(arr);
      id = "dev_" + arr[0] + "-" + arr[1];
    }
    localStorage.setItem("deviceId", id);
  }
  return id;
}
const DEVICE_ID = getOrCreateDeviceId();

// --- cookie helper ---
function getCookie(name) {
  return document.cookie
    .split("; ")
    .find((r) => r.startsWith(name + "="))
    ?.split("=")[1];
}

// --- central API wrapper: always sends device id; adds CSRF on writes; auto-refresh on 401 ---
async function api(url, { method = "GET", body, headers = {} } = {}) {
  const h = { "Content-Type": "application/json", ...headers };

  // Always send device id (GET and POST)
  h["X-Device-Id"] = DEVICE_ID;

  // Bearer, if present
  const token = localStorage.getItem("accessToken");
  if (token) h["Authorization"] = "Bearer " + token;

  // CSRF for state-changing requests
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    const csrf = getCookie("csrf");
    if (csrf) h["X-CSRF-Token"] = csrf;
  }

  const res = await fetch(url, {
    method,
    headers: h,
    credentials: "include",
    body: body ? JSON.stringify(body) : undefined,
  });

  // try one automatic refresh on 401
  if (res.status === 401) {
    const r = await fetch("http://localhost:3000/refresh", {
      method: "POST",
      credentials: "include",
      headers: {
        "X-Device-Id": DEVICE_ID,
        "X-CSRF-Token": getCookie("csrf") || "",
        "Content-Type": "application/json",
      },
    });
    if (r.ok) {
      const data = await r.json();
      if (data?.token) {
        localStorage.setItem("accessToken", data.token);
        // retry original request once
        return api(url, { method, body, headers });
      }
    }
  }

  return res;
}

// --- access guard ---
const token = localStorage.getItem("accessToken");
const role = localStorage.getItem("userRole");
if (!token || role !== "admin") {
  alert("Access denied: Admins only");
  window.location.href = "login.html";
}

// --- greet admin (also confirms device binding) ---
api("http://localhost:3000/api/profile")
  .then((res) => {
    if (!res.ok) throw new Error("Unauthorized");
    return res.json();
  })
  .then((data) => {
    const el = document.getElementById("adminUserInfo");
    if (el) el.innerText = `Hello, ${data.user.name} (Admin)`;
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

  paginatedUsers.forEach((user) => {
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
    if (i === currentPage) btn.classList.add("active");
    btn.addEventListener("click", () => {
      currentPage = i;
      displayUsers(users, currentPage);
    });
    paginationDiv.appendChild(btn);
  }
}

function loadUsers() {
  api("http://localhost:3000/api/users")
    .then((res) => {
      if (!res.ok) throw new Error("Failed to load users");
      return res.json();
    })
    .then((users) => {
      usersData = users;
      displayUsers(usersData, currentPage);
    })
    .catch((e) => console.error(e));
}

window.deleteUser = function (email) {
  if (!confirm(`Delete user ${email}?`)) return;
  api(`http://localhost:3000/api/users/${encodeURIComponent(email)}`, {
    method: "DELETE",
  })
    .then((res) => {
      if (!res.ok) throw new Error("Delete failed");
      loadUsers();
    })
    .catch((e) => alert(e.message || "Delete failed"));
};

window.changeRole = function (email, newRole) {
  api(`http://localhost:3000/api/users/${encodeURIComponent(email)}`, {
    method: "PUT",
    body: { role: newRole },
  })
    .then((res) => {
      if (!res.ok) throw new Error("Role update failed");
      loadUsers();
    })
    .catch((e) => alert(e.message || "Role update failed"));
};

document.getElementById("searchInput")?.addEventListener("input", function () {
  const searchText = this.value.toLowerCase();
  const filtered = usersData.filter(
    (user) =>
      user.name.toLowerCase().includes(searchText) ||
      user.email.toLowerCase().includes(searchText)
  );
  displayUsers(filtered, 1);
});

// ========== LOGS ==========
let logsData = [];
const logsTableBody = document.querySelector("#logsTable tbody");

function loadLogs() {
  api("http://localhost:3000/api/logs")
    .then((res) => {
      if (!res.ok) throw new Error("Failed to load logs");
      return res.json();
    })
    .then((logs) => {
      logsData = logs;
      displayLogs(logsData);
    })
    .catch((e) => console.error(e));
}

function displayLogs(logs) {
  logsTableBody.innerHTML = "";
  logs.forEach((log) => {
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

document.getElementById("logSearchInput")?.addEventListener("input", function () {
  const searchText = this.value.toLowerCase();
  const filtered = logsData.filter(
    (log) =>
      (log.user || "").toLowerCase().includes(searchText) ||
      (log.action || "").toLowerCase().includes(searchText) ||
      ((log.details || "").toLowerCase().includes(searchText))
  );
  displayLogs(filtered);
});

// CSV Export (fixed mapping)
document.getElementById("exportUsersBtn")?.addEventListener("click", () => {
  exportCSV(
    usersData,
    ["Name", "Email", "Role"],
    (u) => [u.name, u.email, u.role]
  );
});

document.getElementById("exportLogsBtn")?.addEventListener("click", () => {
  exportCSV(
    logsData,
    ["Timestamp", "User", "Action", "Details"],
    (l) => [l.timestamp, l.user, l.action, l.details || ""]
  );
});

function exportCSV(data, headers, rowMapper) {
  if (!data?.length) return alert("No data to export");
  const rows = [headers.join(",")];
  data.forEach((item) => {
    const vals = rowMapper(item).map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`);
    rows.push(vals.join(","));
  });
  const blob = new Blob([rows.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "export.csv";
  a.click();
  URL.revokeObjectURL(url);
}

// Tabs
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "logsTab") loadLogs();
    else loadUsers();
  });
});

// Logout (use API so CSRF/device headers are sent)
document.getElementById("logoutBtn")?.addEventListener("click", async () => {
  try {
    const res = await api("http://localhost:3000/logout", { method: "POST" });
    // clear client state regardless
  } catch {}
  localStorage.removeItem("accessToken");
  localStorage.removeItem("userRole");
  // keep deviceId to maintain binding; remove only if you want to force re-bind
  // localStorage.removeItem("deviceId");
  window.location.href = "login.html";
});

// Initial load
loadUsers();
