// ===========================
// admin.js (cleaned, CSP-safe)
// ===========================

// --- Normalize localStorage keys (once) ---
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

// --- Stable device id ---
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

// --- Cookie helper ---
function getCookie(name) {
  return document.cookie
    .split("; ")
    .find((r) => r.startsWith(name + "="))
    ?.split("=")[1];
}

// --- Central API wrapper ---
async function api(url, { method = "GET", body, headers = {} } = {}) {
  const h = { "Content-Type": "application/json", ...headers };
  h["X-Device-Id"] = DEVICE_ID;

  const token = localStorage.getItem("accessToken");
  if (token) h["Authorization"] = "Bearer " + token;

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

  if (res.status === 401) {
    const r = await fetch("/refresh", {
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
        return api(url, { method, body, headers });
      }
    }
  }
  return res;
}

// --- Access guard ---
const token = localStorage.getItem("accessToken");
const role = localStorage.getItem("userRole");
if (!token || role !== "admin") {
  alert("Access denied: Admins only");
  window.location.href = "login.html";
}

// --- Greet admin ---
api("/api/profile")
  .then((res) => {
    if (!res.ok) throw new Error("Unauthorized");
    return res.json();
  })
  .then((data) => {
    document.getElementById("adminUserInfo").innerText = `Hello, ${data.user.name} (Admin)`;
  })
  .catch(() => {
    alert("Session expired or device mismatch, please log in again.");
    window.location.href = "login.html";
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

  paginatedUsers.forEach((user) => {
    const row = document.createElement("tr");

    const roleSelect = document.createElement("select");
    ["user", "admin"].forEach((r) => {
      const opt = document.createElement("option");
      opt.value = r;
      opt.text = r.charAt(0).toUpperCase() + r.slice(1);
      if (user.role === r) opt.selected = true;
      roleSelect.appendChild(opt);
    });
    roleSelect.addEventListener("change", () => changeRole(user.email, roleSelect.value));

    const deleteBtn = document.createElement("button");
    deleteBtn.classList.add("delete-btn");
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => deleteUser(user.email));

    row.innerHTML = `<td>${user.name}</td><td>${user.email}</td>`;
    const roleCell = document.createElement("td");
    const actionCell = document.createElement("td");
    roleCell.appendChild(roleSelect);
    actionCell.appendChild(deleteBtn);
    row.appendChild(roleCell);
    row.appendChild(actionCell);
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
  api("/api/users")
    .then((res) => res.json())
    .then((users) => {
      usersData = users;
      displayUsers(usersData, currentPage);
    })
    .catch((e) => console.error(e));
}

function deleteUser(email) {
  if (!confirm(`Delete user ${email}?`)) return;
  api(`/api/users/${encodeURIComponent(email)}`, { method: "DELETE" })
    .then((res) => {
      if (res.ok) loadUsers();
      else throw new Error("Delete failed");
    })
    .catch((e) => alert(e.message));
}

function changeRole(email, newRole) {
  api(`/api/users/${encodeURIComponent(email)}`, {
    method: "PUT",
    body: { role: newRole },
  })
    .then((res) => {
      if (res.ok) loadUsers();
      else throw new Error("Role update failed");
    })
    .catch((e) => alert(e.message));
}

document.getElementById("searchInput")?.addEventListener("input", function () {
  const searchText = this.value.toLowerCase();
  const filtered = usersData.filter(
    (u) => u.name.toLowerCase().includes(searchText) || u.email.toLowerCase().includes(searchText)
  );
  displayUsers(filtered, 1);
});

// ========== LOGS ==========
let logsData = [];
const logsTableBody = document.querySelector("#logsTable tbody");

function loadLogs() {
  api("/api/logs")
    .then((res) => res.json())
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
      <td>${log.details || "-"}</td>`;
    logsTableBody.appendChild(row);
  });
}

document.getElementById("logSearchInput")?.addEventListener("input", function () {
  const searchText = this.value.toLowerCase();
  const filtered = logsData.filter(
    (l) =>
      (l.user || "").toLowerCase().includes(searchText) ||
      (l.action || "").toLowerCase().includes(searchText) ||
      (l.details || "").toLowerCase().includes(searchText)
  );
  displayLogs(filtered);
});

// CSV Export
document.getElementById("exportUsersBtn")?.addEventListener("click", () => {
  exportCSV(usersData, ["Name", "Email", "Role"], (u) => [u.name, u.email, u.role]);
});

document.getElementById("exportLogsBtn")?.addEventListener("click", () => {
  exportCSV(logsData, ["Timestamp", "User", "Action", "Details"], (l) => [
    l.timestamp,
    l.user,
    l.action,
    l.details || "",
  ]);
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

// Logout
document.getElementById("logoutBtn")?.addEventListener("click", async () => {
  try {
    await api("/logout", { method: "POST" });
  } catch {}
  localStorage.removeItem("accessToken");
  localStorage.removeItem("userRole");
  window.location.href = "login.html";
});

// Initial load
loadUsers();
