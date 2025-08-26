
function getCookie(name) {
  return document.cookie.split("; ").find(r => r.startsWith(name + "="))?.split("=")[1];
}

// ensure stable device id
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

// tiny API wrapper: sends device, bearer; adds CSRF on writes; refresh once on 401/403
async function api(url, { method = "GET", headers = {}, body } = {}) {
  const h = { "Content-Type": "application/json", ...headers };
  const tok = localStorage.getItem("accessToken");
  if (tok) h["Authorization"] = "Bearer " + tok;
  h["X-Device-Id"] = DEVICE_ID;

  if (["POST","PUT","PATCH","DELETE"].includes(method)) {
    const csrf = getCookie("csrf");
    if (csrf) h["X-CSRF-Token"] = csrf;
  }

  let res = await fetch(url, {
    method,
    headers: h,
    credentials: "include",
    body: body ? JSON.stringify(body) : undefined
  });

  if (res.status === 401 || res.status === 403) {
    // try one refresh
    const r = await fetch("http://localhost:3000/refresh", {
      method: "POST",
      credentials: "include",
      headers: {
        "X-Device-Id": DEVICE_ID,
        "X-CSRF-Token": getCookie("csrf") || ""
      }
    });
    if (r.ok) {
      const data = await r.json().catch(() => ({}));
      if (data?.token) {
        localStorage.setItem("accessToken", data.token);
        h["Authorization"] = "Bearer " + data.token;
        res = await fetch(url, {
          method,
          headers: h,
          credentials: "include",
          body: body ? JSON.stringify(body) : undefined
        });
      }
    }
  }

  return res;
}

document.addEventListener("DOMContentLoaded", async () => {
  // side navbar toggles (replaces inline onclick="showNavbar()/closeNavbar()")
  const sidenav = document.querySelector(".side-navbar");
  const openBtn = document.getElementById("navbarToggle");
  const closeBtn = document.getElementById("sideClose");
  openBtn?.addEventListener("click", () => { if (sidenav) sidenav.style.left = "0"; });
  closeBtn?.addEventListener("click", () => { if (sidenav) sidenav.style.left = "-60%"; });

  // logout button (server + client clear)
  document.getElementById("logoutBtn")?.addEventListener("click", async () => {
    try { await api("http://localhost:3000/logout", { method: "POST" }); } catch {}
    localStorage.removeItem("accessToken");
    localStorage.removeItem("userRole");
    window.location.href = "login.html";
  });

  // auth guard
  const token = localStorage.getItem("accessToken");
  if (!token) {
    alert("No token found. Please login.");
    window.location.href = "login.html";
    return;
  }

  // fetch profile -> set greeting + show admin link if admin
  try {
    const res = await api("http://localhost:3000/api/profile");
    if (!res.ok) throw new Error(String(res.status));
    const data = await res.json();

    const userInfo = document.getElementById("userInfo");
    if (userInfo) userInfo.textContent = `Hello, ${data.user.name}!`;
    const role = data.user.role;
    localStorage.setItem("userRole", role);

    if (role === "admin") {
      const navbarLinks = document.querySelector(".navbar-links");
      const sideLinks   = document.querySelector(".side-navbar-links");

      if (navbarLinks && !navbarLinks.querySelector('a[href="admin.html"]')) {
        const p = document.createElement("p");
        p.classList.add("navbar-link");
        p.innerHTML = `<a href="admin.html">Admin Panel</a>`;
        navbarLinks.appendChild(p);
      }
      if (sideLinks && !sideLinks.querySelector('a[href="admin.html"]')) {
        const p = document.createElement("p");
        p.classList.add("side-navbar-link");
        p.innerHTML = `<a href="admin.html">Admin Panel</a>`;
        sideLinks.appendChild(p);
      }
    }
  } catch (e) {
    console.error("Access denied:", e);
    alert("Access denied (token invalid or device not recognized). Please login again.");
    localStorage.removeItem("accessToken");
    localStorage.removeItem("userRole");
    window.location.href = "login.html";
  }
});
