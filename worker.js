/**
 * Jewish Music Downloader — Cloudflare Worker edition.
 *
 * A web version of the original command-line Python downloader, running on
 * Cloudflare Workers. The Worker talks to the GraphQL music API and proxies
 * downloads.
 *
 * Your private values are read from Cloudflare SECRETS (env.API_URL,
 * env.AUDIO_API_BASE, env.USER_TOKEN), set with `wrangler secret put`.
 * They are encrypted at Cloudflare, never stored in this repo, and the
 * token is never sent to the browser (downloads are signed here).
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Password protection is ON when the SITE_PASSWORD secret is set.
    const locked = !!env.SITE_PASSWORD;

    try {
      // Login / logout are always reachable.
      if (path === "/api/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }
      if (path === "/api/logout") {
        return logout();
      }
      if (path === "/api/signup" && request.method === "POST") {
        return await handleSignup(request, env);
      }

      const authed = !locked || (await isAuthed(request, env));

      if (path === "/" || path === "/index.html") {
        return html(authed ? PAGE : LOGIN);
      }
      if (path === "/api/status") {
        return json({
          apiUrl: !!env.API_URL,
          audioBase: !!env.AUDIO_API_BASE,
          token: hasAuth(env),
          autoLogin: canFirebase(env) || canAutoLogin(env),
          firebase: canFirebase(env),
          configured: !!(env.API_URL && env.AUDIO_API_BASE && hasAuth(env)),
          locked: locked,
          authed: authed,
          kv: hasStore(env),
          d1: !!env.DB,
        });
      }
      if (path === "/api/config") {
        return json(await getConfig(env));
      }

      // Everything below requires a login when the site is locked.
      if (!authed) {
        return json({ error: "Please log in.", needLogin: true }, 401);
      }

      if (path === "/api/admin/list" && request.method === "POST") {
        return await handleAdminList(request, env);
      }
      if (path === "/api/admin/add" && request.method === "POST") {
        return await handleAdminAdd(request, env);
      }
      if (path === "/api/admin/remove" && request.method === "POST") {
        return await handleAdminRemove(request, env);
      }
      if (path === "/api/admin/config" && request.method === "POST") {
        return await handleAdminConfig(request, env);
      }
      if (path === "/api/me") {
        return await handleMe(request, env);
      }
      if (path === "/api/me/password" && request.method === "POST") {
        return await handleMePassword(request, env);
      }
      if (path === "/api/pending") {
        return await handlePending(request, env);
      }
      if (path === "/api/presence" && request.method === "POST") {
        return await handlePresence(request, env);
      }
      if (path === "/api/admin/presence" && request.method === "POST") {
        return await handleAdminPresence(request, env);
      }
      if (path === "/api/admin/users" && request.method === "POST") {
        return await handleAdminUsers(request, env);
      }
      if (path === "/api/admin/user" && request.method === "POST") {
        return await handleAdminUser(request, env);
      }
      if (path === "/api/artists" && request.method === "POST") {
        return await handleArtists(env);
      }
      if (path === "/api/artist" && request.method === "POST") {
        return await handleArtist(request, env);
      }
      if (path === "/api/new" && request.method === "POST") {
        return await handleNew(env);
      }
      if (path === "/api/albums" && request.method === "POST") {
        return await handleAlbumsPage(request, env);
      }
      if (path === "/api/check") {
        return await handleCheck(env);
      }
      if (path === "/api/schema") {
        return await handleSchema(env);
      }
      if (path === "/api/schema/full") {
        return await handleFullSchema(env);
      }
      if (path === "/api/query" && request.method === "POST") {
        return await handleRawQuery(request, env);
      }
      if (path === "/api/authquery" && request.method === "POST") {
        return await handleAuthQuery(request, env);
      }
      if (path === "/api/play") {
        return await handlePlay(url, request, env);
      }
      if (path === "/api/download") {
        return await handleDownload(url, env);
      }
      return new Response("Not found", { status: 404 });
    } catch (err) {
      return json({ error: "Server error: " + (err && err.message) }, 500);
    }
  },
};

// --------------------------------------------------------------------------- //
// Access control (optional): active only when the SITE_PASSWORD secret is set.
// Only people you give the password to can open the site.
// --------------------------------------------------------------------------- //
async function sha256hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function authToken(env) {
  // A non-reversible token derived from the password; safe to store in a cookie.
  return await sha256hex("zing-auth-v1:" + (env.SITE_PASSWORD || ""));
}

function parseCookies(request) {
  const out = {};
  const h = request.headers.get("Cookie") || "";
  h.split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

async function isAuthed(request, env) {
  if (!env.SITE_PASSWORD) return true;
  const c = parseCookies(request).auth;
  return !!c && c === (await authToken(env));
}

async function handleLogin(request, env) {
  if (!env.SITE_PASSWORD) return json({ ok: true });
  const body = await request.json().catch(() => ({}));
  const email = (body.email || "").toString().trim().toLowerCase();
  const pw = (body.password || "").toString();

  // Email + password login (a user account).
  if (email) {
    const u = await getUserByEmail(env, email);
    if (!u || u.pass !== (await passHash(email, pw))) {
      return json({ error: "Wrong email or password." }, 401);
    }
    if (u.status === "suspended") return json({ error: "This account has been suspended." }, 403);
    if (u.status !== "approved") {
      return json({ error: u.status === "rejected" ? "This account was not approved." : "Your account is waiting for approval." }, 403);
    }
    return await loginResponse(env, String(u.id));
  }

  // Master password or an access code.
  if (pw && (pw === env.SITE_PASSWORD || (await codeMatches(env, pw)))) {
    return await loginResponse(env, pw === env.SITE_PASSWORD ? "admin" : "");
  }
  return json({ error: "Wrong password." }, 401);
}

function logout() {
  const h = new Headers({ Location: "/" });
  h.append("Set-Cookie", "auth=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  h.append("Set-Cookie", "uid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  return new Response(null, { status: 302, headers: h });
}

// --------------------------------------------------------------------------- //
// Storage for accounts + site settings. Uses a Cloudflare D1 SQL database
// (binding DB) when one is bound, otherwise a KV namespace (binding ZING_KV).
// With either bound, the owner can manage access codes and app settings from
// the in-app admin screen. Any stored code — or the master SITE_PASSWORD —
// can sign in. Managing anything requires the master password.
// --------------------------------------------------------------------------- //
const CODES_KEY = "access_codes";
const CONFIG_KEY = "site_config";
const CONFIG_FEATURES = ["banners", "albums", "popular", "search", "genres", "categories", "playlists", "artists", "stories", "downloads", "favorites"];
const CONFIG_ACCENTS = ["", "purple", "blue", "green", "red", "gold", "teal"];

function hasStore(env) {
  return !!(env.DB || env.ZING_KV);
}

let D1_READY = false;
async function ensureD1(env) {
  if (!env.DB || D1_READY) return;
  try {
    await env.DB.batch([
      env.DB.prepare("CREATE TABLE IF NOT EXISTS accounts (code TEXT PRIMARY KEY, name TEXT, added INTEGER)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, phone TEXT, pass TEXT, photo TEXT, status TEXT, created INTEGER)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS presence (uid TEXT PRIMARY KEY, name TEXT, view TEXT, seen INTEGER)"),
    ]);
    // Best-effort migrations for columns added later (ignored if they exist).
    for (const a of ["ALTER TABLE users ADD COLUMN name TEXT", "ALTER TABLE users ADD COLUMN nodl INTEGER"]) {
      try { await env.DB.prepare(a).run(); } catch (e) { /* column already exists */ }
    }
    D1_READY = true;
  } catch (e) { /* ignore; calls below will surface errors */ }
}

async function getCodes(env) {
  if (env.DB) {
    await ensureD1(env);
    try {
      const r = await env.DB.prepare("SELECT code, name, added FROM accounts ORDER BY added").all();
      return (r.results || []).map((x) => ({ code: x.code, name: x.name, added: x.added }));
    } catch (e) { return []; }
  }
  if (env.ZING_KV) {
    try {
      const raw = await env.ZING_KV.get(CODES_KEY);
      const list = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list : [];
    } catch (e) { return []; }
  }
  return null; // no store bound → feature unavailable
}

async function saveCodes(env, list) {
  if (env.DB) {
    await ensureD1(env);
    const stmts = [env.DB.prepare("DELETE FROM accounts")];
    list.forEach((c) => {
      stmts.push(env.DB.prepare("INSERT OR REPLACE INTO accounts (code, name, added) VALUES (?, ?, ?)")
        .bind(c.code, c.name || "", c.added || Date.now()));
    });
    await env.DB.batch(stmts);
    return;
  }
  if (env.ZING_KV) {
    await env.ZING_KV.put(CODES_KEY, JSON.stringify(list));
  }
}

async function codeMatches(env, pw) {
  const codes = await getCodes(env);
  if (!codes) return false;
  return codes.some((c) => c && typeof c.code === "string" && c.code === pw);
}

function isAdmin(env, body) {
  return !!env.SITE_PASSWORD && (body.admin || "").toString() === env.SITE_PASSWORD;
}

// --------------------------------------------------------------------------- //
// Site settings (admin-controlled, shared for everyone): app name, an
// announcement, and feature on/off toggles. Stored in D1 or KV so the whole
// site picks them up. Reads are public (no secrets); writes need the master
// password.
// --------------------------------------------------------------------------- //
async function getConfig(env) {
  const out = { appName: "", announcement: "", theme: "", lang: "", accent: "", features: {} };
  let raw = null;
  if (env.DB) {
    await ensureD1(env);
    try {
      const r = await env.DB.prepare("SELECT v FROM settings WHERE k = ?").bind(CONFIG_KEY).first();
      raw = r ? r.v : null;
    } catch (e) { /* ignore */ }
  } else if (env.ZING_KV) {
    try { raw = await env.ZING_KV.get(CONFIG_KEY); } catch (e) { /* ignore */ }
  }
  try {
    const c = raw ? JSON.parse(raw) : {};
    if (c && typeof c === "object") {
      out.appName = typeof c.appName === "string" ? c.appName : "";
      out.announcement = typeof c.announcement === "string" ? c.announcement : "";
      out.theme = (c.theme === "dark" || c.theme === "light") ? c.theme : "";
      out.lang = (c.lang === "en" || c.lang === "he") ? c.lang : "";
      out.accent = CONFIG_ACCENTS.indexOf(c.accent) > 0 ? c.accent : "";
      if (c.features && typeof c.features === "object") out.features = c.features;
    }
  } catch (e) { /* ignore */ }
  return out;
}

async function saveConfig(env, cfg) {
  const s = JSON.stringify(cfg);
  if (env.DB) {
    await ensureD1(env);
    await env.DB.prepare("INSERT OR REPLACE INTO settings (k, v) VALUES (?, ?)").bind(CONFIG_KEY, s).run();
    return;
  }
  if (env.ZING_KV) await env.ZING_KV.put(CONFIG_KEY, s);
}

async function handleAdminConfig(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!isAdmin(env, body)) return json({ error: "Wrong password." }, 403);
  if (!hasStore(env)) return json({ error: "Settings storage is not set up yet." }, 400);
  const inC = (body.config && typeof body.config === "object") ? body.config : {};
  const clean = {
    appName: (inC.appName || "").toString().trim().slice(0, 60),
    announcement: (inC.announcement || "").toString().trim().slice(0, 500),
    theme: (inC.theme === "dark" || inC.theme === "light") ? inC.theme : "",
    lang: (inC.lang === "en" || inC.lang === "he") ? inC.lang : "",
    accent: CONFIG_ACCENTS.indexOf(inC.accent) > 0 ? inC.accent : "",
    features: {},
  };
  const inF = (inC.features && typeof inC.features === "object") ? inC.features : {};
  CONFIG_FEATURES.forEach((k) => { clean.features[k] = inF[k] !== false; });
  await saveConfig(env, clean);
  return json({ ok: true, config: clean });
}

// GET the list of access codes (admin only). Reports whether a store is set up.
async function handleAdminList(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!isAdmin(env, body)) return json({ error: "Wrong password." }, 403);
  if (!hasStore(env)) return json({ kv: false, codes: [] });
  const codes = await getCodes(env);
  return json({ kv: true, codes: codes || [] });
}

// Add (or update) a named access code (admin only).
async function handleAdminAdd(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!isAdmin(env, body)) return json({ error: "Wrong password." }, 403);
  if (!hasStore(env)) return json({ error: "Account storage is not set up yet." }, 400);
  const name = (body.name || "").toString().trim().slice(0, 60);
  const code = (body.code || "").toString().trim();
  if (!code) return json({ error: "Enter a code." }, 400);
  if (code.length < 3) return json({ error: "Use at least 3 characters." }, 400);
  if (code === env.SITE_PASSWORD) return json({ error: "That is the main password. Pick a different code." }, 400);
  const codes = (await getCodes(env)) || [];
  const existing = codes.find((c) => c && c.code === code);
  if (existing) {
    existing.name = name || existing.name;
  } else {
    codes.push({ name: name || "Someone", code: code, added: Date.now() });
  }
  await saveCodes(env, codes);
  return json({ ok: true, codes });
}

// Remove an access code by its value (admin only).
async function handleAdminRemove(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!isAdmin(env, body)) return json({ error: "Wrong password." }, 403);
  if (!hasStore(env)) return json({ error: "Account storage is not set up yet." }, 400);
  const code = (body.code || "").toString();
  const codes = (await getCodes(env)) || [];
  const next = codes.filter((c) => !(c && c.code === code));
  await saveCodes(env, next);
  return json({ ok: true, codes: next });
}

// --------------------------------------------------------------------------- //
// User accounts (D1 only): people request access by signing up with an email,
// phone, password and a selfie photo; the owner approves them from the Admin
// panel. Approved users sign in with email + password. The owner can also
// create approved accounts directly (no photo). Passwords are stored hashed.
// --------------------------------------------------------------------------- //
async function passHash(email, password) {
  return await sha256hex("u1:" + email + ":" + password);
}
async function uidToken(env, id) {
  return id + "." + (await sha256hex("uid:" + id + ":" + (env.SITE_PASSWORD || "")));
}
async function verifyUid(env, val) {
  if (!val) return null;
  const i = val.lastIndexOf(".");
  if (i < 0) return null;
  const id = val.slice(0, i);
  if (val.slice(i + 1) === (await sha256hex("uid:" + id + ":" + (env.SITE_PASSWORD || "")))) return id;
  return null;
}
async function loginResponse(env, uid) {
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  h.append("Set-Cookie", "auth=" + (await authToken(env)) + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000");
  h.append("Set-Cookie", "uid=" + (uid ? await uidToken(env, uid) : "") + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000");
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: h });
}
async function getUserByEmail(env, email) {
  if (!env.DB) return null;
  await ensureD1(env);
  try { return await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first(); } catch (e) { return null; }
}
async function getUserById(env, id) {
  if (!env.DB) return null;
  await ensureD1(env);
  try { return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(Number(id)).first(); } catch (e) { return null; }
}
function validEmail(e) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e); }

async function handleSignup(request, env) {
  if (!env.DB) return json({ error: "Sign-up is not set up yet (needs a D1 database)." }, 400);
  await ensureD1(env);
  const b = await request.json().catch(() => ({}));
  const name = (b.name || "").toString().trim().slice(0, 80);
  const email = (b.email || "").toString().trim().toLowerCase();
  const phone = (b.phone || "").toString().trim();
  const password = (b.password || "").toString();
  const photo = (b.photo || "").toString();
  if (name.length < 2) return json({ error: "Enter your full name." }, 400);
  if (!validEmail(email)) return json({ error: "Enter a valid email address." }, 400);
  if (phone.replace(/\D/g, "").length < 6) return json({ error: "Enter a valid phone number." }, 400);
  if (password.length < 4) return json({ error: "Password must be at least 4 characters." }, 400);
  if (!/^data:image\/(png|jpe?g|webp);base64,/.test(photo)) return json({ error: "A selfie photo is required." }, 400);
  if (photo.length > 400000) return json({ error: "Photo is too large — please try again." }, 400);
  if (await getUserByEmail(env, email)) return json({ error: "An account with this email already exists." }, 400);
  try {
    await env.DB.prepare("INSERT INTO users (name, email, phone, pass, photo, status, created) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(name, email, phone, await passHash(email, password), photo, "pending", Date.now()).run();
  } catch (e) { return json({ error: "Could not send the request." }, 500); }
  return json({ ok: true });
}

async function handleMe(request, env) {
  const id = await verifyUid(env, parseCookies(request).uid);
  if (id === "admin") return json({ admin: true, name: "Owner" });
  if (!id) return json({ user: null });
  const u = await getUserById(env, id);
  if (!u) return json({ user: null });
  return json({ user: { id: u.id, email: u.email, phone: u.phone, photo: u.photo, name: u.name || (u.email || "").split("@")[0], nodl: !!u.nodl } });
}

// Change your own password (must be signed in as a user account).
async function handleMePassword(request, env) {
  const id = await verifyUid(env, parseCookies(request).uid);
  if (!id || id === "admin" || !env.DB) return json({ error: "Not available for this login." }, 400);
  const b = await request.json().catch(() => ({}));
  const u = await getUserById(env, id);
  if (!u) return json({ error: "Account not found." }, 404);
  if (u.pass !== (await passHash(u.email, (b.old || "").toString()))) return json({ error: "Current password is wrong." }, 403);
  const np = (b.new || "").toString();
  if (np.length < 4) return json({ error: "New password must be at least 4 characters." }, 400);
  await env.DB.prepare("UPDATE users SET pass = ? WHERE id = ?").bind(await passHash(u.email, np), Number(id)).run();
  return json({ ok: true });
}

// Pending-request count, for the owner's badge.
async function handlePending(request, env) {
  const id = await verifyUid(env, parseCookies(request).uid);
  if (id !== "admin" || !env.DB) return json({ pending: 0, admin: id === "admin" });
  await ensureD1(env);
  try {
    const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE status = 'pending'").first();
    return json({ pending: (r && r.n) || 0, admin: true });
  } catch (e) { return json({ pending: 0, admin: true }); }
}

async function handleAdminUsers(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!isAdmin(env, b)) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "Accounts need a D1 database.", d1: false }, 400);
  await ensureD1(env);
  const r = await env.DB.prepare("SELECT id, name, email, phone, photo, status, nodl, created FROM users ORDER BY created DESC").all();
  return json({ users: r.results || [] });
}

async function handleAdminUser(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!isAdmin(env, b)) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "Accounts need a D1 database." }, 400);
  await ensureD1(env);
  const action = (b.action || "").toString();
  const id = Number(b.id);
  if (action === "approve") { await env.DB.prepare("UPDATE users SET status='approved' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "reject") { await env.DB.prepare("UPDATE users SET status='rejected' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "suspend") { await env.DB.prepare("UPDATE users SET status='suspended' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "unsuspend") { await env.DB.prepare("UPDATE users SET status='approved' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "remove") { await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "nodl") { await env.DB.prepare("UPDATE users SET nodl=? WHERE id=?").bind(b.value ? 1 : 0, id).run(); return json({ ok: true }); }
  if (action === "resetpw") {
    const np = (b.password || "").toString();
    if (np.length < 4) return json({ error: "Password must be at least 4 characters." }, 400);
    const u = await getUserById(env, id);
    if (!u) return json({ error: "Account not found." }, 404);
    await env.DB.prepare("UPDATE users SET pass=? WHERE id=?").bind(await passHash(u.email, np), id).run();
    return json({ ok: true });
  }
  if (action === "create") {
    const name = (b.name || "").toString().trim().slice(0, 80);
    const email = (b.email || "").toString().trim().toLowerCase();
    const phone = (b.phone || "").toString().trim();
    const password = (b.password || "").toString();
    if (!validEmail(email)) return json({ error: "Enter a valid email." }, 400);
    if (password.length < 4) return json({ error: "Password must be at least 4 characters." }, 400);
    if (await getUserByEmail(env, email)) return json({ error: "That email already exists." }, 400);
    await env.DB.prepare("INSERT INTO users (name, email, phone, pass, photo, status, created) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(name, email, phone, await passHash(email, password), "", "approved", Date.now()).run();
    return json({ ok: true });
  }
  return json({ error: "Unknown action." }, 400);
}

// --------------------------------------------------------------------------- //
// Live presence: each open app sends a heartbeat with what it is doing; the
// owner can see who is on the site right now and their current activity.
// --------------------------------------------------------------------------- //
async function presenceName(env, request) {
  const id = await verifyUid(env, parseCookies(request).uid);
  if (id === "admin") return "Owner";
  if (id) { const u = await getUserById(env, id); return u ? (u.name || u.email) : "User"; }
  return "Guest";
}

async function handlePresence(request, env) {
  if (!env.DB) return json({ ok: false });
  await ensureD1(env);
  const b = await request.json().catch(() => ({}));
  const cid = (b.cid || "").toString().slice(0, 64);
  if (!cid) return json({ ok: false });
  const view = (b.view || "").toString().slice(0, 80);
  const name = await presenceName(env, request);
  try {
    await env.DB.prepare("INSERT OR REPLACE INTO presence (uid, name, view, seen) VALUES (?, ?, ?, ?)")
      .bind(cid, name, view, Date.now()).run();
  } catch (e) { /* ignore */ }
  return json({ ok: true });
}

async function handleAdminPresence(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!isAdmin(env, b)) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ online: [], now: Date.now() });
  await ensureD1(env);
  const now = Date.now();
  try { await env.DB.prepare("DELETE FROM presence WHERE seen < ?").bind(now - 3600000).run(); } catch (e) { /* ignore */ }
  const r = await env.DB.prepare("SELECT name, view, seen FROM presence WHERE seen >= ? ORDER BY seen DESC").bind(now - 90000).all();
  return json({ online: r.results || [], now });
}

// --------------------------------------------------------------------------- //
// Auto-login (optional): when ZING_EMAIL + ZING_PASSWORD are set, the Worker
// logs in itself to get a fresh session token, so the token never has to be
// updated by hand. Falls back to the USER_TOKEN secret when auto-login is off.
// --------------------------------------------------------------------------- //
let CACHED_TOKEN = null; // per-isolate cache of the latest session token
let CACHED_EXP = 0; // epoch seconds when the cached token expires (0 = unknown)

function canFirebase(env) {
  return !!(env.FIREBASE_API_KEY && env.FIREBASE_REFRESH_TOKEN);
}

function canAutoLogin(env) {
  return !!(env.API_URL && env.ZING_EMAIL && env.ZING_PASSWORD);
}

function hasAuth(env) {
  return !!(env.USER_TOKEN || canFirebase(env) || canAutoLogin(env));
}

// Exchange the long-lived Firebase refresh token for a fresh ID token.
// Google's endpoint has a valid certificate, so Cloudflare can reach it.
async function firebaseRefresh(env) {
  if (!canFirebase(env)) return { ok: false, error: "FIREBASE_API_KEY / FIREBASE_REFRESH_TOKEN not set." };
  try {
    const r = await fetch(
      "https://securetoken.googleapis.com/v1/token?key=" + encodeURIComponent(env.FIREBASE_API_KEY),
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body:
          "grant_type=refresh_token&refresh_token=" +
          encodeURIComponent(env.FIREBASE_REFRESH_TOKEN),
      }
    );
    const d = await r.json().catch(() => ({}));
    if (!r.ok || d.error) {
      const msg = d.error && (d.error.message || d.error);
      return { ok: false, error: msg || "Refresh returned " + r.status + "." };
    }
    const idt = d.id_token || d.access_token;
    if (idt) {
      CACHED_TOKEN = idt;
      CACHED_EXP = Math.floor(Date.now() / 1000) + (parseInt(d.expires_in, 10) || 3600);
      return { ok: true, token: idt };
    }
    return { ok: false, error: "No id_token in the refresh response." };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}

async function zingLogin(env) {
  if (!canAutoLogin(env)) return { ok: false, error: "ZING_EMAIL / ZING_PASSWORD not set." };
  const query =
    "mutation($e: String!, $p: String!) { authenticateUserWithPassword(email: $e, password: $p) { __typename ... on UserAuthenticationWithPasswordSuccess { sessionToken } ... on UserAuthenticationWithPasswordFailure { message } } }";
  try {
    const r = await fetch(env.API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, variables: { e: env.ZING_EMAIL, p: env.ZING_PASSWORD } }),
    });
    if (!r.ok) return { ok: false, error: "Login endpoint returned " + r.status + "." };
    const d = await r.json().catch(() => ({}));
    if (d && d.errors && d.errors.length) {
      return { ok: false, error: (d.errors[0] && d.errors[0].message) || "GraphQL error." };
    }
    const res = (d && d.data && d.data.authenticateUserWithPassword) || {};
    if (res.sessionToken) {
      CACHED_TOKEN = res.sessionToken;
      CACHED_EXP = 0; // unknown expiry; the 403-retry covers staleness
      return { ok: true, token: res.sessionToken };
    }
    return { ok: false, error: res.message || "Login failed (no session token returned)." };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}

// Ask the GraphQL schema which login-related mutations exist (to find the
// right one when our guess fails). Returns a list like ["name(arg, arg)"].
async function introspectAuthMutations(env) {
  const q =
    "query { __schema { mutationType { fields { name args { name } } } } }";
  try {
    const r = await fetch(env.API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: q }),
    });
    if (!r.ok) return { error: "introspection returned " + r.status };
    const d = await r.json().catch(() => ({}));
    if (d && d.errors && d.errors.length) return { error: "introspection blocked" };
    const fields =
      (((d.data || {}).__schema || {}).mutationType || {}).fields || [];
    const re = /auth|login|session|token|sign|password/i;
    const cand = fields
      .filter((f) => re.test(f.name))
      .map((f) => f.name + "(" + (f.args || []).map((a) => a.name).join(", ") + ")");
    return { total: fields.length, candidates: cand };
  } catch (e) {
    return { error: String((e && e.message) || e) };
  }
}

// List the top-level Query fields AND the content types' fields (the full
// "structure" of the API), so the UI can show real names, durations, etc.
async function handleSchema(env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const q =
    "query { __schema { " +
    "queryType { fields { name args { name } type { name kind ofType { name kind ofType { name kind ofType { name } } } } } } " +
    "types { name kind fields { name type { name kind ofType { name kind ofType { name kind ofType { name } } } } } } " +
    "} }";
  try {
    const r = await fetch(env.API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: q }),
    });
    const d = await r.json().catch(() => ({}));
    if (d && d.errors && d.errors.length) {
      return json({ error: (d.errors[0] && d.errors[0].message) || "introspection blocked" }, 502);
    }
    const schema = (d.data || {}).__schema || {};
    const tn = (t) => {
      while (t && !t.name && t.ofType) t = t.ofType;
      return t ? t.name : null;
    };
    const queryFields = ((schema.queryType || {}).fields || []).map((f) => ({
      name: f.name,
      args: (f.args || []).map((a) => a.name),
      returns: tn(f.type),
    }));
    // Content types worth showing (real track/album/artist fields, etc.).
    const wanted = /track|album|artist|song|genre|playlist|podcast|episode|profile/i;
    const types = {};
    (schema.types || []).forEach((t) => {
      if (t.kind !== "OBJECT" || !t.name || t.name.indexOf("__") === 0) return;
      if (!wanted.test(t.name)) return;
      const fs = (t.fields || []).map((f) => f.name + ": " + (tn(f.type) || "?"));
      if (fs.length) types[t.name] = fs;
    });
    return json({ queryFields, types });
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 502);
  }
}

// Full structure export: the COMPLETE API schema (every query, every type
// with its fields and types, input filters, and enums) as one readable text
// blob. Lets the whole Zing system/structure be captured and rebuilt.
const TYPE_REF =
  "kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } }";

function renderGqlType(t) {
  if (!t) return "?";
  if (t.kind === "NON_NULL") return renderGqlType(t.ofType) + "!";
  if (t.kind === "LIST") return "[" + renderGqlType(t.ofType) + "]";
  return t.name || "?";
}

async function handleFullSchema(env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const q =
    "query { __schema { queryType { name } mutationType { name } types { " +
    "kind name " +
    "fields(includeDeprecated: true) { name args { name type { " + TYPE_REF + " } } type { " + TYPE_REF + " } } " +
    "inputFields { name type { " + TYPE_REF + " } } " +
    "enumValues(includeDeprecated: true) { name } " +
    "} } }";
  try {
    const r = await fetch(env.API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: q }),
    });
    const d = await r.json().catch(() => ({}));
    if (d && d.errors && d.errors.length) {
      return json({ error: (d.errors[0] && d.errors[0].message) || "introspection blocked" }, 502);
    }
    const schema = (d.data || {}).__schema || {};
    const types = schema.types || [];
    const byName = {};
    types.forEach((t) => { if (t && t.name) byName[t.name] = t; });
    const isInternal = (n) => !n || n.indexOf("__") === 0;
    const scalarSkip = { String: 1, Int: 1, Float: 1, Boolean: 1, ID: 1, DateTime: 1, JSON: 1, Json: 1, Decimal: 1, BigInt: 1, Upload: 1 };

    const lines = [];
    lines.push("ZING API — FULL STRUCTURE");
    lines.push("Generated by the app for rebuilding the whole system.");
    lines.push("");

    const rootName = (schema.queryType || {}).name || "Query";
    const root = byName[rootName];
    const queryFields = (root && root.fields) || [];
    lines.push("==================== TOP-LEVEL QUERIES (" + queryFields.length + ") ====================");
    queryFields.forEach((f) => {
      const args = (f.args || []).map((a) => a.name + ": " + renderGqlType(a.type)).join(", ");
      lines.push("- " + f.name + (args ? "(" + args + ")" : "") + " -> " + renderGqlType(f.type));
    });
    lines.push("");

    const objTypes = types.filter((t) => t.kind === "OBJECT" && !isInternal(t.name) && t.name !== rootName && t.name !== ((schema.mutationType || {}).name));
    lines.push("==================== TYPES (" + objTypes.length + ") ====================");
    objTypes.forEach((t) => {
      lines.push(t.name + " {");
      (t.fields || []).forEach((f) => {
        const args = (f.args || []).filter((a) => a.name).map((a) => a.name + ": " + renderGqlType(a.type)).join(", ");
        lines.push("  " + f.name + (args ? "(" + args + ")" : "") + ": " + renderGqlType(f.type));
      });
      lines.push("}");
    });
    lines.push("");

    const inputTypes = types.filter((t) => t.kind === "INPUT_OBJECT" && !isInternal(t.name));
    lines.push("==================== INPUT / FILTER TYPES (" + inputTypes.length + ") ====================");
    inputTypes.forEach((t) => {
      const fs = (t.inputFields || []).map((f) => f.name + ": " + renderGqlType(f.type)).join(", ");
      lines.push(t.name + " { " + fs + " }");
    });
    lines.push("");

    const enums = types.filter((t) => t.kind === "ENUM" && !isInternal(t.name) && !scalarSkip[t.name]);
    lines.push("==================== ENUMS (" + enums.length + ") ====================");
    enums.forEach((t) => {
      lines.push(t.name + " = " + (t.enumValues || []).map((v) => v.name).join(" | "));
    });
    lines.push("");

    const mutName = (schema.mutationType || {}).name;
    if (mutName && byName[mutName]) {
      const mfs = byName[mutName].fields || [];
      lines.push("==================== MUTATIONS (" + mfs.length + ") ====================");
      mfs.forEach((f) => {
        const args = (f.args || []).map((a) => a.name + ": " + renderGqlType(a.type)).join(", ");
        lines.push("- " + f.name + (args ? "(" + args + ")" : "") + " -> " + renderGqlType(f.type));
      });
      lines.push("");
    }

    const text = lines.join("\n");
    return json({
      text,
      counts: {
        queries: queryFields.length,
        types: objTypes.length,
        inputs: inputTypes.length,
        enums: enums.length,
        mutations: mutName && byName[mutName] ? (byName[mutName].fields || []).length : 0,
      },
    });
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 502);
  }
}

// Authenticated GraphQL passthrough: same as /api/query but attaches the
// user's login token, so per-account operations (favorites, my playlists,
// history) work. Retries once with a fresh token on an auth error.
async function handleAuthQuery(request, env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const body = await request.json().catch(() => ({}));
  if (!body.query) return json({ error: "Missing query." }, 400);
  const payload = JSON.stringify({ query: body.query, variables: body.variables || {} });
  const call = async (tok) =>
    fetch(env.API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + (tok || ""),
      },
      body: payload,
    });
  try {
    let r = await call(await currentToken(env, false));
    let d = await r.json().catch(() => ({}));
    const looksAuth =
      r.status === 401 ||
      (d && d.errors && /auth|forbidden|denied|token|unauthor|login|permission/i.test(JSON.stringify(d.errors)));
    if (looksAuth && (canFirebase(env) || canAutoLogin(env))) {
      r = await call(await currentToken(env, true));
      d = await r.json().catch(() => ({}));
    }
    return json(d);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 502);
  }
}

// Run an arbitrary read query against the API (behind the site password).
// Lets the UI fetch genres, playlists, podcasts, etc. without new endpoints.
async function handleRawQuery(request, env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const body = await request.json().catch(() => ({}));
  if (!body.query) return json({ error: "Missing query." }, 400);
  try {
    const r = await fetch(env.API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: body.query, variables: body.variables || {} }),
    });
    const d = await r.json().catch(() => ({}));
    return json(d);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 502);
  }
}

async function currentToken(env, forceLogin) {
  const now = Math.floor(Date.now() / 1000);
  if (!forceLogin && CACHED_TOKEN && (CACHED_EXP === 0 || now < CACHED_EXP - 60)) {
    return CACHED_TOKEN;
  }
  // Preferred: Firebase refresh token (works forever, no re-login).
  if (canFirebase(env)) {
    const res = await firebaseRefresh(env);
    if (res.ok) return res.token;
  }
  // Alternative: email/password login (if the API supports it).
  if (canAutoLogin(env)) {
    const res = await zingLogin(env);
    if (res.ok) return res.token;
  }
  if (!forceLogin && CACHED_TOKEN) return CACHED_TOKEN;
  return env.USER_TOKEN || "";
}

// Fetch from the audio server, retrying once with a fresh token on a 403.
async function fetchAudio(env, trackId, extraHeaders) {
  let token = await currentToken(env, false);
  const build = (t) =>
    env.AUDIO_API_BASE +
    "?trackId=" + encodeURIComponent(trackId) +
    "&token=" + encodeURIComponent(t || "");
  let r = await fetch(build(token), { headers: extraHeaders || {} });
  if (r.status === 403 && (canFirebase(env) || canAutoLogin(env))) {
    token = await currentToken(env, true); // force a fresh token
    r = await fetch(build(token), { headers: extraHeaders || {} });
  }
  return r;
}

// --------------------------------------------------------------------------- //
// GraphQL helpers
// --------------------------------------------------------------------------- //
async function graphql(env, query) {
  if (!env.API_URL) return null;
  const res = await fetch(env.API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  if (!res.ok) return null;
  return await res.json();
}

async function fetchArtists(env) {
  const all = [];
  let skip = 0;
  const batchSize = 500;
  while (true) {
    const query =
      "query { artists(skip: " + skip + ", take: " + batchSize + ") { id enName heName image } }";
    const data = await graphql(env, query);
    if (!data || data.errors) break;
    const batch = ((data.data || {}).artists) || [];
    if (!batch.length) break;
    all.push(...batch);
    if (batch.length < batchSize) break;
    skip += batchSize;
  }
  return all;
}

async function handleArtists(env) {
  if (!env.API_URL) {
    return json({ error: "Server not configured. Set the API_URL secret." }, 400);
  }
  const artists = await fetchArtists(env);
  if (!artists.length) {
    return json({ error: "No artists found. Check the API_URL secret." }, 502);
  }
  return json({ artists });
}

async function handleArtist(request, env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const body = await request.json().catch(() => ({}));
  const id = body.id;
  if (id === undefined || id === null) {
    return json({ error: "Missing artist id." }, 400);
  }
  const query =
    "query { artist(where: { id: " + Number(id) + " }) { id enName heName image bio heDesc enDesc " +
    "albums { id enName heName images { cdnSmall cdnMedium medium small } tracks { id } } } }";
  const data = await graphql(env, query);
  const artist = data && data.data ? data.data.artist : null;
  if (!artist) return json({ error: "No details found for this artist." }, 502);
  return json({ artist });
}

async function handleNew(env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const fields =
    "id enName heName releasedAt images { cdnSmall cdnMedium medium small } artists { enName heName image } tracks { id }";
  // Ask the API for the newest albums directly. Prefer createdAt (most
  // recently ADDED to the catalog — what "new music coming in" means), then
  // the release date, then id, then an unordered page sorted here — so this
  // keeps working even if the API rejects an orderBy field.
  const attempts = [
    "query { albums(take: 20, orderBy: [{ createdAt: desc }]) { " + fields + " } }",
    "query { albums(take: 20, orderBy: [{ releasedAt: desc }]) { " + fields + " } }",
    "query { albums(take: 20, orderBy: [{ id: desc }]) { " + fields + " } }",
    "query { albums(take: 50) { " + fields + " } }",
  ];
  let albums = [];
  for (let i = 0; i < attempts.length; i++) {
    const data = await graphql(env, attempts[i]);
    if (data && !data.errors && ((data.data || {}).albums || []).length) {
      albums = data.data.albums;
      if (i === attempts.length - 1) {
        // Unordered fallback: sort newest-first ourselves.
        albums = albums.slice().sort((a, b) => Number(b.id || 0) - Number(a.id || 0));
      }
      break;
    }
  }
  return json({ albums: albums.slice(0, 12) });
}

// A page of ALL albums, newest first (old + new together), for the Albums
// browse view. Supports skip/take for "load more". Same ordering fallbacks.
async function handleAlbumsPage(request, env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const body = await request.json().catch(() => ({}));
  const take = Math.min(Math.max(parseInt(body.take, 10) || 30, 1), 60);
  const skip = Math.max(parseInt(body.skip, 10) || 0, 0);
  const fields =
    "id enName heName releasedAt images { cdnSmall cdnMedium medium small } artists { enName heName image } tracks { id }";
  const attempts = [
    "query { albums(take: " + take + ", skip: " + skip + ", orderBy: [{ createdAt: desc }]) { " + fields + " } }",
    "query { albums(take: " + take + ", skip: " + skip + ", orderBy: [{ releasedAt: desc }]) { " + fields + " } }",
    "query { albums(take: " + take + ", skip: " + skip + ", orderBy: [{ id: desc }]) { " + fields + " } }",
    "query { albums(take: " + take + ", skip: " + skip + ") { " + fields + " } }",
  ];
  for (let i = 0; i < attempts.length; i++) {
    const data = await graphql(env, attempts[i]);
    if (data && !data.errors) {
      let albums = ((data.data || {}).albums) || [];
      if (i === attempts.length - 1) {
        albums = albums.slice().sort((a, b) => Number(b.id || 0) - Number(a.id || 0));
      }
      return json({ albums });
    }
  }
  return json({ albums: [] });
}

// Read a JWT's non-secret claims (issuer, audience, expiry) to identify the
// auth provider. Never exposes the token itself — only these public claims.
function decodeJwtClaims(token) {
  try {
    const parts = (token || "").split(".");
    if (parts.length < 2) return { error: "not a JWT" };
    let b = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (b.length % 4) b += "=";
    const claims = JSON.parse(atob(b));
    const now = Math.floor(Date.now() / 1000);
    return {
      iss: claims.iss || null,
      aud: typeof claims.aud === "string" ? claims.aud : null,
      exp: claims.exp || null,
      expired: claims.exp ? claims.exp < now : null,
      ttlMinutes: claims.exp ? Math.round((claims.exp - now) / 60) : null,
    };
  } catch (e) {
    return { error: String((e && e.message) || e) };
  }
}

async function handleCheck(env) {
  // Diagnose connectivity: can the Worker actually reach your servers, and
  // does a REAL track play with the current token?
  const out = { api: {}, audio: {} };
  let realTrackId = null;

  // Identify the token's provider/expiry (public claims only, no secrets).
  if (env.USER_TOKEN) out.tokenInfo = decodeJwtClaims(env.USER_TOKEN);

  // Test whichever auto-token method is configured.
  if (canFirebase(env)) {
    const res = await firebaseRefresh(env);
    out.login = res.ok ? { ok: true, method: "firebase" } : { ok: false, method: "firebase", error: res.error };
  } else if (env.ZING_EMAIL && env.ZING_PASSWORD) {
    const res = await zingLogin(env);
    out.login = res.ok ? { ok: true, method: "password" } : { ok: false, method: "password", error: res.error };
    if (!res.ok && env.API_URL) {
      out.authMutations = await introspectAuthMutations(env);
    }
  } else {
    out.login = { configured: false };
  }

  // Test the GraphQL API and grab a real track id to test playback with.
  if (!env.API_URL) {
    out.api = { configured: false };
  } else {
    try {
      const r = await fetch(env.API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "query { albums(take: 5) { id tracks { id } } }" }),
      });
      out.api = { reachable: true, status: r.status };
      if (r.ok) {
        const d = await r.json().catch(() => ({}));
        if (d && d.errors) out.api.graphqlError = true;
        const albums = ((d.data || {}).albums) || [];
        out.api.hasData = albums.length > 0;
        for (let i = 0; i < albums.length; i++) {
          const tracks = albums[i].tracks || [];
          if (tracks.length) { realTrackId = tracks[0].id; break; }
        }
      }
    } catch (e) {
      out.api = { reachable: false, error: String((e && e.message) || e) };
    }
  }

  // Test the audio server with a real track id when we have one.
  if (!env.AUDIO_API_BASE) {
    out.audio = { configured: false };
  } else {
    const tid = realTrackId != null ? realTrackId : 1;
    try {
      const r = await fetchAudio(env, tid, { Range: "bytes=0-0" });
      out.audio = { reachable: true, status: r.status, realTrack: realTrackId != null };
    } catch (e) {
      out.audio = { reachable: false, error: String((e && e.message) || e) };
    }
  }

  return json(out);
}

async function handlePlay(url, request, env) {
  // Stream a track for in-browser playback (inline, with Range support for seeking).
  if (!env.AUDIO_API_BASE) {
    return json({ error: "Server not configured (AUDIO_API_BASE)." }, 400);
  }
  const trackId = (url.searchParams.get("trackId") || "").trim();
  if (!trackId) return json({ error: "Missing track id." }, 400);

  const range = request.headers.get("Range");
  let upstream;
  try {
    upstream = await fetchAudio(env, trackId, range ? { Range: range } : {});
  } catch (exc) {
    return json({ error: "Playback error: " + (exc && exc.message) }, 502);
  }
  if (upstream.status === 403) {
    return json({ error: "Access Denied (403). Token expired and re-login failed." }, 403);
  }
  if (!upstream.ok && upstream.status !== 206) {
    return json({ error: "Server returned code " + upstream.status + "." }, 502);
  }

  const headers = new Headers();
  headers.set("Content-Type", upstream.headers.get("Content-Type") || "audio/mpeg");
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "no-store");
  const cr = upstream.headers.get("Content-Range");
  if (cr) headers.set("Content-Range", cr);
  const cl = upstream.headers.get("Content-Length");
  if (cl) headers.set("Content-Length", cl);

  return new Response(upstream.body, { status: upstream.status, headers });
}

async function handleDownload(url, env) {
  if (!env.AUDIO_API_BASE) {
    return json({ error: "Server not configured (AUDIO_API_BASE)." }, 400);
  }
  const trackId = (url.searchParams.get("trackId") || "").trim();
  const filePath = (url.searchParams.get("file") || "").trim();
  if (!trackId) return json({ error: "Missing track id." }, 400);

  // Build the filename the same way the original script does.
  let filename = filePath ? filePath.split("/").pop() : "track_" + trackId + ".mp3";
  if (!/\.(mp3|wav|m4a)$/i.test(filename)) filename += ".mp3";
  // Keep the header safe.
  filename = filename.replace(/["\\\r\n]/g, "_");

  let upstream;
  try {
    upstream = await fetchAudio(env, trackId, {});
  } catch (exc) {
    return json({ error: "Download error: " + (exc && exc.message) }, 502);
  }
  if (upstream.status === 403) {
    return json({ error: "Access Denied (403). Token expired and re-login failed." }, 403);
  }
  if (!upstream.ok) {
    return json({ error: "Server returned code " + upstream.status + "." }, 502);
  }

  const headers = new Headers();
  headers.set("Content-Disposition", 'attachment; filename="' + filename + '"');
  headers.set("Content-Type", upstream.headers.get("Content-Type") || "audio/mpeg");
  const cl = upstream.headers.get("Content-Length");
  if (cl) headers.set("Content-Length", cl);

  return new Response(upstream.body, { headers });
}

// --------------------------------------------------------------------------- //
// Response helpers
// --------------------------------------------------------------------------- //
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function html(body) {
  return new Response(body, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // Never let the phone/browser serve a stale copy of the app after a
      // new deploy — always fetch the latest page.
      "Cache-Control": "no-store, must-revalidate",
    },
  });
}

// --------------------------------------------------------------------------- //
// Login page — shown when the site is password-protected and you're not in yet.
// --------------------------------------------------------------------------- //
const LOGIN = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Zing — Sign in</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet" />
<style>
  :root{color-scheme:dark;}
  *{box-sizing:border-box;}
  html,body{height:100%;margin:0;}
  body{font-family:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#f4f4fb;
    background:radial-gradient(900px 500px at 20% -10%, rgba(124,92,255,.28), transparent 60%),
      radial-gradient(800px 460px at 100% 0%, rgba(255,77,141,.18), transparent 55%), #0a0a12;
    display:grid; place-items:center; padding:24px;}
  .box{width:100%; max-width:360px; text-align:center;}
  .logo{width:60px;height:60px;border-radius:18px;display:grid;place-items:center;margin:0 auto 18px;font-size:28px;
    background:linear-gradient(135deg,#7c5cff,#ff4d8d); box-shadow:0 12px 30px rgba(124,92,255,.5);}
  h1{font-size:1.5rem; margin:0 0 6px; font-weight:800;}
  p{color:#a3a3c2; margin:0 0 22px;}
  input{width:100%; padding:14px 16px; border-radius:13px; border:1px solid rgba(255,255,255,.1);
    background:#161627; color:#f4f4fb; font-size:1.05rem; font-family:inherit; outline:none; text-align:center;}
  input:focus{border-color:#7c5cff;}
  button{width:100%; margin-top:12px; padding:14px; border:none; border-radius:13px; cursor:pointer;
    font-family:inherit; font-weight:800; font-size:1rem; color:#fff;
    background:linear-gradient(135deg,#7c5cff,#ff4d8d); box-shadow:0 10px 24px rgba(124,92,255,.4);}
  button:disabled{opacity:.6;}
  .msg{min-height:20px; margin-top:14px; font-size:.92rem; color:#fb7185;}
  .tabs2{display:flex; gap:6px; background:#161627; border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:4px; margin:0 0 18px;}
  .tab2{flex:1; margin:0; padding:10px; border-radius:9px; font-weight:700; font-size:.95rem; background:transparent; color:#a3a3c2; box-shadow:none;}
  .tab2.on{background:linear-gradient(135deg,#7c5cff,#ff4d8d); color:#fff;}
  button.ghost{background:#1e1e34; color:#f4f4fb; box-shadow:none; border:1px solid rgba(255,255,255,.1); font-weight:600; font-size:.9rem;}
  .selfie{margin-top:12px;}
  .shot{width:150px; height:150px; margin:0 auto 8px; border-radius:999px; overflow:hidden; background:#161627; border:1px solid rgba(255,255,255,.1);
    display:grid; place-items:center; position:relative;}
  .shot video, .shot img{width:100%; height:100%; object-fit:cover; display:block;}
  .shot #shotHint{position:absolute; padding:0 14px; color:#a3a3c2; font-size:.82rem; text-align:center;}
  .shot video[hidden], .shot img[hidden]{display:none;}
</style>
</head>
<body>
  <div class="box">
    <div class="logo">♪</div>
    <h1>Zing Music</h1>
    <div class="tabs2">
      <button id="tSignin" class="tab2 on" type="button">Sign in</button>
      <button id="tSignup" class="tab2" type="button">Request access</button>
    </div>

    <div id="signin">
      <p>Sign in with your email and password.</p>
      <input id="si_email" type="email" placeholder="Email (owner: leave blank)" autocomplete="username" />
      <input id="si_pw" type="password" placeholder="Password" autocomplete="current-password" style="margin-top:10px" />
      <button id="si_go" type="button">Sign in</button>
      <div class="msg" id="si_msg"></div>
    </div>

    <div id="signup" hidden>
      <p>Create an account. The owner approves new accounts.</p>
      <input id="su_name" type="text" placeholder="Full name" autocomplete="name" />
      <input id="su_email" type="email" placeholder="Email address" autocomplete="email" style="margin-top:10px" />
      <input id="su_phone" type="tel" placeholder="Phone number" autocomplete="tel" style="margin-top:10px" />
      <input id="su_pw" type="password" placeholder="Choose a password" autocomplete="new-password" style="margin-top:10px" />
      <div class="selfie">
        <div id="shot" class="shot"><span id="shotHint">Your selfie photo is required</span><video id="cam" playsinline autoplay muted></video><img id="pic" alt="" /></div>
        <button id="camBtn" type="button" class="ghost">Open camera</button>
        <button id="capBtn" type="button" class="ghost" hidden>Take photo</button>
        <button id="retBtn" type="button" class="ghost" hidden>Retake</button>
      </div>
      <button id="su_go" type="button">Request access</button>
      <div class="msg" id="su_msg"></div>
    </div>
  </div>
  <canvas id="cv" hidden></canvas>
  <script>
    function $(id){ return document.getElementById(id); }
    function show(el,on){ if(el) el.hidden = !on; }
    // Tabs
    function tab(which){
      var inU = which === "up";
      $("tSignin").className = "tab2" + (inU ? "" : " on");
      $("tSignup").className = "tab2" + (inU ? " on" : "");
      show($("signin"), !inU); show($("signup"), inU);
    }
    $("tSignin").onclick = function(){ tab("in"); };
    $("tSignup").onclick = function(){ tab("up"); };

    // Sign in
    function signin(){
      var m = $("si_msg"); m.textContent = "";
      fetch("/api/login", { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ email: $("si_email").value, password: $("si_pw").value }) })
      .then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
      .then(function(x){ if(x.ok){ location.href = "/"; } else { m.textContent = (x.d && x.d.error) || "Wrong email or password."; } })
      .catch(function(){ m.textContent = "Something went wrong. Try again."; });
    }
    $("si_go").onclick = signin;
    $("si_pw").addEventListener("keydown", function(e){ if(e.key === "Enter") signin(); });

    // Selfie camera
    var stream = null, photo = "";
    function stopCam(){ if(stream){ stream.getTracks().forEach(function(t){ t.stop(); }); stream = null; } }
    $("camBtn").onclick = function(){
      var m = $("su_msg"); m.textContent = "";
      if(!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia){ m.textContent = "Camera is not available on this device."; return; }
      navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" }, audio: false }).then(function(s){
        stream = s; var v = $("cam"); v.srcObject = s; show(v, true); show($("pic"), false); $("shotHint").style.display = "none";
        show($("camBtn"), false); show($("capBtn"), true); show($("retBtn"), false);
      }).catch(function(){ m.textContent = "Could not open the camera. Please allow camera access."; });
    };
    $("capBtn").onclick = function(){
      var v = $("cam"), cv = $("cv");
      var w = v.videoWidth || 360, h = v.videoHeight || 360; var scale = 360 / Math.max(w, h);
      cv.width = Math.round(w * scale); cv.height = Math.round(h * scale);
      cv.getContext("2d").drawImage(v, 0, 0, cv.width, cv.height);
      photo = cv.toDataURL("image/jpeg", 0.6);
      stopCam(); show(v, false); var p = $("pic"); p.src = photo; show(p, true);
      show($("capBtn"), false); show($("retBtn"), true);
    };
    $("retBtn").onclick = function(){ photo = ""; $("camBtn").click(); };

    // Request access
    function signup(){
      var m = $("su_msg"); m.textContent = "";
      var name = $("su_name").value.trim(), email = $("su_email").value.trim(), phone = $("su_phone").value.trim(), pw = $("su_pw").value;
      if(name.length < 2){ m.textContent = "Enter your full name."; return; }
      if(email.indexOf("@") < 1){ m.textContent = "Enter a valid email address."; return; }
      if(phone.replace(/[^0-9]/g, "").length < 6){ m.textContent = "Enter a valid phone number."; return; }
      if(pw.length < 4){ m.textContent = "Password must be at least 4 characters."; return; }
      if(!photo){ m.textContent = "Please take your selfie photo first."; return; }
      $("su_go").disabled = true;
      fetch("/api/signup", { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ name: name, email: email, phone: phone, password: pw, photo: photo }) })
      .then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
      .then(function(x){ $("su_go").disabled = false;
        if(x.ok){ $("signup").innerHTML = "<p style=\\"color:#34d399;font-size:1.05rem;line-height:1.6\\">Thank you! Your request was sent.<br>The owner will approve your account soon.</p>"; }
        else { m.textContent = (x.d && x.d.error) || "Could not send the request."; } })
      .catch(function(){ $("su_go").disabled = false; m.textContent = "Something went wrong. Try again."; });
    }
    $("su_go").onclick = signup;
    $("si_email").focus();
  </script>
</body>
</html>`;

// --------------------------------------------------------------------------- //
// Frontend (served at /). Artist catalog is cached in the browser for 24h.
// --------------------------------------------------------------------------- //
const PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <title>Zing — Jewish Music</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <style>
    :root{
      color-scheme: dark;
      --bg:#0a0a12; --bg-2:#0f0f1b; --surface:#161627; --surface-2:#1e1e34; --surface-3:#262640;
      --text:#f4f4fb; --muted:#9aa0c0; --line:rgba(255,255,255,.08);
      --accent:#7c5cff; --accent-2:#ff4d8d; --ok:#34d399; --err:#fb7185; --warn:#fbbf24;
      --grad:linear-gradient(135deg,var(--accent),var(--accent-2));
      --font:"Plus Jakarta Sans", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      --tabs-h:64px; --player-h:66px;
      --bar:rgba(10,10,18,.82); --bar-player:rgba(20,20,34,.94); --bar-tabs:rgba(14,14,24,.96); --ovl-bg:rgba(10,10,18,.97);
    }
    :root[data-theme="light"]{
      color-scheme: light;
      --bg:#f4f4fb; --bg-2:#ececf4; --surface:#ffffff; --surface-2:#f1f1f8; --surface-3:#e7e7f1;
      --text:#191933; --muted:#6a6a86; --line:rgba(0,0,0,.10);
      --bar:rgba(255,255,255,.85); --bar-player:rgba(255,255,255,.95); --bar-tabs:rgba(255,255,255,.96); --ovl-bg:rgba(247,247,251,.98);
    }
    *{ box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
    html,body{ height:100%; margin:0; }
    body{
      font-family:var(--font); color:var(--text);
      background:
        radial-gradient(1000px 520px at 12% -8%, rgba(124,92,255,.18), transparent 60%),
        radial-gradient(900px 460px at 100% 0%, rgba(255,77,141,.12), transparent 55%),
        var(--bg);
      min-height:100%;
    }
    .ms{ width:1em; height:1em; font-size:24px; display:inline-block; vertical-align:middle; flex:none; fill:currentColor; line-height:0; }

    /* Top bar */
    .top{ position:sticky; top:env(safe-area-inset-top,0px); z-index:30;
      display:flex; align-items:center; gap:12px; padding:13px 18px;
      background:var(--bar); backdrop-filter:blur(14px); border-bottom:1px solid var(--line); }
    .brand{ display:flex; align-items:center; gap:10px; }
    .logo{ width:36px; height:36px; border-radius:11px; display:grid; place-items:center; background:var(--grad);
      box-shadow:0 6px 16px rgba(124,92,255,.45); }
    .logo .ms{ font-size:22px; color:#fff; }
    .brand .name{ font-weight:800; font-size:1.2rem; letter-spacing:.3px; }
    .top .spacer{ flex:1; }
    .iconbtn{ width:40px; height:40px; border-radius:11px; border:none; background:transparent; color:var(--muted);
      display:grid; place-items:center; cursor:pointer; }
    .iconbtn:hover{ background:var(--surface-2); color:var(--text); }
    .iconbtn .ms{ font-size:24px; }

    .wrap{ max-width:1000px; margin:0 auto; padding:14px 0 calc(var(--tabs-h) + var(--player-h) + 24px + env(safe-area-inset-bottom,0px)); }
    .pad{ padding-left:18px; padding-right:18px; }

    /* Sections + horizontal rows (Zing-style) */
    .sec{ margin-top:22px; }
    .sec-head{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin:0 18px 12px; }
    .sec-head h2{ margin:0; font-size:1.15rem; font-weight:800; }
    .see{ display:inline-flex; align-items:center; gap:2px; color:var(--muted); font-size:.85rem; cursor:pointer; background:none; border:none; }
    .see:hover{ color:var(--text); }
    .see .ms{ font-size:18px; }
    .hrow{ display:flex; gap:14px; overflow-x:auto; padding:2px 18px 6px; scroll-snap-type:x proximity; -webkit-overflow-scrolling:touch; }
    .hrow::-webkit-scrollbar{ height:0; }
    .hcard{ flex:0 0 auto; width:150px; scroll-snap-align:start; cursor:pointer; }
    .hcard.artist{ width:120px; text-align:center; }
    .hcard.wide{ width:200px; }
    .banner-card{ flex:0 0 auto; width:300px; max-width:82vw; aspect-ratio:16/9; border-radius:16px; scroll-snap-align:start; cursor:pointer;
      background-size:cover; background-position:center; background-color:var(--surface-2); box-shadow:0 8px 22px rgba(0,0,0,.35); }

    .cover{ width:100%; aspect-ratio:1/1; border-radius:14px; display:grid; place-items:center; margin-bottom:9px;
      color:rgba(255,255,255,.95); box-shadow:0 8px 20px rgba(0,0,0,.3), inset 0 0 40px rgba(0,0,0,.18);
      overflow:hidden; position:relative; }
    .cover.round{ border-radius:999px; width:86%; margin:0 auto 9px; }
    .cover .ini{ font-weight:800; font-size:1.8rem; }
    .cover .disc{ width:30%; height:30%; border-radius:999px;
      background:radial-gradient(circle at 50% 50%, #fff 0 13%, rgba(255,255,255,.22) 14% 33%, rgba(0,0,0,.14) 34% 100%); }
    .c-name{ font-weight:600; font-size:.92rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .c-sub{ color:var(--muted); font-size:.78rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:1px; }
    .fab{ position:absolute; right:8px; bottom:8px; width:38px; height:38px; border-radius:999px; background:var(--grad);
      display:grid; place-items:center; color:#fff; box-shadow:0 8px 16px rgba(0,0,0,.45); opacity:0; transform:translateY(6px);
      transition:opacity .15s, transform .15s; }
    .hcard:hover .fab, .tile:hover .fab{ opacity:1; transform:translateY(0); }
    .fab .ms{ font-size:22px; }

    /* Grids (see-all pages) */
    .grid{ display:grid; gap:16px; padding:0 18px; }
    .grid.artists{ grid-template-columns:repeat(auto-fill,minmax(120px,1fr)); }
    .grid.albums{ grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); }
    .tile{ cursor:pointer; position:relative; }
    .tile.artist{ text-align:center; }

    /* Search */
    .searchbar{ display:flex; align-items:center; gap:10px; margin:6px 18px 4px; background:var(--surface); border:1px solid var(--line);
      border-radius:14px; padding:10px 14px; }
    .searchbar .ms{ color:var(--muted); font-size:22px; }
    .searchbar input{ flex:1; min-width:0; background:transparent; border:none; outline:none; color:var(--text); font-family:inherit; font-size:1.02rem; }
    .searchbar input::placeholder{ color:var(--muted); }

    /* Detail (album/playlist) */
    .back{ display:inline-flex; align-items:center; gap:4px; cursor:pointer; color:var(--muted); font-size:.92rem; margin:2px 18px 12px; }
    .back:hover{ color:var(--text); } .back .ms{ font-size:20px; }
    .hero{ display:flex; gap:18px; align-items:flex-end; margin:0 18px 18px; flex-wrap:wrap; }
    .hero .cover{ width:150px; height:150px; margin:0; flex:none; }
    .hero .kicker{ color:var(--muted); font-size:.72rem; letter-spacing:2px; text-transform:uppercase; }
    .hero h2{ margin:5px 0 6px; font-size:clamp(1.3rem,4.5vw,1.9rem); font-weight:800; text-wrap:balance; }
    .hero .sub{ color:var(--muted); font-size:.9rem; }
    .hero .actions{ margin-top:14px; display:flex; gap:10px; flex-wrap:wrap; }
    .btn{ border:none; cursor:pointer; font-family:inherit; font-weight:700; font-size:.92rem; color:#fff; padding:11px 18px;
      border-radius:12px; background:var(--grad); box-shadow:0 8px 18px rgba(124,92,255,.32); display:inline-flex; align-items:center; gap:7px; }
    .btn .ms{ font-size:20px; } .btn:hover{ filter:brightness(1.08); } .btn:active{ transform:translateY(1px); }
    .btn.ghost{ background:var(--surface-2); color:var(--text); box-shadow:none; border:1px solid var(--line); font-weight:600; }
    .btn.sm{ padding:8px 13px; font-size:.85rem; }

    .tracks{ margin:0 18px; border:1px solid var(--line); border-radius:16px; overflow:hidden; background:var(--surface); }
    .track{ display:flex; align-items:center; gap:12px; padding:11px 14px; border-bottom:1px solid var(--line); transition:background .12s; cursor:pointer; }
    .track:last-child{ border-bottom:none; } .track:hover{ background:var(--surface-2); }
    .track.playing{ background:linear-gradient(90deg, rgba(124,92,255,.16), transparent); }
    .track .num{ width:24px; text-align:center; color:var(--muted); font-variant-numeric:tabular-nums; font-size:.9rem; flex:none; }
    .track.playing .num{ color:var(--accent); }
    .track .tk{ flex:1; min-width:0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-size:.95rem; }
    .track .tk .sub{ color:var(--muted); font-size:.8rem; }
    .track .time{ color:var(--muted); font-size:.82rem; font-variant-numeric:tabular-nums; flex:none; }
    .track .dl{ flex:none; width:38px; height:38px; border-radius:999px; border:none; background:transparent; color:var(--muted); cursor:pointer; display:grid; place-items:center; }
    .track .dl:hover{ color:#fff; background:var(--grad); } .track .dl .ms{ font-size:20px; }

    .empty{ color:var(--muted); padding:40px 18px; text-align:center; }
    .spinner{ display:inline-block; width:16px; height:16px; border:2px solid var(--muted); border-top-color:transparent; border-radius:50%; animation:spin .7s linear infinite; vertical-align:-3px; margin-right:8px; }
    @keyframes spin{ to{ transform:rotate(360deg); } }
    #status{ min-height:18px; font-size:.9rem; margin:6px 18px; }
    .ok{ color:var(--ok); } .err{ color:var(--err); } .muted{ color:var(--muted); }

    /* Now-playing bar */
    .player{ position:fixed; left:0; right:0; bottom:calc(var(--tabs-h) + env(safe-area-inset-bottom,0px)); z-index:35;
      display:flex; align-items:center; gap:12px; padding:9px 14px;
      background:var(--bar-player); backdrop-filter:blur(16px); border-top:1px solid var(--line); }
    .player[hidden]{ display:none; }
    .np-cover{ width:46px; height:46px; border-radius:10px; flex:none; display:grid; place-items:center; overflow:hidden; box-shadow:inset 0 0 20px rgba(0,0,0,.3); }
    .np-cover .disc{ width:34%; height:34%; border-radius:999px; background:radial-gradient(circle at 50% 50%,#fff 0 14%,rgba(255,255,255,.22) 15% 33%,rgba(0,0,0,.14) 34% 100%); }
    .np-meta{ flex:1; min-width:0; }
    .np-title{ font-weight:700; font-size:.92rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .np-artist{ color:var(--muted); font-size:.78rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .np-btn{ width:40px; height:40px; border-radius:999px; border:none; background:transparent; color:var(--text); cursor:pointer; display:grid; place-items:center; flex:none; }
    .np-btn:hover{ background:var(--surface-3); } .np-btn .ms{ font-size:24px; }
    .np-btn.main{ width:46px; height:46px; background:var(--grad); color:#fff; box-shadow:0 6px 16px rgba(124,92,255,.4); }
    .np-btn.main .ms{ font-size:26px; }
    .np-seek-wrap{ position:absolute; left:0; right:0; top:-3px; height:3px; }
    .np-seek{ -webkit-appearance:none; appearance:none; width:100%; height:3px; background:var(--surface-3); outline:none; margin:0; }
    .np-seek::-webkit-slider-thumb{ -webkit-appearance:none; width:12px; height:12px; border-radius:999px; background:var(--accent); cursor:pointer; }
    .np-seek::-moz-range-thumb{ width:12px; height:12px; border:none; border-radius:999px; background:var(--accent); }
    @media (max-width:520px){ .np-btn.prev{ display:none; } }

    /* Bottom tabs */
    .tabs{ position:fixed; left:0; right:0; bottom:0; z-index:36; height:calc(var(--tabs-h) + env(safe-area-inset-bottom,0px));
      padding-bottom:env(safe-area-inset-bottom,0px); display:flex; background:var(--bar-tabs); backdrop-filter:blur(16px); border-top:1px solid var(--line); }
    .tab{ flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:2px; background:none; border:none; color:var(--muted); cursor:pointer; font-family:inherit; }
    .tab .ms{ font-size:25px; } .tab span.lbl{ font-size:.66rem; font-weight:600; }
    .tab.active{ color:var(--text); }
    .tab.active .ms{ background:var(--grad); -webkit-background-clip:text; background-clip:text; color:transparent; }

    /* Overlay (lyrics / settings) */
    .ovl{ position:fixed; inset:0; z-index:60; background:var(--ovl-bg); backdrop-filter:blur(8px); overflow:auto;
      padding:18px 18px calc(28px + env(safe-area-inset-bottom,0px)); }
    .ovl .obar{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:16px; position:sticky; top:0; }
    .ovl h2{ margin:0; font-size:1.2rem; }
    .ovl pre{ white-space:pre-wrap; font-family:inherit; font-size:1.02rem; line-height:1.8; margin:0; }
    .banner{ border-radius:14px; padding:13px 15px; margin:0 18px 8px; border:1px solid rgba(251,191,36,.35); background:rgba(251,191,36,.08); color:var(--warn); font-size:.9rem; }
    .banner code{ background:rgba(255,255,255,.1); padding:1px 6px; border-radius:6px; color:var(--text); }
    .toast{ position:fixed; left:50%; bottom:calc(var(--tabs-h) + var(--player-h) + 12px + env(safe-area-inset-bottom,0px)); transform:translateX(-50%) translateY(14px);
      background:var(--surface-3); color:var(--text); border:1px solid var(--line); padding:11px 16px; border-radius:12px;
      box-shadow:0 12px 30px rgba(0,0,0,.5); opacity:0; pointer-events:none; transition:opacity .2s, transform .2s; z-index:70; font-size:.9rem; max-width:88%; text-align:center; }
    .toast.show{ opacity:1; transform:translateX(-50%) translateY(0); }
    .chips{ display:flex; gap:8px; padding:0 18px; flex-wrap:wrap; }
    .chip{ background:var(--surface); border:1px solid var(--line); color:var(--text); border-radius:999px; padding:8px 14px; font-weight:600; font-size:.85rem; cursor:pointer; }

    /* Settings */
    .set-sec{ margin-top:22px; }
    .set-sec:first-child{ margin-top:4px; }
    .set-sec h3{ margin:0 0 10px; font-size:.74rem; letter-spacing:1.6px; text-transform:uppercase; color:var(--muted); }
    .card{ background:var(--surface); border:1px solid var(--line); border-radius:14px; overflow:hidden; }
    .row{ display:flex; align-items:center; gap:12px; padding:13px 15px; border-bottom:1px solid var(--line); }
    .row:last-child{ border-bottom:none; }
    .row .rlabel{ flex:1; min-width:0; }
    .row .rlabel .rt{ font-weight:600; font-size:.98rem; }
    .row .rlabel .rd{ color:var(--muted); font-size:.8rem; margin-top:2px; }
    .row .ms{ color:var(--muted); font-size:22px; flex:none; }
    .seg{ display:inline-flex; background:var(--surface-3); border-radius:11px; padding:3px; flex:none; }
    .seg button{ border:none; background:transparent; color:var(--muted); font-family:inherit; font-weight:600; font-size:.86rem; padding:7px 13px; border-radius:9px; cursor:pointer; }
    .seg button.on{ background:var(--grad); color:#fff; box-shadow:0 4px 10px rgba(124,92,255,.35); }
    .field{ width:100%; padding:12px 14px; border-radius:12px; border:1px solid var(--line); background:var(--bg-2); color:var(--text); font-size:1rem; font-family:inherit; outline:none; }
    .field:focus{ border-color:var(--accent); }
    .code-item{ display:flex; align-items:center; gap:12px; padding:12px 15px; border-bottom:1px solid var(--line); }
    .code-item:last-child{ border-bottom:none; }
    .code-item .ci-name{ font-weight:600; font-size:.96rem; }
    .code-item .ci-code{ color:var(--muted); font-size:.82rem; margin-top:1px; }
    .trash{ margin-left:auto; width:38px; height:38px; border-radius:999px; border:none; background:transparent; color:var(--muted); cursor:pointer; display:grid; place-items:center; flex:none; }
    .trash:hover{ background:rgba(251,113,133,.14); color:var(--err); } .trash .ms{ font-size:20px; }
    .set-sec code, .card code{ background:var(--surface-3); padding:1px 6px; border-radius:6px; font-size:.86em; color:var(--text); }
    .steps{ margin:0; padding-left:20px; line-height:1.85; } .steps li{ margin-bottom:6px; }
    @media (prefers-reduced-motion: reduce){ *{ transition:none !important; animation-duration:.01ms !important; } }
  </style>
</head>
<body>
  <div class="top">
    <div class="brand"><span class="logo"><span class="ms">music_note</span></span><span class="name">Zing</span><span style="font-size:.6rem;font-weight:800;letter-spacing:.5px;color:#fff;background:var(--grad);padding:2px 7px;border-radius:7px;align-self:center">v2</span></div>
    <div class="spacer"></div>
    <span class="muted" id="cfgBadge" style="font-size:.72rem"></span>
    <button class="iconbtn" title="Search" onclick="go('search')"><span class="ms">search</span></button>
    <button class="iconbtn" title="My Music" onclick="browseLibrary()"><span class="ms">favorite</span></button>
    <button class="iconbtn" id="meAvatar" title="You" onclick="openSettings()" hidden style="padding:0"><img id="meImg" alt="" style="width:30px;height:30px;border-radius:999px;object-fit:cover" /></button>
    <button class="iconbtn" title="Settings" onclick="openSettings()"><span class="ms">settings</span></button>
  </div>

  <div class="wrap">
    <div class="banner" id="cfgBanner" hidden>
      Not configured yet. Add your <code>API_URL</code>, <code>AUDIO_API_BASE</code> and a token / auto-login, then reload.
    </div>
    <div id="status"></div>
    <div id="view"></div>
  </div>

  <!-- Now playing -->
  <div class="player" id="player" hidden>
    <div class="np-seek-wrap"><input type="range" class="np-seek" id="seek" min="0" max="1000" value="0" /></div>
    <div class="np-cover" id="npCover"><span class="disc"></span></div>
    <div class="np-meta" onclick="openNowPlaying()"><div class="np-title" id="npTitle">—</div><div class="np-artist" id="npArtist"></div></div>
    <button class="np-btn prev" title="Previous" onclick="prevTrack()"><span class="ms">skip_previous</span></button>
    <button class="np-btn main" id="playBtn" title="Play/Pause" onclick="togglePlay()"><span class="ms">play_arrow</span></button>
    <button class="np-btn" title="Next" onclick="nextTrack()"><span class="ms">skip_next</span></button>
    <button class="np-btn" id="npDl" title="Download" onclick="dlCurrent()"><span class="ms">download</span></button>
  </div>

  <!-- Bottom tabs -->
  <nav class="tabs">
    <button class="tab active" id="tabHome" onclick="go('home')"><span class="ms">home</span><span class="lbl">Home</span></button>
    <button class="tab" id="tabAlbums" onclick="go('albums')"><span class="ms">album</span><span class="lbl">Albums</span></button>
    <button class="tab" id="tabSearch" onclick="go('search')"><span class="ms">search</span><span class="lbl">Search</span></button>
    <button class="tab" id="tabGenres" onclick="go('genres')"><span class="ms">category</span><span class="lbl">Genres</span></button>
    <button class="tab" id="tabPlaylists" onclick="go('playlists')"><span class="ms">featured_play_list</span><span class="lbl">Playlists</span></button>
    <button class="tab" id="tabArtists" onclick="go('artists')"><span class="ms">artist</span><span class="lbl">Artists</span></button>
  </nav>

  <audio id="audio" preload="none"></audio>
  <div class="toast" id="toast"></div>

  <script>
    var artists=[], artistsLoaded=false;
    var CACHE_KEY="zing_artists_cache_v2", CACHE_TTL=3600000;
    var queue=[], qi=-1;
    var curTab="home", _dirtyView=false, _admPw="";

    // ---------- App settings (saved on this device) ----------
    var SET_KEY="zing_settings";
    function loadSettings(){ var d={lang:"en",theme:"dark",autoplay:true};
      try{ var o=JSON.parse(localStorage.getItem(SET_KEY)||"null"); if(o){ if(o.lang==="he")d.lang="he"; if(o.theme==="light")d.theme="light"; if(o.autoplay===false)d.autoplay=false; } }catch(e){}
      return d; }
    var SET=loadSettings();
    function saveSettings(){ try{ localStorage.setItem(SET_KEY, JSON.stringify(SET)); }catch(e){} }
    function applyTheme(){ document.documentElement.setAttribute("data-theme", SET.theme); }
    applyTheme();

    // Admin-controlled site settings (shared for everyone; loaded from the server).
    var CFG_FEATURES=["banners","albums","popular","search","genres","categories","playlists","artists","stories","downloads","favorites"];
    var CFG_ACCENTS={purple:["#7c5cff","#ff4d8d"],blue:["#3b82f6","#06b6d4"],green:["#10b981","#34d399"],red:["#ef4444","#f97316"],gold:["#f59e0b","#fbbf24"],teal:["#14b8a6","#22d3ee"]};
    var CFG={appName:"",announcement:"",theme:"",lang:"",accent:"",features:{}};
    CFG_FEATURES.forEach(function(k){ CFG.features[k]=true; });
    var _setSaved=false; try{ _setSaved=!!localStorage.getItem(SET_KEY); }catch(e){}
    function feat(k){ return CFG.features[k]!==false; }
    function applyConfig(c){
      c=c||{}; CFG.appName=(typeof c.appName==="string"?c.appName:""); CFG.announcement=(typeof c.announcement==="string"?c.announcement:"");
      CFG.theme=(c.theme==="dark"||c.theme==="light")?c.theme:""; CFG.lang=(c.lang==="en"||c.lang==="he")?c.lang:""; CFG.accent=(c.accent&&CFG_ACCENTS[c.accent])?c.accent:"";
      var f=(c.features&&typeof c.features==="object")?c.features:{}; CFG_FEATURES.forEach(function(k){ CFG.features[k]=f[k]!==false; });
      // Accent color (whole app + gradients follow --accent / --accent-2).
      var rs=document.documentElement.style;
      if(CFG.accent){ rs.setProperty("--accent",CFG_ACCENTS[CFG.accent][0]); rs.setProperty("--accent-2",CFG_ACCENTS[CFG.accent][1]); }
      else { rs.removeProperty("--accent"); rs.removeProperty("--accent-2"); }
      // Admin defaults for theme/language apply only if this device has not chosen its own.
      if(!_setSaved){ if(CFG.theme){ SET.theme=CFG.theme; applyTheme(); } if(CFG.lang){ SET.lang=CFG.lang; } }
      var bn=document.querySelector(".brand .name"); if(bn) bn.textContent=CFG.appName||"Zing";
      try{ document.title=(CFG.appName||"Zing")+" — Jewish Music"; }catch(e){}
      var tabMap={tabAlbums:"albums",tabSearch:"search",tabGenres:"genres",tabPlaylists:"playlists",tabArtists:"artists"};
      Object.keys(tabMap).forEach(function(id){ var el=$(id); if(el) el.style.display=feat(tabMap[id])?"":"none"; });
      var favBtn=document.querySelector('.iconbtn[title="My Music"]'); if(favBtn) favBtn.style.display=feat("favorites")?"":"none";
      var srchBtn=document.querySelector('.iconbtn[title="Search"]'); if(srchBtn) srchBtn.style.display=feat("search")?"":"none";
      var npdl=$("npDl"); if(npdl) npdl.style.display=feat("downloads")?"":"none";
      var ann=$("annBanner");
      if(CFG.announcement){ if(!ann){ ann=document.createElement("div"); ann.id="annBanner"; ann.className="banner"; ann.style.marginTop="10px"; var st=$("status"); if(st&&st.parentNode) st.parentNode.insertBefore(ann, st); } ann.textContent=CFG.announcement; ann.hidden=false; }
      else if(ann){ ann.hidden=true; }
    }
    function loadConfig(){ return fetch("/api/config").then(function(r){return r.json();}).then(function(c){ applyConfig(c); }).catch(function(){}); }
    var ME={admin:false,user:null};
    function dlAllowed(){ return feat("downloads") && !(ME.user && ME.user.nodl); }
    function loadMe(){ return fetch("/api/me").then(function(r){return r.json();}).then(function(d){
      ME.admin=!!(d&&d.admin); ME.user=(d&&d.user)||null;
      if(ME.user&&ME.user.photo&&/^data:image/.test(ME.user.photo)){ var a=$("meAvatar"),im=$("meImg"); if(im) im.src=ME.user.photo; if(a) a.hidden=false; }
      updateCfgBanner(); if(ME.admin) loadPending();
      var np=$("npDl"); if(np) np.style.display=dlAllowed()?"":"none";
      if(ME.user&&ME.user.nodl){ go(curTab||"home"); } // re-render so per-account download control applies
    }).catch(function(){}); }
    function loadPending(){ fetch("/api/pending").then(function(r){return r.json();}).then(function(d){ var n=(d&&d.pending)||0;
      var g=document.querySelector('.iconbtn[title="Settings"]'); if(!g) return; g.style.position="relative"; var b=$("pendBadge");
      if(n>0){ if(!b){ b=document.createElement("span"); b.id="pendBadge"; b.style.cssText="position:absolute;top:3px;right:3px;min-width:16px;height:16px;padding:0 4px;border-radius:999px;background:var(--err);color:#fff;font-size:.62rem;font-weight:800;display:grid;place-items:center"; g.appendChild(b); } b.textContent=n; b.hidden=false; }
      else if(b){ b.hidden=true; } }).catch(function(){}); }
    // Live presence: tell the server what this device is doing, so the owner can see who is on.
    var _cid=""; try{ _cid=localStorage.getItem("zing_cid")||""; if(!_cid){ _cid=Date.now().toString(36)+Math.random().toString(36).slice(2,8); localStorage.setItem("zing_cid",_cid); } }catch(e){ _cid="c"+Math.random().toString(36).slice(2,10); }
    var _activity="Home";
    function setActivity(a){ _activity=a||""; sendPresence(); }
    function sendPresence(){ fetch("/api/presence",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cid:_cid,view:_activity})}).catch(function(){}); }

    function $(id){ return document.getElementById(id); }
    function esc(s){ return (s==null?"":String(s)).replace(/[&<>"']/g,function(c){ return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]; }); }
    var ICONS={
      music_note:"M12 3v10.55A4 4 0 1 0 14 17V7h4V3z",
      settings:"M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 16v-2h8v-2h-8v-2h-2v6h2zM7 9v2H3v2h4v2h2V9H7zm14 4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z",
      chevron_right:"M10 6 8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z",
      home:"M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z",
      search:"M15.5 14h-.79l-.28-.27a6.5 6.5 0 1 0-.7.7l.27.28v.79l5 4.99L20.49 19zm-6 0A4.5 4.5 0 1 1 14 9.5 4.5 4.5 0 0 1 9.5 14z",
      category:"M3 3h8v8H3V3zm10 0h8v8h-8V3zM3 13h8v8H3v-8zm10 0h8v8h-8v-8z",
      featured_play_list:"M3 10h11v2H3v-2zm0-4h11v2H3V6zm0 8h7v2H3v-2zm13-1v6l5-3-5-3z",
      artist:"M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
      album:"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 14c-2.21 0-4-1.79-4-4s1.79-4 4-4 4 1.79 4 4-1.79 4-4 4zm0-5c-.55 0-1 .45-1 1s.45 1 1 1 1-.45 1-1-.45-1-1-1z",
      favorite:"M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z",
      favorite_border:"M16.5 3c-1.74 0-3.41.81-4.5 2.09C10.91 3.81 9.24 3 7.5 3 4.42 3 2 5.42 2 8.5c0 3.78 3.4 6.86 8.55 11.54L12 21.35l1.45-1.32C18.6 15.36 22 12.28 22 8.5 22 5.42 19.58 3 16.5 3zm-4.4 15.55l-.1.1-.1-.1C7.14 14.24 4 11.39 4 8.5 4 6.5 5.5 5 7.5 5c1.54 0 3.04.99 3.57 2.36h1.87C13.46 5.99 14.96 5 16.5 5c2 0 3.5 1.5 3.5 3.5 0 2.89-3.14 5.74-7.9 10.05z",
      play_arrow:"M8 5v14l11-7z",
      pause:"M6 5h4v14H6zm8 0h4v14h-4z",
      skip_previous:"M6 6h2v12H6zm3.5 6 8.5 6V6z",
      skip_next:"M16 6h2v12h-2zM6 18l8.5-6L6 6z",
      download:"M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z",
      arrow_back_ios_new:"M17.77 3.77 16 2 6 12l10 10 1.77-1.77L9.54 12z",
      close:"M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z",
      delete:"M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z",
      person_add:"M15 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm-9-1V8H4v3H1v2h3v3h2v-3h3v-2H6zm9 3c-2.67 0-8 1.34-8 4v3h16v-3c0-2.66-5.33-4-8-4z",
      logout:"M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4z",
      lock:"M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"
    };
    function ic(n){ return '<svg class="ms" viewBox="0 0 24 24" aria-hidden="true"><path d="'+(ICONS[n]||ICONS.play_arrow)+'"></path></svg>'; }
    function hydrateIcons(root){ (root||document).querySelectorAll("span.ms").forEach(function(el){ el.outerHTML = ic(el.textContent.trim()); }); }
    function hash(s){ var h=0; s=s||"?"; for(var i=0;i<s.length;i++){ h=(h*31+s.charCodeAt(i))>>>0; } return h; }
    function grad(name){ var h=hash(name); var a=h%360; var b=(a+45+(h>>3)%70)%360; return "linear-gradient(135deg, hsl("+a+",72%,56%), hsl("+b+",70%,44%))"; }
    function ini(name){ var p=(name||"?").trim().split(/\\s+/).filter(Boolean); if(!p.length) return "?"; return (p.length===1?p[0].slice(0,2):(p[0][0]+p[1][0])).toUpperCase(); }
    function fmt(sec){ if(!isFinite(sec)||sec<0) sec=0; var m=Math.floor(sec/60), s=Math.floor(sec%60); return m+":"+(s<10?"0":"")+s; }
    function pick(en,he){ if(SET.lang==="he"){ return he||en||""; } return en||he||""; }
    function trackName(t){ return (pick(t.enName,t.heName)||(t.file||"").split("/").pop()||("Track "+t.id)); }
    function albName(al){ return (pick(al.enName,al.heName)||"Unknown Album"); }
    function artNames(list){ return (list||[]).map(function(a){return pick(a.enName,a.heName)||"Unknown";}).join(", "); }
    function plName(p){ return pick(p.enName||p.name, p.heName)||"Playlist"; }
    function genName(g){ return pick(g.enName,g.heName)||"Genre"; }
    function albImg(al){ var im=al&&al.images; return (im && (im.cdnMedium||im.medium||im.cdnSmall||im.small))||null; }
    function imgUrl(v){ return (typeof v==="string" && /^https?:\\/\\//.test(v)) ? v : null; }

    function setStatus(h,c){ $("status").innerHTML=h||""; $("status").className=c||""; }
    function loading(m){ setStatus('<span class="spinner"></span>'+m,"muted"); }
    var toastT;
    function toast(m){ var t=$("toast"); t.textContent=m; t.classList.add("show"); clearTimeout(toastT); toastT=setTimeout(function(){ t.classList.remove("show"); }, 2600); }
    function setView(h){ $("view").innerHTML=h; window.scrollTo({top:0,behavior:"smooth"}); }

    function coverHtml(name,opts){ opts=opts||{}; var cls="cover"+(opts.round?" round":""); var url=imgUrl(opts.img);
      if(url){ return '<div class="'+cls+'" style="background-image:url(\\''+esc(url)+'\\');background-size:cover;background-position:center;background-color:#161627">'+(opts.fab?'<div class="fab">'+ic("play_arrow")+'</div>':'')+'</div>'; }
      var inner=opts.round?'<span class="ini">'+esc(ini(name))+'</span>':'<span class="disc"></span>';
      return '<div class="'+cls+'" style="background:'+grad(name)+'">'+inner+(opts.fab?'<div class="fab">'+ic("play_arrow")+'</div>':'')+'</div>'; }

    function post(path,payload){
      return fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload||{})})
        .then(function(res){ return res.json().catch(function(){return {};}).then(function(d){
          if(res.status===401&&d.needLogin){ location.href="/"; throw new Error("Please log in."); }
          if(!res.ok) throw new Error(d.error||("Request failed ("+res.status+")")); return d; }); });
    }
    function gql(query,vars){
      return fetch("/api/query",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:query,variables:vars||{}})})
        .then(function(r){ if(r.status===401){ location.href="/"; throw new Error("login"); } return r.json(); })
        .then(function(d){ if(d&&d.errors&&d.errors.length) throw new Error(d.errors[0].message||"query error"); return (d&&d.data)||{}; });
    }
    // Authenticated GraphQL (attaches the login token) for per-account actions.
    function agql(query,vars){
      return fetch("/api/authquery",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:query,variables:vars||{}})})
        .then(function(r){ if(r.status===401){ location.href="/"; throw new Error("login"); } return r.json(); })
        .then(function(d){ if(d&&d.errors&&d.errors.length) throw new Error(d.errors[0].message||"query error"); return (d&&d.data)||{}; });
    }
    var _profileId=null, _profileTried=false;
    function ensureProfile(){
      if(_profileId) return Promise.resolve(_profileId);
      if(_profileTried) return Promise.resolve(_profileId);
      return agql("query { profiles { id name } }").then(function(d){ _profileTried=true; var ps=d.profiles||[]; _profileId=ps.length?ps[0].id:null; return _profileId; })
        .catch(function(){ _profileTried=true; return null; });
    }
    function saveArtist(id){ toast("Saving…"); ensureProfile().then(function(pid){
      var q = pid ? "mutation($a:Int!,$p:Int!){ saveMyArtistToProfile(artistId:$a, profileId:$p){ id } }"
                  : "mutation($a:Int!){ createOneMyArtist(data:{ artist:{ connect:{ id:$a } } }){ id } }";
      var v = pid ? {a:Number(id),p:Number(pid)} : {a:Number(id)};
      agql(q,v).then(function(){ toast("Saved to My Music ♥"); }).catch(function(e){ if(e.message==="login")return; toast("Couldn’t save: "+(e.message||"login not connected")); }); }); }
    function saveAlbum(id){ toast("Saving…"); ensureProfile().then(function(pid){
      var q = pid ? "mutation($a:Int!,$p:Int!){ saveMyAlbumToProfile(albumId:$a, profileId:$p){ id } }"
                  : "mutation($a:Int!){ createOneMyAlbum(data:{ album:{ connect:{ id:$a } } }){ id } }";
      var v = pid ? {a:Number(id),p:Number(pid)} : {a:Number(id)};
      agql(q,v).then(function(){ toast("Saved to My Music ♥"); }).catch(function(e){ if(e.message==="login")return; toast("Couldn’t save: "+(e.message||"login not connected")); }); }); }

    var _configured=true;
    function updateCfgBanner(){ var show=ME.admin && !_configured; var b=$("cfgBanner"); if(b) b.hidden=!show; var bd=$("cfgBadge"); if(bd) bd.textContent=show?"Not configured":""; }
    function checkStatus(){ fetch("/api/status").then(function(r){return r.json();}).then(function(s){ _configured=!!s.configured; updateCfgBanner(); }).catch(function(){}); }

    function loadCache(){ try{ var o=JSON.parse(localStorage.getItem(CACHE_KEY)||"null"); if(o&&Date.now()-o.t<CACHE_TTL&&o.a&&o.a.length) return o.a; }catch(e){} return null; }
    function saveCache(a){ try{ localStorage.setItem(CACHE_KEY, JSON.stringify({t:Date.now(),a:a})); }catch(e){} }
    function refreshArtists(){ return post("/api/artists",{}).then(function(d){ if(d.artists&&d.artists.length){ artists=d.artists; saveCache(artists); } return true; }).catch(function(){ return false; }); }
    function ensureArtists(){
      if(artistsLoaded) return Promise.resolve(true);
      var c=loadCache();
      if(c){ artists=c; artistsLoaded=true; refreshArtists(); return Promise.resolve(true); } // show cached now, refresh in the background
      loading("Loading artists…");
      return post("/api/artists",{}).then(function(d){ artists=d.artists||[]; artistsLoaded=true; saveCache(artists); setStatus(""); return true; })
        .catch(function(e){ setStatus("Could not load: "+esc(e.message),"err"); return false; });
    }

    // ---------- Tabs ----------
    function setTab(id){ ["tabHome","tabAlbums","tabSearch","tabGenres","tabPlaylists","tabArtists"].forEach(function(n){ var el=$(n); if(el) el.classList.toggle("active", n===id); }); }
    var GO_LABEL={home:"Home",albums:"Albums",search:"Searching",genres:"Genres",playlists:"Playlists",artists:"Artists"};
    function go(where){
      curTab=where; setActivity(GO_LABEL[where]||"Home");
      if(where==="home"){ setTab("tabHome"); home(); }
      else if(where==="albums"){ setTab("tabAlbums"); browseAlbums(); }
      else if(where==="search"){ setTab("tabSearch"); searchView(); }
      else if(where==="genres"){ setTab("tabGenres"); browseGenres(); }
      else if(where==="playlists"){ setTab("tabPlaylists"); browsePlaylists(); }
      else if(where==="artists"){ setTab("tabArtists"); browseArtists(); }
    }

    // ---------- Cards ----------
    function albumHCard(al, sub){ return '<div class="hcard album" onclick="openAlbum('+al.id+')">'+coverHtml(albName(al),{img:albImg(al),fab:true})+
      '<div class="c-name">'+esc(albName(al))+'</div><div class="c-sub">'+esc(sub||"")+'</div></div>'; }
    function artistHCard(a){ var nm=pick(a.enName,a.heName)||"Artist"; return '<div class="hcard artist" onclick="openArtist('+a.id+')">'+coverHtml(nm,{round:true,img:a.image})+
      '<div class="c-name">'+esc(nm)+'</div></div>'; }
    function albumTile(al, sub){ return '<div class="tile album" onclick="openAlbum('+al.id+')">'+coverHtml(albName(al),{img:albImg(al),fab:true})+
      '<div class="c-name">'+esc(albName(al))+'</div><div class="c-sub">'+esc(sub||"")+'</div></div>'; }
    function artistTile(a){ var nm=pick(a.enName,a.heName)||"Unknown"; var alt=(SET.lang==="he")?(a.enName||""):(a.heName||"");
      return '<div class="tile artist" onclick="openArtist('+a.id+')">'+coverHtml(nm,{round:true,img:a.image})+
      '<div class="c-name">'+esc(nm)+'</div><div class="c-sub">'+esc(alt)+'</div></div>'; }

    function secHead(title, seeTab, seeFn){
      var see = seeFn ? '<button class="see" onclick="'+seeFn+'">See all '+ic("chevron_right")+'</button>'
        : (seeTab ? '<button class="see" onclick="go(\\''+seeTab+'\\')">See all '+ic("chevron_right")+'</button>' : '');
      return '<div class="sec-head"><h2>'+esc(title)+'</h2>'+see+'</div>'; }

    // ---------- Home ----------
    function bannerImg(b){ return (SET.lang==="he") ? (b.heImage||b.enImage) : (b.enImage||b.heImage); }
    function bannerCard(b){ var u=imgUrl(bannerImg(b)); if(!u) return "";
      return '<div class="banner-card" onclick="openBannerUrl('+esc(JSON.stringify(b.url||"")).replace(/"/g,"&quot;")+')" style="background-image:url(\\''+esc(u)+'\\')"></div>'; }
    function openBannerUrl(url){ url=url||""; var m;
      if((m=url.match(/album[s]?[\\/=](\\d+)/i))){ openAlbum(+m[1]); return; }
      if((m=url.match(/artist[s]?[\\/=](\\d+)/i))){ openArtist(+m[1]); return; }
      if((m=url.match(/playlist[s]?[\\/=](\\d+)/i))){ openPlaylist(+m[1]); return; }
      if(/^https?:/i.test(url)){ window.open(url,"_blank"); } }
    function home(){
      loading("Loading…");
      var pBan=gql("query { banners(take: 15, orderBy: [{ index: asc }]) { id enName heName enImage heImage url index platform } }").then(function(d){return d.banners||[];}).catch(function(){return [];});
      var pNew=post("/api/new",{}).then(function(d){return d.albums||[];}).catch(function(){return [];});
      var pPop=gql("query { getMostPlayed(input: { type: ALBUMS, period: MONTH, limit: 12 }) { albumsWithEntities { plays album { id enName heName images { cdnSmall cdnMedium medium small } artists { enName heName } tracks { id } } } } }").then(function(d){ return (((d.getMostPlayed||{}).albumsWithEntities)||[]).map(function(x){return x.album;}).filter(Boolean); }).catch(function(){return [];});
      var pGen=gql("query { genres(take: 20) { id enName heName } }").then(function(d){return d.genres||[];}).catch(function(){return [];});
      var pCat=gql("query { categories(take: 40) { id enName heName } }").then(function(d){return d.categories||[];}).catch(function(){return [];});
      var pPl=gql("query { playlists(take: 20) { id name enName heName image cdnImage } }").then(function(d){return d.playlists||[];}).catch(function(){return [];});
      var pStr=gql("query { stories(take: 15, orderBy: [{ releaseDate: desc }]) { id enName heName imageUrl } }").then(function(d){return d.stories||[];}).catch(function(){return [];});
      Promise.all([pBan,pNew,pPop,pGen,pCat,pPl,pStr]).then(function(res){
        setStatus("");
        var banners=res[0], albums=res[1], popular=res[2], genres=res[3], categories=res[4], playlists=res[5], stories=res[6];
        window._albums=window._albums||{};
        var html="";
        if(banners.length && feat("banners")){
          var bcards=banners.map(bannerCard).filter(Boolean).join("");
          if(bcards) html+='<div class="sec" style="margin-top:12px"><div class="hrow banners">'+bcards+'</div></div>';
        }
        if(albums.length && feat("albums")){
          html+='<div class="sec">'+secHead("New Releases", null, "go('albums')")+'<div class="hrow">'+albums.map(function(al){ window._albums[al.id]=al;
            return albumHCard(al, artNames(al.artists)); }).join("")+'</div></div>';
        }
        if(popular.length && feat("popular")){
          html+='<div class="sec">'+secHead("Popular this month")+'<div class="hrow">'+popular.map(function(al){ window._albums[al.id]=al;
            return albumHCard(al, artNames(al.artists)); }).join("")+'</div></div>';
        }
        if(genres.length && feat("genres")){
          html+='<div class="sec">'+secHead("Genres","genres")+'<div class="chips">'+genres.map(function(g){
            return '<button class="chip" onclick="openGenre('+g.id+')">'+esc(genName(g))+'</button>'; }).join("")+'</div></div>';
        }
        if(categories.length && feat("categories")){
          html+='<div class="sec">'+secHead("Categories")+'<div class="chips">'+categories.map(function(c){
            return '<button class="chip" onclick="openCategory('+c.id+')">'+esc(genName(c))+'</button>'; }).join("")+'</div></div>';
        }
        if(playlists.length && feat("playlists")){
          html+='<div class="sec">'+secHead("Playlists","playlists")+'<div class="hrow">'+playlists.map(function(p){ var nm=plName(p);
            return '<div class="hcard" onclick="openPlaylist('+p.id+')">'+coverHtml(nm,{img:p.cdnImage||p.image,fab:true})+'<div class="c-name">'+esc(nm)+'</div><div class="c-sub">Playlist</div></div>'; }).join("")+'</div></div>';
        }
        if(stories.length && feat("stories")){
          html+='<div class="sec">'+secHead("Stories")+'<div class="hrow">'+stories.map(function(s){ var nm=pick(s.enName,s.heName)||"Story";
            return '<div class="hcard" onclick="openStory('+s.id+')">'+coverHtml(nm,{img:s.imageUrl})+'<div class="c-name">'+esc(nm)+'</div></div>'; }).join("")+'</div></div>';
        }
        if(!html) html='<div class="empty">Nothing to show yet. Check Settings.</div>';
        setView(html);
      });
    }
    function openCategory(id){ loading("Loading…");
      gql("query { category(where:{id:"+Number(id)+"}) { id enName heName albums { id enName heName images { cdnSmall cdnMedium medium small } artists { enName heName } tracks { id } } } }").then(function(d){
        var g=d.category; var albums=(g&&g.albums)||[]; setStatus(""); window._albumBack=function(){ go("home"); };
        var head='<div class="back" onclick="go(\\'home\\')">'+ic("arrow_back_ios_new")+'Home</div>'+secHead(g?genName(g):"Category");
        if(!albums.length){ setView(head+'<div class="empty">No albums in this category.</div>'); return; }
        window._albums=window._albums||{}; setView(head+'<div class="grid albums">'+albums.map(function(al){ window._albums[al.id]=al; return albumTile(al, artNames(al.artists)); }).join("")+'</div>');
      }).catch(function(e){ if(e.message==="login")return; setStatus("Error: "+esc(e.message),"err"); });
    }
    function openStory(id){ loading("Loading…");
      gql("query { story(where:{id:"+Number(id)+"}) { id enName heName imageUrl articles(orderBy:[{ index: asc }]) { id enName heName pdfUrl releaseDate } } }").then(function(d){
        var s=d.story; setStatus(""); if(!s){ setView('<div class="empty">Story not found.</div>'); return; }
        var nm=pick(s.enName,s.heName)||"Story"; var arts=s.articles||[];
        var back='<div class="back" onclick="go(\\'home\\')">'+ic("arrow_back_ios_new")+'Home</div>';
        var rows=arts.map(function(a){ var an=pick(a.enName,a.heName)||("Part "+a.id);
          return '<div class="track" onclick="openArticle('+esc(JSON.stringify(a.pdfUrl||"")).replace(/"/g,"&quot;")+')"><div class="num">'+ic("featured_play_list")+'</div><div class="tk">'+esc(an)+'</div><div class="dl">'+ic("chevron_right")+'</div></div>'; }).join("");
        setView(back+'<div class="hero">'+coverHtml(nm,{img:s.imageUrl})+'<div><div class="kicker">Story</div><h2>'+esc(nm)+'</h2><div class="sub">'+arts.length+' parts</div></div></div>'+
          (arts.length?'<div class="tracks">'+rows+'</div>':'<div class="empty">No parts to read yet.</div>'));
      }).catch(function(e){ if(e.message==="login")return; setStatus("Error: "+esc(e.message),"err"); });
    }
    function openArticle(pdfUrl){ if(pdfUrl && /^https?:/i.test(pdfUrl)){ window.open(pdfUrl,"_blank"); } else { toast("This part is not available."); } }

    // ---------- Search (real, across songs / albums / artists) ----------
    var _searchT, _searchSeq=0, _searchTracks=[];
    function searchView(){
      setView('<div class="searchbar">'+ic("search")+'<input id="q" type="text" placeholder="Search songs, albums, artists…" autocomplete="off" /></div><div id="sres"></div>');
      var q=$("q"); q.focus();
      q.addEventListener("input", function(){ var val=this.value; clearTimeout(_searchT); _searchT=setTimeout(function(){ doSearch(val); }, 280); });
      doSearch("");
    }
    function nameFilter(){ return "OR:[{enName:{contains:$t,mode:insensitive}},{heName:{contains:$t,mode:insensitive}}]"; }
    function doSearch(v){
      var q=(v||"").trim(); var box=$("sres"); if(!box) return;
      if(!q){ box.innerHTML='<div class="empty">Type to search songs, albums and artists.</div>'; return; }
      box.innerHTML='<div class="empty"><span class="spinner"></span>Searching…</div>';
      var seq=++_searchSeq;
      var query="query($t:String!){"+
        " artists(take:24, where:{"+nameFilter()+"}){ id enName heName image }"+
        " albums(take:24, where:{"+nameFilter()+"}){ id enName heName images { cdnSmall cdnMedium medium small } artists { enName heName } tracks { id } }"+
        " tracks(take:30, where:{"+nameFilter()+"}){ id enName heName file duration album { images { cdnSmall cdnMedium medium small } } artists { enName heName } }"+
        " }";
      gql(query,{t:q}).then(function(d){
        if(seq!==_searchSeq) return; // a newer search superseded this one
        var arts=d.artists||[], albs=d.albums||[], trks=d.tracks||[];
        window._albums=window._albums||{}; albs.forEach(function(al){ window._albums[al.id]=al; });
        _searchTracks=trks;
        if(!arts.length&&!albs.length&&!trks.length){ box.innerHTML='<div class="empty">Nothing found for “'+esc(q)+'”.</div>'; return; }
        var html="";
        if(trks.length){
          html+='<div class="sec">'+secHead("Songs")+'<div class="tracks" style="margin:0 18px">'+trks.map(function(t,i){
            return '<div class="track" onclick="playSearchTrack('+i+')"><div class="num">'+ic("play_arrow")+'</div>'+
              '<div class="tk">'+esc(trackName(t))+(t.artists&&t.artists.length?'<div class="sub">'+esc(artNames(t.artists))+'</div>':'')+'</div>'+
              (t.duration?'<div class="time">'+fmt(t.duration)+'</div>':'')+
              dlBtn(t.id,t.file)+'</div>'; }).join("")+'</div></div>';
        }
        if(albs.length){
          html+='<div class="sec">'+secHead("Albums")+'<div class="grid albums">'+albs.map(function(al){ return albumTile(al, artNames(al.artists)); }).join("")+'</div></div>';
        }
        if(arts.length){
          html+='<div class="sec">'+secHead("Artists")+'<div class="grid artists">'+arts.map(artistTile).join("")+'</div></div>';
        }
        box.innerHTML=html;
      }).catch(function(e){ if(seq!==_searchSeq) return; if(e.message==="login")return; box.innerHTML='<div class="empty">Search error: '+esc(e.message)+'</div>'; });
    }
    function playSearchTrack(i){ playTracks(_searchTracks||[], i, ""); }

    // ---------- Genres ----------
    function browseGenres(){ loading("Loading genres…");
      gql("query { genres(take: 300) { id enName heName } }").then(function(d){ var gs=d.genres||[]; setStatus("");
        if(!gs.length){ setView('<div class="empty">No genres.</div>'); return; }
        setView(secHead("Genres")+'<div class="chips">'+gs.map(function(g){ return '<button class="chip" onclick="openGenre('+g.id+')">'+esc(genName(g))+'</button>'; }).join("")+'</div>');
      }).catch(function(e){ if(e.message==="login")return; setStatus("Error: "+esc(e.message),"err"); });
    }
    function openGenre(id){ loading("Loading…");
      gql("query { genre(where:{id:"+Number(id)+"}) { id enName heName albums { id enName heName images { cdnSmall cdnMedium medium small } artists { enName heName } tracks { id } } } }").then(function(d){
        var g=d.genre; var albums=(g&&g.albums)||[]; setStatus(""); window._albumBack=browseGenres;
        var head='<div class="back" onclick="browseGenres()">'+ic("arrow_back_ios_new")+'Genres</div>'+secHead(g?genName(g):"Genre");
        if(!albums.length){ setView(head+'<div class="empty">No albums in this genre.</div>'); return; }
        window._albums=window._albums||{}; setView(head+'<div class="grid albums">'+albums.map(function(al){ window._albums[al.id]=al; return albumTile(al, artNames(al.artists)); }).join("")+'</div>');
      }).catch(function(e){ if(e.message==="login")return; setStatus("Error: "+esc(e.message),"err"); });
    }

    // ---------- Playlists ----------
    function browsePlaylists(){ loading("Loading playlists…");
      gql("query { playlists(take: 300) { id name enName heName image cdnImage } }").then(function(d){ var ps=d.playlists||[]; setStatus("");
        if(!ps.length){ setView('<div class="empty">No playlists.</div>'); return; }
        setView(secHead("Playlists")+'<div class="grid albums">'+ps.map(function(p){ var nm=plName(p);
          return '<div class="tile album" onclick="openPlaylist('+p.id+')">'+coverHtml(nm,{img:p.cdnImage||p.image,fab:true})+'<div class="c-name">'+esc(nm)+'</div><div class="c-sub">Playlist</div></div>'; }).join("")+'</div>');
      }).catch(function(e){ if(e.message==="login")return; setStatus("Error: "+esc(e.message),"err"); });
    }
    function openPlaylist(id){ loading("Loading…");
      gql("query { playlist(where:{id:"+Number(id)+"}) { id name enName heName image cdnImage playlistTracks { track { id enName heName file duration trackNumber artists { enName heName } } } } }").then(function(d){
        var p=d.playlist; setStatus("");
        var tracks=((p&&p.playlistTracks)||[]).map(function(x){return x.track;}).filter(Boolean);
        var nm=p?plName(p):"Playlist";
        renderTrackList(nm, tracks.length+" tracks", tracks, browsePlaylists, (p&&(p.cdnImage||p.image)), "Playlist");
      }).catch(function(e){ if(e.message==="login")return; setStatus("Error: "+esc(e.message),"err"); });
    }

    // ---------- Albums (all, newest first, with load more) ----------
    var _albPage={skip:0,take:30,loading:false,end:false};
    function browseAlbums(){
      _albPage={skip:0,take:30,loading:false,end:false};
      setView(secHead("Albums")+'<p class="muted" style="margin:-4px 18px 10px">All albums, newest first — old and new together.</p><div id="albGrid" class="grid albums"></div><div id="albMore" style="text-align:center;padding:18px"></div>');
      loadMoreAlbums();
    }
    function loadMoreAlbums(){
      if(_albPage.loading||_albPage.end) return; _albPage.loading=true;
      var more=$("albMore"); if(more) more.innerHTML='<span class="spinner"></span>Loading…';
      post("/api/albums",{skip:_albPage.skip,take:_albPage.take}).then(function(d){
        var got=d.albums||[]; window._albums=window._albums||{};
        got.forEach(function(al){ window._albums[al.id]=al; });
        var grid=$("albGrid"); if(grid) grid.insertAdjacentHTML("beforeend", got.map(function(al){ return albumTile(al, artNames(al.artists)); }).join(""));
        _albPage.skip+=got.length; _albPage.loading=false;
        if(got.length<_albPage.take){ _albPage.end=true; if(more) more.innerHTML=(_albPage.skip?'<span class="muted">That\\'s everything ('+_albPage.skip+' albums).</span>':'<span class="empty">No albums.</span>'); }
        else if(more){ more.innerHTML='<button class="btn ghost" onclick="loadMoreAlbums()">Load more</button>'; }
      }).catch(function(e){ _albPage.loading=false; if(e.message==="login")return; var more=$("albMore"); if(more) more.innerHTML='<span class="err">'+esc(e.message)+'</span>'; });
    }

    // ---------- Artists ----------
    function browseArtists(){ ensureArtists().then(function(ok){ if(!ok) return;
      var sorted=artists.slice().sort(function(a,b){ return (a.enName||"").localeCompare(b.enName||""); }).slice(0,600);
      setView(secHead("Artists")+'<div class="grid artists">'+sorted.map(artistTile).join("")+'</div>'+(artists.length>600?'<div class="empty">Showing 600 of '+artists.length+'. Use Search for a specific artist.</div>':''));
    }); }

    function openArtist(id){ loading("Loading…");
      post("/api/artist",{id:id}).then(function(d){ var a=d.artist, albums=(a&&a.albums)||[]; setStatus(""); var anm=a?(pick(a.enName,a.heName)||"Artist"):"Artist"; var aalt=a?((SET.lang==="he")?(a.enName||""):(a.heName||"")):""; window._curArtist=anm;
        var abio=a?(a.bio||pick(a.enDesc,a.heDesc)||""):"";
        var head='<div class="back" onclick="go(\\'home\\')">'+ic("arrow_back_ios_new")+'Back</div>'+
          '<div class="hero">'+coverHtml(anm,{round:true,img:(a&&a.image)})+'<div><div class="kicker">Artist</div><h2>'+esc(anm)+'</h2>'+(aalt?'<div class="sub">'+esc(aalt)+'</div>':'')+
            (feat("favorites")?'<div class="actions"><button class="btn ghost sm" onclick="saveArtist('+Number(id)+')">'+ic("favorite_border")+' Save</button></div>':'')+'</div></div>'+
          (abio?'<p class="muted" style="margin:-6px 18px 18px;line-height:1.7;font-size:.92rem">'+esc(abio)+'</p>':'');
        window._albumBack=function(){ openArtist(id); };
        if(!albums.length){ setView(head+'<div class="empty">No albums available.</div>'); return; }
        window._albums=window._albums||{}; setView(head+secHead("Albums")+'<div class="grid albums">'+albums.map(function(al){ window._albums[al.id]=al; return albumTile(al,(al.tracks||[]).length+" tracks"); }).join("")+'</div>');
      }).catch(function(e){ setStatus("Error: "+esc(e.message),"err"); });
    }

    // ---------- Album ----------
    function openAlbum(id){ loading("Loading album…");
      gql("query { album(where:{id:"+Number(id)+"}) { id enName heName images { cdnMedium cdnLarge medium large } artists { enName heName image } tracks { id enName heName file duration trackNumber } } }").then(function(d){
        var al=d.album; setStatus(""); if(!al){ setView('<div class="empty">Album not found.</div>'); return; }
        window._albums=window._albums||{}; window._albums[id]=al; renderAlbum(id, al);
      }).catch(function(e){ if(e.message==="login")return; setStatus("Error: "+esc(e.message),"err"); });
    }
    function renderAlbum(id, al){
      var tracks=al.tracks||[]; var artistName=(al.artists&&al.artists.length)?artNames(al.artists):(window._curArtist||"");
      var back='<div class="back" onclick="'+(window._albumBack?'window._albumBack()':'go(\\'home\\')')+'">'+ic("arrow_back_ios_new")+'Back</div>';
      var rows=tracks.map(function(t,i){ return '<div class="track" id="trk'+t.id+'" onclick="playAlbum('+id+','+i+')"><div class="num">'+(t.trackNumber||i+1)+'</div>'+
        '<div class="tk">'+esc(trackName(t))+'</div>'+(t.duration?'<div class="time">'+fmt(t.duration)+'</div>':'')+
        dlBtn(t.id,t.file)+'</div>'; }).join("");
      setView(back+'<div class="hero">'+coverHtml(albName(al),{img:albImg(al)})+'<div><div class="kicker">Album'+(artistName?' · '+esc(artistName):'')+'</div><h2>'+esc(albName(al))+'</h2><div class="sub">'+tracks.length+' tracks</div>'+
        '<div class="actions">'+(tracks.length?'<button class="btn" onclick="playAlbum('+id+',0)">'+ic("play_arrow")+' Play all</button>':'')+(feat("favorites")?'<button class="btn ghost" onclick="saveAlbum('+id+')">'+ic("favorite_border")+' Save</button>':'')+((dlAllowed()&&tracks.length)?'<button class="btn ghost" onclick="downloadAlbum('+id+')">'+ic("download")+' Download all</button>':'')+'</div></div></div>'+
        (tracks.length?'<div class="tracks">'+rows+'</div>':'<div class="empty">No tracks.</div>'));
      highlightPlaying();
    }

    // ---------- Track list (playlists) ----------
    function renderTrackList(title, subtitle, tracks, backFn, img, kicker){
      window._listTracks=tracks; window._listBack=backFn;
      var back='<div class="back" onclick="window._listBack&&window._listBack()">'+ic("arrow_back_ios_new")+'Back</div>';
      var rows=tracks.map(function(t,i){ return '<div class="track" id="ltrk'+t.id+'" onclick="playList('+i+')"><div class="num">'+(i+1)+'</div>'+
        '<div class="tk">'+esc(trackName(t))+(t.artists&&t.artists.length?'<div class="sub">'+esc(artNames(t.artists))+'</div>':'')+'</div>'+
        (t.duration?'<div class="time">'+fmt(t.duration)+'</div>':'')+
        dlBtn(t.id,t.file)+'</div>'; }).join("");
      setView(back+'<div class="hero">'+coverHtml(title,{img:img})+'<div><div class="kicker">'+esc(kicker||"Collection")+'</div><h2>'+esc(title)+'</h2><div class="sub">'+esc(subtitle)+'</div>'+
        '<div class="actions">'+(tracks.length?'<button class="btn" onclick="playList(0)">'+ic("play_arrow")+' Play all</button>':'')+'</div></div></div>'+
        (tracks.length?'<div class="tracks">'+rows+'</div>':'<div class="empty">No tracks.</div>'));
      highlightPlaying();
    }
    function playList(i){ playTracks(window._listTracks||[], i, ""); }

    // ---------- Player ----------
    var audio=$("audio");
    function playAlbum(albumId, index){ var al=(window._albums||{})[albumId]; if(!al) return; var tracks=al.tracks||[];
      var artistName=(al.artists&&al.artists.length)?artNames(al.artists):(window._curArtist||""); var aimg=albImg(al);
      queue=tracks.map(function(t){ return {id:t.id, file:t.file||"", title:trackName(t), artist:artistName, cover:albName(al), coverImg:aimg}; }); playIndex(index); }
    function playTracks(tracks, index, ctx){ queue=tracks.map(function(t){ return {id:t.id, file:t.file||"", title:trackName(t), artist:(t.artists&&t.artists.length?artNames(t.artists):(ctx||"")), cover:ctx||trackName(t), coverImg:null}; }); playIndex(index); }
    function playIndex(i){ if(i<0||i>=queue.length) return; qi=i; var t=queue[i];
      setActivity("Playing: "+(t.title||""));
      audio.src="/api/play?trackId="+encodeURIComponent(t.id)+"&file="+encodeURIComponent(t.file); audio.play().catch(function(){});
      $("player").hidden=false; $("npTitle").textContent=t.title; $("npArtist").textContent=t.artist||"";
      var cu=imgUrl(t.coverImg);
      if(cu){ $("npCover").style.background=""; $("npCover").style.backgroundImage="url('"+cu+"')"; $("npCover").style.backgroundSize="cover"; $("npCover").style.backgroundPosition="center"; $("npCover").innerHTML=""; }
      else { $("npCover").style.backgroundImage=""; $("npCover").style.background=grad(t.cover||t.title); $("npCover").innerHTML='<span class="disc"></span>'; }
      setPlayIcon(true); highlightPlaying();
    }
    function setPlayIcon(p){ $("playBtn").innerHTML=ic(p?"pause":"play_arrow"); }
    function highlightPlaying(){ var cur=queue[qi]; document.querySelectorAll(".track.playing").forEach(function(el){ el.classList.remove("playing"); });
      if(cur){ var el=$("trk"+cur.id)||$("ltrk"+cur.id); if(el) el.classList.add("playing"); } }
    function togglePlay(){ if(!queue.length) return; if(audio.paused) audio.play(); else audio.pause(); }
    function nextTrack(){ if(qi+1<queue.length) playIndex(qi+1); }
    function prevTrack(){ if(audio.currentTime>3){ audio.currentTime=0; return; } if(qi>0) playIndex(qi-1); }
    audio.addEventListener("play", function(){ setPlayIcon(true); });
    audio.addEventListener("pause", function(){ setPlayIcon(false); });
    audio.addEventListener("ended", function(){ if(SET.autoplay) nextTrack(); });
    audio.addEventListener("timeupdate", function(){ if(audio.duration){ $("seek").value=String(Math.round(audio.currentTime/audio.duration*1000)); } });
    audio.addEventListener("error", function(){ toast("Could not play this track."); });
    $("seek").addEventListener("input", function(){ if(audio.duration){ audio.currentTime=this.value/1000*audio.duration; } });
    function dlCurrent(){ var t=queue[qi]; if(t) downloadTrack(t.id, t.file); }

    // ---------- Lyrics ----------
    function showLyrics(){ var t=queue[qi]; if(!t){ return; } toast("Loading lyrics…");
      gql("query { track(where:{id:"+Number(t.id)+"}) { enName heName heLyrics enLyrics } }").then(function(d){
        var tr=d.track||{}; var lyr=tr.heLyrics||tr.enLyrics||""; if(!lyr){ toast("No lyrics for this track."); return; }
        overlay((tr.enName||tr.heName||t.title), '<pre dir="auto">'+esc(lyr)+'</pre>');
      }).catch(function(e){ if(e.message==="login")return; toast("Could not load lyrics."); });
    }
    // ---------- Now Playing sheet (lyrics + similar songs) ----------
    function openNowPlaying(){ var t=queue[qi]; if(!t){ return; }
      var cu=imgUrl(t.coverImg);
      var cover = cu ? '<div class="cover" style="width:210px;height:210px;margin:0 auto 16px;background-image:url(\\''+esc(cu)+'\\');background-size:cover;background-position:center"></div>'
                     : '<div class="cover" style="width:210px;height:210px;margin:0 auto 16px;background:'+grad(t.cover||t.title)+'"><span class="disc"></span></div>';
      overlay("Now Playing", cover+
        '<div style="text-align:center"><div style="font-weight:800;font-size:1.25rem;word-break:break-word">'+esc(t.title)+'</div><div class="muted" style="margin-top:3px">'+esc(t.artist||"")+'</div></div>'+
        '<div class="chips" style="justify-content:center;padding:0;margin:18px 0"><button class="chip" onclick="npLyrics()">Lyrics</button><button class="chip" onclick="npSimilar()">Similar songs</button></div>'+
        '<div id="npExtra"></div>');
    }
    function npBox(h){ var e=$("npExtra"); if(e) e.innerHTML=h; }
    function npLyrics(){ var t=queue[qi]; if(!t) return; npBox('<div class="empty"><span class="spinner"></span>Loading lyrics…</div>');
      gql("query { track(where:{id:"+Number(t.id)+"}) { heLyrics enLyrics } }").then(function(d){ var tr=d.track||{};
        var lyr=(SET.lang==="he"?(tr.heLyrics||tr.enLyrics):(tr.enLyrics||tr.heLyrics))||"";
        npBox(lyr?'<pre dir="auto" style="white-space:pre-wrap;line-height:1.85;font-size:1.02rem;margin:0">'+esc(lyr)+'</pre>':'<div class="empty">No lyrics for this song.</div>');
      }).catch(function(e){ if(e.message==="login")return; npBox('<div class="empty">Could not load lyrics.</div>'); });
    }
    function npSimilar(){ var t=queue[qi]; if(!t) return; npBox('<div class="empty"><span class="spinner"></span>Finding similar songs…</div>');
      gql("query { relatedTracks(trackId:"+Number(t.id)+", take: 30) { track { id enName heName file duration artists { enName heName } } } }").then(function(d){
        var list=(d.relatedTracks||[]).map(function(x){return x.track;}).filter(Boolean); window._npSimilar=list;
        if(!list.length){ npBox('<div class="empty">No similar songs found.</div>'); return; }
        npBox('<div class="tracks">'+list.map(function(tk,i){ return '<div class="track" onclick="playSimilar('+i+')"><div class="num">'+ic("play_arrow")+'</div>'+
          '<div class="tk">'+esc(trackName(tk))+(tk.artists&&tk.artists.length?'<div class="sub">'+esc(artNames(tk.artists))+'</div>':'')+'</div>'+
          (tk.duration?'<div class="time">'+fmt(tk.duration)+'</div>':'')+'</div>'; }).join("")+'</div>');
      }).catch(function(e){ if(e.message==="login")return; npBox('<div class="empty">Could not load similar songs.</div>'); });
    }
    function playSimilar(i){ playTracks(window._npSimilar||[], i, ""); closeOverlay(true); }

    // ---------- My Music (saved favorites) ----------
    function browseLibrary(){ curTab=""; setTab(""); loading("Loading your music…");
      var pArt=agql("query { myArtists { id enName heName image } }").then(function(d){return d.myArtists||[];}).catch(function(){return null;});
      var pAlb=agql("query { myAlbums(take:60) { album { id enName heName images { cdnSmall cdnMedium medium small } artists { enName heName } tracks { id } } } }").then(function(d){return (d.myAlbums||[]).map(function(x){return x.album;}).filter(Boolean);}).catch(function(){return null;});
      Promise.all([pArt,pAlb]).then(function(res){ setStatus("");
        var arts=res[0], albs=res[1];
        if(arts===null&&albs===null){ setView('<div class="back" onclick="go(\\'home\\')">'+ic("arrow_back_ios_new")+'Home</div><div class="empty">Couldn’t load your library — your login may not be connected for saving yet. Tell the developer what this says so it can be fixed.</div>'); return; }
        var html='<div class="back" onclick="go(\\'home\\')">'+ic("arrow_back_ios_new")+'Home</div>'+secHead("My Music"); var any=false;
        if(albs&&albs.length){ any=true; window._albums=window._albums||{}; albs.forEach(function(a){window._albums[a.id]=a;}); html+='<div class="sec">'+secHead("Saved Albums")+'<div class="grid albums">'+albs.map(function(al){return albumTile(al,artNames(al.artists));}).join("")+'</div></div>'; }
        if(arts&&arts.length){ any=true; html+='<div class="sec">'+secHead("Saved Artists")+'<div class="grid artists">'+arts.map(artistTile).join("")+'</div></div>'; }
        if(!any){ html+='<div class="empty">Nothing saved yet. Tap the ♥ on an album or artist to save it here.</div>'; }
        setView(html);
      });
    }

    function overlay(title, bodyHtml){ closeOverlay(true); var o=document.createElement("div"); o.className="ovl"; o.id="ovl";
      o.innerHTML='<div class="obar"><h2 id="ovlTitle">'+esc(title)+'</h2><button class="iconbtn" onclick="closeOverlay()">'+ic("close")+'</button></div><div id="ovlBody">'+bodyHtml+'</div>'; document.body.appendChild(o); }
    function ovlSet(title, bodyHtml){ var t=$("ovlTitle"), b=$("ovlBody"); if(t) t.textContent=title; if(b){ b.innerHTML=bodyHtml; b.scrollIntoView&&window.scrollTo(0,0); } }
    function closeOverlay(quiet){ if(typeof stopPresPoll==="function") stopPresPoll(); var d=$("ovl"); if(d) d.remove(); if(quiet!==true && _dirtyView){ _dirtyView=false; go(curTab); } }

    // ---------- Downloads ----------
    function dlBtn(id,file){ if(!dlAllowed()) return ""; return '<button class="dl" onclick="event.stopPropagation();downloadTrack('+id+', '+esc(JSON.stringify(file||"")).replace(/"/g,"&quot;")+')">'+ic("download")+'</button>'; }
    function dlUrl(id,file){ var p=new URLSearchParams({trackId:id, file:file||""}); return "/api/download?"+p.toString(); }
    function downloadTrack(id,file){ var a=document.createElement("a"); a.href=dlUrl(id,file); a.download=""; document.body.appendChild(a); a.click(); a.remove(); toast("Download started…"); }
    function downloadAlbum(albumId){ var al=(window._albums||{})[albumId]; if(!al) return; var tr=al.tracks||[]; var i=0;
      (function nx(){ if(i>=tr.length){ toast("Started all "+tr.length+" downloads."); return; } downloadTrack(tr[i].id, tr[i].file||""); i++; setTimeout(nx,900); })(); }

    // ---------- Settings ----------
    function openSettings(){ overlay("Settings", settingsHtml()); }
    function row(title, desc, right, click){ return '<div class="row"'+(click?' style="cursor:pointer" onclick="'+click+'"':'')+'><div class="rlabel"><div class="rt">'+esc(title)+'</div>'+(desc?'<div class="rd">'+esc(desc)+'</div>':'')+'</div>'+right+'</div>'; }
    function segEl(id, opts, cur, fn){ return '<div class="seg" id="'+id+'">'+opts.map(function(o){ return '<button data-v="'+esc(o[0])+'" class="'+(o[0]===cur?"on":"")+'" onclick="'+fn+'(\\''+o[0]+'\\')">'+esc(o[1])+'</button>'; }).join("")+'</div>'; }
    function segMark(id,val){ var s=$(id); if(!s) return; [].forEach.call(s.children,function(b){ b.classList.toggle("on", b.getAttribute("data-v")===val); }); }
    function setLang(v){ SET.lang=(v==="he"?"he":"en"); saveSettings(); segMark("segLang",SET.lang); _dirtyView=true; }
    function setTheme(v){ SET.theme=(v==="light"?"light":"dark"); saveSettings(); applyTheme(); segMark("segTheme",SET.theme); }
    function setAutoplay(v){ SET.autoplay=(v==="on"); saveSettings(); segMark("segAuto",v); }
    function signOut(){ location.href="/api/logout"; }
    function settingsHtml(){
      var auto=SET.autoplay?"on":"off";
      return ''+
        '<div class="set-sec"><h3>App</h3><div class="card">'+
          row("Language","Show names in English or Hebrew", segEl("segLang",[["en","English"],["he","עברית"]],SET.lang,"setLang"))+
          row("Theme","Dark or light look", segEl("segTheme",[["dark","Dark"],["light","Light"]],SET.theme,"setTheme"))+
          row("Autoplay","Play the next track automatically", segEl("segAuto",[["on","On"],["off","Off"]],auto,"setAutoplay"))+
        '</div></div>'+
        (ME.user ? ('<div class="set-sec"><h3>Your account</h3><div class="card">'+
          row(esc(ME.user.name||ME.user.email), esc(ME.user.email), ic("chevron_right"), "openProfile()")+
        '</div></div>') : '')+
        '<div class="set-sec"><h3>Admin</h3><div class="card">'+
          row("Admin panel","Accounts, appearance, features, who's online", ic("chevron_right"), "openAccess()")+
        '</div></div>'+
        (ME.admin ? ('<div class="set-sec"><h3>Diagnostics</h3><div class="chips" style="padding:0">'+
          '<button class="chip" onclick="runCheck()">Check connection</button>'+
          '<button class="chip" onclick="showZingConfig()">Zing settings</button>'+
          '<button class="chip" onclick="showZingActions()">Zing actions</button>'+
          '<button class="chip" onclick="showFullSchema()">Full structure</button>'+
          '<button class="chip" onclick="showSchema()">API structure</button>'+
          '<button class="chip" onclick="showImageInfo()">Image info</button></div>'+
          '<div id="diag" style="margin-top:14px"></div></div>') : '')+
        '<div class="set-sec"><h3>Account</h3><div class="card">'+
          '<div class="row" style="cursor:pointer" onclick="signOut()"><div class="rlabel"><div class="rt" style="color:var(--err)">Sign out</div></div>'+ic("logout")+'</div>'+
        '</div></div>';
    }
    function openProfile(){ if(!ME.user){ return; } var u=ME.user;
      overlay("Profile", '<div style="text-align:center;margin-bottom:8px">'+
        (u.photo&&/^data:image/.test(u.photo)?'<img src="'+esc(u.photo)+'" alt="" style="width:120px;height:120px;border-radius:999px;object-fit:cover" />':'<div style="width:120px;height:120px;border-radius:999px;background:var(--grad);display:inline-grid;place-items:center;color:#fff;font-weight:800;font-size:2rem">'+esc((u.name||u.email||"?").slice(0,1).toUpperCase())+'</div>')+
        '<div style="font-weight:800;font-size:1.2rem;margin-top:12px">'+esc(u.name||"")+'</div><div class="muted">'+esc(u.email||"")+'</div>'+(u.phone?'<div class="muted">'+esc(u.phone)+'</div>':'')+'</div>'+
        '<div class="set-sec"><h3>Change password</h3><div class="card" style="padding:15px">'+
          '<input id="pw_old" class="field" type="password" placeholder="Current password" autocomplete="current-password" />'+
          '<input id="pw_new" class="field" style="margin-top:10px" type="password" placeholder="New password" autocomplete="new-password" />'+
          '<button class="btn" style="margin-top:12px;width:100%;justify-content:center" onclick="changePw()">Change password</button>'+
          '<div id="pw_msg" class="err" style="margin-top:8px;min-height:16px"></div></div></div>'+
        '<div class="set-sec"><div class="card"><div class="row" style="cursor:pointer" onclick="signOut()"><div class="rlabel"><div class="rt" style="color:var(--err)">Sign out</div></div>'+ic("logout")+'</div></div></div>');
    }
    function changePw(){ var o=$("pw_old"),n=$("pw_new"),m=$("pw_msg"); if(m) m.textContent="";
      post("/api/me/password",{old:(o||{}).value||"",new:(n||{}).value||""}).then(function(){ toast("Password changed ✓"); if(o)o.value=""; if(n)n.value=""; }).catch(function(e){ if(m) m.textContent=e.message||"Could not change."; }); }

    // ---------- Access management (who can access) ----------
    function backToSettings(){ stopPresPoll(); ovlSet("Settings", settingsHtml()); }
    function accessUnlockHtml(msg){ return '<div class="back" onclick="backToSettings()">'+ic("arrow_back_ios_new")+'Settings</div>'+
      '<div class="card" style="padding:16px">'+
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">'+ic("lock")+'<b>Admin panel</b></div>'+
      '<p class="muted" style="margin:0 0 12px">Enter the main password (the one set in Cloudflare) to continue.</p>'+
      '<input id="admpw" class="field" type="password" placeholder="Main password" autocomplete="off" />'+
      '<button class="btn" style="margin-top:12px;width:100%;justify-content:center" onclick="unlockAccess()">Unlock</button>'+
      '<div id="accmsg" class="err" style="margin-top:10px;min-height:18px">'+esc(msg||"")+'</div></div>'; }
    function openAccess(){ if(_admPw){ loadAccess(); } else { ovlSet("Admin", accessUnlockHtml()); var i=$("admpw"); if(i) i.focus(); } }
    function unlockAccess(){ var i=$("admpw"); var pw=i?i.value:""; if(!pw){ return; } _admPw=pw; loadAccess(); }
    function loadAccess(){ ovlSet("Admin", '<div class="back" onclick="backToSettings()">'+ic("arrow_back_ios_new")+'Settings</div><div id="acc"><span class="spinner"></span>Loading…</div>');
      Promise.all([ post("/api/admin/list",{admin:_admPw}),
        fetch("/api/config").then(function(r){return r.json();}).catch(function(){return {};}),
        post("/api/admin/users",{admin:_admPw}).catch(function(){return {users:null};}),
        post("/api/admin/presence",{admin:_admPw}).catch(function(){return {online:[]};}) ])
        .then(function(res){ renderAdmin(res[0], res[1]||{}, res[2]||{}, res[3]||{}); })
        .catch(function(e){ _admPw=""; ovlSet("Admin", accessUnlockHtml(e.message||"Wrong password.")); var i=$("admpw"); if(i) i.focus(); }); }
    var _presTimer=null;
    function presenceRow(o, now){ var ago=Math.max(0,Math.round((now-(o.seen||0))/1000)); var when=ago<10?"now":(ago<60?ago+"s ago":Math.round(ago/60)+"m ago");
      return '<div class="code-item"><div style="width:40px;height:40px;border-radius:999px;background:var(--grad);display:grid;place-items:center;color:#fff;font-weight:700;flex:none">'+esc((o.name||"?").slice(0,1).toUpperCase())+'</div>'+
        '<div style="min-width:0;flex:1;margin-left:2px"><div class="ci-name">'+esc(o.name||"Guest")+'</div><div class="ci-code">'+esc(o.view||"—")+' · '+when+'</div></div>'+
        '<span style="width:10px;height:10px;border-radius:999px;background:'+(ago<40?"#34d399":"#fbbf24")+';flex:none"></span></div>'; }
    function presenceListHtml(pres){ var now=(pres&&pres.now)||Date.now(); var on=(pres&&pres.online)||[];
      return on.length ? on.map(function(o){ return presenceRow(o, now); }).join("") : '<p class="muted" style="margin:0;padding:12px 15px">Nobody is on right now.</p>'; }
    function stopPresPoll(){ if(_presTimer){ clearInterval(_presTimer); _presTimer=null; } }
    function refreshPres(){ post("/api/admin/presence",{admin:_admPw}).then(function(p){ var el=$("presList"); if(!el){ stopPresPoll(); return; }
      el.innerHTML=presenceListHtml(p); var c=$("presCount"); if(c) c.textContent=((p.online||[]).length); }).catch(function(){}); }
    function userAvatar(u){ return (u.photo && /^data:image/.test(u.photo))
      ? '<img src="'+esc(u.photo)+'" alt="" style="width:46px;height:46px;border-radius:999px;object-fit:cover;flex:none" />'
      : '<div style="width:46px;height:46px;border-radius:999px;background:var(--grad);display:grid;place-items:center;color:#fff;font-weight:700;flex:none">'+esc((u.email||"?").slice(0,1).toUpperCase())+'</div>'; }
    function userAction(id, action, extra){ var body={admin:_admPw,action:action,id:id}; if(extra){ for(var k in extra) body[k]=extra[k]; }
      post("/api/admin/user",body).then(function(){ toast(action==="approve"?"Approved ✓":"Done."); loadAccess(); }).catch(function(e){ toast(e.message||"Failed."); }); }
    function userReset(id){ var p=prompt("Enter a new password for this account:"); if(p===null) return; if(p.length<4){ toast("Password must be at least 4 characters."); return; }
      post("/api/admin/user",{admin:_admPw,action:"resetpw",id:id,password:p}).then(function(){ toast("Password reset ✓"); }).catch(function(e){ toast(e.message||"Failed."); }); }
    function userCreate(){ var nm=$("nu_n"),e=$("nu_e"),p=$("nu_p"),w=$("nu_w"),m=$("nu_msg"); if(m) m.textContent="";
      post("/api/admin/user",{admin:_admPw,action:"create",name:(nm||{}).value||"",email:(e||{}).value||"",phone:(p||{}).value||"",password:(w||{}).value||""}).then(function(){ toast("Account created."); loadAccess(); }).catch(function(err){ if(m) m.textContent=err.message||"Could not create."; }); }
    var _cfgEdit={features:{}};
    function toggleRow(k,label){ var on=_cfgEdit.features[k]!==false;
      return '<div class="row"><div class="rlabel"><div class="rt">'+esc(label)+'</div></div><div class="seg" id="cf_'+k+'">'+
        '<button data-v="on" class="'+(on?"on":"")+'" onclick="cfgSet(\\''+k+'\\',\\'on\\')">On</button>'+
        '<button data-v="off" class="'+(on?"":"on")+'" onclick="cfgSet(\\''+k+'\\',\\'off\\')">Off</button></div></div>'; }
    function cfgSet(k,v){ _cfgEdit.features[k]=(v==="on"); segMark("cf_"+k, v); }
    function cfgPick(key,v){ _cfgEdit[key]=v; segMark("cfp_"+key, v); }
    function optBtn(key,v,label){ var on=(_cfgEdit[key]||"")===v; return '<button data-v="'+esc(v)+'" class="'+(on?"on":"")+'" onclick="cfgPick(\\''+key+'\\',\\''+v+'\\')">'+esc(label)+'</button>'; }
    function cfgAccent(k){ _cfgEdit.accent=k; var box=$("cfgAccent"); if(box){ [].forEach.call(box.children,function(b){ b.style.borderColor=(b.getAttribute("data-v")===k)?"#fff":"transparent"; }); }
      var rs=document.documentElement.style; if(k&&CFG_ACCENTS[k]){ rs.setProperty("--accent",CFG_ACCENTS[k][0]); rs.setProperty("--accent-2",CFG_ACCENTS[k][1]); } else { rs.removeProperty("--accent"); rs.removeProperty("--accent-2"); } }
    function accentRow(){ var opts=[""].concat(Object.keys(CFG_ACCENTS));
      return '<label class="muted" style="font-size:.8rem">Accent color</label><div id="cfgAccent" style="display:flex;gap:9px;flex-wrap:wrap;margin:6px 0 0">'+
        opts.map(function(k){ var bg=k?('linear-gradient(135deg,'+CFG_ACCENTS[k][0]+','+CFG_ACCENTS[k][1]+')'):'var(--surface-3)'; var sel=(_cfgEdit.accent||"")===k;
          return '<button data-v="'+esc(k)+'" onclick="cfgAccent(\\''+k+'\\')" title="'+esc(k||"Default")+'" style="width:34px;height:34px;border-radius:999px;border:2px solid '+(sel?"#fff":"transparent")+';background:'+bg+';cursor:pointer;flex:none"></button>'; }).join("")+'</div>'; }
    var FEAT_LABELS={banners:"Featured banners",albums:"Albums",popular:"Popular",search:"Search",genres:"Genres",categories:"Categories",playlists:"Playlists",artists:"Artists",stories:"Stories",downloads:"Downloads",favorites:"Favorites (♥)"};
    function saveAdminConfig(){ var an=$("cfgApp"), am=$("cfgAnn"), m=$("cfgMsg"); if(m) m.textContent="";
      _cfgEdit.appName=an?an.value:""; _cfgEdit.announcement=am?am.value:"";
      post("/api/admin/config",{admin:_admPw,config:_cfgEdit}).then(function(d){ _setSaved=true; applyConfig(d.config||_cfgEdit); toast("Saved."); })
        .catch(function(e){ if(m) m.textContent=e.message||"Could not save."; }); }
    function renderAdmin(d, cfg, usersData, presData){
      var back='<div class="back" onclick="backToSettings()">'+ic("arrow_back_ios_new")+'Settings</div>';
      if(!d.kv){ ovlSet("Admin", back+kvSetupHtml()); return; }
      var presCard='<div class="set-sec"><h3>Who\\'s online (<span id="presCount">'+(((presData&&presData.online)||[]).length)+'</span>)</h3><div class="card"><div id="presList">'+presenceListHtml(presData)+'</div></div></div>';
      _cfgEdit={appName:cfg.appName||"",announcement:cfg.announcement||"",theme:cfg.theme||"",lang:cfg.lang||"",accent:cfg.accent||"",features:{}};
      CFG_FEATURES.forEach(function(k){ _cfgEdit.features[k]=(cfg.features&&cfg.features[k])!==false; });
      var appCard='<div class="set-sec"><h3>Appearance</h3><div class="card" style="padding:15px">'+
        '<label class="muted" style="font-size:.8rem">App name</label>'+
        '<input id="cfgApp" class="field" style="margin:5px 0 14px" placeholder="Zing" value="'+esc(_cfgEdit.appName)+'" />'+
        accentRow()+
        '<div style="height:12px"></div><label class="muted" style="font-size:.8rem">Announcement (shown at the top for everyone)</label>'+
        '<input id="cfgAnn" class="field" style="margin:5px 0 0" placeholder="(none)" value="'+esc(_cfgEdit.announcement)+'" />'+
        '</div>'+
        '<div class="card" style="margin-top:10px">'+
          '<div class="row"><div class="rlabel"><div class="rt">Default theme</div><div class="rd">For people who haven\\'t chosen</div></div><div class="seg" id="cfp_theme">'+optBtn("theme","","Off")+optBtn("theme","dark","Dark")+optBtn("theme","light","Light")+'</div></div>'+
          '<div class="row"><div class="rlabel"><div class="rt">Default language</div><div class="rd">Names in English or Hebrew</div></div><div class="seg" id="cfp_lang">'+optBtn("lang","","Off")+optBtn("lang","en","EN")+optBtn("lang","he","עברית")+'</div></div>'+
        '</div></div>';
      var featCard='<div class="set-sec"><h3>Features &amp; sections — show / hide for everyone</h3><div class="card">'+
        CFG_FEATURES.map(function(k){ return toggleRow(k, FEAT_LABELS[k]||k); }).join("")+
        '</div></div>'+
        '<div style="margin:12px 0"><button class="btn" style="width:100%;justify-content:center" onclick="saveAdminConfig()">Save app settings</button><div id="cfgMsg" class="err" style="margin-top:8px;min-height:16px"></div></div>';
      var codes=d.codes||[];
      var list = codes.length
        ? '<div class="card">'+codes.map(function(c){ return '<div class="code-item"><div style="min-width:0"><div class="ci-name">'+esc(c.name||"Someone")+'</div><div class="ci-code">'+esc(c.code)+'</div></div>'+
            '<button class="trash" title="Remove" data-code="'+esc(c.code)+'" onclick="removeCode(this)">'+ic("delete")+'</button></div>'; }).join("")+'</div>'
        : '<p class="muted" style="margin:2px 0 0">No accounts yet. Add one below.</p>';
      var accCard='<div class="set-sec"><h3>Quick access codes (optional)</h3>'+
        '<p class="muted" style="margin:0 0 10px;font-size:.85rem">A simple code to sign in with (no account needed). Your main password always works.</p>'+
        list+
        '<div class="card" style="padding:15px;margin-top:10px">'+
          '<input id="cn" class="field" placeholder="Name (for example: Yossi)" autocomplete="off" />'+
          '<input id="cc" class="field" style="margin-top:10px" placeholder="Access code / password" autocomplete="off" />'+
          '<button class="btn" style="margin-top:12px;width:100%;justify-content:center" onclick="addCode()">'+ic("person_add")+' Add code</button>'+
          '<div id="addmsg" class="err" style="margin-top:8px;min-height:16px"></div></div></div>';

      // User accounts (email/phone/password + selfie), needs D1.
      var usersCards="";
      var users=(usersData&&usersData.users);
      if(users===null||users===undefined){
        usersCards='<div class="set-sec"><h3>Accounts</h3><div class="card" style="padding:14px"><p class="muted" style="margin:0">Sign-up accounts need the storage set up first (see below). Then people can request access with email, phone and a selfie.</p></div></div>';
      } else {
        var pending=users.filter(function(u){return u.status==="pending";});
        var others=users.filter(function(u){return u.status!=="pending"&&u.status!=="rejected";});
        if(pending.length){
          usersCards+='<div class="set-sec"><h3>Account requests ('+pending.length+')</h3><div class="card">'+pending.map(function(u){
            return '<div class="code-item">'+userAvatar(u)+'<div style="min-width:0;flex:1;margin-left:2px"><div class="ci-name">'+esc(u.name||u.email)+'</div><div class="ci-code">'+esc(u.email)+' · '+esc(u.phone||"")+'</div></div>'+
              '<button class="btn sm" style="margin:0" onclick="userAction('+u.id+',\\'approve\\')">Approve</button>'+
              '<button class="trash" title="Reject" onclick="userAction('+u.id+',\\'reject\\')">'+ic("close")+'</button></div>'; }).join("")+'</div></div>';
        }
        var alist = others.length
          ? others.map(function(u){ var susp=(u.status==="suspended");
              return '<div class="card" style="padding:12px;margin-bottom:8px">'+
                '<div style="display:flex;align-items:center;gap:12px">'+userAvatar(u)+'<div style="flex:1;min-width:0"><div class="ci-name">'+esc(u.name||u.email)+(susp?' <span class="muted">(suspended)</span>':'')+'</div><div class="ci-code">'+esc(u.email)+' · '+esc(u.phone||"")+'</div></div></div>'+
                '<div class="chips" style="padding:0;margin-top:10px">'+
                  (susp?'<button class="chip" onclick="userAction('+u.id+',\\'unsuspend\\')">Unsuspend</button>':'<button class="chip" onclick="userAction('+u.id+',\\'suspend\\')">Suspend</button>')+
                  '<button class="chip" onclick="userReset('+u.id+')">Reset password</button>'+
                  '<button class="chip" onclick="userAction('+u.id+',\\'nodl\\',{value:'+(u.nodl?0:1)+'})">'+(u.nodl?'Enable downloads':'Disable downloads')+'</button>'+
                  '<button class="chip" onclick="userAction('+u.id+',\\'remove\\')">Remove</button>'+
                '</div></div>'; }).join("")
          : '<p class="muted" style="margin:2px 0 10px">No accounts yet.</p>';
        usersCards+='<div class="set-sec"><h3>Accounts ('+others.length+')</h3>'+alist+
          '<div class="card" style="padding:15px;margin-top:2px">'+
            '<div style="font-weight:600;margin-bottom:8px">Create an account</div>'+
            '<input id="nu_n" class="field" placeholder="Full name" autocomplete="off" />'+
            '<input id="nu_e" class="field" style="margin-top:10px" type="email" placeholder="Email address" autocomplete="off" />'+
            '<input id="nu_p" class="field" style="margin-top:10px" type="tel" placeholder="Phone number" autocomplete="off" />'+
            '<input id="nu_w" class="field" style="margin-top:10px" type="password" placeholder="Password" autocomplete="new-password" />'+
            '<button class="btn" style="margin-top:12px;width:100%;justify-content:center" onclick="userCreate()">'+ic("person_add")+' Create account</button>'+
            '<div id="nu_msg" class="err" style="margin-top:8px;min-height:16px"></div></div></div>';
      }
      ovlSet("Admin", back+presCard+usersCards+appCard+featCard+accCard);
      stopPresPoll(); _presTimer=setInterval(refreshPres, 10000);
    }
    function addCode(){ var n=($("cn")||{}).value||"", c=($("cc")||{}).value||""; var m=$("addmsg"); if(m) m.textContent="";
      if(!c.trim()){ if(m) m.textContent="Enter a code."; return; }
      post("/api/admin/add",{admin:_admPw,name:n,code:c}).then(function(){ toast("Added."); loadAccess(); })
        .catch(function(e){ if(m) m.textContent=e.message||"Could not add."; }); }
    function removeCode(btn){ var code=btn.getAttribute("data-code")||"";
      post("/api/admin/remove",{admin:_admPw,code:code}).then(function(){ toast("Removed."); loadAccess(); })
        .catch(function(e){ toast(e.message||"Could not remove."); }); }
    function kvSetupHtml(){ return '<div class="card" style="padding:16px;line-height:1.6">'+
      '<div style="font-weight:700;margin-bottom:8px">One quick setup step</div>'+
      '<p class="muted" style="margin:0 0 12px">To manage accounts and app settings, the app needs a small storage area (free). You can use a <b>D1 SQL database</b> or a <b>KV namespace</b> — either one.</p>'+
      '<div style="font-weight:600;margin:2px 0 4px">Option A — D1 (SQL database)</div>'+
      '<ol class="steps muted">'+
        '<li>In Cloudflare, open <b>Storage &amp; Databases → D1</b> → <b>Create</b>. Give it any name.</li>'+
        '<li>Open your Worker → <b>Settings → Bindings</b> → <b>Add binding</b> → <b>D1 database</b>. Set the variable name to <code>DB</code> and choose the database you just made.</li>'+
        '<li>Deploy again, then come back. (The tables are created automatically.)</li>'+
      '</ol>'+
      '<div style="font-weight:600;margin:10px 0 4px">Option B — KV</div>'+
      '<ol class="steps muted">'+
        '<li><b>Storage &amp; Databases → KV</b> → <b>Create instance</b>.</li>'+
        '<li>Worker → <b>Settings → Bindings</b> → <b>KV namespace</b>, variable name <code>ZING_KV</code>.</li>'+
        '<li>Deploy again.</li>'+
      '</ol>'+
      '<p class="muted" style="margin:12px 0 0">Until then, everyone signs in with the one main password — that keeps working.</p></div>'; }

    // ---------- Diagnostics ----------
    function diagBox(html){ var d=$("diag"); if(d) d.innerHTML = html? '<div style="background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px">'+html+'</div>':''; }
    function runCheck(){ diagBox('<span class="spinner"></span>Checking…');
      fetch("/api/check").then(function(r){ if(r.status===401){location.href="/";throw new Error("login");} return r.json(); }).then(function(s){
        var api=s.api||{},audio=s.audio||{},login=s.login||{},L=[];
        L.push((api.reachable===false?"❌ ":(api.status===200?"✅ ":"⚠️ "))+"Music API"+(api.error?": "+esc(api.error):""));
        if(login.configured!==false) L.push((login.ok?"✅ ":"❌ ")+"Auto-login"+(login.error?": "+esc(login.error):" works"));
        L.push((audio.reachable===false?"❌ ":(audio.status===403?"❌ ":"✅ "))+"Audio"+(audio.status?" ("+audio.status+")":"")+(audio.error?": "+esc(audio.error):""));
        var ti=s.tokenInfo, extra=""; if(ti&&ti.iss) extra='<div style="margin-top:8px;font-size:.8rem" class="muted">Token: '+esc(ti.iss)+'</div>';
        diagBox('<b>Connection</b><div style="margin-top:8px;line-height:1.9">'+L.join("<br>")+'</div>'+extra);
      }).catch(function(e){ if(e&&e.message==="login")return; diagBox("Error: "+esc(e.message||e)); });
    }
    function showSchema(){ diagBox('<span class="spinner"></span>Reading…');
      fetch("/api/schema").then(function(r){return r.json();}).then(function(s){ if(s.error){diagBox("Error: "+esc(s.error));return;}
        var f=s.queryFields||[]; var txt="QUERIES:\\n"+f.map(function(x){return "- "+x.name+"("+(x.args||[]).join(", ")+") -> "+(x.returns||"?");}).join("\\n");
        var types=s.types||{}; txt+="\\n\\nTYPES:\\n"; Object.keys(types).forEach(function(k){ txt+=k+": "+types[k].join(", ")+"\\n\\n"; });
        window._copy=txt; diagBox('<b>API structure</b> <button class="btn sm" onclick="copyText(this)">Copy</button><pre dir="ltr" style="white-space:pre-wrap;word-break:break-word;font-size:.75rem;margin-top:8px">'+esc(txt)+'</pre>');
      }).catch(function(e){ diagBox("Error: "+esc(e.message||e)); });
    }
    function downloadText(name, text){
      try{ var blob=new Blob([text||""],{type:"text/plain;charset=utf-8"}); var url=URL.createObjectURL(blob);
        var a=document.createElement("a"); a.href=url; a.download=name; document.body.appendChild(a); a.click(); a.remove();
        setTimeout(function(){ URL.revokeObjectURL(url); }, 4000); toast("Saved "+name); }catch(e){ toast("Could not download."); }
    }
    function showFullSchema(){ diagBox('<span class="spinner"></span>Reading the whole structure…');
      fetch("/api/schema/full").then(function(r){ if(r.status===401){location.href="/";throw new Error("login");} return r.json(); }).then(function(s){
        if(s.error){ diagBox("Error: "+esc(s.error)); return; }
        window._copy=s.text||""; var c=s.counts||{};
        diagBox('<b>Full structure</b>'+
          '<div class="muted" style="margin:8px 0;font-size:.85rem">'+(c.queries||0)+' queries · '+(c.types||0)+' types · '+(c.inputs||0)+' filters · '+(c.enums||0)+' enums'+(c.mutations?(' · '+c.mutations+' mutations'):'')+'</div>'+
          '<div class="chips" style="padding:0"><button class="chip" onclick="copyText(this)">Copy</button><button class="chip" onclick="downloadText(\\'zing-structure.txt\\', window._copy)">Download file</button></div>'+
          '<pre dir="ltr" style="white-space:pre-wrap;word-break:break-word;font-size:.72rem;margin-top:10px;max-height:52vh;overflow:auto">'+esc(s.text||"")+'</pre>');
      }).catch(function(e){ if(e&&e.message==="login")return; diagBox("Error: "+esc(e.message||e)); });
    }
    function showZingConfig(){ diagBox('<span class="spinner"></span>Reading Zing settings…');
      gql("query { appConfigs(take: 500, orderBy: [{ priority: desc }]) { id key category value description os zingPlayer isActive appVersion minApiVersion priority updatedAt } }").then(function(d){
        var items=d.appConfigs||[];
        if(!items.length){ diagBox('<b>Zing settings</b><div class="muted" style="margin-top:8px">No settings were returned (they may be admin-only).</div>'); return; }
        var byCat={}; items.forEach(function(c){ var k=c.category||"other"; (byCat[k]=byCat[k]||[]).push(c); });
        var text="ZING SETTINGS (appConfigs) — "+items.length+" entries\\n\\n"; var html='<b>Zing settings</b> ('+items.length+')';
        html+='<div class="chips" style="padding:0;margin:8px 0"><button class="chip" onclick="copyText(this)">Copy</button><button class="chip" onclick="downloadText(\\'zing-settings.txt\\', window._copy)">Download file</button></div>';
        Object.keys(byCat).sort().forEach(function(cat){
          text+="===== "+cat+" =====\\n";
          html+='<div class="set-sec"><h3>'+esc(cat)+'</h3>';
          byCat[cat].forEach(function(c){
            var val; try{ val=JSON.stringify(c.value); }catch(e){ val=String(c.value); }
            text+="- "+c.key+(c.os?(" ["+c.os+"]"):"")+(c.isActive===false?" (inactive)":"")+" = "+val+(c.description?("   // "+c.description):"")+"\\n";
            html+='<div class="card" style="padding:12px;margin-bottom:8px"><div style="font-weight:700;word-break:break-word">'+esc(c.key)+(c.os?' <span class="muted" style="font-weight:400">['+esc(c.os)+']</span>':'')+(c.isActive===false?' <span class="muted">(inactive)</span>':'')+'</div>'+
              (c.description?'<div class="muted" style="font-size:.82rem;margin:3px 0">'+esc(c.description)+'</div>':'')+
              '<pre dir="ltr" style="white-space:pre-wrap;word-break:break-word;font-size:.74rem;margin:6px 0 0">'+esc(val)+'</pre></div>';
          });
          text+="\\n"; html+='</div>';
        });
        window._copy=text; diagBox(html);
      }).catch(function(e){ if(e.message==="login")return; diagBox("Error: "+esc(e.message||e)); });
    }
    function showZingActions(){ diagBox('<span class="spinner"></span>Reading Zing actions…');
      gql("query { __schema { mutationType { fields { name args { name } } } } }").then(function(d){
        var fields=((((d.__schema)||{}).mutationType)||{}).fields||[];
        if(!fields.length){ diagBox('<b>Zing actions</b><div class="muted" style="margin-top:8px">No actions were returned (they may be admin-only).</div>'); return; }
        function verb(n){ var m=n.match(/^(createOne|updateOne|deleteOne|upsertOne|createMany|updateMany|deleteMany|create|update|delete|upsert|set|add|remove|send|generate|import|approve|reject|toggle|assign|revoke|link|unlink|move|reorder|sync|refresh|start|stop|cancel|restore|claim|submit|review)/); return m?m[1]:"other"; }
        var groups={}; fields.forEach(function(f){ var v=verb(f.name); (groups[v]=groups[v]||[]).push(f); });
        var text="ZING ACTIONS (operations you can do on the system) — "+fields.length+"\\n\\n"; var html='<b>Zing actions</b> ('+fields.length+')';
        html+='<div class="muted" style="font-size:.82rem;margin:6px 0">These are the operations Zing\\'s system supports. Shown for reference only.</div>';
        html+='<div class="chips" style="padding:0;margin:8px 0"><button class="chip" onclick="copyText(this)">Copy</button><button class="chip" onclick="downloadText(\\'zing-actions.txt\\', window._copy)">Download file</button></div>';
        Object.keys(groups).sort().forEach(function(g){ text+="===== "+g+" ("+groups[g].length+") =====\\n";
          html+='<div class="set-sec"><h3>'+esc(g)+' ('+groups[g].length+')</h3><div class="card" style="padding:8px 14px">';
          groups[g].forEach(function(f){ var line=f.name+"("+(f.args||[]).map(function(a){return a.name;}).join(", ")+")"; text+="- "+line+"\\n";
            html+='<div style="font-size:.8rem;padding:4px 0;border-bottom:1px solid var(--line);word-break:break-word">'+esc(line)+'</div>'; });
          text+="\\n"; html+='</div></div>'; });
        window._copy=text; diagBox(html);
      }).catch(function(e){ if(e.message==="login")return; diagBox("Error: "+esc(e.message||e)); });
    }
    function showImageInfo(){ diagBox('<span class="spinner"></span>Reading…');
      gql('query { t: __type(name:"Images"){ fields { name type { kind name ofType { kind name } } } } }').then(function(d){
        var fs=(d.t&&d.t.fields)||[]; var scalar=fs.filter(function(f){ var t=f.type||{}; return t.kind==="SCALAR"||(t.kind==="NON_NULL"&&t.ofType&&t.ofType.kind==="SCALAR"); }).map(function(f){return f.name;});
        var sub=scalar.length?"images { "+scalar.join(" ")+" }":"";
        return gql("query { artists(take:1){ image "+sub+" } playlists(take:1){ image cdnImage } albums(take:1){ "+sub+" } }").then(function(dd){
          var txt="scalar: "+scalar.join(", ")+"\\nartist.image="+JSON.stringify(dd.artists&&dd.artists[0]&&dd.artists[0].image)+"\\nplaylist.cdnImage="+JSON.stringify(dd.playlists&&dd.playlists[0]&&dd.playlists[0].cdnImage)+"\\nalbum.images="+JSON.stringify(dd.albums&&dd.albums[0]&&dd.albums[0].images);
          window._copy=txt; diagBox('<b>Image format</b> <button class="btn sm" onclick="copyText(this)">Copy</button><pre dir="ltr" style="white-space:pre-wrap;word-break:break-all;font-size:.75rem;margin-top:8px">'+esc(txt)+'</pre>');
        });
      }).catch(function(e){ if(e.message==="login")return; diagBox("Error: "+esc(e.message||e)); });
    }
    function copyText(btn){ var t=window._copy||""; try{ navigator.clipboard.writeText(t).then(function(){btn.textContent="Copied!";},function(){fb();}); }catch(e){ fb(); }
      function fb(){ var ta=document.createElement("textarea"); ta.value=t; document.body.appendChild(ta); ta.select(); try{document.execCommand("copy");}catch(e){} ta.remove(); btn.textContent="Copied!"; } }

    // expose
    window.go=go; window.openArtist=openArtist; window.openAlbum=openAlbum; window.openGenre=openGenre; window.openPlaylist=openPlaylist;
    window.openCategory=openCategory; window.openBannerUrl=openBannerUrl; window.openStory=openStory; window.openArticle=openArticle;
    window.browseAlbums=browseAlbums; window.loadMoreAlbums=loadMoreAlbums; window.playSearchTrack=playSearchTrack;
    window.playAlbum=playAlbum; window.playList=playList; window.downloadTrack=downloadTrack; window.downloadAlbum=downloadAlbum;
    window.togglePlay=togglePlay; window.nextTrack=nextTrack; window.prevTrack=prevTrack; window.dlCurrent=dlCurrent;
    window.showLyrics=showLyrics; window.closeOverlay=closeOverlay; window.openSettings=openSettings;
    window.runCheck=runCheck; window.showSchema=showSchema; window.showImageInfo=showImageInfo; window.copyText=copyText;
    window.showFullSchema=showFullSchema; window.downloadText=downloadText; window.showZingConfig=showZingConfig; window.showZingActions=showZingActions;
    window.openNowPlaying=openNowPlaying; window.npLyrics=npLyrics; window.npSimilar=npSimilar; window.playSimilar=playSimilar;
    window.browseLibrary=browseLibrary; window.saveArtist=saveArtist; window.saveAlbum=saveAlbum;
    window.setLang=setLang; window.setTheme=setTheme; window.setAutoplay=setAutoplay; window.signOut=signOut;
    window.openAccess=openAccess; window.backToSettings=backToSettings; window.unlockAccess=unlockAccess; window.addCode=addCode; window.removeCode=removeCode;
    window.cfgSet=cfgSet; window.saveAdminConfig=saveAdminConfig; window.cfgPick=cfgPick; window.cfgAccent=cfgAccent;
    window.userAction=userAction; window.userCreate=userCreate; window.userReset=userReset; window.openProfile=openProfile; window.changePw=changePw;

    hydrateIcons(); checkStatus(); loadMe(); sendPresence(); setInterval(sendPresence, 25000); loadConfig().then(function(){ home(); });
  </script>
</body>
</html>`;
