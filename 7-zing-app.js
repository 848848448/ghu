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

const BUILD = "b114-obar-2026-11-03";
const TOKEN_VER = 2; // bump to invalidate any stale cached token in D1
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
        return html(authed ? PAGE_SHELL : LOGIN, request);
      }
      if (path === "/manifest.webmanifest") {
        return new Response(JSON.stringify({
          name: "Zing Music", short_name: "Zing", start_url: "/", scope: "/", display: "standalone",
          background_color: "#0a0a12", theme_color: "#0a0a12",
          icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" }],
        }), { headers: { "Content-Type": "application/manifest+json", "Cache-Control": "public, max-age=3600" } });
      }
      if (path === "/icon.svg") {
        return new Response('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7c5cff"/><stop offset="1" stop-color="#ff4d8d"/></linearGradient></defs><rect width="512" height="512" rx="112" fill="url(#g)"/><path fill="#fff" d="M300 120v200a60 60 0 1 1-30-52V170l-90 22v168a60 60 0 1 1-30-52V150z"/></svg>',
          { headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" } });
      }
      if (path === "/sw.js") {
        const sw = "var OFF='<!DOCTYPE html><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Offline</title><body style=\"font-family:system-ui;background:#0a0a12;color:#f4f4fb;display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center\"><div><h2>You are offline</h2><p style=\"color:#9aa0c0\">Zing needs a connection to stream. Reconnect and reload.</p></div>';\n" +
          "self.addEventListener('install',function(){self.skipWaiting();});\n" +
          "self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim());});\n" +
          "self.addEventListener('fetch',function(e){if(e.request.mode==='navigate'){e.respondWith(fetch(e.request).catch(function(){return new Response(OFF,{headers:{'Content-Type':'text/html; charset=utf-8'}});}));}});\n";
        return new Response(sw, { headers: { "Content-Type": "application/javascript", "Cache-Control": "no-cache", "Service-Worker-Allowed": "/" } });
      }
      if (path === "/img") {
        // Same-origin image proxy: catalog cover art lives on the upstream CDN,
        // which some networks/filters block. Whitelisted hosts only - never an open proxy.
        const IMG_HOSTS = { "image.zingmusic.app": 1, "res.cloudinary.com": 1 };
        const u = url.searchParams.get("u") || "";
        let target = null;
        try { target = new URL(u); } catch (e) { return new Response("bad url", { status: 400 }); }
        if (target.protocol !== "https:" || !IMG_HOSTS[target.host]) return new Response("not allowed", { status: 403 });
        const cache = caches.default;
        const key = new Request(url.toString(), request);
        let resp = await cache.match(key);
        if (!resp) {
          let up;
          // redirect:"manual" - a whitelisted host must not bounce us to an arbitrary one
          try { up = await fetch(target.toString(), { redirect: "manual", cf: { cacheTtl: 604800, cacheEverything: true } }); }
          catch (e) { return new Response("upstream error", { status: 502 }); }
          if (up.status !== 200) return new Response("not found", { status: 404 });
          const ct = up.headers.get("Content-Type") || "image/jpeg";
          if (!/^image\//.test(ct)) return new Response("not an image", { status: 404 });
          resp = new Response(up.body, { status: 200, headers: {
            "Content-Type": ct,
            "Cache-Control": "public, max-age=604800, immutable",
          } });
          try { await cache.put(key, resp.clone()); } catch (e) {}
        }
        return resp;
      }
      if (path === "/api/status") {
        const auth = await hasAuthNow(env);
        return json({
          apiUrl: !!env.API_URL,
          audioBase: !!env.AUDIO_API_BASE,
          token: auth,
          autoLogin: canFirebase(env) || canAutoLogin(env),
          firebase: canFirebase(env),
          configured: !!(env.API_URL && env.AUDIO_API_BASE && auth),
          locked: locked,
          authed: authed,
          kv: hasStore(env),
          d1: !!env.DB,
          build: BUILD,
        });
      }
      if (path === "/api/config") {
        // Public: never expose the owner email here.
        const c = await getConfig(env);
        delete c.ownerEmail;
        return json(c);
      }

      // Everything below requires a login when the site is locked.
      if (!authed) {
        return json({ error: "Please log in.", needLogin: true }, 401);
      }      if (path === "/app.js") { return jsResponse(request); }

      // Single-device session: a non-admin whose stored session no longer
      // matches this device's cookie was signed in elsewhere. Streaming and
      // the claim-device flow stay reachable so the player can recover.
      if (locked && env.DB && path.startsWith("/api/") &&
          path !== "/api/me" && path !== "/api/me/password" && path !== "/api/me/photo" &&
          path !== "/api/claim-device" && path !== "/api/play" && path !== "/api/download" &&
          path !== "/api/status" && path !== "/api/config") {
        const sv = await verifyUidFull(env, parseCookies(request).uid);
        if (sv && sv.id && sv.id !== "admin" && sv.session) {
          const su = await getUserById(env, sv.id);
          if (su && !(await isUserAdmin(env, su)) && su.session && su.session !== sv.session) {
            return json({ error: "Signed in on another device.", otherDevice: true }, 401);
          }
        }
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
      if (path === "/api/admin/curate" && request.method === "POST") {
        return await handleAdminCurate(request, env);
      }
      if (path === "/api/me") {
        return await handleMe(request, env);
      }
      if (path === "/api/me/password" && request.method === "POST") {
        return await handleMePassword(request, env);
      }
      if (path === "/api/me/photo" && request.method === "POST") {
        return await handleMePhoto(request, env);
      }
      if (path === "/api/claim-device" && request.method === "POST") {
        return await handleClaimDevice(request, env);
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
      if (path === "/api/admin/userplays" && request.method === "POST") {
        return await handleAdminUserPlays(request, env);
      }
      if (path === "/api/admin/export" && request.method === "POST") {
        return await handleAdminExport(request, env);
      }
      if (path === "/api/played" && request.method === "POST") {
        return await handlePlayed(request, env);
      }
      if (path === "/api/admin/stats" && request.method === "POST") {
        return await handleAdminStats(request, env);
      }
      if (path === "/api/admin/music" && request.method === "POST") {
        return await handleAdminMusic(request, env);
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
      // Diagnostic / introspection endpoints — admins only (they reveal the
      // upstream API's structure and are only used from the admin panel).
      if (path === "/api/check" || path === "/api/schema" || path === "/api/schema/full" ||
          path === "/api/probe/new" || path === "/api/probe/audio") {
        if (!(await isAdminReq(env, request, {}))) return json({ error: "Admins only." }, 403);
        if (path === "/api/check") return await handleCheck(env);
        if (path === "/api/schema") return await handleSchema(env);
        if (path === "/api/schema/full") return await handleFullSchema(env);
        if (path === "/api/probe/new" && request.method === "POST") return await handleProbeNew(request, env);
        if (path === "/api/probe/audio" && request.method === "POST") return await handleProbeAudio(request, env);
        return new Response("Not found", { status: 404 });
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
      return json({ error: "Server error." }, 500);
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
// Constant-time string compare (for tokens, signatures, password hashes), so a
// comparison can't leak information through timing.
function ctEq(a, b) {
  a = String(a == null ? "" : a); b = String(b == null ? "" : b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
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
  return !!c && ctEq(c, await authToken(env));
}

async function handleLogin(request, env) {
  if (!env.SITE_PASSWORD) return json({ ok: true });
  const body = await request.json().catch(() => ({}));
  const email = (body.email || "").toString().trim().toLowerCase();
  const pw = (body.password || "").toString();

  // Email + password login (a user account).
  if (email) {
    const u = await getUserByEmail(env, email);
    if (!u || !(await passVerify(env, email, pw, u.pass))) {
      return json({ error: "Wrong email or password." }, 401);
    }
    // Transparent upgrade: re-hash legacy SHA-256 passwords as PBKDF2 on login.
    if (!String(u.pass || "").startsWith("pbkdf2$")) {
      try { await env.DB.prepare("UPDATE users SET pass = ? WHERE id = ?").bind(await passHashNew(env, pw), u.id).run(); } catch (e) { /* ignore */ }
    }
    if (u.status === "suspended") return json({ error: "This account has been suspended." }, 403);
    if (u.status !== "approved") {
      return json({ error: u.status === "rejected" ? "This account was not approved." : "Your account is waiting for approval." }, 403);
    }
    // Admins may be on many devices; everyone else is limited to one device,
    // enforced by a session token that a new login replaces.
    if (await isUserAdmin(env, u)) return await loginResponse(env, String(u.id), "");
    const session = randToken();
    try { await env.DB.prepare("UPDATE users SET session = ? WHERE id = ?").bind(session, u.id).run(); } catch (e) { /* ignore */ }
    return await loginResponse(env, String(u.id), session);
  }

  // Master password or an access code.
  if (pw && (ctEq(pw, env.SITE_PASSWORD) || (await codeMatches(env, pw)))) {
    return await loginResponse(env, ctEq(pw, env.SITE_PASSWORD) ? "admin" : "");
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
      env.DB.prepare("CREATE TABLE IF NOT EXISTS plays (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT, track INTEGER, title TEXT, artist TEXT, at INTEGER)"),
    ]);
    // Best-effort migrations for columns added later (ignored if they exist).
    for (const a of ["ALTER TABLE users ADD COLUMN name TEXT", "ALTER TABLE users ADD COLUMN nodl INTEGER",
                     "ALTER TABLE users ADD COLUMN role TEXT", "ALTER TABLE users ADD COLUMN session TEXT"]) {
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
  return codes.some((c) => c && typeof c.code === "string" && ctEq(c.code, pw));
}

function isAdmin(env, body) {
  return !!env.SITE_PASSWORD && ctEq((body.admin || "").toString(), env.SITE_PASSWORD);
}

// --------------------------------------------------------------------------- //
// Site settings (admin-controlled, shared for everyone): app name, an
// announcement, and feature on/off toggles. Stored in D1 or KV so the whole
// site picks them up. Reads are public (no secrets); writes need the master
// password.
// --------------------------------------------------------------------------- //
async function getConfig(env) {
  const out = { appName: "", announcement: "", theme: "", lang: "", accent: "", ownerEmail: "", features: {}, featured: [], hidden: [] };
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
      out.ownerEmail = typeof c.ownerEmail === "string" ? c.ownerEmail : "";
      if (c.features && typeof c.features === "object") out.features = c.features;
      out.featured = Array.isArray(c.featured) ? c.featured.map(Number).filter((n) => n > 0).slice(0, 24) : [];
      out.hidden = Array.isArray(c.hidden) ? c.hidden.map(Number).filter((n) => n > 0).slice(0, 500) : [];
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
  if (!(await isAdminReq(env, request, body))) return json({ error: "Wrong password." }, 403);
  // No config in the body → read the full config (owner email included).
  if (!body.config) return json({ config: await getConfig(env) });
  if (!hasStore(env)) return json({ error: "Settings storage is not set up yet." }, 400);
  const inC = (body.config && typeof body.config === "object") ? body.config : {};
  const oe = (inC.ownerEmail || "").toString().trim().toLowerCase();
  const clean = {
    appName: (inC.appName || "").toString().trim().slice(0, 60),
    announcement: (inC.announcement || "").toString().trim().slice(0, 500),
    theme: (inC.theme === "dark" || inC.theme === "light") ? inC.theme : "",
    lang: (inC.lang === "en" || inC.lang === "he") ? inC.lang : "",
    accent: CONFIG_ACCENTS.indexOf(inC.accent) > 0 ? inC.accent : "",
    ownerEmail: validEmail(oe) ? oe : "",
    features: {},
  };
  const inF = (inC.features && typeof inC.features === "object") ? inC.features : {};
  CONFIG_FEATURES.forEach((k) => { clean.features[k] = inF[k] !== false; });
  // Preserve the curated featured/hidden album lists. Accept them if sent,
  // otherwise keep whatever is already stored (this form doesn't edit them).
  const prev = await getConfig(env);
  clean.featured = Array.isArray(inC.featured) ? inC.featured.map(Number).filter((n) => n > 0).slice(0, 24) : (prev.featured || []);
  clean.hidden = Array.isArray(inC.hidden) ? inC.hidden.map(Number).filter((n) => n > 0).slice(0, 500) : (prev.hidden || []);
  await saveConfig(env, clean);
  return json({ ok: true, config: clean });
}

// Admin: pin/unpin an album to the Home "Featured" row, or hide/unhide an
// album everywhere. Toggled from the album page by a logged-in admin.
async function handleAdminCurate(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, body))) return json({ error: "Not allowed." }, 403);
  if (!hasStore(env)) return json({ error: "Settings storage is not set up yet." }, 400);
  const action = (body.action || "").toString();
  const cfg = await getConfig(env); // full config (keeps ownerEmail, features, etc.)
  let featured = Array.isArray(cfg.featured) ? cfg.featured.slice() : [];
  let hidden = Array.isArray(cfg.hidden) ? cfg.hidden.slice() : [];
  if (action === "clearfeatured" || action === "clearhidden") {
    if (action === "clearfeatured") featured = []; else hidden = [];
    cfg.featured = featured; cfg.hidden = hidden;
    await saveConfig(env, cfg);
    return json({ ok: true, featured, hidden });
  }
  const id = Number(body.id);
  if (!(id > 0)) return json({ error: "Missing album id." }, 400);
  const add = (arr, v) => (arr.indexOf(v) === -1 ? arr.concat([v]) : arr);
  const del = (arr, v) => arr.filter((x) => x !== v);
  if (action === "feature") { featured = add(featured, id).slice(0, 24); hidden = del(hidden, id); }
  else if (action === "unfeature") { featured = del(featured, id); }
  else if (action === "hide") { hidden = add(hidden, id).slice(0, 500); featured = del(featured, id); }
  else if (action === "unhide") { hidden = del(hidden, id); }
  else return json({ error: "Unknown action." }, 400);
  cfg.featured = featured; cfg.hidden = hidden;
  await saveConfig(env, cfg);
  return json({ ok: true, featured, hidden });
}

// GET the list of access codes (admin only). Reports whether a store is set up.
async function handleAdminList(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, body))) return json({ error: "Wrong password." }, 403);
  if (!hasStore(env)) return json({ kv: false, codes: [] });
  const codes = await getCodes(env);
  return json({ kv: true, codes: codes || [] });
}

// Add (or update) a named access code (admin only).
async function handleAdminAdd(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, body))) return json({ error: "Wrong password." }, 403);
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
  if (!(await isAdminReq(env, request, body))) return json({ error: "Wrong password." }, 403);
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
// Password hash, peppered with the master secret so stolen hashes can't be
// cracked without SITE_PASSWORD.
async function passHash(env, email, password) {
  // Legacy SHA-256 hash, kept only to verify accounts created before the
  // PBKDF2 upgrade. New passwords always use passHashNew.
  return await sha256hex("u2:" + email + ":" + password + ":" + (env.SITE_PASSWORD || ""));
}
async function passHashNew(env, password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  const hex = (a) => [...new Uint8Array(a)].map((x) => x.toString(16).padStart(2, "0")).join("");
  return "pbkdf2$100000$" + hex(salt) + "$" + hex(bits);
}
async function passVerify(env, email, password, stored) {
  stored = String(stored || "");
  if (stored.startsWith("pbkdf2$")) {
    const p = stored.split("$");
    if (p.length !== 4) return false;
    const iter = parseInt(p[1], 10) || 100000;
    const m = p[2].match(/.{2}/g) || [];
    const salt = new Uint8Array(m.map((h) => parseInt(h, 16)));
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
    const hex = [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, "0")).join("");
    return ctEq(hex, p[3]);
  }
  return ctEq(stored, await passHash(env, email, password));
}
function randToken() {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}
// The uid cookie is a signed value: "<id>.<session>.<sig>" (session empty for
// admins). The signature uses SITE_PASSWORD, so it cannot be forged.
async function uidSig(env, id, session) {
  return await sha256hex("uid2:" + id + ":" + (session || "") + ":" + (env.SITE_PASSWORD || ""));
}
async function verifyUidFull(env, val) {
  if (!val) return null;
  const p = val.split(".");
  if (p.length === 2) { if (ctEq(p[1], await uidSig(env, p[0], ""))) return { id: p[0], session: "" }; return null; }
  if (p.length === 3) { if (ctEq(p[2], await uidSig(env, p[0], p[1]))) return { id: p[0], session: p[1] }; return null; }
  return null;
}
async function verifyUid(env, val) { const v = await verifyUidFull(env, val); return v ? v.id : null; }
async function loginResponse(env, uid, session) {
  const val = uid ? (uid + (session ? ("." + session) : "") + "." + (await uidSig(env, uid, session || ""))) : "";
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  h.append("Set-Cookie", "auth=" + (await authToken(env)) + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000");
  h.append("Set-Cookie", "uid=" + val + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000");
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: h });
}
// Owner email (from admin settings, or the OWNER_EMAIL secret). That account
// — and any account you mark as admin — can see the admin settings.
async function ownerEmail(env) {
  const c = await getConfig(env);
  return ((c.ownerEmail || env.OWNER_EMAIL || "").toString().trim().toLowerCase());
}
async function isUserAdmin(env, u) {
  if (!u) return false;
  if (u.role === "admin") return true;
  const oe = await ownerEmail(env);
  return !!(oe && (u.email || "").toLowerCase() === oe);
}
// True for the master password, the owner-email account, or a role=admin user.
async function isAdminReq(env, request, body) {
  if (env.SITE_PASSWORD && ctEq(((body && body.admin) || "").toString(), env.SITE_PASSWORD)) return true;
  const id = await verifyUid(env, parseCookies(request).uid);
  if (id === "admin") return true;
  if (id) { const u = await getUserById(env, id); if (await isUserAdmin(env, u)) return true; }
  return false;
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
  if (password.length < 8) return json({ error: "Password must be at least 8 characters." }, 400);
  if (!/^data:image\/(png|jpe?g|webp);base64,/.test(photo)) return json({ error: "A selfie photo is required." }, 400);
  if (photo.length > 400000) return json({ error: "Photo is too large — please try again." }, 400);
  if (await getUserByEmail(env, email)) return json({ error: "An account with this email already exists." }, 400);
  try {
    await env.DB.prepare("INSERT INTO users (name, email, phone, pass, photo, status, created) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(name, email, phone, await passHashNew(env, password), photo, "pending", Date.now()).run();
  } catch (e) { return json({ error: "Could not send the request." }, 500); }
  return json({ ok: true });
}

async function handleMe(request, env) {
  const v = await verifyUidFull(env, parseCookies(request).uid);
  if (!v) return json({ user: null });
  if (v.id === "admin") return json({ admin: true, name: "Owner" });
  const u = await getUserById(env, v.id);
  if (!u) return json({ user: null });
  const admin = await isUserAdmin(env, u);
  // Single device: a non-admin whose stored session no longer matches this
  // device's cookie has been signed in elsewhere.
  if (!admin && u.session && v.session && u.session !== v.session) {
    return json({ user: null, otherDevice: true });
  }
  return json({ admin: admin, user: { id: u.id, email: u.email, phone: u.phone, photo: u.photo, name: u.name || (u.email || "").split("@")[0], nodl: !!u.nodl, role: u.role || "" } });
}

// Re-claim this account on THIS device (kicks the other device), using the
// existing signed cookie — no password needed.
async function handleClaimDevice(request, env) {
  if (!env.DB) return json({ ok: false });
  const v = await verifyUidFull(env, parseCookies(request).uid);
  if (!v || v.id === "admin" || !v.id) return json({ ok: false }, 400);
  const u = await getUserById(env, v.id);
  if (!u) return json({ ok: false }, 400);
  const session = randToken();
  await env.DB.prepare("UPDATE users SET session = ? WHERE id = ?").bind(session, u.id).run();
  return await loginResponse(env, String(u.id), session);
}

// Change your own password (must be signed in as a user account).
async function handleMePassword(request, env) {
  const id = await verifyUid(env, parseCookies(request).uid);
  if (!id || id === "admin" || !env.DB) return json({ error: "Not available for this login." }, 400);
  const b = await request.json().catch(() => ({}));
  const u = await getUserById(env, id);
  if (!u) return json({ error: "Account not found." }, 404);
  if (!(await passVerify(env, u.email, (b.old || "").toString(), u.pass))) return json({ error: "Current password is wrong." }, 403);
  const np = (b.new || "").toString();
  if (np.length < 8) return json({ error: "New password must be at least 8 characters." }, 400);
  await env.DB.prepare("UPDATE users SET pass = ? WHERE id = ?").bind(await passHashNew(env, np), Number(id)).run();
  return json({ ok: true });
}

// Change your own profile photo (a new selfie).
async function handleMePhoto(request, env) {
  const id = await verifyUid(env, parseCookies(request).uid);
  if (!id || id === "admin" || !env.DB) return json({ error: "Not available for this login." }, 400);
  const b = await request.json().catch(() => ({}));
  const photo = (b.photo || "").toString();
  if (!/^data:image\/(png|jpe?g|webp);base64,/.test(photo)) return json({ error: "A photo is required." }, 400);
  if (photo.length > 400000) return json({ error: "Photo is too large — please try again." }, 400);
  await env.DB.prepare("UPDATE users SET photo = ? WHERE id = ?").bind(photo, Number(id)).run();
  return json({ ok: true });
}

// Pending-request count, for the owner's badge.
async function handlePending(request, env) {
  const id = await verifyUid(env, parseCookies(request).uid);
  if (!id || !env.DB) return json({ pending: 0, admin: false });
  let admin = (id === "admin");
  if (!admin) { const u = await getUserById(env, id); admin = u ? await isUserAdmin(env, u) : false; }
  if (!admin) return json({ pending: 0, admin: false });
  await ensureD1(env);
  try {
    const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE status = 'pending'").first();
    return json({ pending: (r && r.n) || 0, admin: true });
  } catch (e) { return json({ pending: 0, admin: true }); }
}

async function handleAdminUsers(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "Accounts need a D1 database.", d1: false }, 400);
  await ensureD1(env);
  const r = await env.DB.prepare("SELECT id, name, email, phone, photo, status, nodl, role, created FROM users ORDER BY created DESC").all();
  const users = r.results || [];
  // Attach per-user play counts and last-seen, so the owner can see who is active.
  const plays = {}, seen = {};
  try { const p = await env.DB.prepare("SELECT uid, COUNT(*) AS c FROM plays GROUP BY uid").all(); (p.results || []).forEach((x) => { plays[String(x.uid)] = x.c; }); } catch (e) {}
  try { const s = await env.DB.prepare("SELECT uid, seen FROM presence").all(); (s.results || []).forEach((x) => { seen[String(x.uid)] = x.seen; }); } catch (e) {}
  users.forEach((u) => { const k = String(u.id); u.plays = plays[k] || 0; u.lastSeen = seen[k] || 0; });
  return json({ users, ownerEmail: await ownerEmail(env) });
}

async function handleAdminUser(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "Accounts need a D1 database." }, 400);
  await ensureD1(env);
  const action = (b.action || "").toString();
  const id = Number(b.id);
  // The owner account can never be suspended, removed, demoted, or reset by
  // anyone — it is protected so nobody can lock the owner out.
  const target = await getUserById(env, id);
  const oe = await ownerEmail(env);
  const targetIsOwner = !!(target && oe && (target.email || "").toLowerCase() === oe);
  if (targetIsOwner && ["reject", "suspend", "remove", "nodl", "setrole", "resetpw"].indexOf(action) !== -1) {
    return json({ error: "The owner account is protected." }, 403);
  }
  if (action === "approve") { await env.DB.prepare("UPDATE users SET status='approved' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "reject") { await env.DB.prepare("UPDATE users SET status='rejected' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "suspend") { await env.DB.prepare("UPDATE users SET status='suspended' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "unsuspend") { await env.DB.prepare("UPDATE users SET status='approved' WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "remove") { await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run(); return json({ ok: true }); }
  if (action === "nodl") { await env.DB.prepare("UPDATE users SET nodl=? WHERE id=?").bind(b.value ? 1 : 0, id).run(); return json({ ok: true }); }
  if (action === "setrole") { await env.DB.prepare("UPDATE users SET role=? WHERE id=?").bind(b.value ? "admin" : "", id).run(); return json({ ok: true }); }
  if (action === "resetpw") {
    const np = (b.password || "").toString();
    if (np.length < 8) return json({ error: "Password must be at least 8 characters." }, 400);
    const u = await getUserById(env, id);
    if (!u) return json({ error: "Account not found." }, 404);
    await env.DB.prepare("UPDATE users SET pass=? WHERE id=?").bind(await passHashNew(env, np), id).run();
    return json({ ok: true });
  }
  if (action === "create") {
    const name = (b.name || "").toString().trim().slice(0, 80);
    const email = (b.email || "").toString().trim().toLowerCase();
    const phone = (b.phone || "").toString().trim();
    const password = (b.password || "").toString();
    if (!validEmail(email)) return json({ error: "Enter a valid email." }, 400);
    if (password.length < 8) return json({ error: "Password must be at least 8 characters." }, 400);
    if (await getUserByEmail(env, email)) return json({ error: "That email already exists." }, 400);
    await env.DB.prepare("INSERT INTO users (name, email, phone, pass, photo, status, created) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(name, email, phone, await passHashNew(env, password), "", "approved", Date.now()).run();
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
  if (!(await isAdminReq(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ online: [], now: Date.now() });
  await ensureD1(env);
  const now = Date.now();
  try { await env.DB.prepare("DELETE FROM presence WHERE seen < ?").bind(now - 3600000).run(); } catch (e) { /* ignore */ }
  const r = await env.DB.prepare("SELECT name, view, seen FROM presence WHERE seen >= ? ORDER BY seen DESC").bind(now - 90000).all();
  return json({ online: r.results || [], now });
}

// Record a play (called by the app when a track actually starts). De-duped so
// the same person replaying/pausing the same track in a short window counts once.
async function handlePlayed(request, env) {
  if (!env.DB) return json({ ok: false });
  const uid = (await verifyUid(env, parseCookies(request).uid)) || "guest";
  const b = await request.json().catch(() => ({}));
  const track = Number(b.track);
  if (!track) return json({ ok: false });
  await ensureD1(env);
  const now = Date.now();
  try {
    const last = await env.DB.prepare("SELECT at FROM plays WHERE uid = ? AND track = ? ORDER BY at DESC LIMIT 1").bind(String(uid), track).first();
    if (last && last.at && now - last.at < 30000) return json({ ok: true, dup: true });
    await env.DB.prepare("INSERT INTO plays (uid, track, title, artist, at) VALUES (?, ?, ?, ?, ?)")
      .bind(String(uid), track, (b.title || "").toString().slice(0, 200), (b.artist || "").toString().slice(0, 200), now).run();
  } catch (e) { /* ignore */ }
  return json({ ok: true });
}

// Admin: listening statistics — totals, top songs, most active people, and a
// recent-plays feed (who played what).
async function handleAdminStats(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "Statistics need a D1 database.", d1: false }, 400);
  await ensureD1(env);
  // Maintenance: clear all listening history.
  if ((b.action || "") === "reset") {
    try { await env.DB.prepare("DELETE FROM plays").run(); } catch (e) { return json({ error: "Could not reset." }, 500); }
    return json({ ok: true, reset: true });
  }
  const now = Date.now(), dayAgo = now - 86400000, weekAgo = now - 7 * 86400000, monthAgo = now - 30 * 86400000;
  // Build a uid -> display-name map from the users table.
  const names = {};
  try {
    const us = await env.DB.prepare("SELECT id, name, email FROM users").all();
    (us.results || []).forEach((u) => { names[String(u.id)] = u.name || u.email || ("User " + u.id); });
  } catch (e) { /* ignore */ }
  const who = (uid) => uid === "admin" ? "Owner" : (uid === "guest" || uid === "" ? "Guest" : (names[uid] || ("User " + uid)));
  const out = { total: 0, today: 0, week: 0, month: 0, listeners: 0, activeToday: 0, activeWeek: 0, topTracks: [], topArtists: [], topUsers: [], recent: [], daily: [] };
  try { const t = await env.DB.prepare("SELECT COUNT(*) AS n FROM plays").first(); out.total = (t && t.n) || 0; } catch (e) {}
  try { const t = await env.DB.prepare("SELECT COUNT(*) AS n FROM plays WHERE at >= ?").bind(dayAgo).first(); out.today = (t && t.n) || 0; } catch (e) {}
  try { const t = await env.DB.prepare("SELECT COUNT(*) AS n FROM plays WHERE at >= ?").bind(weekAgo).first(); out.week = (t && t.n) || 0; } catch (e) {}
  try { const t = await env.DB.prepare("SELECT COUNT(*) AS n FROM plays WHERE at >= ?").bind(monthAgo).first(); out.month = (t && t.n) || 0; } catch (e) {}
  try { const t = await env.DB.prepare("SELECT COUNT(DISTINCT uid) AS n FROM plays").first(); out.listeners = (t && t.n) || 0; } catch (e) {}
  try { const t = await env.DB.prepare("SELECT COUNT(DISTINCT uid) AS n FROM plays WHERE at >= ?").bind(dayAgo).first(); out.activeToday = (t && t.n) || 0; } catch (e) {}
  try { const t = await env.DB.prepare("SELECT COUNT(DISTINCT uid) AS n FROM plays WHERE at >= ?").bind(weekAgo).first(); out.activeWeek = (t && t.n) || 0; } catch (e) {}
  try {
    const r = await env.DB.prepare("SELECT track, title, artist, COUNT(*) AS c FROM plays GROUP BY track ORDER BY c DESC LIMIT 20").all();
    out.topTracks = (r.results || []).map((x) => ({ track: x.track, title: x.title, artist: x.artist, count: x.c }));
  } catch (e) {}
  try {
    const r = await env.DB.prepare("SELECT artist, COUNT(*) AS c FROM plays WHERE artist IS NOT NULL AND artist <> '' GROUP BY artist ORDER BY c DESC LIMIT 12").all();
    out.topArtists = (r.results || []).map((x) => ({ artist: x.artist, count: x.c }));
  } catch (e) {}
  try {
    const r = await env.DB.prepare("SELECT uid, COUNT(*) AS c FROM plays GROUP BY uid ORDER BY c DESC LIMIT 12").all();
    out.topUsers = (r.results || []).map((x) => ({ name: who(x.uid), count: x.c }));
  } catch (e) {}
  try {
    const r = await env.DB.prepare("SELECT uid, track, title, artist, at FROM plays ORDER BY at DESC LIMIT 40").all();
    out.recent = (r.results || []).map((x) => ({ name: who(x.uid), title: x.title, artist: x.artist, at: x.at }));
  } catch (e) {}
  // Plays per day for the last 7 days (oldest → newest), for a mini bar chart.
  try {
    const dayMid = now - (now % 86400000); // UTC midnight of today
    const startDay = Math.floor((dayMid - 6 * 86400000) / 86400000);
    const r = await env.DB.prepare("SELECT CAST(at/86400000 AS INTEGER) AS day, COUNT(*) AS c FROM plays WHERE at >= ? GROUP BY day").bind(dayMid - 6 * 86400000).all();
    const byDay = {}; (r.results || []).forEach((x) => { byDay[x.day] = x.c; });
    const wd = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    for (let i = 0; i < 7; i++) { const d = startDay + i; const ms = d * 86400000; out.daily.push({ label: wd[new Date(ms).getUTCDay()], count: byDay[d] || 0 }); }
  } catch (e) {}
  return json(out);
}

// Admin: one person's listening — their recent plays, totals, and top tracks.
async function handleAdminUserPlays(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "Needs a D1 database." }, 400);
  await ensureD1(env);
  const uid = String(b.id == null ? "" : b.id);
  if (!uid) return json({ error: "Missing id." }, 400);
  const out = { total: 0, week: 0, recent: [], top: [] };
  const weekAgo = Date.now() - 7 * 86400000;
  try { const t = await env.DB.prepare("SELECT COUNT(*) AS n FROM plays WHERE uid = ?").bind(uid).first(); out.total = (t && t.n) || 0; } catch (e) {}
  try { const t = await env.DB.prepare("SELECT COUNT(*) AS n FROM plays WHERE uid = ? AND at >= ?").bind(uid, weekAgo).first(); out.week = (t && t.n) || 0; } catch (e) {}
  try { const r = await env.DB.prepare("SELECT track, title, artist, at FROM plays WHERE uid = ? ORDER BY at DESC LIMIT 50").bind(uid).all(); out.recent = (r.results || []).map((x) => ({ track: x.track, title: x.title, artist: x.artist, at: x.at })); } catch (e) {}
  try { const r = await env.DB.prepare("SELECT track, title, artist, COUNT(*) AS c FROM plays WHERE uid = ? GROUP BY track ORDER BY c DESC LIMIT 10").bind(uid).all(); out.top = (r.results || []).map((x) => ({ track: x.track, title: x.title, artist: x.artist, count: x.c })); } catch (e) {}
  return json(out);
}

// Admin: export plays or accounts as CSV for download.
async function handleAdminExport(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "Needs a D1 database." }, 400);
  await ensureD1(env);
  const what = (b.what || "plays").toString();
  const q = (s) => '"' + String(s == null ? "" : s).replace(/"/g, '""') + '"';
  const iso = (ms) => { try { return new Date(Number(ms)).toISOString(); } catch (e) { return ""; } };
  let csv = "", filename = "export.csv";
  if (what === "accounts") {
    const r = await env.DB.prepare("SELECT id, name, email, phone, status, role, created FROM users ORDER BY created DESC").all();
    const plays = {};
    try { const p = await env.DB.prepare("SELECT uid, COUNT(*) AS c FROM plays GROUP BY uid").all(); (p.results || []).forEach((x) => { plays[String(x.uid)] = x.c; }); } catch (e) {}
    csv = "id,name,email,phone,status,role,joined,plays\n" + (r.results || []).map((u) =>
      [u.id, q(u.name), q(u.email), q(u.phone), u.status || "", u.role || "", iso(u.created), plays[String(u.id)] || 0].join(",")).join("\n");
    filename = "accounts.csv";
  } else {
    const names = {};
    try { const us = await env.DB.prepare("SELECT id, name, email FROM users").all(); (us.results || []).forEach((u) => { names[String(u.id)] = u.name || u.email || ("User " + u.id); }); } catch (e) {}
    const who = (uid) => uid === "admin" ? "Owner" : (uid === "guest" || uid === "" ? "Guest" : (names[uid] || ("User " + uid)));
    const r = await env.DB.prepare("SELECT uid, track, title, artist, at FROM plays ORDER BY at DESC LIMIT 5000").all();
    csv = "when,listener,track,title,artist\n" + (r.results || []).map((x) =>
      [iso(x.at), q(who(String(x.uid))), x.track, q(x.title), q(x.artist)].join(",")).join("\n");
    filename = "plays.csv";
  }
  return new Response(csv, { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="' + filename + '"', "Cache-Control": "no-store" } });
}

// Admin: set the music-server login from inside the app (stored in D1), so
// playback keeps working without touching Cloudflare. Never returns the
// password/token — only whether they are set.
async function handleAdminMusic(request, env) {
  const b = await request.json().catch(() => ({}));
  if (!(await isAdminReq(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.DB) return json({ error: "This needs a D1 database." }, 400);
  const action = (b.action || "status").toString();
  const status = async () => {
    const c = await getMusicCreds(env);
    return {
      token: !!(c.token || env.USER_TOKEN),
      autologin: !!((c.email && c.password) || (env.ZING_EMAIL && env.ZING_PASSWORD)),
      email: c.email || env.ZING_EMAIL || "",
    };
  };
  if (action === "save") {
    const cur = await getMusicCreds(env);
    const obj = Object.assign({}, cur);
    if (typeof b.email === "string") obj.email = b.email.trim();
    if (typeof b.password === "string" && b.password) obj.password = b.password; // keep old if blank
    if (typeof b.token === "7G&��r"bb"�F��V��G&�҂���&��F��V��"�F��V��G&�҂�����G&��66�VB��v��6�F�R�Wr7&VFV�F��2F�RVffV7B���VF�FVǒ�FV�WFR�&��EF��V�FV�WFR�&��DW��FV�WFR�&��f�&V&6U&Vg&W6���v�B6fT�W6�47&VG2�V�b��&����44�TE�D��T���V�ò44�TE�U����&WGW&��6�⇲���G'VR��3�v�B7FGW2��ғ��Т�b�7F������&6�V""���v�B6fT�W6�47&VG2�V�b��ғ��44�TE�D��T���V�ò44�TE�U����&WGW&��6�⇲���G'VR��3�v�B7FGW2��ғ��Т�b�7F������'FW7B"���44�TE�D��T���V�ò44�TE�U����6��7BFWF����Ӱ�G'���6��7B7"�v�B�W6�47&VG2�V�b���FWF���4V����7"�V��òFWF���5F��V��7"�F��V㰢�����rW6W2f�&V&6R(	B6�v���v�F�F�RV����77v�&B�B6GW&RF�R&W7V�B��b�7"�V���bb7"�77v�&B���FWF���f�&V&6T�W�f�V�B��v�BvWDf�&V&6T�W��V�b����6��7Bg"�v�Bf�&V&6U6�v��V�b�7"�V����7"�77v�&B���FWF�����v�����g"�����FWF�����v��W'&�"�g"�����V���g"�W'&�#��Т6��7BF���v�B7W'&V�EF��V�V�b�G'VR���FWF���v�EF��V��F�����b�F���&WGW&��6�⇲���f�6R�7FvS�&��v��"�W'&�#�$6�V�F�(	�BvWB��v��g&��F�R�W6�26W'fW"�"�FWF����3�v�B7FGW2��ғ����f��B&V�G&6��B�F�V�G'�F�RVF��6W'fW"v�F��'�FR&�vR��WBF�B���G'���6��7BB�v�Bw&�V�b�'VW'���'V�2�F�S���G&6�2��B���"���6��7BB����BbbB�FFbbB�FF��'V�2����ҕ�����Ғ�G&6�2���Ӱ��b�E��bbE���B�F�B�E���C���6F6��R��Т6��7B"�v�BfWF6�VF��V�b�F�B��&�vS�&'�FW3��"ғ��FWF���VF��7FGW2�"�7FGW3���b�"�7FGW2���#��"�7FGW2���#b�&WGW&��6�⇲���G'VR�7FGW3�"�7FGW2�FWF����3�v�B7FGW2��ғ��&WGW&��6�⇲���f�6R�7FvS�&VF��"�7FGW3�"�7FGW2�W'&�#�"�7FGW2���C2�%F�R�W6�26W'fW"&V�V7FVBF�R��v���w&��rV����77v�&B��"���rW6W2F�ffW&V�B��v���"��$�W6�26W'fW"&WGW&�VB"�"�7FGW2�"�"��FWF����3�v�B7FGW2��ғ���6F6��R���&WGW&��6�⇲���f�6R�W'&�#�7G&��r��RbbR��W76vR���R��FWF��ғ��ТТ�b�7F������'&V6��"�����&VBF�R&V��Wv�6��W6�2�f���W"�2��VVG2����v���"VF��6W'fW"����6��Bv��wBG&�&FRƖ֗G2�G'��&WGW&��6�⇲���G'VR�&V6��v�B&V6��6ƖV�D�2�V�b�ғ�Т6F6��R��&WGW&��6�⇲���f�6R�W'&�#�7G&��r��RbbR��W76vR���R�ғ�ТТ&WGW&��6�⇲�3�v�B7FGW2��ғ��Р����������������������������������������������������������������������������������WF����v����F����v�V����u�T�������u�55t�$B&R6WB�F�Rv�&�W �����w2���G6V�bF�vWBg&W6�6W76���F��V��6�F�RF��V��WfW"�2F�&P���WFFVB'���B�f��2&6�F�F�RU4U%�D��T�6V7&WBv�V�WF����v���2�fb���������������������������������������������������������������������������������WB44�TE�D��T���V�ò��W"֗6��FR66�R�bF�R�FW7B6W76���F��V��WB44�TE�U�����W�6�6V6��G2v�V�F�R66�VBF��V�W��&W2��V���v␠�gV�7F���6�f�&V&6R�V�b���&WGW&��V�b�d�$T$4U����U�bbV�b�d�$T$4U�$Te$U4��D��T⓰�Р�gV�7F���6�WF���v��V�b���&WGW&��V�b���U$�bbV�b夔�u�T���bbV�b夔�u�55t�$B���Р�gV�7F����4WF��V�b���&WGW&��V�b�U4U%�D��T���6�f�&V&6R�V�b���6�WF���v��V�b����Р���W�6��vRF�R���r�ƗfVBf�&V&6R&Vg&W6�F��V�f�"g&W6��BF��V����v��v�Rw2V�G���B�2fƖB6W'F�f�6FR�6�6��VFf�&R6�&V6��B�7��2gV�7F���f�&V&6U&Vg&W6��V�b����b�6�f�&V&6R�V�b��&WGW&�����f�6R�W'&�#�$d�$T$4U����U��d�$T$4U�$Te$U4��D��T���B6WB�"Ӱ�G'���6��7B"�v�BfWF6���&�GG3���6V7W&WF��V��v��v�V�2�6���c�F��V���W��"�V�6�FUU$�6����V�B�V�b�d�$T$4U����U�������WF��C�%�5B"���VFW'3��$6��FV�B�G�R#�&Ɩ6F������wwr�f�&��W&�V�6�FVB"���&�G���&w&�E�G�S�&Vg&W6��F��V�g&Vg&W6��F��V��"��V�6�FUU$�6����V�B�V�b�d�$T$4U�$Te$U4��D��T���Т���6��7BB�v�B"�6�ₒ�6F6��������Ғ����b�"�����B�W'&�"���6��7B�6r�B�W'&�"bb�B�W'&�"��W76vR��B�W'&�"���&WGW&�����f�6R�W'&�#��6r��%&Vg&W6�&WGW&�VB"�"�7FGW2�"�"Ӱ�Т6��7B�GB�B�E�F��V���B�66W75�F��V㰢�b��GB���44�TE�D��T���GC��44�TE�U���F��f���"�FFR���r������'6T��B�B�W��&W5�������3c���&WGW&�����G'VR�F��V��GBӰ�Т&WGW&�����f�6R�W'&�#�$���E�F��V���F�R&Vg&W6�&W7��6R�"Ӱ��6F6��R���&WGW&�����f�6R�W'&�#�7G&��r��RbbR��W76vR���R�Ӱ�ЧР���F�Rf�&V&6RvV"��W��V&Ɩ2�V�&VFFVB��F�R���rvV"���W6W2F�P���6V7&WB�6fVBf�VR��"WF��F�66�fW'2�Bg&��F�R���rvV'6�FR�F�Rv�&�W ���6�&V6��BWfV�F��Vv��B����2Ɩ�R�W7B���7��2gV�7F���vWDf�&V&6T�W��V�b����b�V�b�d�$T$4U����U��&WGW&�V�b�d�$T$4U����U���6��7B2�v�BvWD�W6�47&VG2�V�b����b�2�f�&V&6T�W��&WGW&�2�f�&V&6T�W���6��7B�W��v�BF�66�fW$f�&V&6T�W��V�b����b��W���2�f�&V&6T�W���W��v�B6fT�W6�47&VG2�V�b�2��Т&WGW&��W���"#��Ц7��2gV�7F���F�66�fW$f�&V&6T�W��V�b���6��7B'������Ӕզץ���׳3W��6��7B6VVG2��&�GG3����Wv�6��W6�2�f�"�&�GG3���wwr�Wv�6��W6�2�f�"�&�GG3����Wv�6��W6�2�f�%Ӱ�f�"�6��7BW&��b6VVG2���G'���6��7B"�v�BfWF6�B�W&�����#����b�"����6��F��VS��6��7B�F���v�B"�FW�B�����WB���F����F6��'�����b�Ғ&WGW&�ճӰ�6��7B67&�G2��Ӱ�6��7B&R���67&�E���ҷ7&3ղ"u҅��"uҲ��"u��v���WB6Ӱ�v���R��6��&R�W�V2��F��bb67&�G2��V�wF���67&�G2�W6��6ճғ��f�"��WB2�b67&�G2���G'����b�2�7F'G5v�F��"��"��2�&�GG3�"�3��V�6R�b�2�7F'G5v�F��"�"��2��WrU$2�W&�&Vc��V�6R�b���GG3����FW7B�2��6��F��VS��6��7B�"�v�BfWF6�B�2����#����b��"����6��F��VS��6��7B�2�v�B�"�FW�B����6��7B����2��F6��'�����b��Ғ&WGW&��ճӰ��6F6��R����W�B��ТТ�6F6��R����W�B6VVB��ТТ&WGW&�"#��Т��&Vg&W6���BF��V�W6��r7F�&VBf�&V&6R&Vg&W6�F��V��F�R�V&Ɩ2��W��7��2gV�7F���f�&V&6U&Vg&W6�v�F��V�b�&Vg&W6�F��V���6��7B�W��v�BvWDf�&V&6T�W��V�b����b��W���&Vg&W6�F��V�&WGW&�����f�6R�W'&�#�$��f�&V&6R�W��&Vg&W6�F��V��"Ӱ�G'���6��7B"�v�BfWF6�B�&�GG3���6V7W&WF��V��v��v�V�2�6���c�F��V���W��"�V�6�FUU$�6����V�B��W������WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F������wwr�f�&��W&�V�6�FVB"���&�G��&w&�E�G�S�&Vg&W6��F��V�g&Vg&W6��F��V��"�V�6�FUU$�6����V�B�&Vg&W6�F��V���S���6��7BB�v�B"�6�ₒ�6F6��������Ғ���6��7B�GB�Bbb�B�E�F��V���B�66W75�F��V⓰��b��GB���6��7BW���F��f���"�FFR���r������'6T��B�B�W��&W5�������3c���44�TE�D��T���GC�44�TE�U��W����W"֗6��FR��Ǔ���B66�VB��C�F�W6RF��V�2&R&V�V7FVB'�F�RVF��6W'fW"��&WGW&�����G'VR�F��V��GBӰ�Т&WGW&�����f�6R�W'&�#��BbbB�W'&�"bb�B�W'&�"��W76vR��B�W'&�"�����%&Vg&W6�&WGW&�VB"�"�7FGW2�Ӱ��6F6��R��&WGW&�����f�6R�W'&�#�7G&��r��RbbR��W76vR���R�ӲЧТ��6�v���F�f�&V&6Rv�F�F�R���rV����77v�&B����rW6W2f�&V&6RWF�����6fW2F�R&Vg&W6�F��V�6�gWGW&RF��V�2&V�WrWF��F�6�ǒ(	Bf�&WfW"�7��2gV�7F���f�&V&6U6�v��V�b�V����77v�&B���6��7B�W��v�BvWDf�&V&6T�W��V�b����b��W��&WGW&�����f�6R�W'&�#�$6�V�F�(	�Bf��BF�R���rf�&V&6R�W��WF��F�66�fW'�f��VB��"Ӱ�G'���6��7B"�v�BfWF6�B�&�GG3����FV�F�G�F��ƶ�B�v��v�V�2�6���c�66�V�G3�6�v��v�F�77v�&C��W��"�V�6�FUU$�6����V�B��W������WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"���&�G���4���7G&��v�g���V����77v�&B�&WGW&�6V7W&UF��V�G'VRҒ��S���6��7BB�v�B"�6�ₒ�6F6��������Ғ����b�BbbB�EF��V���6��7BW���F��f���"�FFR���r������'6T��B�B�W��&W4������3c���44�TE�D��T��B�EF��V㰢44�TE�U��W�����66�RF��2v�&���r6�v�֖�F��V���C�fW'6���VB��6�&VB7&�72�����v�&�W"�6��FW2�6�vRF��wB6�v�����WfW'�&WVW7B�f�&V&6P���&FR�Ɩ֗G2F�B��G'��6��7B2�v�BvWD�W6�47&VG2�V�b��2�EF��V��B�EF��V�2�DW��W��2�F��V�fW"�D��T��dU#�v�B6fT�W6�47&VG2�V�b�2���6F6��R��Т&WGW&�����G'VR�F��V�B�EF��V�Ӱ�Т&WGW&�����f�6R�W'&�#��BbbB�W'&�"bb�B�W'&�"��W76vR��B�W'&�"�����$f�&V&6R6�v�֖�f��VB�"�"�7FGW2�"��"�Ӱ��6F6��R��&WGW&�����f�6R�W'&�#�7G&��r��RbbR��W76vR���R�ӲЧР����W6�2�6W'fW"��v��6�&R6WB��F�RF֖��V��7F�&VB��C���7FVB�`�����ǒf�6��VFf�&R6V7&WG2�6�F�R�v�W"6�f���Bg&��F�V�"���R�F�P������f�VW2F�R&V6VFV�6R�fW"F�R6V7&WG2�F�W6R&R�WfW"6V�BF�F�P���'&�w6W"���ǒ&���V�2&�WBv�WF�W"F�W�w&R6WB��6��7B�U4�5��U��&�W6�5�7&VG2#��7��2gV�7F���vWD�W6�47&VG2�V�b����b�V�b�D"�&WGW&��Ӱ�G'���v�BV�7W&TC�V�b���6��7B"�v�BV�b�D"�&W&R�%4T�T5Bbe$��6WGF��w2t�U$R���"��&��B��U4�5��U���f�'7B����6��7B2�"bb"�b��4���'6R�"�b���Ӱ�&WGW&��2bbG�V�b2���&�&�V7B"��2��Ӱ��6F6��R��&WGW&��ӲЧЦ7��2gV�7F���6fT�W6�47&VG2�V�b��&�����b�V�b�D"�&WGW&㰢v�BV�7W&TC�V�b���v�BV�b�D"�&W&R�$��4U%B�"$U�4R��D�6WGF��w2���b�d�TU2����"��&��B��U4�5��U���4���7G&��v�g���&����Ғ��'Vₓ��Ц7��2gV�7F����W6�47&VG2�V�b���6��7B2�v�BvWD�W6�47&VG2�V�b���&WGW&���F��V��2�F��V���V�b�U4U%�D��T���""���V��â�2�V�����V�b夔�u�T�����""���77v�&C��2�77v�&B��V�b夔�u�55t�$B��""���Ӱ�Ц7��2gV�7F����4WF���r�V�b����b��4WF��V�b��&WGW&�G'VS��6��7B2�v�BvWD�W6�47&VG2�V�b���&WGW&��2�F��V����2�V���bb2�77v�&B����Р���6��7B��v��F�v��6�2�6fRF�&WGW&�F��F֖���WfW"F�R6V7&WG2�����F�BF�R��v��v�&���B�b�BF�B�F�W2F�RVF��6W'fW"7F���&V�V7B�C�7��2gV�7F�����v��F�r�V�b�&WVW7B�&V�G&6��B���G'����b��v�B�4F֖�&W�V�b�&WVW7B��Ғ��&WGW&��V�ð��6F6��R��&WGW&��V�òТ6��7B7"�v�B�W6�47&VG2�V�b���6��7B�WB��'V��C�%T��B��4V��â7"�V�����5F��V�7"�F��V�Ӱ��b�7"�V���bb7"�77v�&B���6��7B�W��v�BvWDf�&V&6T�W��V�b����WB�f�&V&6T�W�f�V�B��W����b��W����WB���FR�$6�V�F�(	�BWF��f��BF�R���rf�&V&6R�W��FV��F�RFWfV��W"�#�&WGW&��WC�Т6��7Bg"�v�Bf�&V&6U6�v��V�b�7"�V����7"�77v�&B����WB�f�&V&6T��v�����g"������WB�f�&V&6T��v��W'&�"�g"�����V����g"�W'&�"��'V���v�"����b�g"�������WB���FR�$f�&V&6R6�v�֖����&�&��r��r���rw2VF��v�G2F�RF��V�(
b#���WB�F��V�6���2�FV6�FT�wD6���2�g"�F��V⓰�6��7B&6R�V�b�TD�����$4S����&�&RF�R5ET�G&6�F�RW6W"G&�VBF������BvV�W&�26��R�����6�vR6�FV��v�WF�W"F��27V6�f�2G&6��2vFVB�6��7BF�B�&V�G&6��B�����WB�&V�G&6��F�C��6��7BW&����B���&6R�#�G&6��C�"�V�6�FUU$�6����V�B��B��"gF��V��"�V�6�FUU$�6����V�B�g"�F��V⓰�G'��6��7B"�v�BfWF6�B�W&F�B����VFW'3��&�vS�&'�FW3��"���#���WB�VF���&V��&�vR�"�7FGW3��6F6��R���WB�VF���&V��&�vR�&W'"#�ТG'��6��7B"�v�BfWF6�B�W&F�B�����#���WB�VF���&V��gV���"�7FGW3��6F6��R���WB�VF���&V��gV���&W'"#�Т��6��&Rv��7B���v�6��RG&6��f�'7BG&6��bF�Rf�'7B�'VҒ�G'���6��7BB�v�Bw&�V�b�'VW'���'V�2�F�S���G&6�2��B���"���6��7B7B����BbbB�FFbbB�FF��'V�2����ҕ�����Ғ�G&6�2���Ӱ��b�7E��bb7E���B���WB�6��UG&6��7E���C�6��7B"�v�BfWF6�B�W&7E���B����VFW'3��&�vS�&'�FW3��"���#���WB�VF���6��R�"�7FGW3�Т�6F6��R���WB�VF���6��R�&W'"#�Т���VWF�R&V&W"�f�&�&�&R��F�R&V�G&6�f�"6���WFV�W72�G'��6��7B"�v�BfWF6�B�&6R�#�G&6��C�"�V�6�FUU$�6����V�B�F�B����VFW'3��&�vS�&'�FW3��"�WF��&��F���$&V&W""�g"�F��V����#���WB�VF���&V��&V&W"�"�7FGW3��6F6��R���WB�VF���&V��&V&W"�&W'"#�Т��6F��r66���RG&6�g&��6WfW&�F�ffW&V�B�'V�2�F�6VR��r�V6�����bF�RƖ'&'�7GV�ǒ7G&V�2v�F�F�R���F��V��#b�g2C2�G'���6��7BB�v�Bw&�V�b�'VW'���'V�2�F�S���&FW$'�����C�FW62�Ғ��BV���RG&6�2�F�S����B���"���6��7B�'2���BbbB�FFbbB�FF��'V�2����ғ���WB�6F��u66���Ӱ�f�"�6��7B�b�'2���6��7BC���G&6�2���ҕ�Ӱ��b�C��C�B���V�6��F��VS���WB2�&W'"#��G'��6��7B"�v�BfWF6�B�W&C�B����VFW'3��&�vS�&'�FW3��"������2�"�7FGW3��6F6��R��Т�WB�6F��u66��W6����'VӢ�B�G&6��C�B�7FGW3�2ғ��Т�WB�6F��u7V��'���WB�6F��u66��&VGV6R���������շ��7FGW5���շ��7FGW5������&WGW&�Ӳ���ғ���6F6��R���WB�6F��u66����W'&�#�7G&��r��RbbR��W76vR���R��ӲТG'���WB�7F'E7G&V֖�u6W76����v�B��G&�7V7D�WFF���V�b�'7F'E7G&V֖�u6W76���"���6F6��R��ТG'���WB�6W76���&W7V�B�v�B��G&�7V7EG�R�V�b�%6W76���&W7V�B"���6F6��R��ТG'���WB�6W76���G'��v�BG'�7F'E6W76���V�b�g"�F��V��F�B���6F6��R���WB�6W76���G'���W'&�#�7G&��r��RbbR��W76vR���R�ӲТG'���WB�&V6���v�B&V6��6ƖV�D�2�V�b���6F6��R���WB�&V6����W'&�#�7G&��r��RbbR��W76vR���R�ӲТ�V�6R���WB���FR�$f�&V&6R6�v�֖�f��VB(	BƖ�VǒF�R���rV����77v�&B�2w&��r�#��Т�V�6R���WB���FR�$��V����77v�&B6fVB(	B6WBF�R�W6�26W'fW"��v���#��Т&WGW&��WC��Р���&WGW&��WFF���w2&r��W2�&WGW&�G�R�F��V&���r�R�r�����7F'E7G&V֖�u6W76����W7B&R6��VB��7��2gV�7F�����G&�7V7D�WFF���V�b���R���6��7B�'VW'����66�V���WFF���G�R�f�V�G2���R&w2���RG�R����B��R�eG�R����B��R���G�R����B��R�eG�R����B��Rf�V�G2���R�������#��G'���6��7B"�v�BfWF6�B�V�b���U$����WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"��&�G���4���7G&��v�g���VW'��Ғ��#���6��7BB�v�B"�6�ₒ�6F6��������Ғ���6��7Bf�V�G2����B�FF���Ғ���66�V����Ғ��WFF���G�R���Ғ�f�V�G2���Ӱ�6��7Bb�f�V�G2�f��B����������R�����R����b�b�&WGW&��f�V�C�f�6RӰ�6��7BF���B����v���R�BbbB���RbbB��eG�R�B�B��eG�S�&WGW&�B��B涖�B�""�B���R��#�#�Ӱ�&WGW&��f�V�C�G'VR�&w3��b�&w2���Ғ����������R�#�"�F��G�R���&WGW&�3�F�b�G�R��&WGW&�f�V�G3����b�G�R���Ғ��eG�R���Ғ�f�V�G2���b�G�R���Ғ�f�V�G2���Ғ������������R�Ӱ��6F6��R��&WGW&��W'&�#�7G&��r��RbbR��W76vR���R�ӲЧР�����G&�7V7B��VBw&��G�RF��V&��G2f�V�G2�R�r�6W76���&W7V�B�6���vR���rv�B7F'E7G&V֖�u6W76���&WGW&�2�B��rF�W6R�B��7��2gV�7F�����G&�7V7EG�R�V�b���R���6��7B�'VW'��F�7G&��r����G�R���S�F◲��R���Bf�V�G2���RG�R����B��R�eG�R����B��R�����#��G'���6��7B"�v�BfWF6�B�V�b���U$����WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"��&�G���4���7G&��v�g���VW'���f&�&�W3�����R�Ғ��#���6��7BB�v�B"�6�ₒ�6F6��������Ғ���6��7BB��B�FF���Ғ���G�S���b�B�&WGW&��f�V�C�f�6RӰ�6��7BF��������v���R��bb����Rbb���eG�R������eG�S�&WGW&�����涖�B�""�����R��#�#�Ӱ�&WGW&��f�V�C�G'VR����C�B涖�B�f�V�G3��B�f�V�G2���Ғ����b���b���R�#�"�F�b�G�R��Ӱ��6F6��R��&WGW&��W'&�#�7G&��r��RbbR��W76vR���R�ӲЧР���6V�B�WF�V�F�6FVBw&��&WVW7BF����rv�F�F�Rf�&V&6R�EF��V��7��2gV�7F������tWF�VB�V�b�F��V��VW'����6��7B"�v�BfWF6�B�V�b���U$����WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"�WF��&��F���$&V&W""��F��V���""���&�G���4���7G&��v�g���VW'�Ғ��#���&WGW&�v�B"�6�ₒ�6F6��������Ғ���Р���GFV�BF��V�7G&V֖�r6W76���f�"G&6��B&W�'Bv�B6��W2&6������"F�Rw&��W'&�'2�v��6�W7V�ǒ��R�&WV�&VB&w2vRw&R֗76��r������G&�7V7Bw&����UBG�Rw2f�V�G2�f�"'V��F��r7&VFR��WG2��7��2gV�7F�����G&�7V7D��WEG�R�V�b���R���6��7B�'VW'��F�7G&��r����G�R���S�F◲��R���B��WDf�V�G2���RG�R����B��R�eG�R����B��R�eG�R����B��R������#��G'���6��7B"�v�BfWF6�B�V�b���U$����WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"��&�G���4���7G&��v�g���VW'���f&�&�W3�����R�Ғ��#���6��7BB�v�B"�6�ₒ�6F6��������Ғ���6��7BB��B�FF���Ғ���G�S���b�B�&WGW&��f�V�C�f�6RӰ�6��7BF���������WB&W�"#��b��bb�涖�B���$�����T��"�&W�"#�v���R��bb����Rbb���eG�R������eG�S�&WGW&������涖�B�""�����R��#�"��&W�Ӱ�&WGW&��f�V�C�G'VR�f�V�G3��B��WDf�V�G2���Ғ����b���b���R�#�"�F�b�G�R��Ӱ��6F6��R��&WGW&��W'&�#�7G&��r��RbbR��W76vR���R�ӲЧР�����G&�7V7B�T�T�G�Rw2f�VW2�7��2gV�7F�����G&�7V7DV�V҆V�b���R���6��7B�'VW'��F�7G&��r����G�R���S�F◲��RV�V�f�VW2���R���#��G'���6��7B"�v�BfWF6�B�V�b���U$����WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"��&�G���4���7G&��v�g���VW'���f&�&�W3�����R�Ғ��#���6��7BB�v�B"�6�ₒ�6F6��������Ғ���6��7BB��B�FF���Ғ���G�S���b�B�&WGW&��f�V�C�f�6RӰ�&WGW&��B�V�V�f�VW2���Ғ����R���R���R����6F6��R��&WGW&��7G&��r��RbbR��W76vR���R�ӲЧР���fWF6�F�R&V��Wv�6��W6�2�f�vV"��W"w2�2�BW�G&7B��r�B'V��G2F�P���VF���7G&V�&WVW7B�6�vR7F�wVW76��rF�R6W76���f�&Ғ�7��2gV�7F���&V6��6ƖV�D�2�V�b���6��7B�WB��'V�F�W3������G3����vW3���Ӱ�6��7BT��%W6W"�vV�B#�$�������R��v��F�w2�B��v��cC��cB��UvV$��B�S3r�3b���D���Ɩ�RvV6��6�&��R�#B�6f&��S3r�3b"�$66WB#�'FW�B��F���Ɩ6F������F�·���"Ӱ�6��7BW62��2���2�&W�6R���⢳��G�҂�ŵ������r�%��Bb"���6��7BVD��7B�������G'��&WGW&��WrU$V�b�TD�����$4R���7C��6F6��R��&WGW&��V�ò�Ғ����6��7B���7B�������G'��&WGW&��WrU$V�b���U$��7C��6F6��R��&WGW&��V�ò�Ғ����6��7B�W�v�&G2��'7F'E7G&V֖�u6W76���"�'6W76���B"�'&���G���FR"�$�V'F&VB"�"�7G&V�"�"��2"�'G&6��B%Ӱ��b�VD��7B��W�v�&G2�W6��VD��7B�����6���V7B6�F�FFR�2U$�2g&����R�"��&RV�G'�vW2�6��7B�5W&�2��Wr6WB����6��7BV�G'�vW2��&�GG3����Wv�6��W6�2�f��"�&�GG3����Wv�6��W6�2�f��"�&�GG3���wwr�Wv�6��W6�2�f��%Ӱ�f�"�6��7BvR�bV�G'�vW2���G'���6��7B"�v�BfWF6�B�vR���VFW'3�T��#���6��7B�F���v�B"�FW�B�����WB�vW2�W6���W&âvR�7FGW3�"�7FGW2��V��F����V�wF���VC��F���6Ɩ6R��c��&W�6R���2��r�""�ғ����'&�BW�G&7F���7&3���&Vc����GV�W&V��B��B&&R���W�B�"�2F�2�6��7BG2�����"u҆�GG3�������"uҳ���5��"uҢ��"u��r����"u҅����"uҳ���5��"uҢ��"u��r�������W�E��7FF�5����"u�2�ҵ��2��r���7&3ղ"u҅��"uҲ��"u��r��Ӱ�6��7B&6T��7B��WrU$vR���&�v�㰢f�"�6��7B�bG2���WBӲv���R�����W�V2��F�����WB2�ճӲ�b����2����B���FW7B�2��6��F��VS�6��7B'2�2�7F'G5v�F��&�GG"��2��&6T��7B��2�7F'G5v�F��"�"��""�"�"��2���5W&�2�FB�'2���Т�b��5W&�2�6��R�'&V����v�B'V�F�W2g&��F��2vP��6F6��R���WB�vW2�W6���W&âvR�W'&�#�7G&��r��RbbR��W76vR���R�ғ�ТТ6��7B'2�'&��g&�҆�5W&�2��6Ɩ6R��b����WB�'V�F�W2�'3��f�"�6��7BR�b'2�6Ɩ6R��"����G'���6��7B�"�v�BfWF6�B�R���VFW'3�T�����b��"����6��F��VS���WB�2�v�B�"�FW�B����b��2��V�wF��3S��2��2�6Ɩ6R��3S���f�"�6��7B�r�b�W�v�&G2���6��7B�&R��Wr&VtW��"���sҒ"�W62��r��"���SҒ"�&r"����WB�������v���R������&R�W�V2��2��bb��"���6��7B�W���r���VD��7B�$TD����5B"��s����WB憗G5��W����WB憗G5��W�����Ғ�W6����ճ��,*�"���r���VD��7B�$��5B"��r��,+�"��ճ%Ғ�&W�6R���2��r�""��6Ɩ6R��#C����ⲳ��ТТ�6F6��R��ТТ&WGW&��WC��Р���Ɨ7B&��BVW'���WFF���f�V�B��W2�F6���rGFW&��F�F�66�fW"��rF���vWBW6W$�B�FWf�6T�B�WF2��7��2gV�7F�����G&�7V7E&��D��W2�V�b�v��6��&R���6��7Bf�V�B�v��6����&�WFF���"�&�WFF���G�R"�'VW'�G�R#��6��7B�'VW'����66�V��"�f�V�B�"�f�V�G2���R����#��G'���6��7B"�v�BfWF6�B�V�b���U$����WF��C�%�5B"��VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"��&�G���4���7G&��v�g���VW'��Ғ��#���6��7BB�v�B"�6�ₒ�6F6��������Ғ���6��7Bg2����B�FF���Ғ���66�V����ҕ�f�V�E����Ғ�f�V�G2���Ӱ�&WGW&�g2����b���b���R��f��FW"�����&R�FW7B�⒒�6Ɩ6R��#R����6F6��R��&WGW&��7G&��r��RbbR��W76vR���R�ӲЧР�7��2gV�7F���G'�7F'E6W76���V�b�F��V��G&6��B���6��7B�WB��Ӱ�G'�����F�66�fW"6�F�FFR&��G2f�"F�R�G2vR7F����VVB��WB�W6W%VW&�W2�v�B��G&�7V7E&��D��W2�V�b�'VW'�"��W6W'�f�WvW'���RG�66�V�G�&�f��R������WB�FWf�6UVW&�W2�v�B��G&�7V7E&��D��W2�V�b�'VW'�"��FWf�6R������WB�FWf�6T�WFF���2�v�B��G&�7V7E&��D��W2�V�b�&�WFF���"��FWf�6W�6W76����������&�f��R�vR���r&�f��W2v�&�2�(	B����f�"W6W$�B���B��WB&�f��T�B��V���W6W$�B��V�ð�G'��6��7B�v�B���tWF�VB�V�b�F��V��'VW'��&�f��W2��BW6W$�B��"��6��7B2����FF���Ғ�&�f��W2����Ӳ�b�5�Ғ�&�f��T�B�5���C��b�5���W6W$�B��V�W6W$�B�5���W6W$�C���WB�&�f��W2�2�6Ɩ6R��"���6F6��R��Т��G'���FgV��bW6W"֖BVW&�W2�f�"�6��7B�b�'VW'���R��B��"�'VW'��7W'&V�EW6W"��B��"�'VW'��f�WvW"��B��"�'VW'��W6W"��B��"�'VW'��66�V�B��B��%Ғ���b�W6W$�B��V�'&V���G'��6��7B"�v�B���tWF�VB�V�b�F��V����6��7B�W����F6���ǵ�2���r���Ӳ6��7Bb��"�FF���ҕ��W�Ӳ�b�bbbb�B��V��W6W$�B�b�C��WB�W6W$g&����W����6F6��R��ТТ�WB�W6W$�B�W6W$�C��WB�&�f��T�B�&�f��T�C�����f��B&V�FWf�6T�B�v�VB'�F��2W6W"�FWf�6T�C�vfP���$��BWF��&��VBf�"F��2FWf�6R"��G'�Ɨ7F��rF�RW6W"w2FWf�6W2fWp���v�3�F�R���R6��V�B�&VG��fR&Vv�7FW&VB��R��WB�FWf�6W2��G&�VC���Ӱ�6��7BFWe6�W2���'VW'��W6W$FWf�6W2�v�W&S��W6W#���C��WV�3�"��V�&W"�W6W$�B��"��Ғ��BVF�B��R��FV��27F�fR�5���u��W"��"��'VW'��W6W$FWf�6W2��BVF�B��R��FV��27F�fR�5���u��W"��"��'VW'��W6W$FWf�6W2�F�S����BVF�B��R�27F�fR��"��Ӱ��WBFWf�6T�B��V���FWf�6TƗ7B��Ӱ�f�"�6��7BG�bFWe6�W2���G'���6��7B"�v�B���tWF�VB�V�b�F��V��G����b�"�FFbb'&��4'&��"�FF�W6W$FWf�6W2���FWf�6TƗ7B�"�FF�W6W$FWf�6W3��WB�FWf�6W2�VW'��G�'&V��Т�WB�FWf�6W2�G&�VB�W6����G�6Ɩ6R��c��W'#��"�W'&�'2���Ғ����R���R��W76vR���ғ���6F6��R���WB�FWf�6W2�G&�VB�W6����G�6Ɩ6R��c��W'#�7G&��r�R�ғ�ТТ�WB�FWf�6W2�Ɨ7B�FWf�6TƗ7B�6Ɩ6R��R����b�FWf�6TƗ7E��bbFWf�6TƗ7E���B��V�FWf�6T�B�FWf�6TƗ7E���C�����v�2�V&�F�R7&VFR�FWf�6R66�V�6�vR6�&Vv�7FW"FVF�6FVBvV ���FWf�6R�b�VVFVB�F�R���Rw2FWf�6R����BWF��&��RvV"7G&V֖�r���WB�7&VFTFWf�6T��WB�v�B��G&�7V7D��WEG�R�V�b�%W6W$FWf�6T7&VFT��WB"����WB��4V�V��v�B��G&�7V7DV�V҆V�b�$�2"����WB�FWf�6T�B�FWf�6T�C�����GFV�B7F'E7G&V֖�u6W76���v�F�V6����v�FWf�6R�B�f�'7BF�Bv�&�2��6��7B'V�6W76����7��2�F�B�����6��7B&w2��'G&6��C�"��V�&W"�G&6��B��&FWf�6T�C�"��V�&W"�F�B�Ӱ��b�W6W$�B��V�&w2�W6��'W6W$�C�"��V�&W"�W6W$�B�����b�&�f��T�B��V�&w2�W6��'&�f��T�C�"��V�&W"�&�f��T�B����&w2�W6��w&���G���FS�$e$TR"r�w�Ff�&Ӣ%tT""r�wfW'6���#��"r���6��7B�&�WFF����7F'E7G&V֖�u6W76���"�&w2����"�"��"��6W76���B���vVB&V6��&���G���FR��#��6��7B"�v�B���tWF�VB�V�b�F��V�����&WGW&��VW'���&W7V�C��"�FFbb"�FF�7F'E7G&V֖�u6W76������V���W'&�'3��"�W'&�'2���Ғ����R���R��W76vR��6Ɩ6R��2�Ӱ�Ӱ�6��7B�G2�FWf�6TƗ7B����B���B�B��f��FW"���������V��6Ɩ6R��2����b��G2��V�wF���G2�W6������f��&6�F�F�R��BwVW72�W7BF�&V6�&BF�RW'&� ��WB�6W76���GFV�G2��Ӱ��WBv��B��V�ð�f�"�6��7BF�B�b�G2���6��7B�v�B'V�6W76���F�B����WB�6W76���GFV�G2�W6���FWf�6T�C�F�B�&W7V�C��&W7V�B�W'&�'3��W'&�'2ғ���b��&W7V�Bbb�&W7V�B����vVB��v��B��FWf�6T�C�F�B�&W7V�C��&W7V�BӲ'&V��ТТ������f�"&W6��fW"F�BGW&�2G&6��6W76�����F�7G&V�U$���BF�P����V'F&VB�V�B�WFF���2(	BF�RVF��6W'fW"���VVBF�R6W76����V'F&V@���&Vf�&R�B6W'fW24ĔT�B�&���G�G&6���WB�7G&V�VW&�W2�v�B��G&�7V7E&��D��W2�V�b�'VW'�"��7G&V��VF���W&����&6���VF��Ɨ7FV�Ɔ�7���fW7B������WB�7G&V��WFF���2�v�B��G&�7V7E&��D��W2�V�b�&�WFF���"��7G&V��VF���W&����&6���VF��Ɨ7FV�ƆV'F&VG�&���G�������WB�V'F&VD&w2�v�B��G&�7V7D�WFF���V�b�'WFFU6W76���V'F&VB"�������b6W76����V�VB�G'�����V'F&VBF�V�&R�&WVW7B��"�fWrVF����f�&�2��WB6���F�f��B&FRƖ֗G2��b�v��B����WB��V�VEv�F��v��B�FWf�6T�C��WB�6W76����v��B�&W7V�C��6��7B&6R�V�b�TD�����$4R�&u6�B�v��B�&W7V�B�6W76���B��"#��6��7B6�B�V�6�FUU$�6����V�B�&u6�B���6��7BF��V�6�FUU$�6����V�B�F��V⓰�6��7BB�&6R�#�G&6��C�"�G&6��B�"gF��V��"�F���6��7BF�B�v��B�FWf�6T�C����6V�B�V'F&VBf�"F�R6W76����&W7B�wVW72&w2g&����G&�7V7F����G'���6��7B�$&w2����WB�V'F&VD&w2���Ғ�&w2���Ғ�������7G&��r���7ƗB�#�"����G&�҂����6��7B'G2��Ӱ��b��$&w2��6�VFW2�'6W76���B"��'G2�W6��w6W76���C�"r�&u6�B�r"r����b��$&w2��6�VFW2�&FWf�6T�B"��'G2�W6��&FWf�6T�C�"��V�&W"�F�B�����b��$&w2��6�VFW2�'W6W$�B"�bbW6W$�B��V�'G2�W6��'W6W$�C�"��V�&W"�W6W$�B�����b��$&w2��6�VFW2�'G&6��B"��'G2�W6��'G&6��C�"��V�&W"�G&6��B�����b��$&w2��6�VFW2�'&�f��T�B"�bb&�f��T�B��V�'G2�W6��'&�f��T�C�"��V�&W"�&�f��T�B����6��7B�%6V�����WB�V'F&VD&w2���Ғ�&WGW&�2��""���FW��b�$�$�T5B"�����"���G�V��R�"�"#��6��7B��&�WFF����WFFU6W76���V'F&VB�"�'G2����"�"��"�"��%6V��"�#���WB�V'F&VD6������6��7B�"�v�B���tWF�VB�V�b�F��V�������WB�V'F&VE&W7V�B��"�FF���V�ð��WB�V'F&VDW'&�'2���"�W'&�'2���Ғ����R���R��W76vR��6Ɩ6R��"����6F6��R���WB�V'F&VDW'&�"�7G&��r��RbbR��W76vR���R��Т6��7B&�&W2���gFW$�%�����W&âB���gFW$�%�6W76���C��W&âB�"g6W76���C�"�6�B���gFW$�%�FWf�6U�6W76����W&âB�"fFWf�6T�C�"�F�B�"g6W76���C�"�6�B���Ӱ��WB�VF��gFW%6W76�����Ӱ�f�"�6��7B���&�&W2���G'��6��7B'"�v�BfWF6�B�&�&W5����W&����VFW'3��&�V7B�76�v⇲&�vS�&'�FW3��"��&�&W5����VFW'2���Ғ�����WB�VF��gFW%6W76��嶵��'"�7FGW3�Т6F6��R���WB�VF��gFW%6W76��嶵��&W'"#�ТТТ&WGW&��WC���6F6��R���WB�W'&�"�7G&��r��RbbR��W76vR���R��&WGW&��WC�ЧР�7��2gV�7F������t��v��V�b���6��7B7"�v�B�W6�47&VG2�V�b����b��V�b���U$�bb7"�V���bb7"�77v�&B��&WGW&�����f�6R�W'&�#�$���W6�2�6W'fW"V����77v�&B6WB�"Ӱ�6��7BVW'�Т&�WFF���FS�7G&��r�G�7G&��r��WF�V�F�6FUW6W%v�F�77v�&B�V��âFR�77v�&C�G����G�V��R�����W6W$WF�V�F�6F���v�F�77v�&E7V66W72�6W76���F��V�������W6W$WF�V�F�6F���v�F�77v�&Df��W&R��W76vR���#��G'���6��7B"�v�BfWF6�B�V�b���U$�����WF��C�%�5B"���VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"���&�G���4���7G&��v�g���VW'��f&�&�W3��S�7"�V�����7"�77v�&B�Ғ����S����b�"����&WGW&�����f�6R�W'&�#�$��v��V�G���B&WGW&�VB"�"�7FGW2�"�"Ӱ�6��7BB�v�B"�6�ₒ�6F6��������Ғ����b�BbbB�W'&�'2bbB�W'&�'2��V�wF����&WGW&�����f�6R�W'&�#��B�W'&�'5��bbB�W'&�'5����W76vR���$w&��W'&�"�"Ӱ�Т6��7B&W2��BbbB�FFbbB�FF�WF�V�F�6FUW6W%v�F�77v�&B����Ӱ��b�&W2�6W76���F��V���44�TE�D��T��&W2�6W76���F��V㰢44�TE�U�����V���v�W��'��F�RC2�&WG'�6�fW'27F�V�W70�&WGW&�����G'VR�F��V�&W2�6W76���F��V�Ӱ�Т&WGW&�����f�6R�W'&�#�&W2��W76vR��$��v��f��VB���6W76���F��V�&WGW&�VB��"Ӱ��6F6��R���&WGW&�����f�6R�W'&�#�7G&��r��RbbR��W76vR���R�Ӱ�ЧР���6�F�Rw&��66�V�v��6���v���&V�FVB�WFF���2W��7B�F�f��BF�P���&�v�B��Rv�V��W"wVW72f��2��&WGW&�2Ɨ7BƖ�R�&��R�&r�&r�%��7��2gV�7F�����G&�7V7DWF��WFF���2�V�b���6��7BТ'VW'����66�V���WFF���G�R�f�V�G2���R&w2���R�����#��G'���6��7B"�v�BfWF6��V�b���U$�����WF��C�%�5B"���VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"���&�G���4���7G&��v�g���VW'��Ғ��ғ���b�"����&WGW&��W'&�#�&��G&�7V7F���&WGW&�VB"�"�7FGW2Ӱ�6��7BB�v�B"�6�ₒ�6F6��������Ғ����b�BbbB�W'&�'2bbB�W'&�'2��V�wF��&WGW&��W'&�#�&��G&�7V7F���&��6�VB"Ӱ�6��7Bf�V�G2Т���B�FF���Ғ���66�V����Ғ��WFF���G�R���Ғ�f�V�G2���Ӱ�6��7B&R��WF����v���6W76����F��V��6�v��77v�&B����6��7B6�B�f�V�G0��f��FW"��b���&R�FW7B�b���R�������b���b���R�"�"��b�&w2���Ғ����������R�����"�"��"�"���&WGW&��F�Fâf�V�G2��V�wF��6�F�FFW3�6�BӰ��6F6��R���&WGW&��W'&�#�7G&��r��RbbR��W76vR���R�Ӱ�ЧР���Ɨ7BF�RF���WfV�VW'�f�V�G2�BF�R6��FV�BG�W2rf�V�G2�F�RgV�����'7G'V7GW&R"�bF�R���6�F�RT�6�6��r&V���W2�GW&F���2�WF2�7��2gV�7F�����F�U66�V��V�b����b�V�b���U$&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�"��C���6��7BТ'VW'����66�V��"��'VW'�G�R�f�V�G2���R&w2���R�G�R���R���B�eG�R���R���B�eG�R���R���B�eG�R���R������"��'G�W2���R���Bf�V�G2���RG�R���R���B�eG�R���R���B�eG�R���R���B�eG�R���R������"��'��#��G'���6��7B"�v�BfWF6��V�b���U$�����WF��C�%�5B"���VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"���&�G���4���7G&��v�g���VW'��Ғ��ғ��6��7BB�v�B"�6�ₒ�6F6��������Ғ����b�BbbB�W'&�'2bbB�W'&�'2��V�wF����&WGW&��6�⇲W'&�#��B�W'&�'5��bbB�W'&�'5����W76vR���&��G&�7V7F���&��6�VB"��S"���Т6��7B66�V���B�FF���Ғ���66�V����Ӱ�6��7BF���B�����v���R�BbbB���RbbB��eG�R�B�B��eG�S��&WGW&�B�B���R��V�ð�Ӱ�6��7BVW'�f�V�G2���66�V��VW'�G�R���Ғ�f�V�G2���Ғ����b��������S�b���R��&w3��b�&w2���Ғ����������R���&WGW&�3�F�b�G�R���Ғ�����6��FV�BG�W2v�'F�6��v��r�&V�G&6���'V��'F�7Bf�V�G2�WF2��6��7Bv�FVB��G&6���'V��'F�7G�6��w�vV�&W���Ɨ7G��F67G�W�6�FW�&�f��R����6��7BG�W2��Ӱ��66�V��G�W2���Ғ�f�$V6���B������b�B涖�B��$�$�T5B"��B���R��B���R��FW��b�%��"�����&WGW&㰢�b�v�FVB�FW7B�B���R��&WGW&㰢6��7Bg2��B�f�V�G2���Ғ����b���b���R�#�"��F�b�G�R���#�"�����b�g2��V�wF��G�W5�B���U��g3��ғ��&WGW&��6�⇲VW'�f�V�G2�G�W2ғ���6F6��R���&WGW&��6�⇲W'&�#�7G&��r��RbbR��W76vR���R���S"���ЧР���gV��7G'V7GW&RW��'C�F�R4���UDR�66�V��WfW'�VW'��WfW'�G�P���v�F��G2f�V�G2�BG�W2���WBf��FW'2��BV�V�2�2��R&VF&�RFW�@���&��"��WG2F�Rv���R���r7�7FV��7G'V7GW&R&R6GW&VB�B&V'V��B�6��7BE�U�$TbТ&���B��R�eG�R����B��R�eG�R����B��R�eG�R����B��R�eG�R����B��R�eG�R����B��R�eG�R����B��R������#���gV�7F���&V�FW$w�G�R�B����b�B�&WGW&�#�#���b�B涖�B���$�����T��"�&WGW&�&V�FW$w�G�R�B��eG�R��"#���b�B涖�B���$ĕ5B"�&WGW&�%�"�&V�FW$w�G�R�B��eG�R��%�#��&WGW&�B���R��#�#��Р�7��2gV�7F�����F�TgV��66�V��V�b����b�V�b���U$&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�"��C���6��7BТ'VW'����66�V��VW'�G�R���R��WFF���G�R���R�G�W2�"��&���B��R"��&f�V�G2���6�VFTFW&V6FVC�G'VR����R&w2���RG�R�"�E�U�$Tb�"��G�R�"�E�U�$Tb�"��"��&��WDf�V�G2���RG�R�"�E�U�$Tb�"��"��&V�V�f�VW2���6�VFTFW&V6FVC�G'VR����R�"��'���#��G'���6��7B"�v�BfWF6��V�b���U$�����WF��C�%�5B"���VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"���&�G���4���7G&��v�g���VW'��Ғ��ғ��6��7BB�v�B"�6�ₒ�6F6��������Ғ����b�BbbB�W'&�'2bbB�W'&�'2��V�wF����&WGW&��6�⇲W'&�#��B�W'&�'5��bbB�W'&�'5����W76vR���&��G&�7V7F���&��6�VB"��S"���Т6��7B66�V���B�FF���Ғ���66�V����Ӱ�6��7BG�W2�66�V��G�W2���Ӱ�6��7B'���R��Ӱ�G�W2�f�$V6���B�����b�BbbB���R�'���U�B���U��C�ғ��6��7B�4��FW&�������������FW��b�%��"������6��7B66�%6����7G&��s����C��f��C��&���V���C��FFUF��S���4����6���FV6��â�&�t��C��W��C�Ӱ��6��7BƖ�W2��Ӱ�Ɩ�W2�W6��%���r�(	BeT��5E%T5EU$R"���Ɩ�W2�W6��$vV�W&FVB'�F�Rf�"&V'V��F��rF�Rv���R7�7FV��"���Ɩ�W2�W6��""����6��7B&��D��R��66�V��VW'�G�R���Ғ���R��%VW'�#��6��7B&��B�'���U�&��D��UӰ�6��7BVW'�f�V�G2��&��Bbb&��B�f�V�G2����Ӱ�Ɩ�W2�W6��#��������������������D���UdT�TU$�U2�"�VW'�f�V�G2��V�wF��"���������������������"���VW'�f�V�G2�f�$V6���b�����6��7B&w2��b�&w2���Ғ����������R�#�"�&V�FW$w�G�R��G�R������"�"���Ɩ�W2�W6��"�"�b���R��&w2�"�"�&w2�"�"�""��"��"�&V�FW$w�G�R�b�G�R����ғ��Ɩ�W2�W6��""����6��7B�&�G�W2�G�W2�f��FW"��B���B涖�B���$�$�T5B"bb�4��FW&�B���R�bbB���R��&��D��RbbB���R����66�V���WFF���G�R���Ғ���R����Ɩ�W2�W6��#��������������������E�U2�"��&�G�W2��V�wF��"���������������������"����&�G�W2�f�$V6���B�����Ɩ�W2�W6��B���R�"�"����B�f�V�G2���Ғ�f�$V6���b�����6��7B&w2��b�&w2���Ғ�f��FW"��������R�����������R�#�"�&V�FW$w�G�R��G�R������"�"���Ɩ�W2�W6��""�b���R��&w2�"�"�&w2�"�"�""��#�"�&V�FW$w�G�R�b�G�R����ғ��Ɩ�W2�W6��'�"���ғ��Ɩ�W2�W6��""����6��7B��WEG�W2�G�W2�f��FW"��B���B涖�B���$��UE��$�T5B"bb�4��FW&�B���R����Ɩ�W2�W6��#����������������������UB�d��DU"E�U2�"���WEG�W2��V�wF��"���������������������"�����WEG�W2�f�$V6���B�����6��7Bg2��B��WDf�V�G2���Ғ����b���b���R�#�"�&V�FW$w�G�R�b�G�R������"�"���Ɩ�W2�W6��B���R�"�"�g2�"�"���ғ��Ɩ�W2�W6��""����6��7BV�V�2�G�W2�f��FW"��B���B涖�B���$T�T�"bb�4��FW&�B���R�bb66�%6���B���Uғ��Ɩ�W2�W6��#��������������������T�T�2�"�V�V�2��V�wF��"���������������������"���V�V�2�f�$V6���B�����Ɩ�W2�W6��B���R�"�"��B�V�V�f�VW2���Ғ����b���b���R�����"�"����ғ��Ɩ�W2�W6��""����6��7B�WD��R��66�V���WFF���G�R���Ғ���S���b��WD��Rbb'���U��WD��UҒ��6��7B�g2�'���U��WD��U��f�V�G2���Ӱ�Ɩ�W2�W6��#���������������������UDD���2�"��g2��V�wF��"���������������������"����g2�f�$V6���b�����6��7B&w2��b�&w2���Ғ����������R�#�"�&V�FW$w�G�R��G�R������"�"���Ɩ�W2�W6��"�"�b���R��&w2�"�"�&w2�"�"�""��"��"�&V�FW$w�G�R�b�G�R����ғ��Ɩ�W2�W6��""���Р�6��7BFW�B�Ɩ�W2����%��"���&WGW&��6�⇰�FW�B��6�V�G3���VW&�W3�VW'�f�V�G2��V�wF���G�W3��&�G�W2��V�wF�����WG3���WEG�W2��V�wF���V�V�3�V�V�2��V�wF����WFF���3��WD��Rbb'���U��WD��U���'���U��WD��U��f�V�G2���Ғ��V�wF�������ғ���6F6��R���&WGW&��6�⇲W'&�#�7G&��r��RbbR��W76vR���R���S"���ЧР���WF�V�F�6FVBw&��77F�&�Vv��6�R2���VW'�'WBGF6�W2F�P���W6W"w2��v��F��V��6�W"�66�V�B�W&F���2�ff�&�FW2�ג��Ɨ7G2������7F�'��v�&��&WG&�W2��6Rv�F�g&W6�F��V����WF�W'&�"������w&��&WVW7BwV&B��������������������������������������������������Т��F�R���VW'��B���WF�VW'�V�G���G2&���w&��F����r�WF�VW'����'V�2v�F�F�R6�&VB66�V�BF��V��6���vvVB֖�W6W"�W7B��B&R&�RF���'V�&&�G&'��W7V6��ǒFW7G'V7F�fR��WFF���2F�&�Vv��B�vR'6RF�P����W&F����B�f�"�WFF���2�&WV�&RWfW'�&��Bf�V�BF�&R���r�Ɨ7FVB�gV�7F���w�7G&�����&WGW&�7G&��r���""���&W�6R��""%��5�5ң�"""�r�""���&��6�7G&��w0��&W�6R��"�����ŵ�%��Ғ�"�r�""�����&��7G&��w0��&W�6R��5����Ң�r�""����6���V�G0�ЦgV�7F���wė4�WFF�����&WGW&����2��WFF����"���FW7B�w�7G&����&W�6R����TdTdb��""���ЦgV�7F���w�&��Df�V�G2����6��7B2�w�7G&�������f��BF�R6V�V7F���6WC�f�'7Bw�rB&V��FWF� ��WB��7F'B����f�"��WB�����2��V�wF�������6��7B2�5��Ӳ�b�2���"�"����V�6R�b�2���"�"��ӲV�6R�b�2���'�"bb�����7F'B���'&V���Т�b�7F'B��&WGW&��Ӱ�6��7B&��G2��Ӳ�WB"�����f�"��WB��7F'C���2��V�wF��������6��7B2�5��Ӱ��b�2���"�"�����6��F��VS�Т�b�2���"�"���Ӳ6��F��VS�Т�b�2���'�"��"���6��F��VS�Т�b�2���'�"��"�Ӳ�b�"����'&V��6��F��VS�Т�b�"���bb���bb��զץ����FW7B�2����6��7B��2�6Ɩ6R�����F6���ⅴզץ�մզףӕ�Ң��2������Ғ򓰢�b�Ғ��b�ճ%���#�"�&��G2�W6��ճғ����ճ���V�wF���ТТТ&WGW&�&��G3��Ц6��7BUD�TU%�����tTE��UDD���2���6fTה'F�7EF�&�f��S��7&VFT��Tה'F�7C���6fTה�'V�F�&�f��S��7&VFT��Tה�'VӢ��FV�WFTה'F�7C��FV�WFTה�'VӢ��FV�WFT��Tה'F�7C��FV�WFT��Tה�'VӢ��Ӱ�gV�7F���wV&Dw&�����vVD�WFF���2����b�wė4�WFF�����&WGW&�����G'VRӲ��&VG2&R���vV@��b����vVD�WFF���2�&WGW&�����f�6RӲ���WFF���2��B���vVB�W&RB���6��7B&��G2�w�&��Df�V�G2�����b�&��G2��V�wF��&WGW&�����f�6RӰ�f�"�6��7Bb�b&��G2���b����vVD�WFF���5�eҒ&WGW&�����f�6R�f�V�C�bӲТ&WGW&�����G'VRӰ�Р�7��2gV�7F�����F�TWF�VW'��&WVW7B�V�b����b�V�b���U$&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�"��C���6��7B&�G��v�B&WVW7B�6�ₒ�6F6��������Ғ����b�&�G��VW'��&WGW&��6�⇲W'&�#�$֗76��rVW'��"��C���6��7BwV&B�wV&Dw&�&�G��VW'��UD�TU%�����tTE��UDD���2����b�wV&B����&WGW&��6�⇲W'&�#�%F��27F����6�(	�B���vVB�"��C2���6��7B���B��4���7G&��v�g���VW'��&�G��VW'��f&�&�W3�&�G��f&�&�W2����ғ��6��7B6���7��2�F�����fWF6��V�b���U$�����WF��C�%�5B"���VFW'3���$6��FV�B�G�R#�&Ɩ6F�����6��"��WF��&��F���$&V&W""��F����""������&�G�����B��ғ��G'����WB"�v�B6�v�B7W'&V�EF��V�V�b�f�6R�����WBB�v�B"�6�ₒ�6F6��������Ғ���6��7B����4WF�Т"�7FGW2���C����BbbB�W'&�'2bb�WF��f�&&�FFV��FV�VG�F��V��V�WF��'���v���W&֗76������FW7B��4���7G&��v�g��B�W'&�'2������b�����4WF�bb�6�f�&V&6R�V�b���6�WF���v��V�b�����"�v�B6�v�B7W'&V�EF��V�V�b�G'VR����B�v�B"�6�ₒ�6F6��������Ғ���Т&WGW&��6��B����6F6��R���&WGW&��6�⇲W'&�#�7G&��r��RbbR��W76vR���R���S"���ЧР���'V��&&�G&'�&VBVW'�v��7BF�R��&V���BF�R6�FR77v�&B�����WG2F�RT�fWF6�vV�&W2���Ɨ7G2��F67G2�WF2�v�F��WB�WrV�G���G2�7��2gV�7F�����F�U&uVW'��&WVW7B�V�b����b�V�b���U$&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�"��C���6��7B&�G��v�B&WVW7B�6�ₒ�6F6��������Ғ����b�&�G��VW'��&WGW&��6�⇲W'&�#�$֗76��rVW'��"��C�����&VB���Ǔ����WFF���2F�&�Vv�F�RV�WF�V�F�6FVB&�����b�wV&Dw&�&�G��VW'���V�����&WGW&��6�⇲W'&�#�$��ǒ&VBVW&�W2&R���vVB�W&R�"��C2���G'���6��7B"�v�BfWF6��V�b���U$�����WF��C�%�5B"���VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"���&�G���4���7G&��v�g���VW'��&�G��VW'��f&�&�W3�&�G��f&�&�W2����Ғ��ғ��6��7BB�v�B"�6�ₒ�6F6��������Ғ���&WGW&��6��B����6F6��R���&WGW&��6�⇲W'&�#�7G&��r��RbbR��W76vR���R���S"���ЧР�7��2gV�7F���7W'&V�EF��V�V�b�f�&6T��v����6��7B��r��F��f���"�FFR���r�������b�f�&6T��v��bb44�TE�D��T�bb�44�TE�U��������r�44�TE�U��c����&WGW&�44�TE�D��T㰢Т��F��V�66�VB��C�6�&VB7&�72���6��FW2�(	B&WW6R�BV�F���Bw0���&�WBF�W��&R�6�vRF��wB6�v�����WfW'�&WVW7B�f�&V&6R&FR�Ɩ֗G0���F�B�v��6�6W6VB��FW&֗GFV�BC72��6��7B3�v�BvWD�W6�47&VG2�V�b����b�f�&6T��v��bb3�EF��V�bb3�F��V�fW"���D��T��dU"bb3�DW�bb��r�3�DW��#���44�TE�D��T��3�EF��V�44�TE�U��3�DW���&WGW&�3�EF��V㰢Т��&VfW'&VC�f�&V&6R&Vg&W6�F��V�g&��6V7&WG2�v�&�2f�&WfW"���b�6�f�&V&6R�V�b����6��7B&W2�v�Bf�&V&6U&Vg&W6��V�b����b�&W2����&WGW&�&W2�F��V㰢Т6��7B7"�v�B�W6�47&VG2�V�b��������rW6W2f�&V&6S�gV��V����77v�&B6�v�֖�v�fW2F��V�F�RVF����6W'fW"66WG2��vRFVƖ&W&FVǒF���BW6RF�R6V7W&WF��V�&Vg&W6�f��r(	@����G2F��V�2&R&V�V7FVB'����rw2VF��6W'fW"�F�R6�v�֖�F��V��266�V@�����C&�fR�6�F��2'V�2B��7B���6R���W"���B��WfW'�&WVW7B␢�b�7"�V���bb7"�77v�&B���6��7B&W2�v�Bf�&V&6U6�v��V�b�7"�V����7"�77v�&B����b�&W2����&WGW&�&W2�F��V㰢Т���7B&W6�'C��W�7F��R�7G��Rw&����v�����7B���r�Ɩ�R�2F��wB�fR��R���b�V�b���U$�bb7"�V���bb7"�77v�&B���6��7B&W2�v�B���t��v��V�b����b�&W2����&WGW&�&W2�F��V㰢Т�b�f�&6T��v��bb44�TE�D��T�&WGW&�44�TE�D��T㰢&WGW&�7"�F��V���"#��Р���fWF6�g&��F�RVF��6W'fW"�&WG'���r��6Rv�F�g&W6�F��V���C2���fWF6�v�F��&BF��V�WB�6�6��r�V�&V6�&�RW7G&V��WfW"��w2F�P���v�&�W"�v��6�v�V�B��RF�RF֖�%FW7B"V"F�F���F���r��7��2gV�7F���fWF6�B�W&���G2��2���6��7B7F���Wr&�'D6��G&���W"����6��7B�B�6WEF��V�WB�����7F��&�'B����2��S���G'���&WGW&�v�BfWF6��W&���&�V7B�76�v⇷���G2������6�v�â7F��6�v��Ғ����f���ǒ�6�V%F��V�WB��B��ЧР�7��2gV�7F���fWF6�VF��V�b�G&6��B�W�G&�VFW'2�f��R����WBF��V��v�B7W'&V�EF��V�V�b�f�6R���6��7B&6R�V�b�TD�����$4S��6��7BF�������V�6�FUU$�6����V�B�F��V���""���6��7B'��B�����&6R�#�G&6��C�"�V�6�FUU$�6����V�B�G&6��B��"gF��V��"�F������6��7B'��Df��R�����&6R�#�G&6��C�"�V�6�FUU$�6����V�B�G&6��B��"ff��S�"�V�6�FUU$�6����V�B�f��R��""��"gF��V��"�F������6��7B'�f��R�����&6R�#�f��S�"�V�6�FUU$�6����V�B�f��R��""��"gF��V��"�F������6��7B�G'2���VFW'3�W�G&�VFW'2����Ӱ��WB"�v�BfWF6�B�'��B����G'2�S�������C2�G'���6R��&Rv�F�g&W6�ǒfWF6�VBF��V��6�fW'2�W��&V@���F��V�v�WF�W"F�R��v��6��W2g&��6V7&WG2�"F�RF֖��V��b�"�7FGW2���C2���F��V��v�B7W'&V�EF��V�V�b�G'VR����b�F��V�"�v�BfWF6�B�'��B����G'2�S���Т��7F���&VgW6VC�F�RF��V����VVBF�G&fV�2�WF��&��F���&V&W ����VFW"���rf�&V&6R�&6VB�2W7V�ǒW�V7B�B�&F�W"F��VW'�&���b�"���bb"�7FGW2��#bbbF��V���6��7B&���&�V7B�76�v⇷��W�G&�VFW'2������WF��&��F���$&V&W""�F��V�ғ��6��7B��F���&6R�#�G&6��C�"�V�6�FUU$�6����V�B�G&6��B���f�"�6��7BR�b���F���'��B��Ғ��G'��6��7B&"�v�BfWF6�B�R���VFW'3�&���S���b�&"�����&"�7FGW2���#b�&WGW&�&#��6F6��R��ТТТ��6��RG&6�2���F&ǒ6��v�W2�6�wB&R&W6��fVB'�G&6��B���R(	B&WG'����v�F�F�Rf��RF���B�f��R�F�V�f��R���ǒ����ǒ'V�2v�V�F�R�B���ǐ���&WVW7Bf��VB�6�G&6�2F�B�&VG�v�&�&RV�F�V6�VB��b�"���bb"�7FGW2��#bbbf��R���f�"�6��7B��R�b�'��Df��R�'�f��UҒ��G'���6��7B#"�v�BfWF6�B���R����G'2�S����b�#"�����#"�7FGW2���#b�&WGW&�##���6F6��R���G'�F�R�W�Bf�&��V�6R�VWF�R�&�v���&W7��6R��ТТТ&WGW&�#��Р����������������������������������������������������������������������������������w&���V�W'0��������������������������������������������������������������������������������7��2gV�7F���w&�V�b�VW'�����b�V�b���U$&WGW&��V�ð�6��7B&W2�v�BfWF6��V�b���U$�����WF��C�%�5B"���VFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��"���&�G���4���7G&��v�g���VW'�Ғ��ғ���b�&W2����&WGW&��V�ð�&WGW&�v�B&W2�6�ₓ��Р�7��2gV�7F���fWF6�'F�7G2�V�b���6��7B����Ӱ��WB6�����6��7B&F6�6��R�S��v���R�G'VR���6��7BVW'�Т'VW'��'F�7G2�6���"�6���"�F�S�"�&F6�6��R�"���BV���R�T��R��vR��#��6��7BFF�v�Bw&�V�b�VW'�����b�FF��FF�W'&�'2�'&V���6��7B&F6����FF�FF���Ғ�'F�7G2����Ӱ��b�&F6���V�wF��'&V������W6�����&F6�����b�&F6���V�wF��&F6�6��R�'&V���6����&F6�6��S��Т&WGW&��ð�Р�7��2gV�7F�����F�T'F�7G2�V�b����b�V�b���U$��&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�6WBF�R��U$�6V7&WB�"��C���Т6��7B'F�7G2�v�BfWF6�'F�7G2�V�b����b�'F�7G2��V�wF����&WGW&��6�⇲W'&�#�$��'F�7G2f�V�B�6�V6�F�R��U$�6V7&WB�"��S"���Т&WGW&��6�⇲'F�7G2ғ��Р�7��2gV�7F�����F�T'F�7B�&WVW7B�V�b����b�V�b���U$&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�"��C���6��7B&�G��v�B&WVW7B�6�ₒ�6F6��������Ғ���6��7B�B�&�G��C���b��B���V�FVf��VB���B����V���&WGW&��6�⇲W'&�#�$֗76��r'F�7B�B�"��C���Т6��7BVW'�Т'VW'��'F�7B�v�W&S���C�"��V�&W"��B��"Ғ��BV���R�T��R��vR&���TFW62V�FW62"��&�'V�2��BV���R�T��R��vW2�6F�6���6F��VF�V��VF�V�6����G&6�2��B����#��6��7BFF�v�Bw&�V�b�VW'����6��7B'F�7B�FFbbFF�FF�FF�FF�'F�7B��V�ð��b�'F�7B�&WGW&��6�⇲W'&�#�$��FWF��2f�V�Bf�"F��2'F�7B�"��S"���&WGW&��6�⇲'F�7Bғ��Р�7��2gV�7F�����F�T�Wr�V�b����b�V�b���U$&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�"��C���6��7B&6RТ&�BV���R�T��R&V�V6VDB��vW2�6F�6���6F��VF�V��VF�V�6����'F�7G2�V���R�T��R��vR�G&6�2��B�#��6��7Bf�V�G42�&6R�"7&VFVDB#����$�Wr�W6�2"���7B&V6V�FǒDDTBF�F�R6F��r���R�7&VFVDBFW62�vP���fWF6�7&VFVDB�B�&FW"'��B�F�RG'VR6�v��&F�W"F��77V֖�rF�P����'V��B��7&V6W2v�F�WfW'�FF�F���(	B�b�G2&V�wB����F��2�����B�6�'B'W&�W2vV�V��Vǒ�Wr&V�V6W2&V���B7F�R��v�֖B�'V�2�vRf��@���&V�V6VDB��B7W&f6W2gWGW&R�FFVB�FV�2�BF�ǒ�F67G2��V6�GFV�@���f��2&6�F�F�R�W�B�bF�R�&V�V7G2f�V�B��&FW$'��6��7BGFV�G2�����'VW'���'V�2�F�S�C��&FW$'����7&VFVDC�FW62�Ғ�"�f�V�G42�"��"�'��&7&VFVDB"�����'VW'���'V�2�F�S�C��&FW$'�����C�FW62�Ғ�"�&6R�"��"�'��&�B"�����'VW'���'V�2�F�S�S��"�&6R�"��"�'��&�B"���Ӱ��WB�'V�2��Ӱ�f�"��WB�����GFV�G2��V�wF��������6��7BFF�v�Bw&�V�b�GFV�G5��������b�FFbbFF�W'&�'2bb��FF�FF���Ғ��'V�2���Ғ��V�wF�����'V�2�FF�FF��'V�3��'&V���ТТ���WvW7B�FFVBf�'7C�'�7&VFVDBv�V�vR�fR�B�V�6R'��B��'V�2�6�'D�WvW7B��'V�2���&WGW&��6�⇲�'V�3��'V�2�6Ɩ6R��"�ғ��Р����v�W"���ǒF�v��7F�3�'V�6WfW&�&�WvW7B�'V�2"VW'�6�W2v��7BF�P�����B&W�'B�f�"V6��v�WF�W"�BW'&�&VB�BF�Rf�'7BfWr�'V�2�@���&WGW&�VB���R��B�&V�V6VDB�7&VFVDB��F��26��w2W�7Fǒv��6�VW'����7GV�ǒ&WGW&�2F�R�WvW7B�W6�2�6�F�R�Wr&V�V6W2��v�26�&RGV�VB�7��2gV�7F�����F�U&�&T�Wr�&WVW7B�V�b���6��7B&�G��v�B&WVW7B�6�ₒ�6F6��������Ғ����b��v�B�4F֖�&W�V�b�&WVW7B�&�G����&WGW&��6�⇲W'&�#�%w&��r77v�&B�"��C2����b�V�b���U$&WGW&��6�⇲W'&�#�%6W'fW"��B6��f�wW&VB�"��C���6��7Bb�&�BV���R�T��R&V�V6VDB#��6��7Bf&��G2�����&Vâ&�&FW$'�7&VFVDBFW62"��'VW'���'V�2�F�S�b��&FW$'����7&VFVDC�FW62�Ғ�"�b�"7&VFVDB��"�����&Vâ&�&FW$'�&V�V6VDBFW62"��'VW'���'V�2�F�S�b��&FW$'����&V�V6VDC�FW62�Ғ�"�b�"��"�����&Vâ&�&FW$'��BFW62"��'VW'���'V�2�F�S�b��&FW$'�����C�FW62�Ғ�"�b�"��"�����&Vâ&�&FW$'��7&VFVDC�FW67���&�V7B�"��'VW'���'V�2�F�S�b��&FW$'���7&VFVDC�FW62Ғ�"�b�"7&VFVDB��"�����&Vâ&���&FW$'��FVfV�B�"��'VW'���'V�2�F�S�b��"�b�"��"�����&Vâ&�FW7D�'V�2"��'VW'���FW7D�'V�2�F�S�b��"�b�"��"�����&Vâ&�Wu&V�V6W2"��'VW'���Wu&V�V6W2�F�S�b��"�b�"��"���Ӱ�6��7B�WB��Ӱ�f�"�6��7Bb�bf&��G2���G'���6��7BB�v�Bw&�V�b�b�����b�B���WB�W6����&Vâb��&V��W'&�#�&��&W7��6R"ғ�6��F��VS�Т�b�B�W'&�'2bbB�W'&�'2��V�wF����WB�W6����&Vâb��&V��W'&�#��B�W'&�'5��bbB�W'&�'5����W76vR���&W'&�""ғ�6��F��VS�Т6��7BFF�B�FF���Ӱ�6��7B�W���&�V7B�W�2�FF��Ӱ�6��7B&�w2��FF��W�����Ғ����������C��B���S��V���R���T��R��""�&V�V6VDC��&V�V6VDB���V���7&VFVDC��7&VFVDB���V��Ғ����WB�W6����&Vâb��&V��6�V�C�&�w2��V�wF��&�w2ғ���6F6��R����WB�W6����&Vâb��&V��W'&�#�7G&��r��RbbR��W76vR���R�ғ��ТТ&WGW&��6�⇲&�&S��WBғ��Р����v�W"���ǒF�v��7F�3�6��&R��rF�RVF��6W'fW"&W7��G2F�4��t�Rg2�����&F��'��'V�G&6��7&�72fWrU$�6�W2�6�vR6�6VRW�7Fǒv�@���6��v�W2�VVB�W6W2F�R7W'&V�B�v�&���r�F��V��7��2gV�7F�����F�U&�&TVF��&WVW7B�V�b���6��7B"�v�B&WVW7B�6�ₒ�6F6��������Ғ����b��v�B�4F֖�&W(env, request, b))) return json({ error: "Wrong password." }, 403);
  if (!env.API_URL || !env.AUDIO_API_BASE) return json({ error: "Server not configured." }, 400);
  let albums = [];
  try {
    const d = await graphql(env, "query { albums(take: 40, orderBy: [{ id: desc }]) { id enName heName tracks { id file } } }");
    albums = ((d && d.data && d.data.albums) || []);
  } catch (e) { return json({ error: "Could not read albums." }, 502); }
  const single = albums.find((a) => (a.tracks || []).length === 1);
  const multi = albums.find((a) => (a.tracks || []).length > 1);
  const token = await currentToken(env, false);
  const base = env.AUDIO_API_BASE;
  const enc = encodeURIComponent;
  const tryOne = async (label, u) => {
    try { const r = await fetchT(u, { headers: { Range: "bytes=0-0" } }, 12000); return { label, status: r.status, type: r.headers.get("Content-Type"), len: r.headers.get("Content-Length") }; }
    catch (e) { return { label, error: String((e && e.message) || e) }; }
  };
  const probeTrack = async (t) => {
    if (!t) return null;
    const id = enc(t.id), file = enc(t.file || ""), tk = enc(token || "");
    const res = [];
    res.push(await tryOne("id", base + "?trackId=" + id + "&token=" + tk));
    res.push(await tryOne("id+file", base + "?trackId=" + id + "&file=" + file + "&token=" + tk));
    res.push(await tryOne("file", base + "?file=" + file + "&token=" + tk));
    return { id: t.id, file: t.file, hasFile: !!t.file, results: res };
  };
  return json({
    single: single ? { album: single.enName || single.heName, tracks: (single.tracks || []).length, track: await probeTrack((single.tracks || [])[0]) } : null,
    album: multi ? { album: multi.enName || multi.heName, tracks: (multi.tracks || []).length, track: await probeTrack((multi.tracks || [])[0]) } : null,
  });
}

// Newest-added first. Prefer createdAt (the real "added to catalog" time) when
// the items carry it; otherwise fall back to id descending. We avoid releasedAt
// here — it surfaces future-dated items and daily podcasts.
function sortNewest(list) {
  const arr = (list || []).slice();
  const hasCreated = arr.some((a) => a && a.createdAt);
  const cv = (a) => { const t = Date.parse((a && a.createdAt) || ""); return isNaN(t) ? -1 : t; };
  if (hasCreated) {
    return arr.sort((a, b) => { const d = cv(b) - cv(a); return d !== 0 ? d : (Number((b && b.id) || 0) - Number((a && a.id) || 0)); });
  }
  return arr.sort((a, b) => Number((b && b.id) || 0) - Number((a && a.id) || 0));
}

// A page of ALL albums, newest first (old + new together), for the Albums
// browse view. Supports skip/take for "load more". Same ordering fallbacks.
async function handleAlbumsPage(request, env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const body = await request.json().catch(() => ({}));
  const take = Math.min(Math.max(parseInt(body.take, 10) || 30, 1), 60);
  const skip = Math.max(parseInt(body.skip, 10) || 0, 0);
  const base =
    "id enName heName releasedAt images { cdnSmall cdnMedium medium small } artists { enName heName image } tracks { id }";
  const fieldsC = base + " createdAt";
  const attempts = [
    "query { albums(take: " + take + ", skip: " + skip + ", orderBy: [{ createdAt: desc }]) { " + fieldsC + " } }",
    "query { albums(take: " + take + ", skip: " + skip + ", orderBy: [{ id: desc }]) { " + base + " } }",
    "query { albums(take: " + take + ", skip: " + skip + ") { " + base + " } }",
  ];
  for (let i = 0; i < attempts.length; i++) {
    const data = await graphql(env, attempts[i]);
    if (data && !data.errors) {
      const albums = sortNewest(((data.data || {}).albums) || []);
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

const PREMIUM_CACHE = new Map(); // trackId -> { premium, at } (per-isolate, 1h)
async function isPremiumTrack(env, trackId) {
  const c = PREMIUM_CACHE.get(trackId);
  if (c && Date.now() - c.at < 3600000) return c.premium;
  let premium = false;
  try {
    const d = await graphql(env, "query { track(where: { id: " + Number(trackId) + " }) { album { premium } } }");
    premium = !!(d && d.data && d.data.track && d.data.track.album && d.data.track.album.premium);
  } catch (e) { /* treat unknown as not premium */ }
  PREMIUM_CACHE.set(trackId, { premium, at: Date.now() });
  return premium;
}

async function handlePlay(url, request, env) {
  // Stream a track for in-browser playback (inline, with Range support for seeking).
  if (!env.AUDIO_API_BASE) {
    return json({ error: "Server not configured (AUDIO_API_BASE)." }, 400);
  }
  const trackId = (url.searchParams.get("trackId") || "").trim();
  if (!trackId) return json({ error: "Missing track id." }, 400);
  const filePath = (url.searchParams.get("file") || "").trim();

  const range = request.headers.get("Range");
  let upstream;
  try {
    upstream = await fetchAudio(env, trackId, range ? { Range: range } : {}, filePath);
  } catch (exc) {
    return json({ error: "Playback error: " + (exc && exc.message) }, 502);
  }
  if (upstream.status === 403) {
    // Locked on Zing's audio server. Premium albums get a clear reason so the
    // listener knows it is a subscription matter, not a broken player.
    const premium = await isPremiumTrack(env, trackId);
    return json({
      error: premium
        ? "This is a premium album — premium access isn’t active on our music account right now."
        : "This track isn’t available to stream.",
      locked: true, premium: premium, status: 403,
    }, 403);
  }
  if (!upstream.ok && upstream.status !== 206) {
    const msg = upstream.status === 429
      ? "The music server is busy right now — please wait a minute and try again."
      : ("Server returned code " + upstream.status + ".");
    return json({ error: msg, status: upstream.status }, 502);
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
    upstream = await fetchAudio(env, trackId, {}, filePath);
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
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      // Never let the phone or a CDN serve stale data — always fetch fresh, so
      // newly added music shows up immediately.
      "Cache-Control": "no-store, must-revalidate",
    },
  });
}

function maybeZip(request, body, headers) { headers["Vary"] = "Accept-Encoding"; return new Response(body, { headers: headers }); } function html(body, request) { return maybeZip(request, body, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store, must-revalidate" }); }

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
      if(pw.length < 8){ m.textContent = "Password must be at least 8 characters."; return; }
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
  <link rel="manifest" href="/manifest.webmanifest" />
  <link rel="icon" href="/icon.svg" type="image/svg+xml" />
  <link rel="apple-touch-icon" href="/icon.svg" />
  <meta name="theme-color" content="#0a0a12" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,400..700,0..1,0&display=block" rel="stylesheet" />
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
    button:focus,a:focus,[onclick]:focus,[tabindex]:focus{ outline:none; }
    button:focus-visible,a:focus-visible,[onclick]:focus-visible,[tabindex]:focus-visible{ outline:2px solid var(--accent); outline-offset:2px; }
    html,body{ height:100%; margin:0; }
    body{
      font-family:var(--font); color:var(--text);
      background:
        radial-gradient(1000px 520px at 12% -8%, rgba(124,92,255,.18), transparent 60%),
        radial-gradient(900px 460px at 100% 0%, rgba(255,77,141,.12), transparent 55%),
        var(--bg);
      min-height:100%;
    }
    /* Icons: inline SVG always works; once Google's Material Symbols font is
       confirmed loaded we upgrade to its modern glyphs (html.symbols). */
    .ms{ display:inline-grid; place-items:center; width:1em; height:1em; font-size:24px; line-height:1; flex:none; vertical-align:middle; overflow:hidden; }
    html.symbols .ms{ overflow:visible; }
    .ms > svg{ width:1em; height:1em; fill:currentColor; display:block; }
    html.symbols .ms{ font-family:'Material Symbols Rounded'; font-weight:normal; font-style:normal; letter-spacing:normal;
      text-transform:none; white-space:nowrap; direction:ltr; width:auto; height:auto; -webkit-font-smoothing:antialiased;
      font-variation-settings:'FILL' 0,'wght' 500,'GRAD' 0,'opsz' 24; }
    html.symbols .ms::before{ content:attr(data-ic); }
    html.symbols .ms > svg{ display:none; }
    html.symbols .ms.fill{ font-variation-settings:'FILL' 1,'wght' 500,'GRAD' 0,'opsz' 24; }

    /* Top bar */
    .top{ position:sticky; top:env(safe-area-inset-top,0px); z-index:30;
      display:flex; align-items:center; gap:12px; padding:13px 18px;
      background:var(--bar); -webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px); border-bottom:1px solid var(--line); }
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
    [hidden]{ display:none !important; }

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
    .hcard, .tile{ transition:transform .12s ease; }
    .hcard:active, .tile:active{ transform:scale(.96); }
    .hcard .cover, .tile .cover{ transition:transform .18s ease, box-shadow .18s ease; }
    .hcard:hover .cover, .tile:hover .cover{ transform:translateY(-2px); box-shadow:0 12px 26px rgba(0,0,0,.4); }
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
    .hero h2{ margin:5px 0 6px; font-size:1.6rem; font-weight:800; text-wrap:balance; }
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

    .empty{ color:var(--muted); padding:44px 22px; text-align:center; line-height:1.6; }
    .spinner{ display:inline-block; width:16px; height:16px; border:2px solid var(--muted); border-top-color:transparent; border-radius:50%; animation:spin .7s linear infinite; vertical-align:-3px; margin-right:8px; }
    @keyframes spin{ to{ transform:rotate(360deg); } }
    /* Loading skeletons (shimmer) */
    .skel{ position:relative; overflow:hidden; background:var(--surface-2); border-radius:12px; }
    .skel::after{ content:""; position:absolute; top:0;right:0;bottom:0;left:0; transform:translateX(-100%);
      background:linear-gradient(90deg,transparent,rgba(255,255,255,.07),transparent); animation:shim 1.35s infinite; }
    :root[data-theme="light"] .skel::after{ background:linear-gradient(90deg,transparent,rgba(0,0,0,.05),transparent); }
    @keyframes shim{ 100%{ transform:translateX(100%); } }
    .sk-card{ width:150px; flex:0 0 auto; }
    .sk-cover{ width:100%; aspect-ratio:1/1; border-radius:14px; }
    .sk-line{ height:11px; border-radius:6px; margin-top:9px; } .sk-line.sm{ width:58%; }
    /* Image fade-in over the gradient placeholder; broken images just fall back */
    .cvimg{ position:absolute; top:0;right:0;bottom:0;left:0; width:100%; height:100%; object-fit:cover; opacity:0; transition:opacity .4s ease; }
    .cvimg.on{ opacity:1; }

    /* Old Android WebView (<Chrome 88) has no aspect-ratio: keep square covers via the padding hack */
    @supports not (aspect-ratio: 1/1){
      .cover{ height:0; padding-top:100%; }
      .cover.round{ padding-top:86%; }
      .cover .ini{ position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); }
      .cover .disc{ position:absolute; top:35%; left:35%; }
      .sk-cover{ height:0; padding-top:100%; }
      .banner-card{ height:169px; }
      .hero .cover{ height:150px; padding-top:0; }
      .np-cover{ height:46px; padding-top:0; }
    }
    @supports (not (backdrop-filter:blur(1px))) and (not (-webkit-backdrop-filter:blur(1px))){
      .top{ background:#0a0a12; } .player{ background:#141422; } .tabs{ background:#0e0e18; } .ovl{ background:#0b0b14; }
      :root[data-theme="light"] .top,:root[data-theme="light"] .player,:root[data-theme="light"] .tabs,:root[data-theme="light"] .ovl{ background:#ffffff; }
    }
    #status{ min-height:18px; font-size:.9rem; margin:6px 18px; }
    .ok{ color:var(--ok); } .err{ color:var(--err); } .muted{ color:var(--muted); }

    /* Now-playing bar */
    .player{ position:fixed; left:0; right:0; bottom:calc(var(--tabs-h) + env(safe-area-inset-bottom,0px)); z-index:35;
      display:flex; align-items:center; gap:12px; padding:9px 14px;
      background:var(--bar-player); -webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px); border-top:1px solid var(--line); }
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

    /* Now-playing full sheet */
    .np-art{ width:74vw; max-width:300px; height:74vw; max-height:300px; border-radius:20px; margin:6px auto 18px; display:grid; place-items:center;
      background-size:cover; background-position:center; box-shadow:0 20px 50px rgba(0,0,0,.5); overflow:hidden; }
    .np-art .disc{ width:32%; height:32%; border-radius:999px; background:radial-gradient(circle at 50% 50%,#fff 0 13%,rgba(255,255,255,.22) 14% 33%,rgba(0,0,0,.14) 34% 100%); }
    .np-info{ text-align:center; margin-bottom:14px; }
    .np-tt{ font-weight:800; font-size:1.3rem; line-height:1.2; word-break:break-word; }
    .np-prog{ margin:6px 2px 8px; }
    .np-seek.big{ height:6px; border-radius:999px; }
    .np-seek.big::-webkit-slider-thumb{ width:15px; height:15px; }
    .np-times{ display:flex; justify-content:space-between; color:var(--muted); font-size:.74rem; margin-top:5px; }
    .np-controls{ display:flex; align-items:center; justify-content:center; gap:8px; margin:6px 0 14px; }
    .np-c{ width:52px; height:52px; border-radius:999px; border:none; background:transparent; color:var(--text); cursor:pointer; display:grid; place-items:center; }
    .np-c:hover{ background:var(--surface-2); } .np-c .ms{ font-size:30px; }
    .np-c.play{ width:66px; height:66px; background:var(--grad); color:#fff; box-shadow:0 10px 24px rgba(124,92,255,.45); }
    .np-c.play .ms{ font-size:34px; }
    .np-c.on{ color:var(--accent); }
    .np-controls2{ display:flex; align-items:center; justify-content:center; gap:10px; margin:-6px 0 10px; }
    .np-c2{ display:inline-flex; align-items:center; gap:3px; border:1px solid var(--line); background:var(--surface-2); color:var(--text);
      font-family:inherit; font-weight:700; font-size:.85rem; padding:7px 13px; border-radius:999px; cursor:pointer; min-width:54px; justify-content:center; transition:transform .12s ease, border-color .2s ease; }
    .np-c2:active{ transform:scale(.95); } .np-c2 .ms{ font-size:18px; }
    .np-vol{ display:flex; align-items:center; gap:10px; margin:0 2px 12px; color:var(--muted); }
    .np-vol .ms{ font-size:20px; flex:none; } .np-vol .np-seek{ flex:1; }
    .np-actions{ display:flex; justify-content:center; gap:10px; flex-wrap:wrap; margin-bottom:6px; }
    .np-seg{ display:flex; width:100%; background:var(--surface-2); border-radius:12px; padding:4px; }
    .np-seg button{ flex:1; border:none; background:transparent; color:var(--muted); font-family:inherit; font-weight:700; font-size:.86rem; padding:9px 6px; border-radius:9px; cursor:pointer; }
    .np-seg button.on{ background:var(--grad); color:#fff; }
    .np-mini{ width:44px; height:44px; border-radius:9px; flex:none; background-size:cover; background-position:center; box-shadow:inset 0 0 16px rgba(0,0,0,.25); }
    .np-eq{ color:var(--accent); display:grid; place-items:center; } .np-eq .ms{ font-size:22px; }

    /* Bottom tabs */
    .tabs{ position:fixed; left:0; right:0; bottom:0; z-index:36; height:calc(var(--tabs-h) + env(safe-area-inset-bottom,0px));
      padding-bottom:env(safe-area-inset-bottom,0px); display:flex; background:var(--bar-tabs); -webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px); border-top:1px solid var(--line); }
    .tab{ flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:2px; background:none; border:none; color:var(--muted); cursor:pointer; font-family:inherit; }
    .tab .ms{ font-size:25px; } .tab span.lbl{ font-size:.66rem; font-weight:600; }
    .tab.active{ color:var(--text); }
    .tab.active .ms{ background:var(--grad); -webkit-background-clip:text; background-clip:text; color:transparent; }

    /* Overlay (lyrics / settings) */
    .ovl{ position:fixed; top:0;right:0;bottom:0;left:0; z-index:60; background:var(--ovl-bg); -webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px); overflow:auto;
      padding:0 18px calc(28px + env(safe-area-inset-bottom,0px)); }
    .ovl .obar{ display:flex; align-items:center; justify-content:space-between; margin:0 -18px 16px; padding:18px 18px 12px; position:sticky; top:0; background:var(--ovl-bg); z-index:5; border-bottom:1px solid var(--line); }
    .ovl h2{ margin:0; font-size:1.2rem; }
    .ovl pre{ white-space:pre-wrap; font-family:inherit; font-size:1.02rem; line-height:1.8; margin:0; }
    .banner{ border-radius:14px; padding:13px 15px; margin:0 18px 8px; border:1px solid rgba(251,191,36,.35); background:rgba(251,191,36,.08); color:var(--warn); font-size:.9rem; }
    .banner code{ background:rgba(255,255,255,.1); padding:1px 6px; border-radius:6px; color:var(--text); }
    .toast{ position:fixed; left:50%; bottom:calc(var(--tabs-h) + var(--player-h) + 12px + env(safe-area-inset-bottom,0px)); transform:translateX(-50%) translateY(14px);
      background:var(--surface-3); color:var(--text); border:1px solid var(--line); padding:11px 16px; border-radius:12px;
      box-shadow:0 12px 30px rgba(0,0,0,.5); opacity:0; pointer-events:none; transition:opacity .2s, transform .2s; z-index:70; font-size:.9rem; max-width:88%; text-align:center; }
    .toast.show{ opacity:1; transform:translateX(-50%) translateY(0); }
    .chips{ display:flex; padding:0 18px; flex-wrap:wrap; } .chips .chip{ margin:0 8px 8px 0; }
    .chip{ background:var(--surface); border:1px solid var(--line); color:var(--text); border-radius:999px; padding:8px 14px; font-weight:600; font-size:.85rem; cursor:pointer; display:inline-flex; align-items:center; }
    .chip .ms{ font-size:18px; margin-right:6px; }
    .chip.on{ color:var(--accent); border-color:var(--accent); }

    /* Settings */
    .set-sec{ margin-top:22px; }
    .set-sec:first-child{ margin-top:4px; }
    .set-sec h3{ margin:0 0 10px; font-size:.74rem; letter-spacing:1.6px; text-transform:uppercase; color:var(--muted); }
    .card{ background:var(--surface); border:1px solid var(--line); border-radius:14px; overflow:hidden; }
    .row{ display:flex; align-items:center; padding:13px 15px; border-bottom:1px solid var(--line); }
    .row:last-child{ border-bottom:none; }
    .arow{ display:flex; align-items:center; padding:12px 12px; cursor:pointer; border-bottom:1px solid var(--line); transition:background .12s; } .arow>*+*{ margin-left:4px; }
    .arow:last-child{ border-bottom:none; }
    .arow:active{ background:var(--surface-2); }
    .arow .aic{ width:38px; height:38px; border-radius:11px; background:var(--surface-3); display:grid; place-items:center; flex:none; margin-right:12px; color:var(--accent); }
    .arow .ms svg{ width:22px; height:22px; }
    .abadge{ display:inline-block; min-width:18px; text-align:center; background:var(--accent); color:#fff; border-radius:999px; font-size:.68rem; font-weight:800; padding:1px 6px; margin-left:6px; vertical-align:1px; }
    .row .rlabel{ flex:1; min-width:0; margin-right:12px; }
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

    /* ---------- Visual polish ---------- */
    @keyframes fadeUp{ from{ opacity:0; transform:translateY(10px); } to{ opacity:1; transform:none; } }
    .sec, .hero, .grid, .tracks.solo{ animation:fadeUp .36s cubic-bezier(.2,.7,.3,1) both; }
    .sec:nth-child(2){ animation-delay:.03s; } .sec:nth-child(3){ animation-delay:.06s; }
    .sec:nth-child(4){ animation-delay:.09s; } .sec:nth-child(5){ animation-delay:.12s; } .sec:nth-child(6){ animation-delay:.15s; }
    /* accent bar before section titles */
    .sec-head h2{ position:relative; padding-left:13px; }
    .sec-head h2::before{ content:""; position:absolute; left:0; top:51%; transform:translateY(-50%); width:4px; height:17px; border-radius:3px; background:var(--grad); }
    /* cover art gently zooms on hover */
    .hcard .cvimg, .tile .cvimg{ transition:opacity .4s ease, transform .55s cubic-bezier(.2,.7,.3,1); }
    .hcard:hover .cvimg, .tile:hover .cvimg{ transform:scale(1.07); }
    /* richer press / hover feedback */
    .btn{ transition:transform .12s ease, box-shadow .2s ease, filter .2s ease; }
    .btn:hover{ filter:brightness(1.06); } .btn:active{ transform:scale(.97); }
    .chip{ transition:transform .12s ease, border-color .2s ease, background .2s ease, color .2s ease; }
    .chip:hover{ border-color:var(--accent); } .chip:active{ transform:scale(.95); }
    .iconbtn{ transition:background .18s ease, color .18s ease, transform .12s ease; } .iconbtn:active{ transform:scale(.9); }
    .track:active, .arow:active, .row:active, .code-item:active{ background:var(--surface-2); }
    .see:active{ transform:scale(.95); }
    /* logo sheen */
    .logo{ position:relative; overflow:hidden; }
    .logo::after{ content:""; position:absolute; top:0;right:0;bottom:0;left:0; background:linear-gradient(120deg,transparent 42%,rgba(255,255,255,.4) 50%,transparent 58%); transform:translateX(-130%); animation:sheen 6s ease-in-out infinite; }
    @keyframes sheen{ 0%,72%{ transform:translateX(-130%); } 88%,100%{ transform:translateX(130%); } }
    /* softer, deeper card shadows */
    .card{ box-shadow:0 1px 2px rgba(0,0,0,.04); transition:border-color .2s ease, box-shadow .2s ease; }
    .cover{ box-shadow:0 10px 24px rgba(0,0,0,.34), inset 0 0 40px rgba(0,0,0,.16); }
    .empty{ font-size:.96rem; }
    @media (prefers-reduced-motion: reduce){ *{ transition:none !important; animation-duration:.01ms !important; } }

.workspace-banner{margin:20px 18px;padding:24px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(135deg,var(--surface-2),var(--surface))}.workspace-banner h2{font-size:1.8rem;margin:6px 0 10px;letter-spacing:-.04em}.workspace-banner p{line-height:1.6;margin:0 0 12px}.workspace-banner .chips{padding:0}.library-tools{margin:12px 18px}.library-tile{text-align:left;color:var(--text);background:none;border:0;font:inherit;cursor:pointer;padding:0}.library-tile .kicker{margin-top:6px;font-size:.65rem}.tab{min-width:0;padding:0 2px}.tab .lbl{font-size:.63rem}button:disabled{opacity:.3;cursor:default}html[data-density="compact"] .track{min-height:46px;padding-top:5px;padding-bottom:5px}html[data-motion="reduced"] *,html[data-motion="reduced"] *::before{animation:none!important;transition:none!important;scroll-behavior:auto!important}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}@media(max-width:480px){.workspace-banner{padding:18px}.track .iconbtn{width:30px;min-width:30px}.seg{flex-wrap:wrap}.row{flex-wrap:wrap;gap:10px}.row .rlabel{min-width:160px}.row .seg{max-width:100%;box-sizing:border-box}}

.eq-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:18px 0}.eq-band{padding:16px;border:1px solid var(--line);border-radius:16px;background:var(--surface)}.eq-band label,.eq-band output{display:block;font-size:.85rem}.eq-band input{width:100%;accent-color:var(--accent);margin:16px 0}.mix-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:0 18px 22px}.mix-card{padding:16px;text-align:left;border:1px solid var(--line);border-radius:20px;background:linear-gradient(135deg,var(--surface-3),var(--surface));color:var(--text);font:inherit;cursor:pointer;display:flex;flex-direction:column;gap:10px;min-height:0}.mix-card strong{font-size:1.1rem}.mix-card span:not(.kicker),.mix-card small{color:var(--muted);line-height:1.5}.track[hidden]{display:none!important}@media(min-width:700px){.eq-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:480px){.mix-grid{gap:10px}.mix-card{padding:14px}.mix-card strong{font-size:1rem}.mix-card span:not(.kicker){display:none}}
    /* Touch devices: the blur on the fixed bars is a top scroll-jank source on phones, and the bars are nearly opaque anyway. */ @media (pointer:coarse){ :root{ --bar:rgba(10,10,18,.96); --bar-player:rgba(20,20,34,.98); --bar-tabs:rgba(14,14,24,.98); } :root[data-theme="light"]{ --bar:rgba(255,255,255,.97); --bar-player:rgba(255,255,255,.98); --bar-tabs:rgba(255,255,255,.98); } .top,.player,.tabs,.ovl{ backdrop-filter:none; -webkit-backdrop-filter:none; } }  </style>
</head>
<body>
  <div class="top">
    <div class="brand"><span class="logo"><span class="ms">music_note</span></span><span class="name">Zing</span></div>
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
    <button class="tab" id="tabPlaylists" onclick="go('playlists')"><span class="ms">fVGW&VE����Ɨ7C��7���7�6�73�&�&�#���Ɨ7G3��7����'WGF����'WGF��6�73�'F""�C�'F$Ɩ'&'�"��6Ɩ6��&'&�w6TƖ'&'���#��7�6�73�&�2#�ff�&�FS��7���7�6�73�&�&�#�Ɩ'&'���7����'WGF����'WGF��6�73�'F""�C�'F$'F�7G2"��6Ɩ6��&v�v'F�7G2r�#��7�6�73�&�2#�'F�7C��7���7�6�73�&�&�#�'F�7G3��7����'WGF������cࠢ�VF���C�&VF��"&V��C�&���R#���VF����F�b6�73�'F�7B"�C�'F�7B#���F�cࠢ�67&�C�f"'F�7G3յ��'F�7G4��FVC�f�6S��f"44�U��U��'���u�'F�7G5�66�U�c""�44�U�ED��3c��f"VWVSյ�������f"7W%F#�&���R"��F�'G�f�Ws�f�6R��F�s�"#���������������6WGF��w2�6fVB��F��2FWf�6R����������Тf"4UE��U��'���u�6WGF��w2#��gV�7F�����E6WGF��w2���f"C׶��s�&V�"�F�V�S�&F&�"�WF����G'VR�&F��G'VR�7VVC��6���R�&W7V�S�G'VR�fFS�f�6R�f�ãӰ�G'��f"�ԥ4���'6R���6�7F�&vR�vWD�FV҅4UE��U����&�V��"���b���b�����s���&�R"�B���s�&�R#��b���F�V�S���&Ɩv�B"�B�F�V�S�&Ɩv�B#��b���WF������f�6R�B�WF����f�6S��b���&F�����f�6R�B�&F���f�6S���b���sR���#R��R��sR�%���FW��b���7VVB����B�7VVC���7VVC��b���R�3���FW��b���6������B�6�����6����b���&W7V�S���f�6R�B�&W7V�S�f�6S��b���fFS���G'VR�B�fFS�G'VS��b�G�V�b��f�����&�V�&W""bf��f����bf��f�����B�f�����f�ò��6F6��R��Т&WGW&�C�Тf"4UC���E6WGF��w2����gV�7F���6fU6WGF��w2���G'����6�7F�&vR�6WD�FV҅4UE��U���4���7G&��v�g��4UB����6F6��R���ТgV�7F���ǕF�V�R���F�7V�V�B�F�7V�V�DV�V�V�B�6WDGG&�'WFR�&FF�F�V�R"�4UB�F�V�R��ТǕF�V�R�������F֖��6��G&���VB6�FR6WGF��w2�6�&VBf�"WfW'���S���FVBg&��F�R6W'fW"��f"4du�dTEU$U3ղ&&��W'2"�&�'V�2"�'�V�""�'6V&6�"�&vV�&W2"�&6FVv�&�W2"�'��Ɨ7G2"�&'F�7G2"�'7F�&�W2"�&F�v���G2"�&ff�&�FW2%Ӱ�f"4du�44T�E3׷W'�S��"3v3V6fb"�"6fcFC�B%��&�VS��"36#�&cb"�"3f#fCB%��w&VV㥲"3#��"�"33FC3��%��&VC��"6VcCCCB"�"6c�s3b%��v��C��"6cS�S""�"6f&&c#B%��FVå�"3F#�b"�"3#&C6VR%�Ӱ�f"4ds׶��S�""����V�6V�V�C�""�F�V�S�""���s�""�66V�C�""�fVGW&W3����fVGW&VC���Ɔ�FFV㥵�Ӱ�4du�dTEU$U2�f�$V6��gV�7F��↲��4dr�fVGW&W5����G'VS�ғ��f"�6WE6fVC�f�6S�G'���6WE6fVC���6�7F�&vR�vWD�FV҅4UE��U����6F6��R��ТgV�7F���fVB����&WGW&�4dr�fVGW&W5�����f�6S�ТgV�7F����4��FFV↖B��&WGW&�4dr憖FFV�bd4dr憖FFV���FW��b��V�&W"��B�����ТgV�7F����4fVGW&VB��B��&WGW&�4dr�fVGW&VBbd4dr�fVGW&VB��FW��b��V�&W"��B�����ТgV�7F���G&���FFV�Ɨ7B���b�4dr憖FFV���4dr憖FFV���V�wF��&WGW&�Ɨ7G�ŵӲ&WGW&��Ɨ7G�ŵҒ�f��FW"�gV�7F�����&WGW&�bb�4��FFV��B��ғ�ТgV�7F���ǔ6��f�r�2���3�7�ǷӲ4dr���S҇G�V�b2���S���'7G&��r#�2���S�""��4dr����V�6V�V�C҇G�V�b2����V�6V�V�C���'7G&��r#�2����V�6V�V�C�""���4dr�F�V�S҆2�F�V�S���&F&�'��2�F�V�S���&Ɩv�B"��2�F�V�S�"#�4dr���s҆2���s���&V�'��2���s���&�R"��2���s�"#�4dr�66V�C҆2�66V�Bbd4du�44T�E5�2�66V�Eғ�2�66V�C�"#��f"c҆2�fVGW&W2bgG�V�b2�fVGW&W3���&�&�V7B"��2�fVGW&W3��Ӳ4du�dTEU$U2�f�$V6��gV�7F��↲��4dr�fVGW&W5����e�����f�6S�ғ��4dr�fVGW&VC�'&��4'&��2�fVGW&VB��2�fVGW&VB����V�&W"���Ӳ4dr憖FFV��'&��4'&��2憖FFV��2憖FFV�����V�&W"���Ӱ���66V�B6���"�v���R�w&F�V�G2f����r��66V�B���66V�B�"��f"'3�F�7V�V�B�F�7V�V�DV�V�V�B�7G��S���b�4dr�66V�B��'2�6WE&�W'G��"��66V�B"�4du�44T�E5�4dr�66V�Eճғ�'2�6WE&�W'G��"��66V�B�""�4du�44T�E5�4dr�66V�Eճғ�ТV�6R�'2�&V��fU&�W'G��"��66V�B"��'2�&V��fU&�W'G��"��66V�B�""��Т��F֖�FVfV�G2f�"F�V�R���wVvRǒ��ǒ�bF��2FWf�6R�2��B6��6V��G2�v���b��6WE6fVB���b�4dr�F�V�R��4UB�F�V�S�4dr�F�V�S�ǕF�V�R�����b�4dr���r��4UB���s�4dr���s��Тf"&��F�7V�V�B�VW'�6V�V7F�"�"�'&�B���R"���b�&�&��FW�D6��FV�C�4dr���W��%���r#��G'��F�7V�V�B�F�F�S҄4dr���W��%���r"��"(	B�Wv�6��W6�2#��6F6��R��Тf"F$�׷F$�'V�3�&�'V�2"�F%6V&6��'6V&6�"�F$vV�&W3�&vV�&W2"�F%��Ɨ7G3�'��Ɨ7G2"�F$'F�7G3�&'F�7G2'Ӱ��&�V7B�W�2�F$���f�$V6��gV�7F��↖B��f"V��B��B���b�VV��7G��R�F�7���fVB�F$���Eғ�"#�&���R#�ғ��f"fd'F��F�7V�V�B�VW'�6V�V7F�"�r�6��'F�F�F�S�$ג�W6�2%�r���b�fd'F�fd'F��7G��R�F�7���fVB�&ff�&�FW2"��"#�&���R#��f"7&6�'F��F�7V�V�B�VW'�6V�V7F�"�r�6��'F�F�F�S�%6V&6�%�r���b�7&6�'F�7&6�'F��7G��R�F�7���fVB�'6V&6�"��"#�&���R#��f"�F��B�&�F�"���b��F�F��7G��R�F�7���fVB�&F�v���G2"��"#�&���R#��f"���B�&��&��W""����b�4dr����V�6V�V�B���b��◲���F�7V�V�B�7&VFTV�V�V�B�&F�b"�����C�&��&��W"#����6�74��S�&&��W"#����7G��R��&v��F��#�#�f"7C�B�'7FGW2"���b�7Bbg7B�&V�D��FR�7B�&V�D��FR��6W'D&Vf�&R����7B������FW�D6��FV�C�4dr����V�6V�V�C���憖FFV��f�6S�ТV�6R�b��◲��憖FFV��G'VS�ТТgV�7F�����D6��f�r���&WGW&�fWF6��"���6��f�r"��F�V�gV�7F���"��&WGW&�"�6�ₓ�Ғ�F�V�gV�7F���2��ǔ6��f�r�2��Ғ�6F6��gV�7F��ₗ�ғ�Тf"�S׶F֖�f�6R�W6W#��V��Ӱ�gV�7F���F����vVB���&WGW&�fVB�&F�v���G2"�bb��R�W6W"bb�R�W6W"���F�ТgV�7F�����D�R���&WGW&�fWF6��"����R"��F�V�gV�7F���"��&WGW&�"�6�ₓ�Ғ�F�V�gV�7F���B����b�BbfB��F�W$FWf�6R��6��uF�V�fW"���&WGW&�Т��FUF�V�fW"�����R�F֖���BbfB�F֖⓲�R�W6W#҆BbfB�W6W"����V�ð��b��R�W6W"bd�R�W6W"���F�bb��FF���vR��FW7B��R�W6W"���F򒗲f"�B�&�TfF""�Ɩ��B�&�T��r"���b��Ғ���7&3��R�W6W"���F��b��憖FFV��f�6S�ТWFFT6ft&��W"����b��R�F֖���EV�F��r����f"��B�&�F�"���b�����7G��R�F�7���F����vVB���"#�&���R#����&R�&V�FW"F�R7W'&V�Bf�Wr��ǒv�V�F�RF�v���BW&֗76���7GV�ǐ���6��vW2(	B�WfW"��WfW'�����F�Bv�V�B&�V�6R��R�fb��W"vR��@����WfW"v�g&��v�W&R��R&R�vR&R�ǒF�R6fVB&�WFR���6R��f"F��F����vVB�����b��F�7FFR���V��bb�F�7FFR��F�G'��&W7F�&U&�WFR����6F6��R���Т�F�7FFS�Fð�Ғ�6F6��gV�7F��ₗ�ғ�Тf"�F�7FFS��V�ð�gV�7F�����EV�F��r���fWF6��"���V�F��r"��F�V�gV�7F���"��&WGW&�"�6�ₓ�Ғ�F�V�gV�7F���B��f"�҆BbfB�V�F��r�����f"s�F�7V�V�B�VW'�6V�V7F�"�r�6��'F�F�F�S�%6WGF��w2%�r���b�r�&WGW&�r�7G��R��6�F����'&V�F�fR#�f"#�B�'V�D&FvR"����b������b�"��#�F�7V�V�B�7&VFTV�V�V�B�'7�"��"�C�'V�D&FvR#�"�7G��R�775FW�C�'�6�F���'6��WFS�F��7��&�v�C�7��֖��v�GF��g���V�v�C�g��FF��s�G��&�&FW"�&F�W3������&6�w&�V�C�f"���W'"��6���#�6ffc�f��B�6��S��c'&VӶf��B�vV�v�C���F�7���w&�C��6R֗FV�3�6V�FW"#�r�V�D6���B�"���"�FW�D6��FV�C��"憖FFV��f�6S�ТV�6R�b�"��"憖FFV��G'VS��Ғ�6F6��gV�7F��ₗ�ғ�Т��ƗfR&W6V�6S�FV��F�R6W'fW"v�BF��2FWf�6R�2F���r�6�F�R�v�W"6�6VRv���2���f"�6�C�"#�G'���6�C���6�7F�&vR�vWD�FV҂'���u�6�B"���"#��b��6�B���6�C�FFR���r���F�7G&��r�3b���F��&�F�҂��F�7G&��r�3b��6Ɩ6R�"Â����6�7F�&vR�6WD�FV҂'���u�6�B"��6�B����6F6��R���6�C�&2"��F��&�F�҂��F�7G&��r�3b��6Ɩ6R�"���Тf"�7F�f�G��$���R#��gV�7F���6WD7F�f�G�����7F�f�G����"#�6V�E&W6V�6R���ТgV�7F���6V�E&W6V�6R���fWF6��"���&W6V�6R"Ƕ�WF��C�%�5B"ƆVFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��'��&�G���4���7G&��v�g���6�C��6�B�f�Ws��7F�f�G�җҒ�6F6��gV�7F��ₗ�ғ�Р�gV�7F���B��B��&WGW&�F�7V�V�B�vWDV�V�V�D'��B��B��ТgV�7F���W62�2��&WGW&��3���V���"#�7G&��r�2���&W�6R���c��"u��r�gV�7F���2��&WGW&���"b#�"f��"�#�#�"f�C�"�#�#�"fwC�"�r"s�"gV�C�"�"r#�"b33��'ҕ�5Ӳғ�Тf"�4��3װ�7F#�$�"r�#r���#���cB�r�4�#"��#F��r����c�""�����c2"��#F�R�CbB�s4�R�"#�"��7F%�&�&FW#�$�#"��#F��r����c$�""�����c2"��#F�R�CbB�s4�R�"#"r�#r���#���c2�r�4�#"��#G��"R�F��2�sb"�#r�B�#��2�3"�"ヂB�3���3��"b���sB�BB�3��3��2�3""ヂB�#��"��f�6�&�ƗG��$�"B�T3rB�R"�s2r�c&3�s2B�3�br�Rr�W3��#r�2��r�V2��s2�B�3��b�r�R��r�W��"v2�"�sb�R�"�#B�R�W3"�#B�RR�RR"�#BRR�"�#BR�RW��ӆ2��cb�2�3B�273�3B2222��3B2�2��3B�2�2�7�"��f��V�U�W�$�2�cf�F�RUcD�r��7��2�R63��sr��"�2�#��"�R�B�7c��V3�C���s2"�R�"�#R"�R�B�'��B2�#7c"�f3"ヒ�bR2�SBRb�s2�"�R�R�Rb�sc"�f3B���r�B�C�rӂ�sw2�"㓒�r�b�rӂ�sw�"��7VVC�$�#�3���Sv���#2�V����#"r�S��R�t��R�S�b�V��R��#42�3R�""�s"�2�V""�sB���#r��CG��Ӓ�s�b�F"""�2�R�cbӂ�C�ӂ�C�R�cf"""�7�"��f7E�&Wv��C�$��cf�ӂ�Rb��Rg���R�fÂ�Recf�ӂ�Rg�"��f7E�f�'v&C�$�B�Â�R�d�Bgc'�Ӓ�'c&Â�R�d�2g�"��f�6�&�ƗG���fc�$�"v3"�sbR"�#BRR�cR��2�#b��3b�6�"�""�&3�S��#b"�r�"ヒ2�C2�B�sR��s2�B�3��b�r�R��r�R��B�"�sB�#R�2㓂�v�"�b"�d3�sBr�2�3Rr"w��"B�#v�"�#�"�#��Cb�Cd32����2�s��"&3�s2B�3�br�Rr�R�SR2�2��2B�3���F��C"�C$���s2#"##�s22�#r7��r�S2����SR�SV2��R�#����C2����cR�cb�3B222�#"�CB��2�cR�����SR�SV2��cr�32��C�S2�"�"�S2�"�sb�R�"�#B�R�R��s��"��S2�S2�"�'��B�3��s�2�R2�R�"��f3��cb��3B�2�2�7�"���W6�5���FS�$�"7c�STBBBucv�Ec7�"��6WGF��w3�$�2wc&�gb�$�7��2Wc&�cT�7��gb�&��b�&�Ӈb�&��'cf�'��r�c$�7c&�Gc&�%c��w��BGb�$�c&����b�F�%cv�EcV��Ec6��'cg�"��6�Wg&���&�v�C�$�b��S�r�C2�r&��B�S�B�S����b�g�"�����S�$�#b�f�Gcf�Wbӆ�4�"2"&�7c��"��6V&6��$�R�RF���s����#���#vb�Rb�R��r�v��#r�#�b�s��RB㓔�#�C�����bB�RB�RB��RB�RB�R��RG�"��6FVv�'��$�26��c��5c7����c��Ӆc7��26��c��7bӇ����c��ӇbӇ�"��fVGW&VE����Ɨ7C�$�2�c$�7b�'���F�c$�5cg����wc$�7b�'��2�cf�R�2�R�7�"��'F�7C�$�"&3"�#B��s�B�G2��s��B�B�B�B�s��BB�s�BBG��&2�"�crӂ�3BӂGc&�gb�&3�"�cb�R�32�Bӂ�G�"���'VӢ$�"$3b�C�""b�C�"'3B�C��B�C��3r�S"""'��F2�"�#�B��s��B�G3�s��BB�BB�s�BB��s�B�BG���V2��SR��CR�2�CR��CR���CR����"��ff�&�FS�$�"#�3V���CR��3$3R�BR�3b""�#�"��R"R�C"B�C"2r�R63�sB2�C�B�R"��32��2�B�sb2b�R2��S�2#"R�C"#"��V32�s��2�Bb�bӂ�SR�SD�"#�3W�"��ff�&�FU�&�&FW#�$�b�R62��sB�2�C��B�R"��3�2���#B2r�R2B�C"2"R�C""��V32�s�2�Bb�b��SR�SD�"#�3V��CR��3$3��bR�3b#""�#�#"��R#"R�C"��S�2b�R7���B�BR�SV��������3r�BB�#BB�3�B��RBb�RR�RRr�RV3�SB2�B㓒2�Sr"�3f��t32�CbR㓒B�bRb�RV3"2�R�R2�R2�R"ヒ�2�BR�sB�r��W�"�����'&�s�$ӂWcF��w�"��W6S�$�bV�GcD�g�ӂ�GcF��G�"��6���&Wf��W3�$�bf�'c$�g��2�Rb��Recg�"��6����W�C�$�bf�'c&��'��b�Â�R�d�bg�"��6�Vff�S�$��S���rR�CBBR�C�R�rR�r�C"��C��B�RF�"�B"�D�B��S�R�C#r�br�Cb#��UcF��R�W���32��C��C�C2�22�4�B�R#�#b�R�V��"�B"�B�2�2�2�7�"��&WVC�$�rv�c6�B�B�B�Gc4�Wcf�%cw���wb�6��BBBGb�6�'b�f��'cG�"��&WVE���S�$�rv�c6�B�B�B�Gc4�Wcf�%cw���wb�6��BBBGb�6�'b�f��'cG���B�%c�����"c��WcD�7�"����7F�'��$�262�B�rӒB�2Ӓ���2ヒ2ヒ�r�DÒ$�f3�2�r2�2�rr�w3r2�2rr�2�2r�rv2��2�2�c���s��B�B�"�f���C"�C$3��#r�㓒�S#2#3B�r��B�2�ӗ2�B�2ӒӒӗ���WcV�B�#�"�SB�s"��#�2�R�"��c��'�"��w&��5�W�$�r��%cd�wc'��BF�%c&��'c#��ӂӆ�'b�D�7cG��"F�%cf��'c'��BӇcF�'b�F��'�"��VWVU��W6�3�$�Rd�7c&�%cg��D�7c&�'b�'��2f��b�$�7c'��rgc���2��3����cR���������cb�2�3B�273�3B2222��3B2�5c��5cf��W�"��&VGF��S�$�"6����3��Cb��B��"����3fR�3�R�3��B�B"�#bR�BR�B�2�BӒ�2��CB��b������3b���"����&U�fW'C�$�"�3�"��"�'2���"�"�"�"��""�""'��&2���"��"'2�""""��"�"���"�"�'��f2���"��"'2�""""��"�"���"�"�'�"����Ɨ7E�FC�$�B�'c&�'b�'���D�'c&�%cg��"f��b�$�'c'����b��C��C�b"�ucF��'c��v��2�S��2�S�Ò�RRR�W�"��F�v���C�$�����Ec4��cd�V�rrr�w��R�c&�Gb�$�W�"�W��C�$Ӓf�gb�f�F��r�r�rv�Gcg���B&�Gc$�Wb�'�"��'&�u�&6����5��Ws�$�r�sr2�srb"b&��sr��stÒ�SB'�"��6��6S�$��b�Cr�S�R"�S�b�CRRb�C�S�"Rr�S�b�C�"2�Cr�S���r�S�2�C'�"��FV�WFS�$�b�3��""&��3�"��"�%ct�gc'���F��2�V�����V���Wc&�EcG�"��W'6���FC�$�R&3"�#B��s�B�G2��s��B�B�B�B�s��BB�s�BBG��Ӓ�c��Gc4�c&�7c6�'b�6�7b�$�g�Ӓ62�"�crӂ�3BӂGc6�gb�63�"�cb�R�32�Bӂ�G�"����v�WC�$�rv���C�C���r��c&��v��"�S�"�S��rv�R�W��BV��c4�F2���"��"'cF3��""&��b�$�G�"����6��$�����cf3�"�sb�"�#B�R�R�U3r2�#Brgc$�f2���"��"'c3��""&�&3�"��"�%c3�����"�"�'���b�2���"���"�'2��""�""�""��"�"'��2�Ӕ���cf3��s�3��2�2��2�32��3�2�2�c'� �Ӱ���V6��6��6'&�W2&�F����Ɩ�R5dr��v�2&V�FW'2��B�G2�FW&�����7��&��2��R��FF֖2�W6VB��6RF�Rf��B��G2�f�552��&Vf�&R��gV�7F����2�◲&WGW&�s�7�6�73�&�2"FF֖3�"r��r#��7frf�Wt&���##B#B"&�ֆ�FFV��'G'VR#��F�C�"r���4��5����Ĕ4��2����'&�r��r#���F����7fs���7��s�ТgV�7F�����G&FT�6��2�&��B���&��G��F�7V�V�B��VW'�6V�V7F�$�'7���3���B��FF֖5Ғ"��f�$V6��gV�7F���V�V���WFW$�D����2�V��FW�D6��FV�B�G&�҂���ғ�Т��Ww&FRF�v��v�Rw2�FW&��7��&��2vǗ�2��ǒ��6RF�W�$T�Œ&V�FW"���vR�V7W&R���v�ƖvGW&S�v�F�F�R�6��f��B�&���R"6���6W2F���P����'&�r7V&RvǗ��v�F��WB�B�F�Rf�W"�WGFW'2&R�V6�v�FW"�F��0���v�&��6�VB�"6��rf��B�WfW"�VfW2&rv�&G2��67&VV��gV�7F���7��&��5&V�FW"���G'��f"3�F�7V�V�B�7&VFTV�V�V�B�'7�"���2�FW�D6��FV�C�&���R#�2�7G��R�775FW�C�'�6�F���'6��WFS��VgC�ӓ�����F��ӓ�����f��B�6��S�C���Ɩ�RֆV�v�C��v��FR�76S���w&�f��B�f֖Ǔ�t�FW&��7��&��2&�V�FVBr#��F�7V�V�B�&�G��V�D6���B�2��f"t�6���2��fg6WEv�GF��2�7G��R�f��Df֖Ǔ�&����76R#�f"t�����2��fg6WEv�GF��F�7V�V�B�&�G��&V��fT6���B�2���&WGW&�t�6���bbt�����bbt�6���t�����c��6F6��R��&WGW&�f�6S��ТgV�7F���G'�V�&�U7��&��2����b�F�7V�V�B�F�7V�V�DV�V�V�B�6�74Ɨ7B�6��F��2�'7��&��2"��&WGW&�G'VS��b�7��&��5&V�FW"����F�7V�V�B�F�7V�V�DV�V�V�B�6�74Ɨ7B�FB�'7��&��2"��&WGW&�G'VS��&WGW&�f�6S�Т�gV�7F��ₗ�G'���f"G&�W3��F��W#�6WD��FW'fgV�7F��ₗ�G&�W2����b�G'�V�&�U7��&��2����G&�W3�#�6�V$��FW'fF��W"����#S����b�F�7V�V�B�f��G2bfF�7V�V�B�f��G2���B��F�7V�V�B�f��G2���B�s#G�$�FW&��7��&��2&�V�FVB"r��F�V�G'�V�&�U7��&��2��6F6��gV�7F��ₗ�ғ�Т�6F6��R���Ғ����gV�7F����6��2��f"���3�7��#�#�f�"�f"�����2��V�wF��������҆��3�2�6�$6�FTB���������&WGW&���ТgV�7F���w&B���R��f"�ֆ6����R��f"ւS3c�f"#҆�CR�����2�Ss�S3c�&WGW&�&Ɩ�V"�w&F�V�B�3VFVr��6"��"�s"R�SbR���6"�"�"�sR�CBR��#�ТgV�7F����撆��R��f"҆��W��#�"��G&�҂��7ƗB����2���f��FW"�&���V⓲�b���V�wF��&WGW&�#�#�&WGW&����V�wF��������6Ɩ6R��"����ճҷ�ճҒ��F�WW$66R���ТgV�7F���f�B�6V2���b��4f��FR�6V2���6V3��6V3��f"���F��f���"�6V2�c��3��F��f���"�6V2Sc��&WGW&�Ҳ#�"��3��##�""��3�ТgV�7F����6��V�ƆR���b�4UB���s���&�R"��&WGW&��W��V���"#��&WGW&�V��ƆW��"#�ТgV�7F���G&6���R�B��&WGW&���6��B�V���R�B�T��R��B�f��W��""��7ƗB�"�"������%G&6�"�B�B���ТgV�7F����$��R��&WGW&���6����V���R���T��R���%V���v��'V�"��ТgV�7F���'D��W2�Ɨ7B��&WGW&��Ɨ7G�ŵҒ���gV�7F�����&WGW&��6���V���R��T��R���%V���v�#�Ғ����"�"��ТgV�7F������R���&WGW&��6���V���W�����R��T��R���%��Ɨ7B#�ТgV�7F���vV���R�r��&WGW&��6��r�V���R�r�T��R���$vV�&R#�ТgV�7F����$��r��f"����bf���vW3�&WGW&����bb����6F��VF�V��Ɩ���VF�V��Ɩ��6F�6����Ɩ��6������V�òТgV�7F�����uW&b���b�G�V�bb��'7G&��r"����GG3���������FW7B�b��&WGW&��V�ò&WGW&���GG3��������vU��禖�v�W6�5����&W5���6��VF��'����6�ҕ�����FW7B�b���"���s�S�"�V�6�FUU$�6����V�B�b���c�Р�gV�7F���6WE7FGW2���2��B�'7FGW2"����W$�D��և��"#�B�'7FGW2"��6�74��S�7��"#�ТgV�7F�����F��r�җ�6WE7FGW2�s�7�6�73�'7���W"#���7��r���&�WFVB"��Тf"F�7EC��gV�7F���F�7B�җ�f"C�B�'F�7B"��B�FW�D6��FV�C�ӲB�6�74Ɨ7B�FB�'6��r"��6�V%F��V�WB�F�7EB��F�7EC�6WEF��V�WB�gV�7F��ₗ�B�6�74Ɨ7B�&V��fR�'6��r"����#c��ТgV�7F���6WEf�Wr����B�'f�Wr"����W$�D��փ�v��F�r�67&���F����Р�gV�7F���6�fW$�F���R��G2���G3��G7�ǷӲf"6�3�&6�fW""���G2�&�V�C�"&�V�B#�""��f"W&�֖�uW&�G2��r���f"f#��G2�f#�s�F�b6�73�&f"#�r��2�'���'&�r"��s��F�c�s�rs��f"���W#��G2�&�V�C�s�7�6�73�&��#�r�W62��撆��R���s��7��s�s�7�6�73�&F�62#���7��s����F�Rw&F�V�B���F���F�626��rf�'7C�F�R&V�6�fW"fFW2���fW"�@���v�V��B��G2��B'&��V���vR�W7B&V��fW2�G6V�b�w&F�V�B7F�2��f"��s�W&��sƖ�r6�73�&7f��r"7&3�"r�W62�W&�r"�C�""��F��s�&���"����C�'F��2�6�74Ɨ7B�FB���v����r�"��W'&�#�'F��2�&V��fR��"��s�rs��&WGW&�s�F�b6�73�"r�6�2�r"7G��S�&&6�w&�V�C�r�w&B���R��r#�r����W"���r�f"�s��F�c�s�Р���6����W"6�V�WF��26��v�v���R6��FV�B��G2��6W"F��&&R7���W"��gV�7F���6�6&B���&WGW&�s�F�b6�73�'6��6&B#��F�b6�73�'6�V�6��6�fW"#���F�c��F�b6�73�'6�V�6��Ɩ�R#���F�c��F�b6�73�'6�V�6��Ɩ�R6�#���F�c���F�c�s�ТgV�7F���6�&�r�◲f"3�"#�f�"�f"�������b������2��6�6&B���&WGW&�s�F�b6�73�&�&�r#�r�2�s��F�c�s�ТgV�7F���6�w&�B�◲f"3�"#�f�"�f"������Ò������2��s�F�b6�73�'F��R#��F�b6�73�'6�V�6��6�fW"#���F�c��F�b6�73�'6�V�6��Ɩ�R#���F�c��F�b6�73�'6�V�6��Ɩ�R6�#���F�c���F�c�s�&WGW&�s�F�b6�73�&w&�B�'V�2#�r�2�s��F�c�s�ТgV�7F���6�6V2�F�F�R�◲&WGW&�s�F�b6�73�'6V2#�r�6V4�VB�F�F�R��6�&�r�⒲s��F�c�s�ТgV�7F���6����R���&WGW&�s�F�b6�73�'6V2"7G��S�&�&v���F��'�#��F�b6�73�'6�V�"7G��S�&�V�v�C�S��&�&FW"�&F�W3�g���&v����#���F�c���F�c�r�6�6V2�$�Wr&V�V6W2"��6�6V2�%�V�"F��2���F�"��ТgV�7F���6�F��W2�◲f"3�"#�f�"�f"������Ò������2��s�F�b6�73�'F��R#��F�b6�73�'6�V�6��6�fW"#���F�c��F�b6�73�'6�V�6��Ɩ�R#���F�c��F�b6�73�'6�V�6��Ɩ�R6�#���F�c���F�c�s�&WGW&�3�ТgV�7F���6�FWF���&WGW&�s�F�b6�73�&�W&�"7G��S�&�&v���F����#��F�b6�73�'6�V�"7G��S�'v�GF��S���V�v�C�S��&�&FW"�&F�W3�g��f�W�����R#���F�c��F�b7G��S�&f�W���֖��v�GF��c�#��F�b6�73�'6�V�6��Ɩ�R"7G��S�'v�GF��CS��V�v�C���#���F�c��F�b6�73�'6�V�6��Ɩ�R"7G��S�'v�GF��sRS��V�v�C�#'���&v���F��'�#���F�c��F�b6�73�'6�V�6��Ɩ�R6�"7G��S�&�&v���F���#���F�c���F�c���F�c�r��s�F�b7G��S�&�&v��g���#�r�gV�7F��ₗ�f"#�"#�f�"�f"�����s�����"��s�F�b6�73�'6�V�6��Ɩ�R"7G��S�&�V�v�C�C���&v���F����&�&FW"�&F�W3�'�#���F�c�s�&WGW&�#�҂��s��F�c�s�Р�gV�7F����7B�F�����B���&WGW&�fWF6��F�Ƕ�WF��C�%�5B"ƆVFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��'��&�G���4���7G&��v�g�����G�ǷҗҐ��F�V�gV�7F���&W2��&WGW&�&W2�6�ₒ�6F6��gV�7F��ₗ�&WGW&��ӷҒ�F�V�gV�7F���B����b�&W2�7FGW3���CbfB��VVD��v�◲��6F����&Vc�"�#�F�&�r�WrW'&�"�%�V6R��r���"��Т�b�&W2����F�&�r�WrW'&�"�B�W'&�'�%&WVW7Bf��VB�"�&W2�7FGW2�"�"���&WGW&�C�ғ�ғ��ТgV�7F���wVW'��f'2���&WGW&�fWF6��"���VW'�"Ƕ�WF��C�%�5B"ƆVFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��'��&�G���4���7G&��v�g���VW'��VW'��f&�&�W3�f'7�Ƿ�җҐ��F�V�gV�7F���"���b�"�7FGW3���C����6F����&Vc�"�#�F�&�r�WrW'&�"�&��v��"���&WGW&�"�6�ₓ�Ґ��F�V�gV�7F���B���b�BbfB�W'&�'2bfB�W'&�'2��V�wF��F�&�r�WrW'&�"�B�W'&�'5����W76vW��'VW'�W'&�""��&WGW&��BbfB�FF��ǷӲғ��Т��WF�V�F�6FVBw&���GF6�W2F�R��v��F��V�f�"W"�66�V�B7F���2�gV�7F���wVW'��f'2���&WGW&�fWF6��"���WF�VW'�"Ƕ�WF��C�%�5B"ƆVFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��'��&�G���4���7G&��v�g���VW'��VW'��f&�&�W3�f'7�Ƿ�җҐ��F�V�gV�7F���"���b�"�7FGW3���C����6F����&Vc�"�#�F�&�r�WrW'&�"�&��v��"���&WGW&�"�6�ₓ�Ґ��F�V�gV�7F���B���b�BbfB�W'&�'2bfB�W'&�'2��V�wF��F�&�r�WrW'&�"�B�W'&�'5����W76vW��'VW'�W'&�""��&WGW&��BbfB�FF��ǷӲғ��Тf"�&�f��T�C��V����&�f��UG&�VC�f�6S��gV�7F���V�7W&U&�f��R�����b��&�f��T�B�&WGW&�&�֗6R�&W6��fR��&�f��T�B����b��&�f��UG&�VB�&WGW&�&�֗6R�&W6��fR��&�f��T�B���&WGW&�w'VW'��&�f��W2��B��R��"��F�V�gV�7F���B���&�f��UG&�VC�G'VS�f"3�B�&�f��W7�ŵӲ�&�f��T�C�2��V�wF��5���C��V�ò&WGW&��&�f��T�C�Ґ��6F6��gV�7F��ₗ��&�f��UG&�VC�G'VS�&WGW&��V�òғ��ТgV�7F���6fT'F�7B��B��F�7B�%6f��~(
b"��V�7W&U&�f��R���F�V�gV�7F����B���f"��B�&�WFF���F���B�G���B��6fTה'F�7EF�&�f��R�'F�7D�C�F�&�f��T�C�G���B�� ��&�WFF���F���B��7&VFT��Tה'F�7B�FF��'F�7C��6���V7C���C�F��җ��B��#��f"b��B����V�&W"��B����V�&W"��B������V�&W"��B�Ӱ�w�b��F�V�gV�7F��ₗ�F�7B�%6fVBF�ג�W6�2)�R"��Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�F�7B�$6�V�F�(	�B6fS�"��R��W76vW��&��v����B6���V7FVB"���ғ�ғ�ТgV�7F���6fT�'V҆�B��F�7B�%6f��~(
b"��V�7W&U&�f��R���F�V�gV�7F����B���f"��B�&�WFF���F���B�G���B��6fTה�'V�F�&�f��R��'VԖC�F�&�f��T�C�G���B�� ��&�WFF���F���B��7&VFT��Tה�'V҆FF���'Vӧ�6���V7C���C�F��җ��B��#��f"b��B����V�&W"��B����V�&W"��B������V�&W"��B�Ӱ�w�b��F�V�gV�7F��ₗ�F�7B�%6fVBF�ג�W6�2)�R"��Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�F�7B�$6�V�F�(	�B6fS�"��R��W76vW��&��v����B6���V7FVB"���ғ�ғ�Р�f"�6��f�wW&VC�G'VS��gV�7F���WFFT6ft&��W"���f"6��s��R�F֖�bb�6��f�wW&VC�f"#�B�&6ft&��W""���b�"�"憖FFV��6��s�f"&C�B�&6ft&FvR"���b�&B�&B�FW�D6��FV�C�6��s�$��B6��f�wW&VB#�"#�ТgV�7F���6�V6�7FGW2���fWF6��"���7FGW2"��F�V�gV�7F���"��&WGW&�"�6�ₓ�Ғ�F�V�gV�7F���2���6��f�wW&VC�2�6��f�wW&VC�WFFT6ft&��W"���Ғ�6F6��gV�7F��ₗ�ғ�Р�gV�7F�����D66�R���G'��f"�ԥ4���'6R���6�7F�&vR�vWD�FV҄44�U��U����&�V��"���b��bdFFR���r�����C�44�U�ED�bf��bf����V�wF��&WGW&�����6F6��R���&WGW&��V�òТgV�7F���6fT66�R���G'����6�7F�&vR�6WD�FV҄44�U��U���4���7G&��v�g���C�FFR���r����Ғ���6F6��R���ТgV�7F���&Vg&W6�'F�7G2���&WGW&��7B�"���'F�7G2"ǷҒ�F�V�gV�7F���B���b�B�'F�7G2bfB�'F�7G2��V�wF���'F�7G3�B�'F�7G3�6fT66�R�'F�7G2���&WGW&�G'VS�Ғ�6F6��gV�7F��ₗ�&WGW&�f�6S�ғ�ТgV�7F���V�7W&T'F�7G2�����b�'F�7G4��FVB�&WGW&�&�֗6R�&W6��fR�G'VR���f"3���D66�R�����b�2��'F�7G3�3�'F�7G4��FVC�G'VS�&Vg&W6�'F�7G2���&WGW&�&�֗6R�&W6��fR�G'VR�����6��r66�VB��r�&Vg&W6���F�R&6�w&�V�@���F��r�$��F��r'F�7G>(
b"���&WGW&��7B�"���'F�7G2"ǷҒ�F�V�gV�7F���B��'F�7G3�B�'F�7G7�ŵӲ'F�7G4��FVC�G'VS�6fT66�R�'F�7G2��6WE7FGW2�""��&WGW&�G'VS�Ґ��6F6��gV�7F���R��6WE7FGW2�$6�V�B��B��C�"�W62�R��W76vR��&W'""��&WGW&�f�6S�ғ��Р�������������F'2���������ТgV�7F���6WEF"��B���'F$���R"�'F$�'V�2"�'F%6V&6�"�'F$vV�&W2"�'F%��Ɨ7G2"�'F$'F�7G2"�'F$Ɩ'&'�%��f�$V6��gV�7F���◲f"V��B�⓲�b�VV��6�74Ɨ7B�F�vv�R�&7F�fR"����֖B��ғ�Тf"t���$T�׶���S�$���R"��'V�3�$�'V�2"�6V&6��%6V&6���r"�vV�&W3�$vV�&W2"���Ɨ7G3�%��Ɨ7G2"�'F�7G3�$'F�7G2'Ӱ�gV�7F���v�v�W&R���7W%F#�v�W&S�6WD7F�f�G��t���$Tŷv�W&U���$���R"��6fU&�WFR�v�W&R����b�v�W&S���&���R"��6WEF"�'F$���R"�����R���ТV�6R�b�v�W&S���&�'V�2"��6WEF"�'F$�'V�2"��'&�w6T�'V�2���ТV�6R�b�v�W&S���'6V&6�"��6WEF"�'F%6V&6�"��6V&6�f�Wr���ТV�6R�b�v�W&S���&vV�&W2"��6WEF"�'F$vV�&W2"��'&�w6TvV�&W2���ТV�6R�b�v�W&S���'��Ɨ7G2"��6WEF"�'F%��Ɨ7G2"��'&�w6U��Ɨ7G2���ТV�6R�b�v�W&S���&'F�7G2"��6WEF"�'F$'F�7G2"��'&�w6T'F�7G2���ТТ��&V�V�&W"v�W&R��R&R6�&Vg&W6�'&��w2��R&�v�B&6�F�F�R6�P����6R��7FVB�b�V���rF����R�gV�7F���6fU&�WFR�����G'����6�7F�&vR�6WD�FV҂'���u�&�WFR"��4���7G&��v�g������������V���"#��Ғ���6F6��R���ТgV�7F���&W7F�&U&�WFR���f"#��V�òG'��#ԥ4���'6R���6�7F�&vR�vWD�FV҂'���u�&�WFR"���&�V��"���6F6��R��Т�b�'��"沗�v�&���R"��&WGW&�Тf"F'3׶���S���'V�3��6V&6���vV�&W3����Ɨ7G3��'F�7G3�Ӱ��b�F'5�"�җ��b�"����'6V&6�"bg"���7W%F#�'6V&6�#�6WEF"�'F%6V&6�"��6fU&�WFR�'6V&6�"�"���6V&6�f�Wr���f"�B�'"���b����f�VS�"��F�6V&6��"�����V�6R�v�"沓��&WGW&�Тf"�V�3׷G&6���V�G&6�&�WFR��'VӦ�V��'V��'F�7C��V�'F�7B���Ɨ7C��V���Ɨ7B�vV�&S��V�vV�&R�6FVv�'���V�6FVv�'��7F�'���V�7F�'�Ӱ��b��V�5�"�җ�G'���V�5�"�҇"����6F6��R��v�&���R"���&WGW&�Тv�&���R"���Р�������������6&G2���������ТgV�7F����'VԄ6&B���7V"��&WGW&�s�F�b6�73�&�6&B�'V�"��6Ɩ6��&�V��'V҂r���B�r�#�r�6�fW$�F��$��R�Ƕ��s��$��r��f#�G'VWҒ��s�F�b6�73�&2���R#�r�W62��$��R���s��F�c��F�b6�73�&2�7V"#�r�W62�7V'��""��s��F�c���F�c�s�ТgV�7F���'F�7D�6&B���f"����6���V���R��T��R���$'F�7B#�&WGW&�s�F�b6�73�&�6&B'F�7B"��6Ɩ6��&�V�'F�7B�r��B�r�#�r�6�fW$�F���Ƿ&�V�C�G'VRƖ�s���vWҒ��s�F�b6�73�&2���R#�r�W62��Ғ�s��F�c���F�c�s�ТgV�7F����'V�F��R���7V"��&WGW&�s�F�b6�73�'F��R�'V�"��6Ɩ6��&�V��'V҂r���B�r�#�r�6�fW$�F��$��R�Ƕ��s��$��r��f#�G'VWҒ��s�F�b6�73�&2���R#�r�W62��$��R���s��F�c��F�b6�73�&2�7V"#�r�W62�7V'��""��s��F�c���F�c�s�ТgV�7F���'F�7EF��R���f"����6���V���R��T��R���%V���v�#�f"�C҅4UB���s���&�R"���V���W��""����T��W��""���&WGW&�s�F�b6�73�'F��R'F�7B"��6Ɩ6��&�V�'F�7B�r��B�r�#�r�6�fW$�F���Ƿ&�V�C�G'VRƖ�s���vWҒ��s�F�b6�73�&2���R#�r�W62��Ғ�s��F�c��F�b6�73�&2�7V"#�r�W62��B��s��F�c���F�c�s�Р�gV�7F���6V4�VB�F�F�R�6VUF"�6VTf◰�f"6VR�6VTf��s�'WGF��6�73�'6VR"��6Ɩ6��"r�6VTf�r#�6VR��r��2�&6�Wg&���&�v�B"��s��'WGF���p���6VUF"�s�'WGF��6�73�'6VR"��6Ɩ6��&v���rr�6VUF"�u��r�#�6VR��r��2�&6�Wg&���&�v�B"��s��'WGF���r�rr���&WGW&�s�F�b6�73�'6V2ֆVB#�ƃ#�r�W62�F�F�R��s���#�r�6VR�s��F�c�s�Р����������������R���������ТgV�7F���&��W$��r�"��&WGW&��4UB���s���&�R"���"�T��vW��"�V��vR���"�V��vW��"�T��vR��ТgV�7F���&��W$6&B�"��f"S֖�uW&&��W$��r�"����b�R�&WGW&�"#��&WGW&�s�F�b6�73�&&��W"�6&B"��6Ɩ6��&�V�&��W%W&r�W62��4���7G&��v�g��"�W&���""���&W�6R��"�r�"gV�C�"��r�"7G��S�&&6�w&�V�B֖�vS�W&��rr�W62�R��u��r�#���F�c�s�ТgV�7F����V�&��W%W&W&�W&��W&���"#�f"Ӱ��b����W&���F6����'Vշ5�������҅��B���������V��'V҂�ճғ�&WGW&�Т�b����W&���F6���'F�7E�5�������҅��B���������V�'F�7B��ճғ�&WGW&�Т�b����W&���F6�����Ɨ7E�5�������҅��B���������V���Ɨ7B��ճғ�&WGW&�Т�b���GG3����FW7B�W&��v��F�r��V�W&��%�&��"���ТgV�7F������R����6WE7FGW2�""��6WEf�Wr�6����R�����f"&��w'VW'��&��W'2�F�S�R���BV���R�T��RV��vR�T��vRW&���FW��Ff�&���"��F�V�gV�7F���B��f"#�B�&��W'7�ŵӲ"�6�'B�gV�7F��⇂ǒ��&WGW&�����FW����҇���FW�����ғ�&WGW&�#�Ғ�6F6��gV�7F��ₗ�&WGW&��ӷғ��f"�Ws��7B�"����Wr"ǷҒ�F�V�gV�7F���B��&WGW&�B��'V�7�ŵӷҒ�6F6��gV�7F��ₗ�&WGW&��ӷғ��f"��w'VW'��vWD��7E��VB���WC��G�S��%T�2�W&��C����D��Ɩ֗C�"Ғ��'V�5v�F�V�F�F�W2���2�'V���BV���R�T��R��vW2�6F�6���6F��VF�V��VF�V�6����'F�7G2�V���R�T��R�G&6�2��B�����"��F�V�gV�7F���B��&WGW&����B�vWD��7E��VG�ǷҒ��'V�5v�F�V�F�F�W2��ŵҒ���gV�7F��⇂��&WGW&����'VӷҒ�f��FW"�&���V⓲Ғ�6F6��gV�7F��ₗ�&WGW&��ӷғ��f"vV��w'VW'��vV�&W2�F�S�#���BV���R�T��R��"��F�V�gV�7F���B��&WGW&�B�vV�&W7�ŵӷҒ�6F6��gV�7F��ₗ�&WGW&��ӷғ��f"6C�w'VW'��6FVv�&�W2�F�S�C���BV���R�T��R��"��F�V�gV�7F���B��&WGW&�B�6FVv�&�W7�ŵӷҒ�6F6��gV�7F��ₗ�&WGW&��ӷғ��f"��w'VW'����Ɨ7G2�F�S�#���B��RV���R�T��R��vR6F��vR��"��F�V�gV�7F���B��&WGW&�B���Ɨ7G7�ŵӷҒ�6F6��gV�7F��ₗ�&WGW&��ӷғ��f"7G#�w'VW'��7F�&�W2�F�S�R��&FW$'����&V�V6TFFS�FW62�Ғ��BV���R�T��R��vUW&���"��F�V�gV�7F���B��&WGW&�B�7F�&�W7�ŵӷҒ�6F6��gV�7F��ₗ�&WGW&��ӷғ��f"fVC҄4dr�fVGW&VBbd4dr�fVGW&VB��V�wF���w'VW'���'V�2�v�W&S���C���㥲"�4dr�fVGW&VB����"�"��%��Ғ��BV���R�T��R��vW2�6F�6���6F��VF�V��VF�V�6����'F�7G2�V���R�T��R�G&6�2��B���"��F�V�gV�7F���B��&WGW&�B��'V�7�ŵӷҒ�6F6��gV�7F��ₗ�&WGW&��ӷғ�&�֗6R�&W6��fR��ғ��&�֗6R���&���Wr���vV��6B���7G"�fVEҒ�F�V�gV�7F���&W2���6WE7FGW2�""���f"&��W'3�&W5����'V�3�G&���FFV�&W5�Ғ��V�#�G&���FFV�&W5�%Ғ�vV�&W3�&W5�5��6FVv�&�W3�&W5�E����Ɨ7G3�&W5�U��7F�&�W3�&W5�e��fVGW&VC�&W5�u��ŵӰ����VWfVGW&VB��F�RF֖��6��6V��&FW"��b�fVGW&VB��V�wF���f"f�׷ӲfVGW&VB�f�$V6��gV�7F�����fն�E���ғ�fVGW&VC�4dr�fVGW&VB���gV�7F��↖B��&WGW&�fն�EӷҒ�f��FW"�&���V⓲Тv��F�r���'V�3�v��F�r���'V�7�ǷӰ�f"�F���W'6���֗�W4�F�����b�&��W'2��V�wF�bbfVB�&&��W'2"����f"&6&G3�&��W'2���&��W$6&B��f��FW"�&���V�����""����b�&6&G2��F�³�s�F�b6�73�'6V2"7G��S�&�&v���F��'�#��F�b6�73�&�&�r&��W'2#�r�&6&G2�s��F�c���F�c�s��Т�b�fVGW&VB��V�wF�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�$fVGW&VB"��s�F�b6�73�&�&�r#�r�fVGW&VB���gV�7F����v��F�r���'V�5���E��ð�&WGW&��'VԄ6&B���'D��W2���'F�7G2���Ғ����""��s��F�c���F�c�s��Тf"��7C�vWD��7F�'������b���7B��V�wF�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�%&V6V�Fǒ��VB"��V���&�V䆗7F�'���"��s�F�b6�73�&�&�r#�r���7B�6Ɩ6R��"����gV�7F���Bƒ���&WGW&�s�F�b6�73�&�6&B"��6Ɩ6��'����7F�'��r���r�#�r�6�fW$�F�B�F�F�RǶ��s�B�6�fW$��r�f#�G'VWҒ�s�F�b6�73�&2���R#�r�W62�B�F�F�R��s��F�c��F�b6�73�&2�7V"#�r�W62�B�'F�7G��""��s��F�c���F�c�s�Ғ����""��s��F�c���F�c�s��Тf"Ɩ�VC�vWDƖ�VB�����b�Ɩ�VB��V�wF�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�$Ɩ�VB6��w2"��V���&�V�Ɩ�VB��"��s�F�b6�73�&�&�r#�r�Ɩ�VB�6Ɩ6R��"����gV�7F���Bƒ���&WGW&�s�F�b6�73�&�6&B"��6Ɩ6��'��Ɩ�VB�r���r�#�r�6�fW$�F�B�F�F�RǶ��s�B�6�fW$��r�f#�G'VWҒ�s�F�b6�73�&2���R#�r�W62�B�F�F�R��s��F�c��F�b6�73�&2�7V"#�r�W62�B�'F�7G��""��s��F�c���F�c�s�Ғ����""��s��F�c���F�c�s��Тf"ח��vWE��Ɨ7G2�����b�ח���V�wF�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�%��W"��Ɨ7G2"��V���&�V�ו��Ɨ7G2��"��s�F�b6�73�&�&�r#�r�ח��6Ɩ6R��"����gV�7F������&WGW&�s�F�b6�73�&�6&B"��6Ɩ6��&�V�ו��Ɨ7B���rr��B�u��r�#��F�b6�73�&6�fW""7G��S�&&6�w&�V�C�r�w&B����R��s�F�7���w&�C��6R֗FV�3�6V�FW#�6���#�6ffb#�r��2�'VWVU��W6�2"��s��F�c��F�b6�73�&2���R#�r�W62����R��s��F�c��F�b6�73�&2�7V"#�r��G&6�2��V�wF��r6��w3��F�c���F�c�s�Ғ����""��s��F�c���F�c�s��Т�b��'V�2��V�wF�bbfVB�&�'V�2"�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�$�Wr&V�V6W2"��V���&v�v�'V�2r�"��s�F�b6�73�&�&�r"�C�&�Wu&�r#�r��Wu&�t�F��'V�2��s��F�c���F�c�s��Т�b��V�"��V�wF�bbfVB�'�V�""�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�%�V�"F��2���F�"��s�F�b6�73�&�&�r#�r��V�"���gV�7F����v��F�r���'V�5���E��ð�&WGW&��'VԄ6&B���'D��W2���'F�7G2���Ғ����""��s��F�c���F�c�s��Т�b�vV�&W2��V�wF�bbfVB�&vV�&W2"�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�$vV�&W2"�&vV�&W2"��s�F�b6�73�&6��2#�r�vV�&W2���gV�7F���r���&WGW&�s�'WGF��6�73�&6��"��6Ɩ6��&�V�vV�&R�r�r�B�r�#�r�W62�vV���R�r���s��'WGF���s�Ғ����""��s��F�c���F�c�s��Т�b�6FVv�&�W2��V�wF�bbfVB�&6FVv�&�W2"�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�$6FVv�&�W2"��s�F�b6�73�&6��2#�r�6FVv�&�W2���gV�7F���2���&WGW&�s�'WGF��6�73�&6��"��6Ɩ6��&�V�6FVv�'��r�2�B�r�#�r�W62�vV���R�2���s��'WGF���s�Ғ����""��s��F�c���F�c�s��Т�b���Ɨ7G2��V�wF�bbfVB�'��Ɨ7G2"�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�%��Ɨ7G2"�'��Ɨ7G2"��s�F�b6�73�&�&�r#�r���Ɨ7G2���gV�7F�����f"������R����&WGW&�s�F�b6�73�&�6&B"��6Ɩ6��&�V���Ɨ7B�r��B�r�#�r�6�fW$�F���Ƕ��s��6F��vW����vR�f#�G'VWҒ�s�F�b6�73�&2���R#�r�W62��Ғ�s��F�c��F�b6�73�&2�7V"#���Ɨ7C��F�c���F�c�s�Ғ����""��s��F�c���F�c�s��Т�b�7F�&�W2��V�wF�bbfVB�'7F�&�W2"�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�%7F�&�W2"��s�F�b6�73�&�&�r#�r�7F�&�W2���gV�7F���2��f"����6��2�V���R�2�T��R���%7F�'�#��&WGW&�s�F�b6�73�&�6&B"��6Ɩ6��&�V�7F�'��r�2�B�r�#�r�6�fW$�F���Ƕ��s�2��vUW&�Ғ�s�F�b6�73�&2���R#�r�W62��Ғ�s��F�c���F�c�s�Ғ����""��s��F�c���F�c�s��Т�b��F��F���s�F�b6�73�&V�G�#���F���rF�6��r�WB�6�V6�6WGF��w2���F�c�s��6WEf�Wr��F���ғ��Т��'V��BF�R�Wr&V�V6W2&�r�B&V�V�&W"F�R�'V�26��v��6�vR6�FV�����v�V��Wr�W6�2�26��R���gV�7F����Wu&�t�F��'V�2��v��F�r���'V�3�v��F�r���'V�7�ǷӲ��Wt�G3��'V�2���gV�7F�����&WGW&��C�Ғ����"�"���&WGW&��'V�2���gV�7F����v��F�r���'V�5���E��ò&WGW&��'VԄ6&B���'D��W2���'F�7G2���Ғ����""��Т��WF��&Vg&W6��v���R��Rw&R�����R�V�WFǒ&R�6�V6�f�"�Wr�W6�2WfW'����֖�WFR�BWFFRF�R�Wr&V�V6W2&�r���6R�b�F���r6��vVB�f"��Wt�G3�"#��gV�7F���&Vg&W6��Wr����b�7W%F"��&���R"�&WGW&��b�F�7V�V�B憖FFV�&WGW&�f"&�s�B�&�Wu&�r"���b�&�r�&WGW&㰢�7B�"����Wr"ǷҒ�F�V�gV�7F���B��f"�'V�3�G&���FFV�B��'V�7�ŵғ��b��'V�2��V�wF��&WGW&㰢f"�G3��'V�2���gV�7F�����&WGW&��C�Ғ����"�"����b��G2����Wt�G2��&�r���W$�D����Wu&�t�F��'V�2����G&FT�6��2���ТҒ�6F6��gV�7F��ₗ�ғ�ТgV�7F����V�6FVv�'���B��6fU&�WFR�&6FVv�'�"ƖB��6WE7FGW2�""��6WEf�Wr�6V4�VB�$6FVv�'�"��s�F�b6�73�&w&�B�'V�2#�r�6�F��W2�b��s��F�c�r���w'VW'��6FVv�'��v�W&S���C�"��V�&W"��B��'Ғ��BV���R�T��R�'V�2��BV���R�T��R��vW2�6F�6���6F��VF�V��VF�V�6����'F�7G2�V���R�T��R�G&6�2��B����"��F�V�gV�7F���B���f"s�B�6FVv�'��f"�'V�3҆rbfr��'V�2��ŵӲ6WE7FGW2�""��v��F�r���'V�&6��gV�7F��ₗ�v�&���R"��Ӱ�f"�VC�s�F�b6�73�&&6�"��6Ɩ6��&v���v���U��r�#�r��2�&'&�u�&6����5��Wr"��t���S��F�c�r�6V4�VB�s�vV���R�r��$6FVv�'�"����b��'V�2��V�wF���6WEf�Wr��VB�s�F�b6�73�&V�G�#����'V�2��F��26FVv�'����F�c�r��&WGW&�Тv��F�r���'V�3�v��F�r���'V�7�ǷӲ6WEf�Wr��VB�s�F�b6�73�&w&�B�'V�2#�r��'V�2���gV�7F����v��F�r���'V�5���E��ò&WGW&��'V�F��R���'D��W2���'F�7G2���Ғ����""��s��F�c�r���Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��ТgV�7F����V�7F�'���B��6fU&�WFR�'7F�'�"ƖB����F��r�$��F��~(
b"���w'VW'��7F�'��v�W&S���C�"��V�&W"��B��'Ғ��BV���R�T��R��vUW&�'F�6�W2��BV���R�T��RFeW&�&V�V6TFFR��FW����"��F�V�gV�7F���B���f"3�B�7F�'��6WE7FGW2�""���b�2��6WEf�Wr�s�F�b6�73�&V�G�#�7F�'���Bf�V�B���F�c�r��&WGW&�Тf"����6��2�V���R�2�T��R���%7F�'�#�f"'G3҇2�'F�6�W7�ŵҒ�6Ɩ6R���6�'B�gV�7F��⇂ǒ��&WGW&�����FW����҇���FW�����ғ��f"&6��s�F�b6�73�&&6�"��6Ɩ6��&v���v���U��r�#�r��2�&'&�u�&6����5��Wr"��t���S��F�c�s��f"&�w3�'G2���gV�7F�����f"���6���V���R��T��R��%'B"��B���&WGW&�s�F�b6�73�'G&6�"��6Ɩ6��&�V�'F�6�R�r�W62��4���7G&��v�g���FeW&���""���&W�6R��"�r�"gV�C�"��r�#��F�b6�73�&�V�#�r��2�&fVGW&VE����Ɨ7B"��s��F�c��F�b6�73�'F�#�r�W62�⒲s��F�c��F�b6�73�&F�#�r��2�&6�Wg&���&�v�B"��s��F�c���F�c�s�Ғ����""���6WEf�Wr�&6��s�F�b6�73�&�W&�#�r�6�fW$�F���Ƕ��s�2��vUW&�Ғ�s�F�c��F�b6�73�&��6�W"#�7F�'���F�c�ƃ#�r�W62��Ғ�s���#��F�b6�73�'7V"#�r�'G2��V�wF��r'G3��F�c���F�c���F�c�r���'G2��V�wF��s�F�b6�73�'G&6�2#�r�&�w2�s��F�c�s�s�F�b6�73�&V�G�#���'G2F�&VB�WB���F�c�r����Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��ТgV�7F����V�'F�6�R�FeW&��b�FeW&�bb��GG3����FW7B�FeW&��v��F�r��V�FeW&��%�&��"���V�6R�F�7B�%F��2'B�2��Bf��&�R�"���Р�������������6V&6��&V��7&�726��w2��'V�2�'F�7G2����������Тf"�6V&6�B��6V&6�6W���6V&6�G&6�3յӰ�gV�7F���6V&6�f�Wr����6WEf�Wr�s�F�b6�73�'6V&6�&"#�r��2�'6V&6�"��sƖ�WB�C�'"G�S�'FW�B"�6V���FW#�%6V&6�6��w2��'V�2�'F�7G>(
b"WF�6���WFS�&�fb"����F�c��F�b�C�'7&W2#���F�c�r���f"�B�'"���f�7W2�����FDWfV�DƗ7FV�W"�&��WB"�gV�7F��ₗ�f"f��F��2�f�VS�6fU&�WFR�'6V&6�"�f�6�V%F��V�WB��6V&6�B���6V&6�C�6WEF��V�WB�gV�7F��ₗ�F�6V&6��f���#���ғ��F�6V&6��""���ТgV�7F�����Tf��FW"���&WGW&�$�#���V���S��6��F��3�GB���FS���6V�6�F�fW��Ƕ�T��S��6��F��3�GB���FS���6V�6�F�fW���#�ТgV�7F���F�6V&6��b���f"҇g��""��G&�҂��f"&���B�'7&W2"���b�&���&WGW&㰢�b���f"'3�vWE&V6V�E���&�����W$�D���s�F�b6�73�&V�G�#�G�RF�6V&6�6��w2��'V�2�B'F�7G2���F�c�r��'2��V�wF��s�F�b7G��S�'FF��s���#��F�b6�73�&�WFVB"7G��S�&f��B�6��S��s�&VӶ�&v��g�#�&V6V�B6V&6�W2��&Vc�"2"��6Ɩ6��&6�V%&V6V�E���&WGW&�f�6R"7G��S�&�&v����VgC���#�6�V#�����F�c�r�'2���gV�7F��⇂ƒ��&WGW&�s�7�6�73�&6��"7G��S�&F�7�����Ɩ�R�&��6���&v�������FF��s�w�7��&�&FW"�&F�W3������&6�w&�V�C�f"���7W&f6R�"��7W'6�#����FW""��6Ɩ6��'�6�&V6V�E�r���r�#�r�W62����s��7��s�Ғ����""��s��F�c�s�rr��&WGW&�Т&�����W$�D���s�F�b6�73�&V�G�#��7�6�73�'7���W"#���7��6V&6���~(
c��F�c�s��f"6WҲ��6V&6�6W��f"VW'��'VW'��GC�7G&��r��"��"'F�7G2�F�S�#B�v�W&S��"���Tf��FW"���'җ��BV���R�T��R��vR�"��"�'V�2�F�S�#B�v�W&S��"���Tf��FW"���'җ��BV���R�T��R��vW2�6F�6���6F��VF�V��VF�V�6����'F�7G2�V���R�T��R�G&6�2��B��"��"G&6�2�F�S�3�v�W&S��"���Tf��FW"���'җ��BV���R�T��Rf��RGW&F����'V����vW2�6F�6���6F��VF�V��VF�V�6�����'F�7G2�V���R�T��R��"��"�#��wVW'�ǷC�Ғ�F�V�gV�7F���B����b�6W���6V&6�6W�&WGW&����WvW"6V&6�7WW'6VFVBF��2��P�f"'G3�B�'F�7G7�ŵ���'3�B��'V�7�ŵ��G&�3�B�G&6�7�ŵӰ�v��F�r���'V�3�v��F�r���'V�7�ǷӲ�'2�f�$V6��gV�7F����v��F�r���'V�5���E��òғ���6V&6�G&6�3�G&�3���b�'G2��V�wF����'2��V�wF���G&�2��V�wF��6fU&V6V�E�����b�'G2��V�wF�bb�'2��V�wF�bbG&�2��V�wF���&�����W$�D���s�F�b6�73�&V�G�#���F���rf�V�Bf�"(	�r�W62���~(	����F�c�s�&WGW&�Тf"�F���"#���b�G&�2��V�wF�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�%6��w2"��s�F�b6�73�'G&6�2"7G��S�&�&v����#�r�G&�2���gV�7F���Bƒ���&WGW&�s�F�b6�73�'G&6�"��6Ɩ6��'��6V&6�G&6��r���r�#��F�b6�73�&�V�#�r��2�'���'&�r"��s��F�c�r��s�F�b6�73�'F�#�r�W62�G&6���R�B����B�'F�7G2bgB�'F�7G2��V�wF��s�F�b6�73�'7V"#�r�W62�'D��W2�B�'F�7G2���s��F�c�s�rr��s��F�c�r���B�GW&F����s�F�b6�73�'F��R#�r�f�B�B�GW&F��⒲s��F�c�s�rr���F�'F�B�B�B�f��R��s��F�c�s�Ғ����""��s��F�c���F�c�s��Т�b��'2��V�wF�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�$�'V�2"��s�F�b6�73�&w&�B�'V�2#�r��'2���gV�7F����&WGW&��'V�F��R���'D��W2���'F�7G2���Ғ����""��s��F�c���F�c�s��Т�b�'G2��V�wF�����F�³�s�F�b6�73�'6V2#�r�6V4�VB�$'F�7G2"��s�F�b6�73�&w&�B'F�7G2#�r�'G2���'F�7EF��R�����""��s��F�c���F�c�s��Т&�����W$�D��ևF�ð�Ғ�6F6��gV�7F���R���b�6W���6V&6�6W�&WGW&��b�R��W76vS���&��v��"�&WGW&�&�����W$�D���s�F�b6�73�&V�G�#�6V&6�W'&�#�r�W62�R��W76vR��s��F�c�s�ғ��ТgV�7F�����6V&6�G&6�������G&6�2��6V&6�G&6�7�ŵ����""��Р�������������vV�&W2���������ТgV�7F���'&�w6TvV�&W2�����F��r�$��F��rvV�&W>(
b"���w'VW'��vV�&W2�F�S�3���BV���R�T��R��"��F�V�gV�7F���B��f"w3�B�vV�&W7�ŵӲ6WE7FGW2�""����b�w2��V�wF���6WEf�Wr�s�F�b6�73�&V�G�#���vV�&W2���F�c�r��&WGW&�Т6WEf�Wr�6V4�VB�$vV�&W2"��s�F�b6�73�&6��2#�r�w2���gV�7F���r��&WGW&�s�'WGF��6�73�&6��"��6Ɩ6��&�V�vV�&R�r�r�B�r�#�r�W62�vV���R�r���s��'WGF���s�Ғ����""��s��F�c�r���Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��ТgV�7F����V�vV�&R��B��6fU&�WFR�&vV�&R"ƖB��6WE7FGW2�""��6WEf�Wr�6V4�VB�$vV�&R"��s�F�b6�73�&w&�B�'V�2#�r�6�F��W2�b��s��F�c�r���w'VW'��vV�&R�v�W&S���C�"��V�&W"��B��'Ғ��BV���R�T��R�'V�2��BV���R�T��R��vW2�6F�6���6F��VF�V��VF�V�6����'F�7G2�V���R�T��R�G&6�2��B����"��F�V�gV�7F���B���f"s�B�vV�&S�f"�'V�3҆rbfr��'V�2��ŵӲ6WE7FGW2�""��v��F�r���'V�&6��'&�w6TvV�&W3��f"�VC�s�F�b6�73�&&6�"��6Ɩ6��&'&�w6TvV�&W2��#�r��2�&'&�u�&6����5��Wr"��tvV�&W3��F�c�r�6V4�VB�s�vV���R�r��$vV�&R"����b��'V�2��V�wF���6WEf�Wr��VB�s�F�b6�73�&V�G�#����'V�2��F��2vV�&R���F�c�r��&WGW&�Тv��F�r���'V�3�v��F�r���'V�7�ǷӲ6WEf�Wr��VB�s�F�b6�73�&w&�B�'V�2#�r��'V�2���gV�7F����v��F�r���'V�5���E��ò&WGW&��'V�F��R���'D��W2���'F�7G2���Ғ����""��s��F�c�r���Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��Р���������������Ɨ7G2���������ТgV�7F���'&�w6U��Ɨ7G2���6WE7FGW2�""��6WEf�Wr�6V4�VB�%��Ɨ7G2"��s�F�b6�73�&w&�B�'V�2#�r�6�F��W2�b��s��F�c�r���w'VW'����Ɨ7G2�F�S�3���B��RV���R�T��R��vR6F��vR��"��F�V�gV�7F���B��f"3�B���Ɨ7G7�ŵӲ6WE7FGW2�""����b�2��V�wF���6WEf�Wr�s�F�b6�73�&V�G�#�����Ɨ7G2���F�c�r��&WGW&�Т6WEf�Wr�6V4�VB�%��Ɨ7G2"��s�F�b6�73�&w&�B�'V�2#�r�2���gV�7F�����f"������R����&WGW&�s�F�b6�73�'F��R�'V�"��6Ɩ6��&�V���Ɨ7B�r��B�r�#�r�6�fW$�F���Ƕ��s��6F��vW����vR�f#�G'VWҒ�s�F�b6�73�&2���R#�r�W62��Ғ�s��F�c��F�b6�73�&2�7V"#���Ɨ7C��F�c���F�c�s�Ғ����""��s��F�c�r���Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��ТgV�7F����V���Ɨ7B��B��6fU&�WFR�'��Ɨ7B"ƖB����F��r�$��F��~(
b"���w'VW'����Ɨ7B�v�W&S���C�"��V�&W"��B��'Ғ��B��RV���R�T��R��vR6F��vR��Ɨ7EG&6�2�G&6���BV���R�T��Rf��RGW&F���G&6��V�&W"'F�7G2�V���R�T��R�����"��F�V�gV�7F���B���f"�B���Ɨ7C�6WE7FGW2�""���f"G&6�3҂�bg���Ɨ7EG&6�2��ŵҒ���gV�7F��⇂��&WGW&���G&6��Ғ�f��FW"�&���V⓰�f"�������R���%��Ɨ7B#��&V�FW%G&6�Ɨ7B����G&6�2��V�wF��"G&6�2"�G&6�2�'&�w6U��Ɨ7G2��bb��6F��vW����vR���%��Ɨ7B"���Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��Р��������������'V�2�����WvW7Bf�'7B�v�F���B��&R����������Тf"��%vS׷6����F�S�3���F��s�f�6R�V�C�f�6WӰ�gV�7F���'&�w6T�'V�2������%vS׷6����F�S�3���F��s�f�6R�V�C�f�6WӰ�6WEf�Wr�6V4�VB�$�'V�2"��s�6�73�&�WFVB"7G��S�&�&v���G����#����'V�2��WvW7Bf�'7B(	B��B�B�WrF�vWF�W"�����F�b�C�&�$w&�B"6�73�&w&�B�'V�2#�r�6�F��W2����s��F�c��F�b�C�&�$��&R"7G��S�'FW�B�Ɩv�6V�FW#�FF��s���#���F�c�r�����D��&T�'V�2����ТgV�7F�����D��&T�'V�2�����b���%vR���F��w����%vR�V�B�&WGW&���%vR���F��s�G'VS��f"��&S�B�&�$��&R"���b���&R���&R���W$�D���s�7�6�73�'7���W"#���7����F��~(
bs���7B�"����'V�2"Ƿ6�����%vR�6���F�S���%vR�F�WҒ�F�V�gV�7F���B���f"&s�B��'V�7�ŵӲf"v�C�G&���FFV�&r��v��F�r���'V�3�v��F�r���'V�7�ǷӰ�v�B�f�$V6��gV�7F����v��F�r���'V�5���E��òғ��f"w&�C�B�&�$w&�B"���b�w&�B���b���%vR�6������w&�B���W$�D���"#�w&�B��6W'DF�6V�D�D�&&Vf�&VV�B"�v�B���gV�7F����&WGW&��'V�F��R���'D��W2���'F�7G2���Ғ����""���Т��%vR�6����&r��V�wF����%vR���F��s�f�6S���b�v�B��V�wF����%vR�F�R����%vR�V�C�G'VS��b���&R���&R���W$�D��҅��%vR�6���s�7�6�73�&�WFVB#�F�E��w2WfW'�F���r�r���%vR�6���r�'V�2����7��s�s�7�6�73�&V�G�#����'V�2���7��r��ТV�6R�b���&R����&R���W$�D���s�'WGF��6�73�&'F�v��7B"��6Ɩ6��&��D��&T�'V�2��#���B��&S��'WGF���s�ТҒ�6F6��gV�7F���R����%vR���F��s�f�6S��b�R��W76vS���&��v��"�&WGW&�f"��&S�B�&�$��&R"���b���&R���&R���W$�D���s�7�6�73�&W'"#�r�W62�R��W76vR��s��7��s�ғ��Р�������������'F�7G2���������Тf"�'F�7DƖ֗C�#��'F�7Df��FW#�"#��gV�7F�����&T'F�7G2����'F�7DƖ֗B��#�f"s�B�&'Dw&�B"���b�r�r���W$�D���'Dw&�D�F��'F�7Df��FW"��ТgV�7F���'Dw&�D�F���҇��""��G&�҂��F���vW$66R����f"Ɨ7C�'F�7G2�6Ɩ6R���6�'B�gV�7F����"��&WGW&���V���W��""����6�T6��&R�"�V���W��""��ғ���b��Ɨ7C�Ɨ7B�f��FW"�gV�7F�����&WGW&���V���W��""��F���vW$66R����FW��b������T��W��""��F���vW$66R����FW��b�����ғ��f"6��v��Ɨ7B�6Ɩ6R���'F�7DƖ֗B���&WGW&��6��v���V�wF��s�F�b6�73�&w&�B'F�7G2#�r�6��v����'F�7EF��R�����""��s��F�c�s�s�F�b6�73�&V�G�#���'F�7G2�F6����F�c�r���Ɨ7B��V�wF��6��v���V�wF��s�F�b6�73�&V�G�#�6��v��rr�6��v���V�wF��r�br�Ɨ7B��V�wF��r'F�7G2��'#��'WGF��6�73�&'F�v��7B"��6Ɩ6��&��&T'F�7G2��#���B��&R'F�7G3��'WGF�����F�c�s�rr��ТgV�7F���f��FW$'F�7G2�b���'F�7Df��FW#�c��'F�7DƖ֗C�#�f"s�B�&'Dw&�B"���b�r�r���W$�D���'Dw&�D�F�b��ТgV�7F���'&�w6T'F�7G2����'F�7Df��FW#�"#��'F�7DƖ֗C�#�V�7W&T'F�7G2���F�V�gV�7F��������b����&WGW&㰢6WEf�Wr�6V4�VB�$'F�7G2"��s�F�b6�73�'6V&6�&""7G��S�&�&v����'�#��7�6�73�&�2#�r��2�'6V&6�"��s��7��Ɩ�WB�C�&'E"G�S�'FW�B"�6V���FW#�$f��B�'F�7N(
b"WF�6���WFS�&�fb"���WC�&f��FW$'F�7G2�F��2�f�VR�#���F�c��F�b�C�&'Dw&�B#�r�'Dw&�D�F�""��s��F�c�r���ғ�Тf"�'F�7EG&6�3յ���'F�7E6��w4f�#���gV�7F���'F�7E6��t�V�R����f"C҅�'F�7EG&6�7�ŵҕ��Ӷ�b�B�6��t�V�R���&�G&6��B���ТgV�7F�����'F�7EG&6�������G&6�2��'F�7EG&6�7�ŵ����""��ТgV�7F�����D'F�7E6��w2��B���&R��f"&���B�&'E6��w2"���b�&���&WGW&��b���&R���'F�7EG&6�3յӲ�'F�7E6��w4f�#֖C�&�����W$�D���s�F�b6�73�&V�G�#��7�6�73�'7���W"#���7����F��r6��w>(
c��F�c�s�Тf"6����'F�7EG&6�2��V�wF���w'VW'��G&6�2�F�S�c�6���"�6���"�v�W&S��'F�7G3��6��S���C��WV�3�"��V�&W"��B��'���Ғ��BV���R�T��Rf��RGW&F����'V����vW2�6F�6���6F��VF�V��VF�V�6�����'F�7G2�V���R�T��R���"��F�V�gV�7F���B����b��'F�7E6��w4f�"�֖G��B�&'E6��w2"��&WGW&�f"v�C�B�G&6�7�ŵӲ�'F�7EG&6�3��'F�7EG&6�2�6��6B�v�B��f"#�B�&'E6��w2"����b��'F�7EG&6�2��V�wF���"���W$�D���rs�&WGW&�Т"���W$�D���6V4�VB�%6��w2"��s�F�b6�73�'G&6�2"7G��S�&�&v����#�r��'F�7EG&6�2���gV�7F���Bƒ���&WGW&�s�F�b6�73�'G&6�"��6Ɩ6��'��'F�7EG&6��r���r�#��F�b6�73�&�V�#�r��2�'���'&�r"��s��F�c�r��s�F�b6�73�'F�#�r�W62�G&6���R�B����B�'F�7G2bgB�'F�7G2��V�wF��s�F�b6�73�'7V"#�r�W62�'D��W2�B�'F�7G2���s��F�c�s�rr��s��F�c�r���B�GW&F����s�F�b6�73�'F��R#�r�f�B�B�GW&F��⒲s��F�c�s�rr��F�'F�B�B�B�f��R��s�'WGF��6�73�&��'F�"F�F�S�%6��r�F���2"��6Ɩ6��&WfV�B�7F�&�vF��ₓ�'F�7E6��t�V�R�r���r�#�r��2�&��&U�fW'B"��s��'WGF�����F�c�s�Ғ����""��s��F�c�r���v�B��V�wF���c�s�F�b7G��S�'FW�B�Ɩv�6V�FW#��&v��'�#��'WGF��6�73�&'F�v��7B"��6Ɩ6��&��D'F�7E6��w2�r��V�&W"��B��r�G'VR�#���B��&R6��w3��'WGF�����F�c�s�rr���Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�f"#�B�&'E6��w2"���b�"bb��&R�"���W$�D���rs�ғ��Р�gV�7F����V�'F�7B��B��6fU&�WFR�&'F�7B"ƖB��6WE7FGW2�""��6WEf�Wr�6�FWF������7B�"���'F�7B"Ƕ�C��GҒ�F�V�gV�7F���B��f"�B�'F�7B��'V�3҆bf��'V�2��ŵӲv��F�r��'F�7E&V6�&G3�v��F�r��'F�7E&V6�&G7�ǷӲ�b��v��F�r��'F�7E&V6�&G5��E���6WE7FGW2�""��f"�����6���V���R��T��R���$'F�7B"��$'F�7B#�f"�C��4UB���s���&�R"���V���W��""����T��W��""���"#�v��F�r��7W$'F�7C��Ӱ�f"&�����&�����6���V�FW62��TFW62���""��"#��f"��6�7F���3�s�F�b6�73�&6��2"7G��S�&�&v��'���#��'WGF���C�&f����t'F�7B"6�73�&6��"��6Ɩ6��&f����t��6�'F�7B�r��V�&W"��B��r�#�r��f����vVD'F�7B��B��tf����v��r�V�f����rs�tf����r'F�7Br��s��'WGF����'WGF��6�73�&6��"��6Ɩ6��'6�&UvR��#�6�&R'F�7C��'WGF�����F�c�s��f"�VC�s�F�b6�73�&&6�"��6Ɩ6��&v���v���U��r�#�r��2�&'&�u�&6����5��Wr"��t&6���F�c�r��s�F�b6�73�&�W&�#�r�6�fW$�F���Ƿ&�V�C�G'VRƖ�s��bf��vR�Ғ�s�F�c��F�b6�73�&��6�W"#�'F�7C��F�c�ƃ#�r�W62��Ғ�s���#�r���C�s�F�b6�73�'7V"#�r�W62��B��s��F�c�s�rr����fVB�&ff�&�FW2"�bd�R�W6W#�s�F�b6�73�&7F���2#��'WGF��6�73�&'F�v��7B6�"��6Ɩ6��'6fT'F�7B�r��V�&W"��B��r�#�r��2�&ff�&�FU�&�&FW""��r6fRF�6���V7FVBƖ'&'���'WGF�����F�c�s�rr��s��F�c���F�c�r���&���s�6�73�&�WFVB"7G��S�&�&v���g������Ɩ�RֆV�v�C��s�f��B�6��S��'&V�#�r�W62�&��s���s�rr���v��F�r���'V�&6��gV�7F��ₗ��V�'F�7B��B��Ӱ��b��'V�2��V�wF���6WEf�Wr��VB���6�7F���2�s�F�b�C�&'E6��w2#���F�c�r����D'F�7E6��w2��B��&WGW&�Тv��F�r���'V�3�v��F�r���'V�7�ǷӲ6WEf�Wr��VB���6�7F���2�6V4�VB�$�'V�2"��s�F�b6�73�&w&�B�'V�2#�r��'V�2���gV�7F����v��F�r���'V�5���E��ò&WGW&��'V�F��R����G&6�7�ŵҒ��V�wF��"G&6�2"��Ғ����""��s��F�c��F�b�C�&'E6��w2#���F�c�r����D'F�7E6��w2��B���Ғ�6F6��gV�7F���R��6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��Р��������������'V����������ТgV�7F����V��'V҆�B��6fU&�WFR�&�'V�"ƖB��6WE7FGW2�""��6WEf�Wr�6�FWF�����w'VW'���'V҇v�W&S���C�"��V�&W"��B��'Ғ��BV���R�T��R��vW2�6F��VF�V�6F��&vR�VF�V��&vR�'F�7G2�V���R�T��R��vR�G&6�2��BV���R�T��Rf��RGW&F���G&6��V�&W"���"��F�V�gV�7F���B���f"��B��'VӲ6WE7FGW2�""���b��6WEf�Wr�s�F�b6�73�&V�G�#��'V���Bf�V�B���F�c�r��&WGW&�Тv��F�r���'V�3�v��F�r���'V�7�ǷӲv��F�r���'V�5��E��ò&V�FW$�'V҆�B���Ғ�6F6��gV�7F���R���b�R��W76vS���&��v��"�&WGW&�6WE7FGW2�$W'&�#�"�W62�R��W76vR��&W'""��ғ��ТgV�7F���&V�FW$�'V҆�B���f"G&6�3���G&6�7�ŵӲf"'F�7D��S҆��'F�7G2bf��'F�7G2��V�wF���'D��W2���'F�7G2���v��F�r��7W$'F�7G��""���f"&6��s�F�b6�73�&&6�"��6Ɩ6��"r��v��F�r���'V�&6��wv��F�r���'V�&6���s�vv���v���U��r�r��r#�r��2�&'&�u�&6����5��Wr"��t&6���F�c�s�� var rows=tracks.map(function(t,i){ return '<div class="track" id="trk'+t.id+'"><div class="num" onclick="playAlbum('+id+','+i+')">'+(t.trackNumber||i+1)+'</div>'+
        '<div class="tk" onclick="playAlbum('+id+','+i+')">'+esc(trackName(t))+'</div>'+(t.duration?'<div class="time">'+fmt(t.duration)+'</div>':'')+
        dlBtn(t.id,t.file)+'<button class="np-btn" title="More" onclick="songMenuAlbum('+id+','+i+')">'+ic("more_vert")+'</button></div>'; }).join("");
      setView(back+'<div class="hero">'+coverHtml(albName(al),{img:albImg(al)})+'<div><div class="kicker">Album'+(artistName?' · '+esc(artistName):'')+'</div><h2>'+esc(albName(al))+'</h2><div class="sub">'+tracks.length+' tracks</div>'+
        '<div class="actions">'+(tracks.length?'<button class="btn" onclick="playAlbum('+id+',0)">'+ic("play_arrow")+' Play all</button><button class="btn ghost" onclick="shuffleAlbum('+id+')">'+ic("shuffle")+' Shuffle</button>':'')+(feat("favorites")&&ME.user?'<button class="btn ghost" onclick="saveAlbum('+id+')">'+ic("favorite_border")+' Save to connected library</button>':'')+((dlAllowed()&&tracks.length)?'<button class="btn ghost" onclick="downloadAlbum('+id+')">'+ic("download")+' Download all</button>':'')+'</div>'+
        (ME.admin?('<div class="chips" style="padding:0;margin-top:10px"><span class="muted" style="font-size:.74rem;align-self:center;margin-right:2px">Admin:</span>'+
          '<button class="chip" id="curFeat" onclick="curate('+id+',\\''+(isFeatured(id)?'unfeature':'feature')+'\\')">'+ic(isFeatured(id)?"star":"star_border")+(isFeatured(id)?' Unpin from Home':' Pin to Home')+'</button>'+
          '<button class="chip" id="curHide" onclick="curate('+id+',\\''+(isHidden(id)?'unhide':'hide')+'\\')">'+ic(isHidden(id)?"visibility":"visibility_off")+(isHidden(id)?' Unhide':' Hide from everyone')+'</button></div>'):'')+
        '</div></div><div class="chips" style="margin:12px 18px"><button class="chip" onclick="saveLocalAlbum('+Number(id)+')">'+(savedAlbum(id)?'Saved on device - remove':'Save album on device')+'</button><button class="chip" onclick="sharePage()">Share album</button></div>'+
        (tracks.length?'<div class="tracks">'+rows+'</div>':'<div class="empty">No tracks.</div>'));
      highlightPlaying();
    }
    function clearCurate(which){ if(!confirm("Clear all "+(which==="featured"?"pinned":"hidden")+" albums?")) return;
      post("/api/admin/curate",{action:which==="featured"?"clearfeatured":"clearhidden"}).then(function(d){
        CFG.featured=(d.featured||[]).map(Number); CFG.hidden=(d.hidden||[]).map(Number); toast("Cleared."); loadAccess();
      }).catch(function(e){ toast(e.message||"Couldn’t clear."); }); }
    function curate(id, action){ toast("Saving…");
      post("/api/admin/curate",{id:id,action:action}).then(function(d){
        CFG.featured=(d.featured||[]).map(Number); CFG.hidden=(d.hidden||[]).map(Number);
        toast(action==="feature"?"Pinned to Home ★":action==="unfeature"?"Unpinned.":action==="hide"?"Hidden from everyone.":"Unhidden.");
        if(window._albums&&window._albums[id]) renderAlbum(id, window._albums[id]);
      }).catch(function(e){ toast(e.message||"Couldn’t save."); }); }

    // ---------- Track list (playlists) ----------
    function renderTrackList(title, subtitle, tracks, backFn, img, kicker){
      window._listTracks=tracks; window._listBack=backFn;
      var back='<div class="back" onclick="window._listBack&&window._listBack()">'+ic("arrow_back_ios_new")+'Back</div>';
      var rows=tracks.map(function(t,i){ return '<div class="track" id="ltrk'+t.id+'" onclick="playList('+i+')"><div class="num">'+(i+1)+'</div>'+
        '<div class="tk">'+esc(trackName(t))+(t.artists&&t.artists.length?'<div class="sub">'+esc(artNames(t.artists))+'</div>':'')+'</div>'+
        (t.duration?'<div class="time">'+fmt(t.duration)+'</div>':'')+
        dlBtn(t.id,t.file)+'<button class="np-btn" title="Song options" onclick="event.stopPropagation();listSongMenu('+i+')">'+ic("more_vert")+'</button></div>'; }).join("");
      setView(back+'<div class="hero">'+coverHtml(title,{img:img})+'<div><div class="kicker">'+esc(kicker||"Collection")+'</div><h2>'+esc(title)+'</h2><div class="sub">'+esc(subtitle)+'</div>'+
        '<div class="actions">'+(tracks.length?'<button class="btn" onclick="playList(0)">'+ic("play_arrow")+' Play all</button><button class="btn ghost" onclick="shuffleList()">'+ic("shuffle")+' Shuffle</button>':'')+'</div></div></div>'+
        (tracks.length?'<div class="tracks">'+rows+'</div>':'<div class="empty">No tracks.</div>'));
      highlightPlaying();
    }
    function listSongMenu(i){var t=(window._listTracks||[])[i];if(t)songMenu(normTrack(t));}
    function playList(i){ playTracks(window._listTracks||[], i, ""); }

    // ---------- Player ----------
    var audio=$("audio"), _players=[audio,document.createElement("audio")], _warm=null, _warmTimer=null; _players[1].id="audioNext"; _players[1].preload="none"; document.body.appendChild(_players[1]); var _audioAdd=audio.addEventListener; audio.addEventListener=function(k,fn,opt){ _players.forEach(function(p){ _audioAdd.call(p,k,function(e){ if(p===audio) fn.call(p,e); },opt); }); }; function warmNext(){ return; /* prefetch disabled: next-track swap removed, kept simple single-element playback */ clearTimeout(_warmTimer); _warmTimer=setTimeout(function(){ if(audio.paused||!queue.length||(navigator.connection&&navigator.connection.saveData)) return; var p=_order.indexOf(qi), n=_repeat==="one"?qi:(p+1<_order.length?_order[p+1]:(_repeat==="all"&&!_shuffle?_order[0]:-1)), t=queue[n]; if(!t) return; var src=trackSrc(t,false); if(_warm&&_warm.src===src) return; var spare=_players[0]===audio?_players[1]:_players[0]; _warm={el:spare,src:src}; spare.preload="auto"; spare.src=src; spare.load(); },600); } _players.forEach(function(p){ _audioAdd.call(p,"playing",function(){ if(p===audio) warmNext(); }); }); function selectAudio(t){ var src=trackSrc(t,false), old=audio, ready=_warm&&_warm.src===src&&!_warm.el.error&&_warm.el.readyState>=2; clearTimeout(_warmTimer); if(_fadeTimer){clearInterval(_fadeTimer);_fadeTimer=null;} if(ready){ audio=_warm.el; _warm=null; audio.muted=old.muted; old.pause(); old.removeAttribute("src"); old.load(); if(audio.readyState>=1) audio.dispatchEvent(new Event("loadedmetadata")); } else { _warm=null; var spare=_players[0]===audio?_players[1]:_players[0]; spare.removeAttribute("src"); spare.load(); audio.preload="auto"; audio.src=src; } }
    var _retry=0, _fails=0;
    var _shuffle=false, _repeat="off", _order=[], _dur=0;
    try{ _shuffle=localStorage.getItem("zing_shuffle")==="1"; _repeat=localStorage.getItem("zing_repeat")||"off"; }catch(e){}
    // Build the play order (a permutation of queue indices). Shuffle keeps the
    // current track first so playback continues smoothly.
    function buildOrder(startIdx){ _order=queue.map(function(_,i){ return i; });
      if(_shuffle){ for(var i=_order.length-1;i>0;i--){ var j=Math.floor(Math.random()*(i+1)); var t=_order[i]; _order[i]=_order[j]; _order[j]=t; }
        var pos=_order.indexOf(startIdx); if(pos>0){ var tmp=_order[0]; _order[0]=_order[pos]; _order[pos]=tmp; } } }
    function startQueue(tracks, index){ _fails=0; _diagShown=false; queue=tracks; buildOrder(index); playIndex(index); }
    function playAlbum(albumId, index){ var al=(window._albums||{})[albumId]; if(!al) return; var tracks=al.tracks||[];
      var artistName=(al.artists&&al.artists.length)?artNames(al.artists):(window._curArtist||""); var aimg=albImg(al);
      startQueue(tracks.map(function(t){ return {id:t.id, file:t.file||"", title:trackName(t), artist:artistName, cover:albName(al), coverImg:aimg}; }), index); }
    function playTracks(tracks, index, ctx){ startQueue(tracks.map(function(t){ return {id:t.id, file:t.file||"", title:trackName(t), artist:(t.artists&&t.artists.length?artNames(t.artists):(ctx||"")), cover:ctx||trackName(t), coverImg:(t.album&&t.album.images)?(t.album.images.cdnSmall||t.album.images.cdnMedium||t.album.images.small):null}; }), index); }
    function trackSrc(t,bust){ return "/api/play?trackId="+encodeURIComponent(t.id)+"&file="+encodeURIComponent(t.file)+(bust?("&r="+Date.now()):""); }
    function playIndex(i){ if(i<0||i>=queue.length) return; qi=i; var t=queue[i]; _retry=0; _dur=0; _resumed=false;
      setActivity("Playing: "+(t.title||""));
      audio=_players[0]; try{ _players[1].pause(); }catch(e){} _warm=null; audio.src=trackSrc(t,false); try{ audio.playbackRate=SET.speed||1; }catch(e){} audio.volume=(SET.fade?0:(SET.vol==null?1:SET.vol));
      audio.play().catch(function(){});
      $("player").hidden=false; $("npTitle").textContent=t.title; $("npArtist").textContent=t.artist||"";
      var cu=imgUrl(t.coverImg);
      if(cu){ $("npCover").style.background=""; $("npCover").style.backgroundImage="url('"+cu+"')"; $("npCover").style.backgroundSize="cover"; $("npCover").style.backgroundPosition="center"; $("npCover").innerHTML=""; }
      else { $("npCover").style.backgroundImage=""; $("npCover").style.background=grad(t.cover||t.title); $("npCover").innerHTML='<span class="disc"></span>'; }
      setPlayIcon(true); highlightPlaying(); syncSheet();
      try{ if(window.ZingNative&&ZingNative.updateNowPlaying){ ZingNative.updateNowPlaying(String(t.title||""),String(t.artist||""),String(imgUrl(t.coverImg)||"")); } }catch(e){}
    }
    window.zingMediaAction=function(a){ try{ if(a==="toggle") togglePlay(); else if(a==="next") nextTrack(); else if(a==="prev") prevTrack(); }catch(e){} };
    function setPlayIcon(p){ $("playBtn").innerHTML=ic(p?"pause":"play_arrow"); var b=$("shPlay"); if(b) b.innerHTML=ic(p?"pause":"play_arrow"); }
    function highlightPlaying(){ var cur=queue[qi]; document.querySelectorAll(".track.playing").forEach(function(el){ el.classList.remove("playing"); });
      if(cur){ var el=$("trk"+cur.id)||$("ltrk"+cur.id); if(el) el.classList.add("playing"); } }
    function togglePlay(){ if(!queue.length) return; if(audio.paused) audio.play(); else audio.pause(); }
    // Advance to the next queue index in the current play order.
    function nextInOrder(){ var pos=_order.indexOf(qi); var np=pos+1;
      if(np>=_order.length){ if(_repeat==="all"){ if(_shuffle) buildOrder(_order.length?_order[0]:0); return _order.length?_order[0]:-1; } return -1; }
      return _order[np]; }
    function nextTrack(){ if(!queue.length) return; if(_repeat==="one"){ playIndex(qi); return; } var n=nextInOrder(); if(n>=0){ playIndex(n); return; } if(_repeat==="off" && SET.radio) extendRadio(); }
    // Endless radio: when the queue runs out, keep going with similar songs.
    function extendRadio(){ var t=queue[qi]; if(!t){ return; }
      gql("query { relatedTracks(trackId:"+Number(t.id)+", take: 20) { track { id enName heName file duration artists { enName heName } album { images { cdnSmall cdnMedium } } } } }").then(function(d){
        var list=(d.relatedTracks||[]).map(function(x){return x.track;}).filter(Boolean).filter(function(tk){ return !queue.some(function(q){ return q.id===tk.id; }); });
        if(!list.length){ toast("End of the queue."); return; }
        var startIdx=queue.length;
        list.forEach(function(tk){ queue.push(normTrack({id:tk.id,file:tk.file||"",title:trackName(tk),artist:(tk.artists&&tk.artists.length?artNames(tk.artists):""),coverImg:(tk.album&&tk.album.images)?(tk.album.images.cdnSmall||tk.album.images.cdnMedium):null})); _order.push(queue.length-1); });
        toast("Radio — more like this ♫"); playIndex(startIdx);
      }).catch(function(){ toast("End of the queue."); }); }
    function prevTrack(){ if(audio.currentTime>3){ audio.currentTime=0; return; } if(!queue.length) return;
      var pos=_order.indexOf(qi); var pp=pos-1; if(pp<0){ if(_repeat==="all") pp=_order.length-1; else { audio.currentTime=0; return; } } playIndex(_order[pp]); }
    function toggleShuffle(){ _shuffle=!_shuffle; try{ localStorage.setItem("zing_shuffle",_shuffle?"1":"0"); }catch(e){} if(queue.length) buildOrder(qi); syncSheet(); toast(_shuffle?"Shuffle on":"Shuffle off"); }
    function cycleRepeat(){ _repeat=(_repeat==="off"?"all":(_repeat==="all"?"one":"off")); try{ localStorage.setItem("zing_repeat",_repeat); }catch(e){} syncSheet(); toast(_repeat==="off"?"Repeat off":(_repeat==="all"?"Repeat all":"Repeat one")); }
    audio.addEventListener("play", function(){ setPlayIcon(true); try{ if("mediaSession" in navigator) navigator.mediaSession.playbackState="playing"; }catch(e){} });
    audio.addEventListener("pause", function(){ setPlayIcon(false); savePos(); try{ if("mediaSession" in navigator) navigator.mediaSession.playbackState="paused"; }catch(e){} });
    var _resumed=false, _fadeTimer=null;
    audio.addEventListener("playing", function(){ _fails=0; var t=queue[qi]; pushHistory(t); reportPlay(t); setMediaMeta(t); // played fine → clear failures, record history + stats
      try{ audio.playbackRate=SET.speed||1; }catch(e){}
      if(SET.fade){ if(_fadeTimer) clearInterval(_fadeTimer); var target=(SET.vol==null?1:SET.vol); audio.volume=0; var step=target/16; _fadeTimer=setInterval(function(){ var v=audio.volume+step; if(v>=target){ v=target; clearInterval(_fadeTimer); _fadeTimer=null; } audio.volume=v; },40); }
    });
    var _lastReport=0;
    function reportPlay(t){ if(!t) return; var now=Date.now(); if(now-_lastReport<3000) return; _lastReport=now;
      post("/api/played",{track:t.id,title:t.title||"",artist:t.artist||""}).catch(function(){}); }
    audio.addEventListener("ended", function(){ var t=queue[qi]; if(t) clearPos(t.id); if(_sleepEnd){ _sleepEnd=false; toast("Sleep timer — paused"); syncSheet(); return; } nextTrack(); }); // keep playing one after another
    audio.addEventListener("loadedmetadata", function(){ _dur=audio.duration||0; var d=$("shDur"); if(d) d.textContent=fmt(_dur);
      // Resume long tracks (shiurim/stories) where you left off.
      if(SET.resume && !_resumed){ _resumed=true; var t=queue[qi]; if(t && _dur>600){ var p=getPos(t.id); if(p>30 && p<_dur-30){ try{ audio.currentTime=p; toast("Resumed where you left off"); }catch(e){} } } } });
    var _lastPosSave=0;
    audio.addEventListener("timeupdate", function(){ if(audio.duration){ var pct=Math.round(audio.currentTime/audio.duration*1000); $("seek").value=String(pct); var s=$("shSeek"); if(s) s.value=String(pct); var c=$("shCur"); if(c) c.textContent=fmt(audio.currentTime);
      var now=Date.now(); if(now-_lastPosSave>4000){ _lastPosSave=now; savePos(); } } });
    // Remember position for long tracks only, so you can resume.
    function posMap(){ try{ return JSON.parse(localStorage.getItem("zing_pos")||"{}")||{}; }catch(e){ return {}; } }
    function getPos(id){ return posMap()[String(id)]||0; }
    function savePos(){ var t=queue[qi]; if(!t||!audio.duration||audio.duration<=600) return; try{ var m=posMap(); if(audio.currentTime>30 && audio.currentTime<audio.duration-30){ m[String(t.id)]=Math.floor(audio.currentTime); } else { delete m[String(t.id)]; } var ks=Object.keys(m); if(ks.length>60){ ks.slice(0,ks.length-60).forEach(function(k){ delete m[k]; }); } localStorage.setItem("zing_pos",JSON.stringify(m)); }catch(e){} }
    function clearPos(id){ try{ var m=posMap(); delete m[String(id)]; localStorage.setItem("zing_pos",JSON.stringify(m)); }catch(e){} }
    // Skip forward / back by the chosen interval.
    function skipBy(sec){ if(!audio.duration) return; audio.currentTime=Math.max(0,Math.min(audio.duration,audio.currentTime+sec)); }
    function cycleSpeed(){ var opts=[1,1.25,1.5,1.75,2,0.75]; var i=opts.indexOf(SET.speed); SET.speed=opts[(i+1)%opts.length]; saveSettings(); try{ audio.playbackRate=SET.speed; }catch(e){} var b=$("shSpeed"); if(b) b.innerHTML=speedLabel(); toast("Speed "+SET.speed+"×"); }
    function speedLabel(){ return (SET.speed||1)+"×"; }
    function setVol(v){ SET.vol=Math.max(0,Math.min(1,v/100)); saveSettings(); if(!(_fadeTimer)) audio.volume=SET.vol; }
    // Media Session: show controls + artwork on the phone lock screen / notification.
    function setMediaMeta(t){ if(!("mediaSession" in navigator)||!t) return; try{
        var art=imgUrl(t.coverImg); var meta={ title:t.title||"", artist:t.artist||"", album:(CFG.appName||"Zing") };
        if(art) meta.artwork=[{src:art,sizes:"512x512",type:"image/jpeg"}];
        navigator.mediaSession.metadata=new MediaMetadata(meta);
      }catch(e){} }
    if("mediaSession" in navigator){ try{
      navigator.mediaSession.setActionHandler("play", function(){ audio.play(); });
      navigator.mediaSession.setActionHandler("pause", function(){ audio.pause(); });
      navigator.mediaSession.setActionHandler("previoustrack", function(){ prevTrack(); });
      navigator.mediaSession.setActionHandler("nexttrack", function(){ nextTrack(); });
      navigator.mediaSession.setActionHandler("seekbackward", function(){ skipBy(-(SET.skip||15)); });
      navigator.mediaSession.setActionHandler("seekforward", function(){ skipBy(SET.skip||15); });
    }catch(e){} }
    // If a track won't load: retry once, then skip past a single bad track. But
    // if several in a row fail, it's the music-server login — stop churning and
    // show one clear message (pointing the owner to the setup).
    function playbackDown(){ audio.pause();
      if(ME.admin){ toast("Music won’t play — set the Music server login in ⚙ Settings → Admin."); }
      else { toast("Music isn’t playing right now — please tell the owner."); } }
    // Owner-only: when a track fails, capture exactly why (audio error code +
    // the real HTTP response from the music server) so we can pinpoint the bug.
    var _diagShown=false;
    function diagPlay(t){ if(!ME.admin||!t||_diagShown) return; _diagShown=true;
      var ec=(audio.error&&audio.error.code)||0; var codes={1:"aborted",2:"network",3:"decode",4:"format not supported"};
      var info="Track: "+(t.title||"")+"\\nid="+t.id+"\\nfile="+(t.file||"(none)")+"\\naudio.error="+ec+" ("+(codes[ec]||"?")+")";
      fetch(trackSrc(t,true),{headers:{Range:"bytes=0-1"}}).then(function(r){ info+="\\n/api/play → HTTP "+r.status+"  "+(r.headers.get("Content-Type")||"");
        if(r.status>=400){ return r.text().then(function(tx){
          try{ var j=JSON.parse(tx); if(j.error) info+="\\nerror: "+j.error; var dg=j.diag;
            if(dg){ if(dg.build) info+="\\nBUILD: "+dg.build;
              if(dg.firebaseKeyFound!==undefined) info+="\\nFirebase key found: "+(dg.firebaseKeyFound?"yes":"NO");
              if(dg.firebaseLoginOk!==undefined) info+="\\nFirebase login: "+(dg.firebaseLoginOk?"OK ✓":"FAILED ✗");
              if(dg.firebaseLoginError) info+="\\nFirebase error: "+dg.firebaseLoginError;
              if(dg.realTrack!==undefined) info+="\\nreal track "+dg.realTrack+" → ?token range: "+dg.audio_real_range+"  full: "+dg.audio_real_full+"  Bearer: "+dg.audio_real_bearer;
              if(dg.sampleTrack!==undefined) info+="\\nsample track "+dg.sampleTrack+" → ?token: "+dg.audio_sample;
              if(dg.catalogSummary) info+="\\ncatalog scan (10 albums): "+JSON.stringify(dg.catalogSummary)+"  "+JSON.stringify(dg.catalogScan).slice(0,260);
              if(dg.tokenClaims) info+="\\ntoken: iss="+(dg.tokenClaims.iss||"?")+" aud="+(dg.tokenClaims.aud||"?")+(dg.tokenClaims.user_id?(" uid="+dg.tokenClaims.user_id):"");
              if(dg.startStreamingSession){ var ss=dg.startStreamingSession; info+="\\nstartStreamingSession: "+(ss.found?("args["+(ss.args||[]).join(", ")+"] returns "+ss.returns):JSON.stringify(ss)); }
              if(dg.sessionResult){ var sr=dg.sessionResult; info+="\\nSessionResult fields: "+(sr.fields?sr.fields.join(", "):JSON.stringify(sr)); }
              if(dg.sessionTry){ var tr=dg.sessionTry;
                info+="\\nsession try: userId="+tr.userId+" profileId="+tr.profileId+" deviceId="+tr.deviceId;
                if(tr.devices){ if(tr.devices.list) info+="\\n  devices: "+JSON.stringify(tr.devices.list).slice(0,300); if(tr.devices.tried&&tr.devices.tried.length) info+="\\n  device-query errs: "+JSON.stringify(tr.devices.tried).slice(0,300); }
                if(tr.createDeviceInput) info+="\\n  UserDeviceCreateInput: "+(tr.createDeviceInput.fields?tr.createDeviceInput.fields.join(", "):JSON.stringify(tr.createDeviceInput)).slice(0,400);
                if(tr.osEnum) info+="\\n  OS enum: "+(Array.isArray(tr.osEnum)?tr.osEnum.join(", "):JSON.stringify(tr.osEnum));
                if(tr.sessionAttempts) info+="\\n  session attempts: "+JSON.stringify(tr.sessionAttempts).slice(0,400);
                if(tr.streamQueries) info+="\\n  stream queries: "+tr.streamQueries.join(", ");
                if(tr.streamMutations) info+="\\n  stream mutations: "+tr.streamMutations.join(", ");
                if(tr.heartbeatArgs) info+="\\n  updateSessionHeartbeat: "+(tr.heartbeatArgs.args?("args["+tr.heartbeatArgs.args.join(", ")+"] returns "+tr.heartbeatArgs.returns):JSON.stringify(tr.heartbeatArgs));
                if(tr.openedWith!==undefined) info+="\\n  opened with deviceId="+tr.openedWith+" session="+JSON.stringify(tr.session);
                if(tr.heartbeatCall) info+="\\n  heartbeat: "+(tr.heartbeatErrors&&tr.heartbeatErrors.length?("ERR "+tr.heartbeatErrors.join(" | ")):("ok "+JSON.stringify(tr.heartbeatResult||{})));
                if(tr.audioAfterSession) info+="\\n  audio after session: "+JSON.stringify(tr.audioAfterSession);
                if(tr.error) info+="\\n  error: "+tr.error; }
              if(dg.recon){ var rc=dg.recon; info+="\\nrecon bundles: "+((rc.bundles||[]).length); if(rc.error) info+="\\n  recon error: "+rc.error; if(rc.hits){ for(var kw in rc.hits){ info+="\\n  ["+kw+"] "+rc.hits[kw].join("  ||  "); } } }
              if(dg.note) info+="\\nnote: "+dg.note; }
          }catch(e){ info+="\\nbody: "+(tx||"").slice(0,400); }
          showDiag(info); }); } showDiag(info);
      }).catch(function(e){ info+="\\nfetch error: "+((e&&e.message)||e); showDiag(info); }); }
    function showDiag(info){ window._copy=info; overlay("Why it won’t play", '<pre dir="ltr" style="white-space:pre-wrap;word-break:break-word;font-size:.8rem;margin:0">'+esc(info)+'</pre><button class="btn sm" style="margin-top:10px" onclick="copyText(this)">Copy</button><div class="muted" style="margin-top:8px">Send this to the developer.</div>'); }
    audio.addEventListener("error", function(){ var t=queue[qi]; if(!t) return;
      if(_retry<1){ _retry++; audio.src=trackSrc(t,true); audio.play().catch(function(){}); return; }
      // Find out *why* it failed: a 403 means this one track is locked/unavailable
      // (most of the catalog still plays), not that the whole player is down.
      fetch(trackSrc(t,true),{headers:{Range:"bytes=0-1"}}).then(function(r){ return r.json().catch(function(){ return {}; }).then(function(j){ return {st:r.status, msg:(j && j.error) || ""}; }); }).catch(function(){ return {st:0, msg:""}; }).then(function(res){
        var locked=(res.st===403);
        var msg=res.msg || "This song isn’t available to stream right now.";
        _fails++; var n=nextInOrder();
        if(n>=0 && _fails<3){ if(locked) toast(msg + " — skipping."); else toast("Skipping a track that won’t play…"); playIndex(n); return; }
        // Nothing else to try.
        if(locked){ toast(msg); }
        else { playbackDown(); } // real outage (login/server) ⇒ alert
      });
    });
    $("seek").addEventListener("input", function(){ if(audio.duration){ audio.currentTime=this.value/1000*audio.duration; } });
    function dlCurrent(){ var t=queue[qi]; if(t) downloadTrack(t.id, t.file); }

    // ---------- Recently played (History) ----------
    function pushHistory(t){ if(!t) return; try{ var h=JSON.parse(localStorage.getItem("zing_hist")||"[]"); if(!Array.isArray(h)) h=[];
      h=h.filter(function(x){ return x&&x.id!==t.id; }); h.unshift({id:t.id,file:t.file||"",title:t.title||"",artist:t.artist||"",coverImg:t.coverImg||null,at:Date.now()}); h=h.slice(0,60);
      localStorage.setItem("zing_hist",JSON.stringify(h)); }catch(e){} }
    function getHistory(){ try{ var h=JSON.parse(localStorage.getItem("zing_hist")||"[]"); return Array.isArray(h)?h:[]; }catch(e){ return []; } }
    function openHistory(){ var h=getHistory();
      if(!h.length){ overlay("Recently played", '<div class="empty">Nothing played yet. Your recently played songs will show here.</div>'); return; }
      var rows=h.map(function(t,i){ return '<div class="track" onclick="playHistory('+i+')"><div class="np-mini" style="background:'+(imgUrl(t.coverImg)?("center/cover url(\\'"+esc(imgUrl(t.coverImg))+"\\')"):grad(t.title))+'"></div>'+
        '<div class="tk">'+esc(t.title)+(t.artist?'<div class="sub">'+esc(t.artist)+'</div>':'')+'</div><div class="np-btn" onclick="event.stopPropagation();dlFromHistory('+i+')">'+ic("play_arrow")+'</div></div>'; }).join("");
      overlay("Recently played", '<div class="tracks">'+rows+'</div>'); }
    function playHistory(i){ var h=getHistory(); if(!h[i]) return; startQueue(h.map(function(x){ return {id:x.id,file:x.file||"",title:x.title,artist:x.artist,cover:x.title,coverImg:x.coverImg}; }), i); closeOverlay(true); }
    function dlFromHistory(i){ var h=getHistory(); if(h[i]) playHistory(i); }

    // ---------- Liked songs (♥ per track, kept on this device) ----------
    function getLiked(){ try{ var l=JSON.parse(localStorage.getItem("zing_liked")||"[]"); return Array.isArray(l)?l:[]; }catch(e){ return []; } }
    function isLiked(id){ return getLiked().some(function(x){ return x.id===id; }); }
    function toggleLike(t){ if(!t) return; var l=getLiked(); var was=l.some(function(x){ return x.id===t.id; });
      if(was){ l=l.filter(function(x){ return x.id!==t.id; }); } else { l.unshift({id:t.id,file:t.file||"",title:t.title||"",artist:t.artist||"",coverImg:t.coverImg||null}); l=l.slice(0,300); }
      try{ localStorage.setItem("zing_liked",JSON.stringify(l)); }catch(e){}
      toast(was?"Removed from Liked":"Added to Liked ♥"); syncSheet(); }
    function likeCurrent(){ toggleLike(queue[qi]); }
    function openLiked(){ var l=getLiked();
      if(!l.length){ overlay("Liked songs", '<div class="empty">No liked songs yet. Tap the ♥ on a song to save it here.</div>'); return; }
      var rows=l.map(function(t,i){ return '<div class="track" onclick="playLiked('+i+')"><div class="np-mini" style="background:'+(imgUrl(t.coverImg)?("center/cover url(\\'"+esc(imgUrl(t.coverImg))+"\\')"):grad(t.title))+'"></div>'+
        '<div class="tk">'+esc(t.title)+(t.artist?'<div class="sub">'+esc(t.artist)+'</div>':'')+'</div><div class="np-btn" onclick="event.stopPropagation();unlike('+t.id+')">'+ic("favorite")+'</div></div>'; }).join("");
      overlay("Liked songs", '<div class="tracks">'+rows+'</div>'); }
    function playLiked(i){ var l=getLiked(); if(!l[i]) return; startQueue(l.map(function(x){ return {id:x.id,file:x.file||"",title:x.title,artist:x.artist,cover:x.title,coverImg:x.coverImg}; }), i); closeOverlay(true); }
    function unlike(id){ toggleLike({id:id}); openLiked(); }

    // ---------- Sleep timer ----------
    var _sleepAt=0, _sleepTimer=null;
    function openSleep(){ var opts=[["off","Off"],["15","15 minutes"],["30","30 minutes"],["45","45 minutes"],["60","1 hour"],["end","End of this song"]];
      var cur=_sleepAt?("in "+Math.max(1,Math.round((_sleepAt-Date.now())/60000))+" min"):(_sleepEnd?"end of song":"off");
      overlay("Sleep timer", '<p class="muted" style="margin:0 0 12px">Music stops automatically. Currently: '+esc(cur)+'.</p>'+
        '<div class="tracks">'+opts.map(function(o){ return '<div class="track" onclick="setSleep(\\''+o[0]+'\\')"><div class="tk">'+esc(o[1])+'</div>'+((o[0]==="off"&&!_sleepAt&&!_sleepEnd)?'<div class="np-eq">'+ic("favorite")+'</div>':'')+'</div>'; }).join("")+'</div>'); }
    var _sleepEnd=false;
    function setSleep(v){ if(_sleepTimer){ clearTimeout(_sleepTimer); _sleepTimer=null; } _sleepAt=0; _sleepEnd=false;
      if(v==="off"){ toast("Sleep timer off"); }
      else if(v==="end"){ _sleepEnd=true; toast("Will stop at end of this song"); }
      else { var mins=parseInt(v,10); _sleepAt=Date.now()+mins*60000; _sleepTimer=setTimeout(function(){ audio.pause(); _sleepAt=0; toast("Sleep timer — paused"); syncSheet(); }, mins*60000); toast("Sleep timer set for "+mins+" min"); }
      closeOverlay(true); syncSheet(); }

    // ---------- Queue actions: play next / add to queue ----------
    function normTrack(t){ return {id:t.id, file:t.file||"", title:t.title||trackName(t)||"", artist:t.artist||(t.artists&&t.artists.length?artNames(t.artists):""), cover:t.cover||t.title||"", coverImg:t.coverImg||((t.album&&t.album.images)?(t.album.images.cdnSmall||t.album.images.cdnMedium):null)||null}; }
    function playNext(t){ if(!t) return; if(!queue.length){ startQueue([normTrack(t)],0); toast("Playing"); return; }
      queue.push(normTrack(t)); var idx=queue.length-1; var pos=_order.indexOf(qi); _order.splice(pos+1,0,idx); toast("Playing next ▸"); syncSheet(); }
    function addToQueue(t){ if(!t) return; if(!queue.length){ startQueue([normTrack(t)],0); toast("Playing"); return; }
      queue.push(normTrack(t)); _order.push(queue.length-1); toast("Added to queue"); syncSheet(); }

    // ---------- Your own playlists (kept on this device) ----------
    function getPlaylists(){ try{ var l=JSON.parse(localStorage.getItem("zing_playlists")||"[]"); return Array.isArray(l)?l:[]; }catch(e){ return []; } }
    function savePlaylists(l){ try{ localStorage.setItem("zing_playlists",JSON.stringify(l)); }catch(e){} }
    function createPlaylist(name){ name=(name||"").trim(); if(!name) return null; var l=getPlaylists(); var pl={id:Date.now().toString(36)+Math.random().toString(36).slice(2,6),name:name.slice(0,60),tracks:[]}; l.unshift(pl); savePlaylists(l); return pl; }
    function addToPlaylist(plId,t){ var l=getPlaylists(); var pl=l.filter(function(p){return p.id===plId;})[0]; if(!pl||!t) return; if(pl.tracks.some(function(x){return x.id===t.id;})){ toast("Already in “"+pl.name+"”"); return; } pl.tracks.push(normTrack(t)); savePlaylists(l); toast("Added to “"+pl.name+"” ♪"); }
    function removeFromPlaylist(plId,trackId){ var l=getPlaylists(); var pl=l.filter(function(p){return p.id===plId;})[0]; if(!pl) return; pl.tracks=pl.tracks.filter(function(x){return x.id!==trackId;}); savePlaylists(l); openMyPlaylist(plId); }
    function deletePlaylist(plId){ if(!confirm("Delete this playlist?")) return; savePlaylists(getPlaylists().filter(function(p){return p.id!==plId;})); openMyPlaylists(); }
    function newPlaylistPrompt(){ var n=prompt("Playlist name:"); if(n===null) return; var pl=createPlaylist(n); if(pl){ toast("Playlist created"); openMyPlaylist(pl.id); } }
    function openMyPlaylists(){ var l=getPlaylists();
      var head='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><b style="font-size:1.05rem">Your playlists</b><button class="chip" onclick="newPlaylistPrompt()">'+ic("person_add")+' New</button></div>';
      if(!l.length){ overlay("Your playlists", head+'<div class="empty">No playlists yet. Make one, then add songs from the ⋮ menu or the player.</div>'); return; }
      var rows=l.map(function(p){ return '<div class="track" onclick="openMyPlaylist(\\''+p.id+'\\')"><div class="np-mini" style="background:'+grad(p.name)+';display:grid;place-items:center;color:#fff">'+ic("queue_music")+'</div><div class="tk">'+esc(p.name)+'<div class="sub">'+p.tracks.length+' songs</div></div>'+ic("chevron_right")+'</div>'; }).join("");
      overlay("Your playlists", head+'<div class="tracks">'+rows+'</div>'); }
    function openMyPlaylist(plId){ var l=getPlaylists(); var pl=l.filter(function(p){return p.id===plId;})[0]; if(!pl){ openMyPlaylists(); return; }
      var head='<div class="back" onclick="openMyPlaylists()">'+ic("arrow_back_ios_new")+'Playlists</div>'+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin:0 0 10px"><div><div style="font-weight:800;font-size:1.15rem">'+esc(pl.name)+'</div><div class="muted" style="font-size:.85rem">'+pl.tracks.length+' songs</div></div>'+
        (pl.tracks.length?'<button class="btn sm" onclick="playMyPlaylist(\\''+pl.id+'\\',0)">'+ic("play_arrow")+' Play</button>':'')+'</div>';
      var rows=pl.tracks.length? pl.tracks.map(function(t,i){ return '<div class="track"><div class="np-mini" onclick="playMyPlaylist(\\''+pl.id+'\\','+i+')" style="background:'+(imgUrl(t.coverImg)?("center/cover url('"+esc(imgUrl(t.coverImg))+"')"):grad(t.title))+'"></div>'+
        '<div class="tk" onclick="playMyPlaylist(\\''+pl.id+'\\','+i+')">'+esc(t.title)+(t.artist?'<div class="sub">'+esc(t.artist)+'</div>':'')+'</div>'+
        '<button class="iconbtn" aria-label="Move song up" '+(i===0?'disabled':'')+' onclick="movePlaylistTrack('+esc(JSON.stringify(pl.id))+','+i+',-1)">'+ic("arrow_upward")+'</button><button class="iconbtn" aria-label="Move song down" '+(i===pl.tracks.length-1?'disabled':'')+' onclick="movePlaylistTrack('+esc(JSON.stringify(pl.id))+','+i+',1)">'+ic("arrow_downward")+'</button><button class="trash" title="Remove" onclick="removeFromPlaylist(\\''+pl.id+'\\','+t.id+')">'+ic("close")+'</button></div>'; }).join("") : '<div class="empty">No songs yet. Add from the ⋮ menu on a song or the player.</div>';
      overlay("Playlist", head+'<div class="tracks">'+rows+'</div>'+'<div class="chips" style="margin-top:14px"><button class="chip" onclick="renamePlaylist('+esc(JSON.stringify(pl.id))+')">Rename</button><button class="chip" onclick="duplicatePlaylist('+esc(JSON.stringify(pl.id))+')">Duplicate</button><button class="chip" onclick="deletePlaylist(\\''+pl.id+'\\')">'+ic("delete")+' Delete playlist</button></div>'); }
    function playMyPlaylist(plId,i){ var pl=getPlaylists().filter(function(p){return p.id===plId;})[0]; if(!pl||!pl.tracks.length) return; startQueue(pl.tracks.map(normTrack), i); closeOverlay(true); }
    // Choose which playlist to add a song to (or make a new one).
    function choosePlaylist(t){ if(!t) return; window._addTrack=normTrack(t); var l=getPlaylists();
      var rows=l.map(function(p){ return '<div class="track" onclick="addToPlaylistUI(\\''+p.id+'\\')"><div class="np-mini" style="background:'+grad(p.name)+';display:grid;place-items:center;color:#fff">'+ic("queue_music")+'</div><div class="tk">'+esc(p.name)+'<div class="sub">'+p.tracks.length+' songs</div></div></div>'; }).join("");
      overlay("Add to playlist", '<button class="btn" style="width:100%;justify-content:center;margin-bottom:12px" onclick="newPlaylistAdd()">'+ic("person_add")+' New playlist</button>'+(l.length?('<div class="tracks">'+rows+'</div>'):'<div class="empty">No playlists yet — make one above.</div>')); }
    function addToPlaylistUI(plId){ addToPlaylist(plId, window._addTrack); closeOverlay(true); }
    function newPlaylistAdd(){ var n=prompt("Playlist name:"); if(n===null) return; var pl=createPlaylist(n); if(pl&&window._addTrack){ addToPlaylist(pl.id, window._addTrack); } closeOverlay(true); }

    // ---------- Song menu (⋮): like, add to playlist, play next, add to queue ----------
    function songMenu(t){ if(!t) return; window._menuTrack=normTrack(t); var liked=isLiked(t.id);
      var item=function(icn,label,fn){ return '<div class="track" onclick="'+fn+'"><div class="np-btn">'+ic(icn)+'</div><div class="tk">'+esc(label)+'</div></div>'; };
      overlay(t.title||"Song", '<div class="muted" style="margin:-4px 0 10px">'+esc(t.artist||"")+'</div><div class="tracks">'+
        item(liked?"favorite":"favorite_border", liked?"Remove from Liked":"Add to Liked", "menuLike()")+
        item("queue_music","Add to playlist","menuPlaylist()")+
        item("play_arrow","Play next","menuPlayNext()")+
        item("queue_music","Add to queue","menuAddQueue()")+item("share","Share song","shareSong(window._menuTrack)")+
        '</div>'); }
    function menuLike(){ toggleLike(window._menuTrack); closeOverlay(true); }
    function menuPlaylist(){ var t=window._menuTrack; closeOverlay(true); choosePlaylist(t); }
    function menuPlayNext(){ playNext(window._menuTrack); closeOverlay(true); }
    function menuAddQueue(){ addToQueue(window._menuTrack); closeOverlay(true); }
    function songMenuAlbum(albId, idx){ var al=(window._albums||{})[albId]; if(!al) return; var t=(al.tracks||[])[idx]; if(!t) return;
      songMenu({id:t.id,file:t.file||"",title:trackName(t),artist:(al.artists&&al.artists.length?artNames(al.artists):(window._curArtist||"")),coverImg:albImg(al)}); }

    // ---------- Lyrics ----------
    function showLyrics(){ var t=queue[qi]; if(!t){ return; } toast("Loading lyrics…");
      gql("query { track(where:{id:"+Number(t.id)+"}) { enName heName heLyrics enLyrics } }").then(function(d){
        var tr=d.track||{}; var lyr=tr.heLyrics||tr.enLyrics||""; if(!lyr){ toast("No lyrics for this track."); return; }
        overlay((tr.enName||tr.heName||t.title), '<pre dir="auto">'+esc(lyr)+'</pre>');
      }).catch(function(e){ if(e.message==="login")return; toast("Could not load lyrics."); });
    }
    // ---------- Now Playing sheet (full player) ----------
    var _npTab="queue";
    function openNowPlaying(){ var t=queue[qi]; if(!t){ return; }
      var cu=imgUrl(t.coverImg);
      var cover = cu ? '<div class="np-art" id="npArt" style="background-image:url(\\''+esc(cu)+'\\')"></div>'
                     : '<div class="np-art" id="npArt" style="background:'+grad(t.cover||t.title)+'"><span class="disc"></span></div>';
      overlay("Now Playing", cover+
        '<div class="np-info"><div class="np-tt" id="shTitle">'+esc(t.title)+'</div><div class="muted" id="shArtist">'+esc(t.artist||"")+'</div></div>'+
        '<div class="np-prog"><input type="range" class="np-seek big" id="shSeek" min="0" max="1000" value="0" oninput="seekTo(this.value)" /><div class="np-times"><span id="shCur">0:00</span><span id="shDur">'+(_dur?fmt(_dur):"0:00")+'</span></div></div>'+
        '<div class="np-controls">'+
          '<button class="np-c" id="shShuffle" title="Shuffle" onclick="toggleShuffle()">'+ic("shuffle")+'</button>'+
          '<button class="np-c" title="Previous" onclick="prevTrack()">'+ic("skip_previous")+'</button>'+
          '<button class="np-c play" id="shPlay" title="Play/Pause" onclick="togglePlay()">'+ic(audio.paused?"play_arrow":"pause")+'</button>'+
          '<button class="np-c" title="Next" onclick="nextTrack()">'+ic("skip_next")+'</button>'+
          '<button class="np-c" id="shRepeat" title="Repeat" onclick="cycleRepeat()">'+ic("repeat")+'</button>'+
        '</div>'+
        '<div class="np-controls2">'+
          '<button class="np-c2" id="shSpeed" title="Playback speed" onclick="cycleSpeed()">'+speedLabel()+'</button>'+
          '<button class="np-c2" title="Back '+SET.skip+' seconds" onclick="skipBy(-(SET.skip||15))">'+ic("fast_rewind")+SET.skip+'s</button>'+
          '<button class="np-c2" title="Forward '+SET.skip+' seconds" onclick="skipBy(SET.skip||15)">'+SET.skip+'s'+ic("fast_forward")+'</button>'+
        '</div>'+
        '<div class="np-vol">'+ic("volume_up")+'<input type="range" min="0" max="100" value="'+Math.round((SET.vol==null?1:SET.vol)*100)+'" oninput="setVol(this.value)" class="np-seek" aria-label="Volume" /></div>'+
        '<div class="np-actions"><button class="chip" id="shLike" onclick="likeCurrent()">'+ic(isLiked(t.id)?"favorite":"favorite_border")+' Like</button><button class="chip" onclick="choosePlaylist(queue[qi])">'+ic("playlist_add")+' Playlist</button><button class="chip" onclick="openSleep()">'+ic("bedtime")+' Sleep</button><button class="chip" onclick="openEqualizer()">Equalizer</button><button class="chip" onclick="shareSong(queue[qi])">Share song</button><button class="chip" onclick="dlCurrent()">'+ic("download")+' Download</button><button class="chip" onclick="openHistory()">'+ic("history")+' Recently played</button></div>'+
        '<div class="seg np-seg" style="margin:4px 0 12px"><button id="npTQ" onclick="npTab(\\'queue\\')">Up next</button><button id="npTL" onclick="npTab(\\'lyrics\\')">Lyrics</button><button id="npTS" onclick="npTab(\\'similar\\')">Similar</button></div>'+
        '<div id="npExtra"></div>');
      syncSheet(); npTab(_npTab);
    }
    function seekTo(v){ if(audio.duration){ audio.currentTime=v/1000*audio.duration; } }
    function npTab(which){ _npTab=which; ["npTQ","npTL","npTS"].forEach(function(id){ var e=$(id); if(e) e.classList.remove("on"); });
      var m={queue:"npTQ",lyrics:"npTL",similar:"npTS"}; var on=$(m[which]); if(on) on.classList.add("on");
      if(which==="queue") npQueue(); else if(which==="lyrics") npLyrics(); else npSimilar(); }
    // Keep the open sheet in sync with the player state.
    function syncSheet(){ var t=queue[qi]; var sh=$("shTitle"); if(!sh) return; // sheet not open
      sh.textContent=(t&&t.title)||""; var sa=$("shArtist"); if(sa) sa.textContent=(t&&t.artist)||"";
      var art=$("npArt"); if(art&&t){ var cu=imgUrl(t.coverImg); if(cu){ art.style.background=""; art.style.backgroundImage="url('"+cu+"')"; art.style.backgroundSize="cover"; art.style.backgroundPosition="center"; art.innerHTML=""; } else { art.style.backgroundImage=""; art.style.background=grad(t.cover||t.title); art.innerHTML='<span class="disc"></span>'; } }
      var sp=$("shPlay"); if(sp) sp.innerHTML=ic(audio.paused?"play_arrow":"pause");
      var sf=$("shShuffle"); if(sf) sf.classList.toggle("on",_shuffle);
      var sr=$("shRepeat"); if(sr){ sr.classList.toggle("on",_repeat!=="off"); sr.innerHTML=ic(_repeat==="one"?"repeat_one":"repeat"); }
      var lk=$("shLike"); if(lk&&t){ var liked=isLiked(t.id); lk.classList.toggle("on",liked); lk.innerHTML=ic(liked?"favorite":"favorite_border")+" Like"; }
      if(_npTab==="queue" && $("npExtra")) npQueue();
    }
    // Up-next: the tracks coming after the current one, in play order.
    function npQueue(){ var e=$("npExtra"); if(!e) return; var pos=_order.indexOf(qi); var items=[];
      for(var k=pos;k<_order.length;k++){ items.push(_order[k]); }
      if(items.length<=1){ e.innerHTML='<div class="empty">Nothing else in the queue.</div>'; return; }
      e.innerHTML='<div class="tracks">'+items.map(function(qidx){ var t=queue[qidx]; var now=(qidx===qi);
        return '<div class="track'+(now?" playing":"")+'" onclick="jumpQueue('+qidx+')"><div class="np-mini" style="background:'+(imgUrl(t.coverImg)?("center/cover url('"+esc(imgUrl(t.coverImg))+"')"):grad(t.cover||t.title))+'"></div>'+
          '<div class="tk">'+esc(t.title)+(t.artist?'<div class="sub">'+esc(t.artist)+'</div>':'')+'</div>'+(now?'<div class="np-eq">'+ic("graphic_eq")+'</div>':'<button class="iconbtn" aria-label="Move up in queue" onclick="event.stopPropagation();moveQueueTrack('+qidx+',-1)">'+ic("arrow_upward")+'</button><button class="iconbtn" aria-label="Move down in queue" onclick="event.stopPropagation();moveQueueTrack('+qidx+',1)">'+ic("arrow_downward")+'</button><button class="iconbtn" title="Remove from queue" onclick="event.stopPropagation();removeFromQ('+qidx+')">'+ic("close")+'</button>')+'</div>'; }).join("")+
        '<div style="padding:10px 0;text-align:center"><button class="btn" onclick="clearUpcoming()">Clear upcoming</button></div></div>';
    }
    function removeFromQ(idx){ if(idx===qi||idx<0||idx>=queue.length) return; queue.splice(idx,1); if(idx<qi) qi--;
      _order=_order.filter(function(x){ return x!==idx; }).map(function(x){ return x>idx?x-1:x; }); npQueue(); }
    function clearUpcoming(){ var pos=_order.indexOf(qi); var keep=_order.slice(0,pos+1); var cur=queue[qi];
      var keepSet={}; keep.forEach(function(x){ keepSet[x]=1; }); var map={}; var nq=[];
      queue.forEach(function(t,i){ if(keepSet[i]){ map[i]=nq.length; nq.push(t); } });
      queue=nq; _order=keep.map(function(x){ return map[x]; }); qi=map[qi]; npQueue(); toast("Cleared upcoming songs."); }
    function jumpQueue(qidx){ playIndex(qidx); }
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
        var html='<div class="back" onclick="go(\\'home\\')">'+ic("arrow_back_ios_new")+'Home</div>'+secHead("My Music")+
          '<div class="chips" style="margin-bottom:6px"><button class="chip" onclick="openMyPlaylists()">'+ic("queue_music")+' Your playlists</button><button class="chip" onclick="openLiked()">'+ic("favorite")+' Liked songs</button><button class="chip" onclick="openHistory()">'+ic("history")+' Recently played</button></div>'; var any=false;
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
    function setSpeed(v){ var n=parseFloat(v); if([0.75,1,1.25,1.5,1.75,2].indexOf(n)<0) n=1; SET.speed=n; saveSettings(); try{ audio.playbackRate=n; }catch(e){} segMark("segSpeed",v); var b=$("shSpeed"); if(b) b.innerHTML=speedLabel(); }
    function setSkip(v){ var n=parseInt(v,10); if([10,15,30].indexOf(n)<0) n=15; SET.skip=n; saveSettings(); segMark("segSkip",v); }
    function setResume(v){ SET.resume=(v==="on"); saveSettings(); segMark("segResume",v); }
    function setFade(v){ SET.fade=(v==="on"); saveSettings(); segMark("segFade",v); if(!SET.fade && !_fadeTimer){ audio.volume=(SET.vol==null?1:SET.vol); } }
    function setRadio(v){ SET.radio=(v==="on"); saveSettings(); segMark("segRadio",v); }
    function clearData(key,label){ if(!confirm("Clear "+label+"?")) return; try{ localStorage.removeItem(key); }catch(e){} toast(label+" cleared"); }
    function signOut(){ location.href="/api/logout"; }
    function appUpdateHtml(){
      if(!window.ZingNative) return "";
      var ver="unknown";
      try{ ver=ZingNative.getAppVersion()+" (build "+ZingNative.getAppBuild()+")"; }catch(e){}
      return '<div class="set-sec"><h3>App updates</h3><div class="card">'+
        row("Zing app","Installed: "+ver,'<button class="chip" onclick="checkAppUpdate()">Check for updates</button>')+
      '</div></div>';
    }
    function checkAppUpdate(){ try{ window.ZingNative.checkForUpdates(); toast("Checking for updates\u2026"); }catch(e){ toast("Update check neeG2F�R���r�G&��B"���ТgV�7F���6��uV��f򂗲f"C�B�&F�r"���b�B�B���W$�D���s�F�b6�73�&6&B"7G��S�'FF��s�W�#��F�b6�73�''B#�'&�w6W"V�v��S��F�c��F�b6�73�&�WFVB"7G��S�'v�&B�'&V��'&V���ö�&v���F��g�#�r�W62��f�vF�"�W6W$vV�B��s��F�c���F�c�s�ТgV�7F���6WGF��w4�F����f"WF��4UB�WF����&��#�&�fb#�f"&F���4UB�&F���&��#�&�fb#��&WGW&�rr��s�F�b6�73�'v�&�76R�&��W"#��F�b6�73�&��6�W"#���R�B��U%3��F�c�ƃ#�6WGF��w2bƗ7FV��rF���3���#��6�73�&�WFVB#�W'6���&VfW&V�6W2&R6fVB��F��2'&�w6W"�����F�b6�73�&6��2#��'WGF��6�73�&6��"��6Ɩ6��&�V�WVƗ�W"��#�WVƗ�W#��'WGF����'WGF��6�73�&6��"��6Ɩ6��&�V�W'6���֗�W2��#�W'6���֗�W3��'WGF����'WGF��6�73�&6��"��6Ɩ6��&�V�6�VW��#�6�VWF��W#��'WGF����'WGF��6�73�&6��"��6Ɩ6��&�W�&�&D�V���#�W�&�&B6��'F7WG3��'WGF����'WGF��6�73�&6��"��6Ɩ6��'6�&UvR��#�6�&RvS��'WGF�����F�c���F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3�V&�6S���3��F�b6�73�&6&B#�r��&�r�$66V�B"�%��W"W'6���6���#�F�W2��B6��vRF�R6�FRf�"�F�W'2"�6VtV'W�66V�B"ŵ�'6�FR"�%6�FR%�Ų'W'�R"�%W'�R%�Ų&w&VV�"�$w&VV�%�Ų&&�VR"�$&�VR%�Ų'&�6R"�%&�6R%���U��66V�B�'6WD66V�B"����&�r�$FV�6�G�"�%&��ג�"6��7B6��rƗ7G2"�6VtV'W�FV�6�G�"ŵ�&6��f�'F&�R"�%&��ג%�Ų&6��7B"�$6��7B%���U��FV�6�G��'6WDFV�6�G�"����&�r�$��F���"�%W6R��W"FWf�6R&VfW&V�6R�"GW&���F���2�fb"�6VtV'W���F���"ŵ�'7�7FV�"�%7�7FV�%�Ų'&VGV6VB"�%&VGV6VB%���U����F����'6WD��F���"����s��F�c���F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3����3��F�b6�73�&6&B#�r��&�r�$��wVvR"�%6��r��W2��V�vƗ6��"�V'&Wr"�6VtV'6Vt��r"ŵ�&V�"�$V�vƗ6�%�Ų&�R"�%�SVS%�SVC�SVS��SVC��SVV%���4UB���r�'6WD��r"����&�r�%F�V�R"�$F&��"Ɩv�B����"�6VtV'6VuF�V�R"ŵ�&F&�"�$F&�%�Ų&Ɩv�B"�$Ɩv�B%���4UB�F�V�R�'6WEF�V�R"����&�r�$WF���"�%��F�R�W�BG&6�WF��F�6�ǒ"�6VtV'6VtWF�"ŵ�&��"�$��%�Ų&�fb"�$�fb%���WF��'6WDWF���"����&�r�$WF���&F��"�$�VW����r6�֖�"6��w2v�V�F�RVWVRV�G2"�6VtV'6Vu&F��"ŵ�&��"�$��%�Ų&�fb"�$�fb%���&F���'6WE&F��"����s��F�c���F�c�r��WFFT�F����s�F�b6�73�'6WB�6V2#�ƃ3���&6����3��F�b6�73�&6&B#�r��&�r�%7VVB"�$FVfV�B��&6�7VVB"�6VtV'6Vu7VVB"ŵ�#�sR"�#�sU�SCr%�Ų#"�#�SCr%�Ų#�#R"�#�#U�SCr%�Ų#�R"�#�U�SCr%�Ų#""�#%�SCr%���7G&��r�4UB�7VVB��'6WE7VVB"����&�r�%6��'WGF��2"�$��rf"F�R6��'WGF��2�V�"�6VtV'6Vu6��"ŵ�#"�#2%�Ų#R"�#W2%�Ų#3"�#32%���7G&��r�4UB�6����'6WE6��"����&�r�%&W7V�R���rG&6�2"�$6��F��VR6��W&��b7F�&�W2v�W&R��R7F�VB"�6VtV'6Vu&W7V�R"ŵ�&��"�$��%�Ų&�fb"�$�fb%���4UB�&W7V�S�&��#�&�fb"�'6WE&W7V�R"����&�r�$fFR��"�$V6RV6�G&6���vV�Fǒ"�6VtV'6VtfFR"ŵ�&��"�$��%�Ų&�fb"�$�fb%���4UB�fFS�&��#�&�fb"�'6WDfFR"����s��F�c���F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3�VF��bF�v���G3���3��F�b6�73�&6&B#�r��&�r�$VF��VƗG�"�$�&�v���VƗG�&�f�FVB'�F�R�W6�26�W&6R���W�G&&�G&FR�"�ffƖ�RF�W"�2f��&�R�"�""���&�r�$�'V�F�v���B6��f�&�F���"�$6�&Vf�&R7F'F��r�V�F��RF�v���G2"�6VtV'W�F�v���B"ŵ�&��"�$��%�Ų&�fb"�$�fb%���U��6��f�&�F�v���G3�&��#�&�fb"�'6WDF�v���D6��f�&�"����&�r�$F�v���B��6F���"�%��W"'&�w6W"6��G&��2F�RF�v���Bf��FW"�Bf��R&��G2"�""���s��F�c��6�73�&�WFVB#�fFR֖��2f��&�R&�fR�7&�76fFR�BG'VRv�W72��&6�&R��B7W�'FVB'�F��27G&V֖�r��W"�&V֗V�&W7G&�7F���27F���ǒ������F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3��W"Ɩ'&'����3��F�b6�73�&6&B#�r��&�r�$Ɩ'&'�"�$'&�w6R����W"�W6�2"��2�&6�Wg&���&�v�B"��&'&�w6TƖ'&'���"���&�r�%��W"��Ɨ7G2"�%��Ɨ7G2��U�wfR�FR"��2�&6�Wg&���&�v�B"��&�V�ו��Ɨ7G2��"���&�r�$Ɩ�VB6��w2"�%6��w2��U�wfR�S#ccU�vB"��2�&6�Wg&���&�v�B"��&�V�Ɩ�VB��"���&�r�%&V6V�Fǒ��VB"�%��W"����7F�'�"��2�&6�Wg&���&�v�B"��&�V䆗7F�'���"���s��F�c���F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3�7F�&vR��F��2FWf�6S���3��F�b6�73�&6&B#�r��&�r�$6�V"��7F�'�"�%&V��fR��W"&V6V�Fǒ��VBƗ7B"��2�&FV�WFR"��&6�V$FF��w���u���7E�r��u&V6V�Fǒ��VE�r�"���&�r�$6�V"Ɩ�VB6��w2"�%&V��fR����W"Ɩ�VB6��w2"��2�&FV�WFR"��&6�V$FF��w���u�Ɩ�VE�r��tƖ�VB6��w5�r�"���s��F�c���F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3�&6�Wb&�f7����3��F�b6�73�&6&B#�r��&�r�$W��'B��W"Ɩ'&'�"�$F�v���BƖ�W2���Ɨ7G2�f����w2��'V�2���7F�'��B&VfW&V�6W2"Ɩ2�&F�v���B"��&W��'DƖ'&'���"���&�r�%&W7F�&R&6�W"�$�W&vR&�fFR�4��&6�Wg&����F�W"'&�w6W""Ɩ2�'W��B"��'�6�Ɩ'&'�&6�W��"���&�r�$Ɩ'&'�7F�&vR"�%7F�&VB��F��2FWf�6R�6�V&��r'&�w6W"FF&V��fW2�C�&6�W2&R��BWF��F�2�"�""���s��F�c���F�c�r����R�W6W"��s�F�b6�73�'6WB�6V2#�ƃ3��W"66�V�C���3��F�b6�73�&6&B#�r��&�r�W62��R�W6W"���W���R�W6W"�V���W62��R�W6W"�V����2�&6�Wg&���&�v�B"��&�V�&�f��R��"���s�F�b6�73�'&�r"7G��S�&7W'6�#����FW""��6Ɩ6��'6�v��WB��#��F�b6�73�'&�&V�#��F�b6�73�''B"7G��S�&6���#�f"���W'"�#�6�v��WC��F�c���F�c�r��2�&��v�WB"��s��F�c�r��s��F�c���F�c�r���s�F�b6�73�'6WB�6V2#�ƃ3�66�V�C���3��F�b6�73�&6&B#�r��s�F�b6�73�'&�r"7G��S�&7W'6�#����FW""��6Ɩ6��'6�v��WB��#��F�b6�73�'&�&V�#��F�b6�73�''B"7G��S�&6���#�f"���W'"�#�6�v��WC��F�c���F�c�r��2�&��v�WB"��s��F�c�r��s��F�c���F�c�r������R�F֖���s�F�b6�73�'6WB�6V2#�ƃ3�F֖����3��F�b6�73�&6&B#�r��&�r�$F֖��V�"�$66�V�G2�V&�6R�fVGW&W2�v��w2��Ɩ�R"��2�&6�Wg&���&�v�B"��&�V�66W72��"���s��F�c���F�c�r��rr�����R�F֖���s�F�b6�73�'6WB�6V2#�ƃ3�F�v��7F�73���3��F�b6�73�&6&B"7G��S�'FF��s�'�W�#��F�b6�73�&6��2"7G��S�'FF��s�#�r��s�'WGF��6�73�&6��"��6Ɩ6��''V�6�V6���#�6�V6�6���V7F�����'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'6��u���t6��f�r��#妖�r6WGF��w3��'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'6��u���t7F���2��#妖�r7F���3��'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'6��tgV��66�V���#�gV��7G'V7GW&S��'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'6��u66�V���#��7G'V7GW&S��'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'&�&T�Wr��#��Wr&V�V6W2�FV'Vr���'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'&�&TVF��#�6��v�W2�FV'Vr���'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'6��t��vT��f�#��vR��f���'WGF����'WGF��6�73�&6��"��6Ɩ6��'6��uV��f�#�'&�w6W"��f���'WGF�����F�c���F�c�r��s�F�b�C�&F�r"7G��S�&�&v���F��G�#���F�c���F�c�r��rr���ТgV�7F����V�&�f��R����b��R�W6W"��&WGW&��f"S��R�W6W#���fW&���%&�f��R"�s�F�b7G��S�'FW�B�Ɩv�6V�FW#��&v���&�GF�ӣ��#�r���R���F�bb��FF���vR��FW7B�R���F��sƖ�r7&3�"r�W62�R���F�r"�C�""7G��S�'v�GF��#���V�v�C�#��&�&FW"�&F�W3�������&�V7B�f�C�6�fW""��s�s�F�b7G��S�'v�GF��#���V�v�C�#��&�&FW"�&F�W3������&6�w&�V�C�f"���w&B��F�7�����Ɩ�R�w&�C��6R֗FV�3�6V�FW#�6���#�6ffc�f��B�vV�v�C���f��B�6��S�'&V�#�r�W62��R���W��R�V�����#�"��6Ɩ6R����F�WW$66R����s��F�c�r���s�F�b7G��S�&f��B�vV�v�C���f��B�6��S��'&VӶ�&v���F��'�#�r�W62�R���W��""��s��F�c��F�b6�73�&�WFVB#�r�W62�R�V�����""��s��F�c�r��R����S�s�F�b6�73�&�WFVB#�r�W62�R����R��s��F�c�s�rr��s��F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3�&�f��R�7GW&S���3��F�b6�73�&6&B"7G��S�'FF��s�W�#�r��s�F�b�C�'e�6�"7G��S�&F�7������R#��f�FV��C�'e�f�FV�"WF�����6��Ɩ�R�WFVB7G��S�'v�GF��S����v�GF��#���&�&FW"�&F�W3�G��&6�w&�V�C�3�F�7���&��6���&v��WF�#���f�FV��r��s�F�b7G��S�&F�7���f�W��v����&v���F��'�#��'WGF��6�73�&'F�"7G��S�&f�W����W7F�g��6��FV�C�6V�FW""��6Ɩ6��'e6���#�F�R��F���'WGF����'WGF��6�73�&6��"��6Ɩ6��'e7F���#�6�6V���'WGF�����F�c���F�c�r��s�F�b�C�'e�7F'B#��'WGF��6�73�&'F�"7G��S�'v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��'d6҂�#�6��vR��F���'WGF�����F�c�r��s�6�f2�C�'e�6�f2"7G��S�&F�7������R#���6�f3�r��s�F�b�C�'e��6r"6�73�&W'""7G��S�&�&v���F�����֖�ֆV�v�C�g�#���F�c���F�c���F�c�r��s�F�b6�73�'6WB�6V2#�ƃ3�6��vR77v�&C���3��F�b6�73�&6&B"7G��S�'FF��s�W�#�r��sƖ�WB�C�'u���B"6�73�&f�V�B"G�S�'77v�&B"�6V���FW#�$7W'&V�B77v�&B"WF�6���WFS�&7W'&V�B�77v�&B"��r��sƖ�WB�C�'u��Wr"6�73�&f�V�B"7G��S�&�&v���F���"G�S�'77v�&B"�6V���FW#�$�Wr77v�&B"WF�6���WFS�&�Wr�77v�&B"��r��s�'WGF��6�73�&'F�"7G��S�&�&v���F��'��v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��&6��vUr��#�6��vR77v�&C��'WGF���r��s�F�b�C�'u��6r"6�73�&W'""7G��S�&�&v���F�����֖�ֆV�v�C�g�#���F�c���F�c���F�c�r��s�F�b6�73�'6WB�6V2#��F�b6�73�&6&B#��F�b6�73�'&�r"7G��S�&7W'6�#����FW""��6Ɩ6��'6�v��WB��#��F�b6�73�'&�&V�#��F�b6�73�''B"7G��S�&6���#�f"���W'"�#�6�v��WC��F�c���F�c�r��2�&��v�WB"��s��F�c���F�c���F�c�r���ТgV�7F���6��vUr���f"��B�'u���B"����B�'u��Wr"����B�'u��6r"���b�Ғ��FW�D6��FV�C�"#���7B�"����R�77v�&B"Ƕ��C����ǷҒ�f�VW��""��Ws����ǷҒ�f�VW��"'Ғ�F�V�gV�7F��ₗ�F�7B�%77v�&B6��vVB)�2"���b����f�VS�"#��b����f�VS�"#�Ғ�6F6��gV�7F���R���b�Ғ��FW�D6��FV�C�R��W76vW��$6�V�B��B6��vR�#�ғ�Тf"�e7G&V���V�ð�gV�7F���d6҂��f"��B�'e��6r"���b�Ғ��FW�D6��FV�C�"#��b��f�vF�"��VF�FWf�6W7���f�vF�"��VF�FWf�6W2�vWEW6W$�VF����b�Ғ��FW�D6��FV�C�$6�W&��Bf��&�R�#�&WGW&�Т�f�vF�"��VF�FWf�6W2�vWEW6W$�VF���f�FV�f6��t��FS�'W6W"'�Ғ�F�V�gV�7F���2���e7G&V��3�f"c�B�'e�f�FV�"���b�b��b�7&4�&�V7C�3��f"3�B�'e�6�"��7C�B�'e�7F'B"���b�2�2�7G��R�F�7���&&��6�#��b�7B�7B�7G��R�F�7���&���R#�Ғ�6F6��gV�7F��ₗ��b�Ғ��FW�D6��FV�C�$6�V�B��B�V�F�R6�W&�#�ғ�ТgV�7F���e7F�����b��e7G&Vҗ�G'���e7G&V��vWEG&6�2���f�$V6��gV�7F���B��B�7F����ғ��6F6��R����e7G&V���V�ò�f"3�B�'e�6�"��7C�B�'e�7F'B"���b�2�2�7G��R�F�7���&���R#��b�7B�7B�7G��R�F�7���"#�ТgV�7F���e6����f"c�B�'e�f�FV�"��7c�B�'e�6�f2"����B�'e��6r"���b�g��7b��&WGW&��f"s�b�f�FV�v�GF���3cƃ�b�f�FV�V�v�G��3c�f"׃�3c�63��F��֖��ׂ��F�����rƂ���7b�v�GF���F��&�V�B�r�62��7b�V�v�C��F��&�V�B���62���f"7G��7b�vWD6��FW�B�#&B"��7G��G&t��vR�b���7b�v�GF��7b�V�v�B��f"FF�7b�F�FFU$&��vR��Vr"��b��e7F������b�Ғ��FW�D6��FV�C�%6f��~(
b#��7B�"����R���F�"Ƿ��F�FFҒ�F�V�gV�7F��ₗ��R�W6W"���F��FF�f"���B�&�T��r"���B�&�TfF""���b��Җ���7&3�FF��b��憖FFV��f�6S�F�7B�%��F�WFFVB)�2"���V�&�f��R���Ғ�6F6��gV�7F���R���b�җ���6�74��S�&W'"#���FW�D6��FV�C�R��W76vW��$6�V�B��B6fR�#��ғ�Р�������������6��v�RFWf�6S���R66�V�B���RFWf�6R���������Тf"�F������V�ð�gV�7F���6��uF�V�fW"���f"V��B�'F�V�fW""���b�V�V�憖FFV��f�6S�&WGW&�ТV��F�7V�V�B�7&VFTV�V�V�B�&F�b"��V��C�'F�V�fW"#�V��7G��R�775FW�C�'�6�F���f��VC�F���&�v�C��&�GF�ӣ��VgC���֖�FW�������&6�w&�V�C�f"���&r��F�7���w&�C��6R֗FV�3�6V�FW#�FF��s�#G��FW�B�Ɩv�6V�FW"#��V����W$�D���s�F�b7G��S�&���v�GF��3��#��F�b7G��S�'v�GF��cG���V�v�C�cG��&�&FW"�&F�W3������&6�w&�V�C�f"���w&B��F�7�����Ɩ�R�w&�C��6R֗FV�3�6V�FW#��&v���&�GF�ӣg�#�r��2�&��6�"��s��F�c�r��sƃ"7G��S�&�&v����#��R&R6�v�VB������F�W"FWf�6S���#�r��s�6�73�&�WFVB"7G��S�&�&v����#��W"66�V�B6���ǒ&R6�v�VB������RFWf�6RBF��R�F�W6R�B�W&R�6�v��WBF�R�F�W"FWf�6R����r��s�'WGF��6�73�&'F�"�C�'F�'F�"7G��S�'v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��&6���FWf�6R��#�W6RF��2FWf�6S��'WGF���r��s�F�b�C�'F��6r"6�73�&W'""7G��S�&�&v���F����֖�ֆV�v�C�g�#���F�c�r��s�F�b6�73�'&�r"7G��S�&7W'6�#����FW#��W7F�g��6��FV�C�6V�FW#��&v���F��G�"��6Ɩ6��'6�v��WB��#��F�b6�73�''B"7G��S�&6���#�f"���W'"�#�6�v��WC��F�c���F�c���F�c�s��F�7V�V�B�&�G��V�D6���B�V��ТgV�7F�����FUF�V�fW"���f"V��B�'F�V�fW""���b�V�V�憖FFV��G'VS��ТgV�7F���6���FWf�6R���f"��B�'F��6r"���b�Ғ��FW�D6��FV�C�"#���7B�"���6����FWf�6R"ǷҒ�F�V�gV�7F��ₗ���FUF�V�fW"�����D�R���F�V�gV�7F��ₗ�v�7W%F'��&���R"��ғ�Ғ�6F6��gV�7F���R���b�Ғ��FW�D6��FV�C҆RbfR��W76vR���$6�V�B��B7v�F6��#�ғ�Р�������������66W72��vV�V�B�v��6�66W72����������ТgV�7F���&6�F�6WGF��w2���7F�&W5�����f�6WB�%6WGF��w2"�6WGF��w4�F����ТgV�7F���66W75V���6��F��6r��&WGW&�s�F�b6�73�&&6�"��6Ɩ6��&&6�F�6WGF��w2��#�r��2�&'&�u�&6����5��Wr"��u6WGF��w3��F�c�r��s�F�b6�73�&6&B"7G��S�'FF��s�g�#�r��s�F�b7G��S�&F�7���f�W��Ɩv�֗FV�3�6V�FW#�v����&v���&�GF�ӣ�#�r��2�&��6�"��s�#�F֖��V���#���F�c�r��s�6�73�&�WFVB"7G��S�&�&v��'�#�V�FW"F�R���77v�&B�F�R��R6WB��6��VFf�&R�F�6��F��VR����r��sƖ�WB�C�&F�r"6�73�&f�V�B"G�S�'77v�&B"�6V���FW#�$���77v�&B"WF�6���WFS�&�fb"��r��s�'WGF��6�73�&'F�"7G��S�&�&v���F��'��v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��'V���6�66W72��#�V���6���'WGF���r��s�F�b�C�&66�6r"6�73�&W'""7G��S�&�&v���F����֖�ֆV�v�C���#�r�W62��6w��""��s��F�c���F�c�s�ТgV�7F����V�66W72����b��F�w���R�F֖◲��D66W72����V�6R��f�6WB�$F֖�"�66W75V���6��F����f"��B�&F�r"���b�����f�7W2����ТgV�7F���V���6�66W72���f"��B�&F�r"��f"s֓���f�VS�"#��b�r��&WGW&���F�s�s���D66W72���ТgV�7F�����D66W72����f�6WB�$F֖�"�s�F�b6�73�&&6�"��6Ɩ6��&&6�F�6WGF��w2��#�r��2�&'&�u�&6����5��Wr"��u6WGF��w3��F�c��F�b�C�&62#��7�6�73�'7���W"#���7����F��~(
c��F�c�r���&�֗6R����7B�"���F֖��Ɨ7B"ǶF֖��F�wҒ���7B�"���F֖��6��f�r"ǶF֖��F�wҒ�F�V�gV�7F���B��&WGW&�B�6��f�w�ǷӷҒ�6F6��gV�7F��ₗ�&WGW&��ӷҒ���7B�"���F֖��W6W'2"ǶF֖��F�wҒ�6F6��gV�7F��ₗ�&WGW&��W6W'3��V��ӷҒ���7B�"���F֖��&W6V�6R"ǶF֖��F�wҒ�6F6��gV�7F��ₗ�&WGW&����Ɩ�S���ӷҒҐ��F�V�gV�7F���&W2��&V�FW$F֖�&W5���&W5���Ƿ��&W5�%��Ƿ��&W5�5��Ƿғ�Ґ��6F6��gV�7F���R���F�s�"#��f�6WB�$F֖�"�66W75V���6��F�R��W76vW��%w&��r77v�&B�"���f"��B�&F�r"���b�����f�7W2���ғ�Тf"�&W5F��W#��V�ð�gV�7F���&W6V�6U&�r�����r��f"v���F�������F��&�V�B����r҆��6VV���������f"v�V��v���&��r#��v��c�v�'2v�#��F��&�V�B�v��c��&�v�"���&WGW&�s�F�b6�73�&6�FR֗FV�#��F�b7G��S�'v�GF��C���V�v�C�C��&�&FW"�&F�W3������&6�w&�V�C�f"���w&B��F�7���w&�C��6R֗FV�3�6V�FW#�6���#�6ffc�f��B�vV�v�C�s�f�W�����R#�r�W62������W��#�"��6Ɩ6R����F�WW$66R����s��F�c�r��s�F�b7G��S�&֖��v�GF���f�W����&v����VgC�'�#��F�b6�73�&6����R#�r�W62�����W��$wVW7B"��s��F�c��F�b6�73�&6��6�FR#�r�W62���f�Ww��.(	B"��r+rr�v�V�s��F�c���F�c�r��s�7�7G��S�'v�GF�����V�v�C���&�&FW"�&F�W3������&6�w&�V�C�r��v��C�"33FC3��#�"6f&&c#B"��s�f�W�����R#���7����F�c�s�ТgV�7F���&W6V�6TƗ7D�F�&W2��f"��s҇&W2bg&W2���r���FFR���r���f"��҇&W2bg&W2���Ɩ�R��ŵӰ�&WGW&�����V�wF�������gV�7F����&WGW&�&W6V�6U&�r�����r��Ғ����""��s�6�73�&�WFVB"7G��S�&�&v���FF��s�'�W�#���&�G��2��&�v�B��r����s�ТgV�7F���7F�&W5�����b��&W5F��W"��6�V$��FW'f�&W5F��W"���&W5F��W#��V�ò�ТgV�7F���&Vg&W6�&W2����7B�"���F֖��&W6V�6R"ǶF֖��F�wҒ�F�V�gV�7F�����f"V��B�'&W4Ɨ7B"���b�V�7F�&W5����&WGW&�ТV����W$�D���&W6V�6TƗ7D�F���f"3�B�'&W46�V�B"���b�2�2�FW�D6��FV�C҂����Ɩ�W�ŵҒ��V�wF���Ғ�6F6��gV�7F��ₗ�ғ�ТgV�7F���W6W$fF"�R��&WGW&��R���F�bb��FF���vR��FW7B�R���F򒐢�sƖ�r7&3�"r�W62�R���F�r"�C�""7G��S�'v�GF��Cg���V�v�C�Cg��&�&FW"�&F�W3�������&�V7B�f�C�6�fW#�f�W�����R"��p��s�F�b7G��S�'v�GF��Cg���V�v�C�Cg��&�&FW"�&F�W3������&6�w&�V�C�f"���w&B��F�7���w&�C��6R֗FV�3�6V�FW#�6���#�6ffc�f��B�vV�v�C�s�f�W�����R#�r�W62��R�V�����#�"��6Ɩ6R����F�WW$66R����s��F�c�s�ТgV�7F���W6W$7F��↖B�7F����W�G&��f"&�G�׶F֖��F�r�7F���7F���ƖC��GӲ�b�W�G&��f�"�f"���W�G&�&�G�����W�G&��ӲТ�7B�"���F֖��W6W""�&�G���F�V�gV�7F��ₗ�F�7B�7F������&&�fR#�$&�fVB)�2#�$F��R�"����D66W72���Ғ�6F6��gV�7F���R��F�7B�R��W76vW��$f��VB�"��ғ�ТgV�7F���W6W%&W6WB��B��f"�&��B�$V�FW"�Wr77v�&Bf�"F��266�V�C�"���b�����V�&WGW&��b���V�wF�Â��F�7B�%77v�&B�W7B&RB�V7B�6�&7FW'2�"��&WGW&�Т�7B�"���F֖��W6W""ǶF֖��F�r�7F���'&W6WGr"ƖC��B�77v�&C�Ғ�F�V�gV�7F��ₗ�F�7B�%77v�&B&W6WB)�2"��Ғ�6F6��gV�7F���R��F�7B�R��W76vW��$f��VB�"��ғ�ТgV�7F���W6W$7&VFR���f"���B�&�U��"��S�B�&�U�R"���B�&�U�"��s�B�&�U�r"����B�&�U��6r"���b�Ғ��FW�D6��FV�C�"#���7B�"���F֖��W6W""ǶF֖��F�r�7F���&7&VFR"���S�����ǷҒ�f�VW��""�V��â�W�ǷҒ�f�VW��""����S���ǷҒ�f�VW��""�77v�&C��w�ǷҒ�f�VW��"'Ғ�F�V�gV�7F��ₗ�F�7B�$66�V�B7&VFVB�"����D66W72���Ғ�6F6��gV�7F���W'"���b�Ғ��FW�D6��FV�C�W'"��W76vW��$6�V�B��B7&VFR�#�ғ�Тf"�6ftVF�C׶fVGW&W3���Ӱ�gV�7F���F�vv�U&�r����&V�f"����6ftVF�B�fVGW&W5�����f�6S��&WGW&�s�F�b6�73�'&�r#��F�b6�73�'&�&V�#��F�b6�73�''B#�r�W62��&V�s��F�c���F�c��F�b6�73�'6Vr"�C�&6e�r���r#�r��s�'WGF��FF�c�&��"6�73�"r�����&��#�""��r"��6Ɩ6��&6fu6WB���rr���u��r���v����r�#�����'WGF���r��s�'WGF��FF�c�&�fb"6�73�"r�����"#�&��"��r"��6Ɩ6��&6fu6WB���rr���u��r���v�fe��r�#��fc��'WGF�����F�c���F�c�s�ТgV�7F���6fu6WB���b���6ftVF�B�fVGW&W5���҇c���&��"��6Vt�&��&6e�"���b��ТgV�7F���6fu�6���W��b���6ftVF�E��W���c�6Vt�&��&6g�"��W��b��ТgV�7F����D'F↶W��b��&V�f"��҅�6ftVF�E��W����""����c�&WGW&�s�'WGF��FF�c�"r�W62�b��r"6�73�"r�����&��#�""��r"��6Ɩ6��&6fu�6����rr��W��u��r���rr�b�u��r�#�r�W62��&V�s��'WGF���s�ТgV�7F���6ft66V�B�����6ftVF�B�66V�Cֳ�f"&���B�&6ft66V�B"���b�&�������f�$V6��6�&���6���G&V��gV�7F���"��"�7G��R�&�&FW$6���#҆"�vWDGG&�'WFR�&FF�b"���ֲ��"6ffb#�'G&�7&V�B#�ғ�Тf"'3�F�7V�V�B�F�7V�V�DV�V�V�B�7G��S��b��bd4du�44T�E5��җ�'2�6WE&�W'G��"��66V�B"�4du�44T�E5��ճғ�'2�6WE&�W'G��"��66V�B�""�4du�44T�E5��ճғ��V�6R�'2�&V��fU&�W'G��"��66V�B"��'2�&V��fU&�W'G��"��66V�B�""���ТgV�7F���66V�E&�r���f"�G3ղ"%��6��6B��&�V7B�W�2�4du�44T�E2����&WGW&�s��&V�6�73�&�WFVB"7G��S�&f��B�6��S��&V�#�66V�B6���#���&V���F�b�C�&6ft66V�B"7G��S�&F�7���f�W��v����f�W��w&�w&��&v��g�#�r���G2���gV�7F��↲��f"&sֳ�vƖ�V"�w&F�V�B�3VFVr�r�4du�44T�E5��ճҲr�r�4du�44T�E5��ճҲr�r��wf"���7W&f6R�2�s�f"6V�҅�6ftVF�B�66V�G��""���ֳ��&WGW&�s�'WGF��FF�c�"r�W62����r"��6Ɩ6��&6ft66V�B���rr���u��r�"F�F�S�"r�W62����$FVfV�B"��r"7G��S�'v�GF��3G���V�v�C�3G��&�&FW"�&F�W3������&�&FW#�'�6�ƖBr��6V��"6ffb#�'G&�7&V�B"��s�&6�w&�V�C�r�&r�s�7W'6�#����FW#�f�W�����R#���'WGF���s�Ғ����""��s��F�c�s�Тf"dTE��$T�3׶&��W'3�$fVGW&VB&��W'2"��'V�3�$�'V�2"��V�#�%�V�""�6V&6��%6V&6�"�vV�&W3�$vV�&W2"�6FVv�&�W3�$6FVv�&�W2"���Ɨ7G3�%��Ɨ7G2"�'F�7G3�$'F�7G2"�7F�&�W3�%7F�&�W2"�F�v���G3�$F�v���G2"�ff�&�FW3�$ff�&�FW2�)�R�'Ӱ�gV�7F���6fTF֖�6��f�r���f"��B�&6ft"����B�&6ft��"���s�B�&6ft�v�W""����B�&6ft�6r"���b�Ғ��FW�D6��FV�C�"#���b���6ftVF�B���S���f�VS��b�Ғ�6ftVF�B����V�6V�V�C���f�VS��b��r��6ftVF�B��v�W$V�����r�f�VS���7B�"���F֖��6��f�r"ǶF֖��F�r�6��f�s��6ftVF�GҒ�F�V�gV�7F���B���6WE6fVC�G'VS��F��6fs�B�6��f�w���6ftVF�C�ǔ6��f�r�B�6��f�w���6ftVF�B��F�7B�%6fVB)�2"��Ґ��6F6��gV�7F���R���b�җ���FW�D6��FV�C�R��W76vW��$6�V�B��B6fR�#��V�6RF�7B�R��W76vW��$6�V�B��B6fR�"��ғ�Р�������F֖��V"�6W&FR6V7F���vW2���Тf"�F�׷Ӱ�gV�7F���6V7E&�r��W�Ɩ6���F�F�R�7V"�&FvR��&WGW&�s�F�b6�73�&&�r"��6Ɩ6��&F֖�6V7F�����rr��W��u��r�#�r��s�F�b6�73�&�2#�r��2��6�⒲s��F�c��F�b6�73�'&�&V�"7G��S�&f�W���֖��v�GF��#��F�b6�73�''B#�r�W62�F�F�R���&FvS�r�7�6�73�&&FvR#�r�W62�7G&��r�&FvR���s��7��s�rr��s��F�c��F�b6�73�'&B#�r�W62�7V'��""��s��F�c���F�c�r��2�&6�Wg&���&�v�B"��s��F�c�s�ТgV�7F���&V�FW$F֖�B�6fr�W6W'4FF�&W4FF����F�׶C�B�6fs�6fw�Ƿ��W6W'3�W6W'4FF�Ƿ��&W3�&W4FF�Ƿ�Ӱ�f"&6��s�F�b6�73�&&6�"��6Ɩ6��&&6�F�6WGF��w2��#�r��2�&'&�u�&6����5��Wr"��u6WGF��w3��F�c�s���b�B�b���f�6WB�$F֖�"�&6���e6WGW�F����&WGW&�Т�6ftVF�C׶��S��F��6fr���W��""����V�6V�V�C��F��6fr����V�6V�V�G��""�F�V�S��F��6fr�F�V�W��""���s��F��6fr���w��""�66V�C��F��6fr�66V�G��""��v�W$V��å�F��6fr��v�W$V�����""�fVGW&W3���Ӱ�4du�dTEU$U2�f�$V6��gV�7F��↲���6ftVF�B�fVGW&W5���҅�F��6fr�fVGW&W2be�F��6fr�fVGW&W5��Ғ��f�6S�ғ��F֖�V"����ТgV�7F���F֖�V"����7F�&W5�����f"&6��s�F�b6�73�&&6�"��6Ɩ6��&&6�F�6WGF��w2��#�r��2�&'&�u�&6����5��Wr"��u6WGF��w3��F�c�s��f"6fs��F��6fw�Ƿ��W6W'3҅�F��W6W'2be�F��W6W'2�W6W'2��ŵ��&W3��F��&W7�ǷӰ�f"�5W6W'3��W6W'3����V����W6W'3���V�FVf��VB���f"V�F��sֆ5W6W'3�W6W'2�f��FW"�gV�7F���R��&WGW&�R�7FGW3���'V�F��r#�Ғ��V�wF����f"7F�fSֆ5W6W'3�W6W'2�f��FW"�gV�7F���R��&WGW&�R�7FGW2��'V�F��r"bgR�7FGW2��'&V�V7FVB#�Ғ��V�wF����f"��Ɩ�S҂�&W2���Ɩ�R��ŵҒ��V�wF���f"�fVC҂�6fr�fVGW&VB��ŵҒ��V�wF��䆖C҂�6fr憖FFV��ŵҒ��V�wF���f"&�w3�s�F�b6�73�'6WB�6V2#�ƃ3�F֖�6V�FW#���3��F�b6�73�&6&B"7G��S�'FF��s�g�#�r��6V7E&�r�vF6�&�&Br�vw&��5�Wr�tF6�&�&Br�u��2�Ɨ7FV�W'2b6�'G2r���6V7E&�r�v��Ɩ�Rr�v���Rr�uv��(	�2��Ɩ�Rr���Ɩ�S���Ɩ�R�r��Ɩ�R��rr��t��&�G�&�v�B��rr���Ɩ�W��""���6V7E&�r�v66�V�G2r�v'F�7Br�t66�V�G2r�7F�fR�r7F�fRr��V�F��s�r+rr�V�F��r�rv�F��rr��rr��V�F��w��""���6V7E&�r�v6��FV�Br�w7F"r�t6��FV�Br�fVG��䆖B���fVB�r���VB+rr�䆖B�r��FFV�r��tfVGW&R�"��FR�'V�2r���6V7E&�r�v�W6�2r�v�W6�5���FRr�t�W6�26W'fW"��v��r�u���r66�V�Bf�"��&6�r���6V7E&�r�vV&�6Rr�w6WGF��w2r�tV&�6Rr�t��R�6���"�F�V�R���wVvRr���6V7E&�r�vfVGW&W2r�v6FVv�'�r�tfVGW&W2b6V7F���2r�u6��r�"��FR'G2�bF�Rr���6V7E&�r�v6�FW2r�v��6�r�t66W726�FW2r�u6���R6�v�֖�6�FW2r���6V7E&�r�w7�7FV�r�vfVGW&VE����Ɨ7Br�u7�7FV�b��f�r�ufW'6����7F�&vRb7FGW2r���s��F�c���F�c�s���f�6WB�$F֖�"�&6��&�w2���ТgV�7F���F֖�6V7F��↶W����7F�&W5�����f"&6��s�F�b6�73�&&6�"��6Ɩ6��&F֖�V"��#�r��2�&'&�u�&6����5��Wr"��tF֖�6V�FW#��F�c�s��f"�F���""�gFW#��V�ð��b��W����&F6�&�&B"���F���6V5w&�$F6�&�&B"�s�F�b�C�'7FG4&��#���F�c��F�b6�73�&6��2"7G��S�'FF��s���&v���F��'�#��'WGF��6�73�&6��"��6Ɩ6��&��E7FG2��#�r��2�&��7F�'�"��r&Vg&W6���'WGF����'WGF��6�73�&6��"��6Ɩ6��&W��'D77b���w��5��r�#�r��2�&F�v���B"��rW��'B��3��'WGF����'WGF��6�73�&6��"��6Ɩ6��'&W6WE7FG2��#�r��2�&FV�WFR"��r&W6WB��7F�'���'WGF�����F�c�r��gFW#���E7FG3�ТV�6R�b��W����&��Ɩ�R"���F���6V5w&�%v��(	�2��Ɩ�R��7��C���'&W46�V�E��#�"�����F��&W2be�F��&W2���Ɩ�R��ŵҒ��V�wF���#��7��"�s�F�b�C�'&W4Ɨ7B#�r�&W6V�6TƗ7D�F��F��&W2��s��F�c�r��gFW#�gV�7F��ₗ��&W5F��W#�6WD��FW'f&Vg&W6�&W2���ӲТV�6R�b��W����&66�V�G2"���F���66�V�G56V7F��ₓ�ТV�6R�b��W����&6��FV�B"���F���6��FV�E6V7F��ₓ�ТV�6R�b��W����&�W6�2"���F����W6�56V7F��ₓ�gFW#���D�W6�57FGW3�ТV�6R�b��W����&V&�6R"���F���V&�6U6V7F��ₓ�ТV�6R�b��W����&fVGW&W2"���F���fVGW&W56V7F��ₓ�ТV�6R�b��W����&6�FW2"���F���6�FW56V7F��ₓ�ТV�6R�b��W����'7�7FV�"���F���7�7FV�6V7F��ₓ�gFW#���E7�7FVԖ�f�Т�f�6WB�$F֖�"�&6���F����b�gFW"�gFW"����ТgV�7F���6V5w&�F�F�RƖ��W"��&WGW&�s�F�b6�73�'6WB�6V2#�ƃ3�r�F�F�R�s���3��F�b6�73�&6&B"7G��S�'FF��s�W�#�r����W"�s��F�c���F�c�s�ТgV�7F���66�V�G56V7F��ₗ��f"�V���҂��F��W6W'2be�F��W6W'2��v�W$V����""��F���vW$66R����f"W6W'3҅�F��W6W'2be�F��W6W'2�W6W'2����b�W6W'3����V����W6W'3���V�FVf��VB��&WGW&�6V5w&�$66�V�G2"�s�6�73�&�WFVB"7G��S�&�&v��#�6�v��W66�V�G2�VVBF�R7F�&vR6WBWf�'7B�F�V�V��R6�&WVW7B66W72v�F�V�������R�B6V�f�R����r��Тf"�WC�"#��f"V�F��s�W6W'2�f��FW"�gV�7F���R��&WGW&�R�7FGW3���'V�F��r#�ғ��f"�F�W'3�W6W'2�f��FW"�gV�7F���R��&WGW&�R�7FGW2��'V�F��r"bgR�7FGW2��'&V�V7FVB#�ғ���b�V�F��r��V�wF�����WB��s�F�b6�73�'6WB�6V2#�ƃ3�&WVW7G2v�F��r�r�V�F��r��V�wF��r����3��F�b6�73�&6&B#�r�V�F��r���gV�7F���R���&WGW&�s�F�b6�73�&6�FR֗FV�#�r�W6W$fF"�R��s�F�b7G��S�&֖��v�GF���f�W����&v����VgC�'�#��F�b6�73�&6����R#�r�W62�R���W��R�V���s��F�c��F�b6�73�&6��6�FR#�r�W62�R�V���r+rr�W62�R����W��""��s��F�c���F�c�r��s�'WGF��6�73�&'F�6�"7G��S�&�&v��"��6Ɩ6��'W6W$7F���r�R�B�r���v&�fU��r�#�&�fS��'WGF���r��s�'WGF��6�73�'G&6�"F�F�S�%&V�V7B"��6Ɩ6��'W6W$7F���r�R�B�r���w&V�V7E��r�#�r��2�&6��6R"��s��'WGF�����F�c�s�Ғ����""��s��F�c���F�c�s��Тf"Ɨ7B��F�W'2��V�wF���sƖ�WB�C�&67E6V&6�"6�73�&f�V�B"�6V���FW#�%6V&6�'���R�V�������^(
b"WF�6���WFS�&�fb"���WC�&f��FW$66�V�G2��"7G��S�&�&v���&�GF�ӣ�"���F�b�C�&67DƗ7B#�r��F�W'2���gV�7F���R��f"7W7҇R�7FGW3���'7W7V�FVB"��f"�4�v�W#҆�V���bb�R�V�����""��F���vW$66R������V����f"6��W62���R���W��""��""��R�V�����""��""��R����W��""���F���vW$66R�����f"�WF�s�7��r��R���7����r��3��7��r��R��7E6VV��r+r�7��6VV�r�F��Tv�R��7E6VV⒲s��7��s�rr���R�7&VFVC�r+r�7�����VBr�F��Tv�R�7&VFVB��s��7��s�rr���&WGW&�s�F�b6�73�&6&B67B"FF�6V&6��"r�6��r"7G��S�'FF��s�'���&v���&�GF�ӣ��#�r��s�F�b7G��S�&F�7���f�W��Ɩv�֗FV�3�6V�FW#�v�'�#�r�W6W$fF"�R��s�F�b7G��S�&f�W���֖��v�GF��#��F�b6�73�&6����R#�r�W62�R���W��R�V�����4�v�W#�r�7�7G��S�&6���#�f"���66V�B�#��v�W"���7��s��R�&��S���&F֖�#�r�7�7G��S�&6���#�f"���66V�B�#�F֖���7��s�rr����7W7�r�7�6�73�&�WFVB#�7W7V�FVB���7��s�rr��s��F�c��F�b6�73�&6��6�FR#�r�W62�R�V���r+rr�W62�R����W��""��s��F�c��F�b6�73�&6��6�FR"7G��S�&6���#�f"����WFVB���&v���F��'�#�r��WF�s��F�c���F�c���F�c�r��s�F�b6�73�&6��2"7G��S�'FF��s���&v���F���#�r��s�'WGF��6�73�&6��"��6Ɩ6��&�V�W6W$FWF�r�R�B�r�#�r��2�&w&��5�W"��rƗ7FV��s��'WGF���r���7W7�s�'WGF��6�73�&6��"��6Ɩ6��'W6W$7F���r�R�B�r���wV�7W7V�E��r�#�V�7W7V�C��'WGF���s�s�'WGF��6�73�&6��"��6Ɩ6��'W6W$7F���r�R�B�r���w7W7V�E��r�#�7W7V�C��'WGF���r�����4�v�W#�rs�s�'WGF��6�73�&6��"��6Ɩ6��'W6W$7F���r�R�B�r���w6WG&��U��rǷf�VS�r��R�&��S���&F֖�#����wҒ#�r��R�&��S���&F֖�#�%&V��fRF֖�#�$��RF֖�"��s��'WGF���r���s�'WGF��6�73�&6��"��6Ɩ6��'W6W%&W6WB�r�R�B�r�#�&W6WB77v�&C��'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'W6W$7F���r�R�B�r���v��F���rǷf�VS�r��R���F�����wҒ#�r��R���F��tV�&�RF�v���G2s�tF�6&�RF�v���G2r��s��'WGF���r��s�'WGF��6�73�&6��"��6Ɩ6��'W6W$7F���r�R�B�r���w&V��fU��r�#�&V��fS��'WGF���r��s��F�c���F�c�s�Ғ����""��s�F�b�C�&67D���R"6�73�&�WFVB"7G��S�&F�7������S�FF��s�g�'�#���66�V�G2�F6����F�c���F�c�p��s�6�73�&�WFVB"7G��S�&�&v��'��#���66�V�G2�WB����s���WB��s�F�b6�73�'6WB�6V2#�ƃ3�66�V�G2�r��F�W'2��V�wF��r����3�r����F�W'2��V�wF��s�F�b6�73�&6��2"7G��S�'FF��s���&v���&�GF�ӣ�#��'WGF��6�73�&6��"��6Ɩ6��&W��'D77b���v66�V�G5��r�#�r��2�&F�v���B"��rW��'B66�V�G2�55b���'WGF�����F�c�s�rr��Ɨ7B��s�F�b6�73�&6&B"7G��S�'FF��s�W���&v���F��'�#�r��s�F�b7G��S�&f��B�vV�v�C�c��&v���&�GF�ӣ��#�7&VFR�66�V�C��F�c�r��sƖ�WB�C�&�U��"6�73�&f�V�B"�6V���FW#�$gV����R"WF�6���WFS�&�fb"��r��sƖ�WB�C�&�U�R"6�73�&f�V�B"7G��S�&�&v���F���"G�S�&V���"�6V���FW#�$V���FG&W72"WF�6���WFS�&�fb"��r��sƖ�WB�C�&�U�"6�73�&f�V�B"7G��S�&�&v���F���"G�S�'FV�"�6V���FW#�%���R�V�&W""WF�6���WFS�&�fb"��r��sƖ�WB�C�&�U�r"6�73�&f�V�B"7G��S�&�&v���F���"G�S�'77v�&B"�6V���FW#�%77v�&B"WF�6���WFS�&�Wr�77v�&B"��r��s�'WGF��6�73�&'F�"7G��S�&�&v���F��'��v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��'W6W$7&VFR��#�r��2�'W'6���FB"��r7&VFR66�V�C��'WGF���r��s�F�b�C�&�U��6r"6�73�&W'""7G��S�&�&v���F�����֖�ֆV�v�C�g�#���F�c���F�c���F�c�s��&WGW&��WC��ТgV�7F���6��FV�E6V7F��ₗ�f"6fs��F��6fw�ǷӲf"�fVC҂�6fr�fVGW&VB��ŵҒ��V�wF��䆖C҂�6fr憖FFV��ŵҒ��V�wF���&WGW&�6V5w&�$6��FV�B(	BfVGW&VBf����FFV�"��s�6�73�&�WFVB"7G��S�&�&v���#��V���'V��BW6RF�R�#�F֖���#�'WGF��2F�W&RF��#���F����S��#��6��w2��(	�fVGW&VN(	�&�r��"�#䆖FS��#��Bg&��WfW'���R����r��s�F�b7G��S�&F�7���f�W��v����FW�B�Ɩv�6V�FW"#�r�7FEF��R��fVB�%���VBF����R"�wf"���66V�B�r��7FEF��R�䆖B�$��FFV�"��s��F�c�r�����fVG��䆖B��s�F�b6�73�&6��2"7G��S�'FF��s���&v���F���#�r���fVC�s�'WGF��6�73�&6��"��6Ɩ6��&6�V$7W&FR���vfVGW&VE��r�#�6�V"���VC��'WGF���s�rr���䆖C�s�'WGF��6�73�&6��"��6Ɩ6��&6�V$7W&FR���v��FFV���r�#�6�V"��FFV���'WGF���s�rr��s��F�c�r��rr����ТgV�7F����W6�56V7F��ₗ�&WGW&�6V5w&�$�W6�26W'fW"��v��"��s�F�b�C�&�W6�57FGW2"6�73�&�WFVB"7G��S�&�&v���&�GF�ӣ'�#��7�6�73�'7���W"#���7��6�V6���~(
c��F�c�r��s�F�b7G��S�&f��B�vV�v�C�c��&v���&�GF�ӣg�#�6�v���v�F���W"���r66�V�B��VW2v�&���r(	B&Vg&W6�W2�G6V�b���F�c�r��sƖ�WB�C�&פV���"6�73�&f�V�B"G�S�&V���"�6V���FW#�%���rV���"WF�6���WFS�&�fb"��r��sƖ�WB�C�&ץ72"6�73�&f�V�B"7G��S�&�&v���F���"G�S�'77v�&B"�6V���FW#�%���r77v�&B"WF�6���WFS�&�Wr�77v�&B"��r��s�F�b6�73�&�WFVB"7G��S�&f��B�6��S��s�&VӶ�&v���#��"7FR��R�F��R6W76���F��V���7FVC���F�c�r��sƖ�WB�C�&ץF��V�"6�73�&f�V�B"7G��S�&�&v���F��g�"�6V���FW#�%6W76���F��V���F���"WF�6���WFS�&�fb"��r��s�F�b7G��S�&F�7���f�W��v�����&v���F��'�#��'WGF��6�73�&'F�"7G��S�&f�W����W7F�g��6��FV�C�6V�FW""��6Ɩ6��'6fT�W6�2��#�6fRf��FW7C��'WGF����'WGF��6�73�&6��"��6Ɩ6��'FW7D�W6�2��#�FW7C��'WGF�����F�c�r��s�F�b�C�&�W6�4�6r"7G��S�&�&v���F�����֖�ֆV�v�C�g��f��B�6��S��W&V�#���F�c�r��s�F�b7G��S�&�&v���F��g��F�7���f�W��v���#��'WGF��6�73�&6��"��6Ɩ6��&6�V$�W6�2��#�6�V"��v����'WGF����'WGF��6�73�&6��"��6Ɩ6��'&V6���W6�2��#�7G&V�&V6���FWb���'WGF�����F�c�r���ТgV�7F���V&�6U6V7F��ₗ�&WGW&�s�F�b6�73�'6WB�6V2#�ƃ3�V&�6S���3��F�b6�73�&6&B"7G��S�'FF��s�W�#�r��s��&V�6�73�&�WFVB"7G��S�&f��B�6��S��&V�#���S���&V��r��sƖ�WB�C�&6ft"6�73�&f�V�B"7G��S�&�&v��W�G�"�6V���FW#�%���r"f�VS�"r�W62��6ftVF�B���R��r"��r��66V�E&�r����s�F�b7G��S�&�V�v�C�'�#���F�c���&V�6�73�&�WFVB"7G��S�&f��B�6��S��&V�#����V�6V�V�B�6��v�BF�RF�f�"WfW'���R����&V��r��sƖ�WB�C�&6ft��"6�73�&f�V�B"7G��S�&�&v��W�"�6V���FW#�"����R�"f�VS�"r�W62��6ftVF�B����V�6V�V�B��r"��r��s��F�c�r��s�F�b6�73�&6&B"7G��S�&�&v���F���#�r��s�F�b6�73�'&�r#��F�b6�73�'&�&V�#��F�b6�73�''B#�FVfV�BF�V�S��F�c��F�b6�73�'&B#�f�"V��Rv���fV���wB6��6V���F�c���F�c��F�b6�73�'6Vr"�C�&6g�F�V�R#�r��D'F�'F�V�R"�""�$�fb"���D'F�'F�V�R"�&F&�"�$F&�"���D'F�'F�V�R"�&Ɩv�B"�$Ɩv�B"��s��F�c���F�c�r��s�F�b6�73�'&�r#��F�b6�73�'&�&V�#��F�b6�73�''B#�FVfV�B��wVvS��F�c��F�b6�73�'&B#���W2��V�vƗ6��"�V'&Ws��F�c���F�c��F�b6�73�'6Vr"�C�&6g���r#�r��D'F�&��r"�""�$�fb"���D'F�&��r"�&V�"�$T�"���D'F�&��r"�&�R"�-z-yz�y�z�"��s��F�c���F�c�r��s��F�c�r��s�F�b6�73�&6&B"7G��S�&�&v���F����FF��s�W�#���&V�6�73�&�WFVB"7G��S�&f��B�6��S��&V�#��v�W"V���(	BF��266�V�B��B���R��R��R�F֖�6VW2F�RF֖�6WGF��w3���&V��r��sƖ�WB�C�&6ft�v�W""6�73�&f�V�B"7G��S�&�&v��W�"G�S�&V���"�6V���FW#�'��TW���R�6��"f�VS�"r�W62��6ftVF�B��v�W$V���r"WF�6���WFS�&�fb"����F�c�r��s�F�b7G��S�&�&v��'�#��'WGF��6�73�&'F�"7G��S�'v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��'6fTF֖�6��f�r��#�6fRV&�6S��'WGF����F�b�C�&6ft�6r"6�73�&W'""7G��S�&�&v���F�����֖�ֆV�v�C�g�#���F�c���F�c���F�c�s�ТgV�7F���fVGW&W56V7F��ₗ�&WGW&�s�F�b6�73�'6WB�6V2#�ƃ3�fVGW&W2f��6V7F���2(	B6��r���FRf�"WfW'���S���3��F�b6�73�&6&B#�r��4du�dTEU$U2���gV�7F��↲��&WGW&�F�vv�U&�r���dTE��$T�5����Ʋ��Ғ����""���s��F�c�r��s�F�b7G��S�&�&v��'�#��'WGF��6�73�&'F�"7G��S�'v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��'6fTF֖�6��f�r��#�6fRfVGW&W3��'WGF����F�b�C�&6ft�6r"6�73�&W'""7G��S�&�&v���F�����֖�ֆV�v�C�g�#���F�c���F�c���F�c�s�ТgV�7F���6�FW56V7F��ₗ�f"6�FW3҅�F��Bbe�F��B�6�FW2��ŵӰ�f"Ɨ7B�6�FW2��V�wF���s�F�b6�73�&6&B#�r�6�FW2���gV�7F���2��&WGW&�s�F�b6�73�&6�FR֗FV�#��F�b7G��S�&֖��v�GF��#��F�b6�73�&6����R#�r�W62�2���W��%6��V��R"��s��F�c��F�b6�73�&6��6�FR#�r�W62�2�6�FR��s��F�c���F�c�r��s�'WGF��6�73�'G&6�"F�F�S�%&V��fR"FF�6�FS�"r�W62�2�6�FR��r"��6Ɩ6��'&V��fT6�FR�F��2�#�r��2�&FV�WFR"��s��'WGF�����F�c�s�Ғ����""��s��F�c�p��s�6�73�&�WFVB"7G��S�&�&v��'�#���6�FW2�WB�FB��R&V��r����s��&WGW&�s�F�b6�73�'6WB�6V2#�ƃ3�V�6�66W726�FW2��F������3�r��s�6�73�&�WFVB"7G��S�&�&v����f��B�6��S��W&V�#�6���R6�FRF�6�v���v�F����66�V�B�VVFVB����W"���77v�&B�v�2v�&�2����r��Ɨ7B��s�F�b6�73�&6&B"7G��S�'FF��s�W���&v���F���#�r��sƖ�WB�C�&6�"6�73�&f�V�B"�6V���FW#�$��R�f�"W���S���76��"WF�6���WFS�&�fb"��r��sƖ�WB�C�&62"6�73�&f�V�B"7G��S�&�&v���F���"�6V���FW#�$66W726�FR�77v�&B"WF�6���WFS�&�fb"��r��s�'WGF��6�73�&'F�"7G��S�&�&v���F��'��v�GF��S��W7F�g��6��FV�C�6V�FW""��6Ɩ6��&FD6�FR��#�r��2�'W'6���FB"��rFB6�FS��'WGF���r��s�F�b�C�&FF�6r"6�73�&W'""7G��S�&�&v���F�����֖�ֆV�v�C�g�#���F�c���F�c���F�c�s�ТgV�7F���7�7FV�6V7F��ₗ�&WGW&�6V5w&�%7�7FV�b��f�"�s�F�b�C�'7�4&��#��7�6�73�'7���W"#���7��6�V6���~(
c��F�c�r��ТgV�7F���7�5&�r��&V��f������&WGW&�s�F�b6�73�&6�FR֗FV�#��F�b7G��S�&֖��v�GF���f�W��#��F�b6�73�&6����R#�r�W62��&V�s��F�c���F�c��F�b7G��S�&f��B�vV�v�C�s�f�W�����S�6���#�r�������G'VS�wf"������s������f�6S�wf"���W'"�s�wf"���FW�B�r��r#�r�W62�7G&��r�f��s��F�c���F�c�s�ТgV�7F�����E7�7FVԖ�f򂗲f"&���B�'7�4&��"���b�&���&WGW&㰢f"W6W'3҅�F��W6W'2be�F��W6W'2�W6W'2��ŵӲf"6fs��F��6fw�ǷӰ�fWF6��"���7FGW2"��F�V�gV�7F���"��&WGW&�"�6�ₓ�Ғ�F�V�gV�7F���2����b�B�'7�4&��"��&WGW&㰢f"��7�5&�r�$fW'6���"�2�'V��G��.(	B"���7�5&�r�$�W6�2Ɩ'&'����"�2��W&��$6���V7FVB#�$��B6WB"�2��W&��7�5&�r�$VF��6W'fW""�2�VF��&6S�$6���V7FVB#�$��B6WB"�2�VF��&6R���7�5&�r�$�W6�2��v��"�2�F��V��%6�v�VB��#�$��B6�v�VB��"�2�F��V⒰�7�5&�r�$WF��&Vg&W6���v��"�2�WF���v���$��#�$�fb"�2�WF���v�⒰�7�5&�r�$FF&6R�C�"�2�C�$6���V7FVB#�$��B6WB"�2�C���7�5&�r�%7F�&vR"�2�c�%&VG�#�$��B6WB"�2�b���7�5&�r�$66�V�G2"�W6W'2��V�wF����7�5&�r�%���VB�'V�2"���6fr�fVGW&VB��ŵҒ��V�wF����7�5&�r�$��FFV��'V�2"���6fr憖FFV��ŵҒ��V�wF����&�����W$�D��փ��Ғ�6F6��gV�7F��ₗ��b�B�'7�4&��"��&�����W$�D���s�F�b6�73�&V�G�#�6�V�B��B��B���F�c�s�ғ�ТgV�7F���&V�FW$�W6�57FGW2�����և�ǷӲf"V��B�&�W6�57FGW2"���b�V&WGW&�f"'G3յӰ��b���WF���v��'G2�W6��.)�26�v�VB��"����V����"�"�W62���V���"�"��""����b���F��V�'G2�W6��.)�2F��V�6WB"���V����W$�D���'G2��V�wF��s�7�7G��S�&6���#�f"������#�r�'G2����"+r"��s��7��r��s�7�7G��S�&6���#�f"���v&�#���B6WB(	B6��w2v����wB��V�F����R6�v����W&R���7��s��f"V��B�&פV���"���b�V�bf��V���bbV��f�VR�V��f�VSւ�V��òТgV�7F�����D�W6�57FGW2����7B�"���F֖���W6�2"ǶF֖��F�r�7F���'7FGW2'Ғ�F�V�gV�7F���B��&V�FW$�W6�57FGW2�B�2��Ғ�6F6��gV�7F��ₗ�ғ�ТgV�7F����W6�4�6r�G�B�6���"��f"��B�&�W6�4�6r"���b�җ���7G��R�6���#�6���'��'f"����WFVB�#���FW�D6��FV�C�G�G��"#��ТgV�7F���6fT�W6�2����W6�4�6r�%6f��rbFW7F��~(
b"�'f"����WFVB�"����7B�"���F֖���W6�2"ǶF֖��F�r�7F���'6fR"�V��â�B�&פV���"��ǷҒ�f�VW��""�77v�&C��B�&ץ72"��ǷҒ�f�VW��""�F��V㢂B�&ץF��V�"��ǷҒ�f�VW��"'Ғ�F�V�gV�7F���B��&V�FW$�W6�57FGW2�B�2��f"�B�&ץ72"���b���f�VS�"#�FW7D�W6�2���Ғ�6F6��gV�7F���R���W6�4�6r�R��W76vW��$6�V�B��B6fR�"�'f"���W'"�"��ғ�ТgV�7F���FW7D�W6�2����W6�4�6r�%FW7F��rF�R�W6�26W'fW.(
b�WF��36V6��G2�"�'f"����WFVB�"���f"F��S�f�6R�F��6WEF��V�WB�gV�7F��ₗ��b�F��R��W6�4�6r�%F�R�W6�26W'fW"F�F�(	�B�7vW"��F��R(	B�B��&RV�&V6�&�R��"F�R��v���2w&��r�G'�v����"W6RF��V��"�'f"���W'"�"����C����7B�"���F֖���W6�2"ǶF֖��F�r�7F���'FW7B'Ғ�F�V�gV�7F���B��F��S�G'VS�6�V%F��V�WB�F��b�B�2�&V�FW$�W6�57FGW2�B�2����b�B������W6�4�6r�.)�2v�&�2�W6�26��V�B����r�"�'f"������"��ТV�6R�f"W�G&�"#�f"GC�B�FWF���ǷӰ��b�GB���v��W'&�"�W�G&��%�����v��W'&�#�"�GB���v��W'&�#���b�GB�VF��7FGW2�W�G&��%���VF��6W'fW#��EE"�GB�VF��7FGW3���b�GB�WF��WFF���2bfGB�WF��WFF���2�6�F�FFW2�W�G&��%���f��&�R��v��3�"��GB�WF��WFF���2�6�F�FFW2����"�"���"����Rf�V�B�"���f"�6s҆B�W'&�'��%FW7Bf��VB�"��W�G&��f"��B�&�W6�4�6r"���b�җ���7G��R�6���#�'f"���W'"�#�����W$�D���s�&RF�#�&�G""7G��S�'v��FR�76S�&R�w&��&v���f��B�6��S��&V�#�r�W62��6r��s��&S��'WGF��6�73�&'F�6�"7G��S�&�&v���F��g�"��6Ɩ6��'v��F�r��6���r��4���7G&��v�g���4���7G&��v�g���6r���s�6��FW�B�F��2�#�6����'WGF���s�Т�Ғ�6F6��gV�7F���R��F��S�G'VS�6�V%F��V�WB�F��W6�4�6r�R��W76vW��%FW7Bf��VB�"�'f"���W'"�"��ғ�ТgV�7F���6�V$�W6�2����b�6��f�&҂$6�V"F�R6fVB�W6�2�6W'fW"��v���"��&WGW&��7B�"���F֖���W6�2"ǶF֖��F�r�7F���&6�V"'Ғ�F�V�gV�7F���B��&V�FW$�W6�57FGW2�B�2���W6�4�6r�$6�V&VB�"�'f"����WFVB�"��Ғ�6F6��gV�7F��ₗ�ғ�ТgV�7F���&V6���W6�2����W6�4�6r�%&VF��rF�R���r��W.(
b�WF��36V6��G2�"�'f"����WFVB�"����7B�"���F֖���W6�2"ǶF֖��F�r�7F���'&V6��'Ғ�F�V�gV�7F���B��f"&3҆BbfB�&V6���ǷӲf"��f��'&V6��'V�F�W3�"���&2�'V�F�W7�ŵҒ��V�wF�����b�&2�W'&�"���f��%���W'&�#�"�&2�W'&�#���b�&2�vW2����f��%���vW3�#�&2�vW2�f�$V6��gV�7F�������f��%���"��W&²"(i""���W'&�#�$U%""��W'&�"���$�EE"��7FGW2�"�V��"���V�"�"���VG��""����ғ�Т�b�&2�'V�F�W2bg&2�'V�F�W2��V�wF����f��%���'V�F�W3����"�&2�'V�F�W2����%���"����b�&2憗G2��f�"�f"�r��&2憗G2����f��%������"��r�%����"�&2憗G5��u�����%���"���Тv��F�r��6��֖�f�f"��B�&�W6�4�6r"���b�җ���7G��R�6���#�'f"���FW�B�#�����W$�D���s�&RF�#�&�G""7G��S�'v��FR�76S�&R�w&�v�&B�'&V��'&V��v�&C��&v���f��B�6��S��sW&VӶ��ֆV�v�C�Sf���fW&f��s�WF�#�r�W62���f�s��&S��'WGF��6�73�&'F�6�"7G��S�&�&v���F��g�"��6Ɩ6��&6��FW�B�F��2�#�6����'WGF���s�ТҒ�6F6��gV�7F���R���W6�4�6r�R��W76vW��%&V6��f��VB�"�'f"���W'"�"��ғ�ТgV�7F���7FEF��R����&V��66V�B��&WGW&�s�F�b7G��S�&f�W���֖��v�GF���&6�w&�V�C�f"���7W&f6R�"��&�&FW"�&F�W3�G��FF��s�7�g�#��F�b7G��S�&f��B�6��S��W&VӶf��B�vV�v�C���6���#�r��66V�G��wf"���FW�B�r��r#�r�������s��F�c��F�b6�73�&�WFVB"7G��S�&f��B�6��S��w&VӶƖ�RֆV�v�C��"#�r�W62��&V�s��F�c���F�c�s�ТgV�7F���F��Tv�B���b�B�&WGW&�.(	B#�f"3��F�������F��&�V�B��FFR���r��҆G���������b�3�c�&WGW&�2�'2v�#�f"���F��&�V�B�2�c���b���c�&WGW&�Ҳ&�v�#�f"���F��&�V�B���c���b���#B�&WGW&���&�v�#�&WGW&��F��&�V�B���#B��&Bv�#�ТgV�7F���&$6�'B�F�ǒ���b�F�Ǘ��F�ǒ��V�wF��&WGW&�"#��f"����F�ǒ�f�$V6��gV�7F���B���b�B�6�V�C�������B�6�V�C�ғ��f"&'3�F�ǒ���gV�7F���B��f"���F��&�V�B��B�6�V�B�����SB��&WGW&�s�F�b7G��S�&f�W���F�7���f�W��f�W��F�&V7F���6��V��Ɩv�֗FV�3�6V�FW#�v�G��֖��v�GF��#�r��s�F�b6�73�&�WFVB"7G��S�&f��B�6��S��cg&V�#�r�B�6�V�B�s��F�c�r��s�F�b7G��S�'v�GF��sS����v�GF��#g���V�v�C�r��F�������2��w��&6�w&�V�C�Ɩ�V"�w&F�V�B��FVr�f"���66V�B��f"���66V�C"�f"���66V�B����&�&FW"�&F�W3�W�W�'�'�#���F�c�r��s�F�b6�73�&�WFVB"7G��S�&f��B�6��S��cG&V�#�r�W62�B��&V�s��F�c���F�c�s�Ғ����""���&WGW&�s�F�b7G��S�&f��B�vV�v�C�s��&v��g���#���2(	B�7BrF�3��F�c��F�b7G��S�&F�7���f�W��Ɩv�֗FV�3�f�W��V�C�v�W��&6�w&�V�C�f"���7W&f6R�"��&�&FW"�&F�W3�G��FF��s�'����V�v�C�G�#�r�&'2�s��F�c�s�ТgV�7F���&�&�r�����R�7V"�6�V�B��&WGW&�s�F�b6�73�&6�FR֗FV�#��F�b7G��S�'v�GF��#'��6���#�f"����WFVB��f��B�vV�v�C�s�f�W�����R#�r������s��F�c��F�b7G��S�&֖��v�GF���f�W��#��F�b6�73�&6����R#�r�W62���R��s��F�c�r��7V#�s�F�b6�73�&6��6�FR#�r�W62�7V"��s��F�c�s�rr��s��F�c��F�b7G��S�&f��B�vV�v�C���6���#�f"���66V�B��f�W�����R#�r�6�V�B�s��F�c���F�c�s�ТgV�7F���7FG4�F�2����b�2�C���f�6W��2�W'&�"��&WGW&�s�F�b6�73�&V�G�#�r�W62�2�W'&�'��$��Bf��&�R�"��s��F�c�s�Т�b�2�F�F�&WGW&�s�F�b6�73�&V�G�#�����2�WB���6RV��R7F'BƗ7FV��r���U��v��6VRv�E��w2�V�"�W&R���F�c�s�Тf"F��W3�s�F�b7G��S�&F�7���f�W��v�w��FW�B�Ɩv�6V�FW#��&v���&�GF�ӣ��#�r�7FEF��R�2�F�F��$���F��R��2"��7FEF��R�2����F��%F��2���F�"��7FEF��R�2�vVV��%F��2vVV�"��7FEF��R�2�F�F��%F�F�"��s��F�c�r��s�F�b7G��S�&F�7���f�W��v�w��FW�B�Ɩv�6V�FW#��&v���&�GF�ӣg�#�r�7FEF��R�2�Ɨ7FV�W'2�$Ɨ7FV�W'2"�wf"���66V�B�r��7FEF��R�2�7F�fUvVV��$7F�fRF��2vVV�"�wf"���66V�B�r��7FEF��R�2�7F�fUF�F��$7F�fRF�F�"�wf"���66V�B�r��s��F�c�s��f"6�'C�&$6�'B�2�F�ǒ���f"F�҇2�F�G&6�7�ŵҒ��V�wF��s�F�b7G��S�&f��B�vV�v�C�s��&v��g�g�#�F�6��w3��F�c�r��2�F�G&6�7�ŵҒ�6Ɩ6R��"����gV�7F���Bƒ��&WGW&�&�&�r���B�F�F�W�%G&6�"�B�G&6���B�'F�7G��""�B�6�V�B��Ғ����""���rs��f"'G3҇2�F�'F�7G7�ŵҒ��V�wF��s�F�b7G��S�&f��B�vV�v�C�s��&v��g�g�#�F�'F�7G3��F�c�r��2�F�'F�7G7�ŵҒ�6Ɩ6R������gV�7F���ƒ��&WGW&�&�&�r����'F�7B�""��6�V�B��Ғ����""���rs��f"W6W'3҇2�F�W6W'7�ŵҒ��V�wF��s�F�b7G��S�&f��B�vV�v�C�s��&v��g�g�#���7B7F�fRƗ7FV�W'3��F�c�r��2�F�W6W'7�ŵҒ���gV�7F���Rƒ��&WGW&�&�&�r���R���R�""�R�6�V�B��Ғ����""���rs��f"&V6V�C҇2�&V6V�G�ŵҒ��V�wF��s�F�b7G��S�&f��B�vV�v�C�s��&v��g�g�#�&V6V�B��3��F�c�r��2�&V6V�G�ŵҒ�6Ɩ6R��#R����gV�7F���"��&WGW&�s�F�b6�73�&6�FR֗FV�#��F�b7G��S�&֖��v�GF���f�W��#��F�b6�73�&6����R#�r�W62�"�F�F�W��.(	B"��s��F�c��F�b6�73�&6��6�FR#�r�W62�"���R���"�'F�7C�r+rr�W62�"�'F�7B��rr��r+rr�F��Tv�"�B��s��F�c���F�c���F�c�s�Ғ����""���rs��&WGW&�F��W2�6�'B�F��'G2�W6W'2�&V6V�C��ТgV�7F���f��FW$66�V�G2���f"҂�B�&67E6V&6�"��ǷҒ�f�VW��""��G&�҂��F���vW$66R���f"Ɨ7C�B�&67DƗ7B"���b�Ɨ7B�&WGW&�f"6&G3�Ɨ7B�VW'�6V�V7F�$�"�67B"��f"6��v����6&G2�f�$V6��gV�7F���2��f"����2�vWDGG&�'WFR�&FF�6V&6�"���""���FW��b�����2�7G��R�F�7������"#�&���R#��b����6��vⲳ�ғ��f"���S�B�&67D���R"���b����R����R�7G��R�F�7���6��v��&���R#�&&��6�#�ТgV�7F���W��'D77b�v�B��F�7B�%&W&��~(
b"���fWF6��"���F֖��W��'B"Ƕ�WF��C�%�5B"ƆVFW'3��$6��FV�B�G�R#�&Ɩ6F�����6��'��&�G���4���7G&��v�g���F֖��F�r�v�C�v�GҗҒ�F�V�gV�7F���"���b�"����F�&�r�WrW'&�"�$W��'Bf��VB�"�"�7FGW2�"�"��&WGW&�"�&��"���Ғ�F�V�gV�7F���&��"���f"W&��U$��7&VFT�&�V7EU$&��"��f"�F�7V�V�B�7&VFTV�V�V�B�&"���&Vc�W&ò�F�v���C҇v�C���&66�V�G2#�&66�V�G2�77b#�'��2�77b"��F�7V�V�B�&�G��V�D6���B����6Ɩ6�����6WEF��V�WB�gV�7F��ₗ�U$��&Wf��T�&�V7EU$W&��&V��fR�����S��F�7B�$F�v���FVB)�2"���Ғ�6F6��gV�7F���R��F�7B�R��W76vW��$W��'Bf��VB"��ғ�ТgV�7F���&W6WE7FG2����b�6��f�&҂$6�V"��Ɨ7FV��r��7F�'��F��26���B&RV�F��R�"��&WGW&㰢�7B�"���F֖��7FG2"ǶF֖��F�r�7F���'&W6WB'Ғ�F�V�gV�7F��ₗ�F�7B�$��7F�'�6�V&VB�"����E7FG2���Ғ�6F6��gV�7F���R��F�7B�R��W76vW��$f��VB�"��ғ�ТgV�7F����V�W6W$FWF��B���f"W6W'3҅�F��W6W'2be�F��W6W'2�W6W'2��ŵӲf"S��V�òf�"�f"�����W6W'2��V�wF��������b�W6W'5����C��֖B��S�W6W'5��Ӳ'&V���Тf"&6��s�F�b6�73�&&6�"��6Ɩ6��&F֖�6V7F�����v66�V�G5��r�#�r��2�&'&�u�&6����5��Wr"��t66�V�G3��F�c�s���f�6WB�$F֖�"�&6��6V5w&�S�W62�R���W��R�V���$66�V�B"�s�F�b�C�'VD&��#��7�6�73�'7���W"#���7����F��~(
c��F�c�r�����7B�"���F֖��W6W'��2"ǶF֖��F�rƖC��GҒ�F�V�gV�7F���B��f"&���B�'VD&��"���b�&���&WGW&㰢f"�VC�S�s�F�b7G��S�&F�7���f�W��Ɩv�֗FV�3�6V�FW#�v�'���&v���&�GF�ӣ'�#�r�W6W$fF"�R��s�F�b7G��S�&֖��v�GF��#��F�b6�73�&6����R#�r�W62�R���W��R�V���s��F�c��F�b6�73�&6��6�FR#�r�W62�R�V���r+rr�W62�R����W��""��s��F�c�r��R��7E6VV��s�F�b6�73�&6��6�FR"7G��S�&6���#�f"����WFVB�#��7B6VV�r�F��Tv�R��7E6VV⒲s��F�c�s�rr��s��F�c���F�c�r��rs��f"F��W3�s�F�b7G��S�&F�7���f�W��v����FW�B�Ɩv�6V�FW#��&v���&�GF�ӣg�#�r�7FEF��R�B�F�F��%F�F���2"��7FEF��R�B�vVV��%F��2vVV�"��s��F�c�s��f"F�҆B�F��ŵҒ��V�wF��s�F�b7G��S�&f��B�vV�v�C�s��&v��G�g�#�F�V�"F�6��w3��F�c�r��B�F��ŵҒ���gV�7F���Bƒ��&WGW&�&�&�r���B�F�F�W�%G&6�"�B�G&6���B�'F�7G��""�B�6�V�B��Ғ����""���rs��f"&V3҆B�&V6V�G�ŵҒ��V�wF��s�F�b7G��S�&f��B�vV�v�C�s��&v��G�g�#�&V6V�B��3��F�c�r��B�&V6V�G�ŵҒ���gV�7F���"��&WGW&�s�F�b6�73�&6�FR֗FV�#��F�b7G��S�&֖��v�GF���f�W��#��F�b6�73�&6����R#�r�W62�"�F�F�W��.(	B"��s��F�c��F�b6�73�&6��6�FR#�r�W62�"�'F�7G��""��r+rr�F��Tv�"�B��s��F�c���F�c���F�c�s�Ғ����""���s�F�b6�73�&V�G�#�����2�WB���F�c�s��&�����W$�D��ֆVB�F��W2�F��&V3��Ғ�6F6��gV�7F���R��f"&���B�'VD&��"���b�&���&�����W$�D���s�F�b6�73�&V�G�#�r�W62�R��W76vW��$6�V�B��B��B�"��s��F�c�s�ғ�ТgV�7F�����E7FG2���f"&���B�'7FG4&��"���b�&���&WGW&�&�����W$�D���s�F�b6�73�&V�G�"7G��S�'FF��s�g�#��7�6�73�'7���W"#���7����F��~(
c��F�c�s���7B�"���F֖��7FG2"ǶF֖��F�wҒ�F�V�gV�7F���2��&�����W$�D���7FG4�F�2��Ғ�6F6��gV�7F���R���b�RbfR��W76vS���&��v��"�&WGW&�&�����W$�D���s�F�b6�73�&V�G�#�r�W62��RbfR��W76vR���$6�V�B��B��B�"��s��F�c�s�ғ�ТgV�7F���FD6�FR���f"�҂B�&6�"��ǷҒ�f�VW��""�3҂B�&62"��ǷҒ�f�VW��"#�f"��B�&FF�6r"���b�Ғ��FW�D6��FV�C�"#���b�2�G&�҂����b�Ғ��FW�D6��FV�C�$V�FW"6�FR�#�&WGW&�Т�7B�"���F֖��FB"ǶF֖��F�r���S���6�FS�7Ғ�F�V�gV�7F��ₗ�F�7B�$FFVB�"����D66W72���Ґ��6F6��gV�7F���R���b�Ғ��FW�D6��FV�C�R��W76vW��$6�V�B��BFB�#�ғ�ТgV�7F���&V��fT6�FR�'F◲f"6�FS�'F��vWDGG&�'WFR�&FF�6�FR"���"#���7B�"���F֖��&V��fR"ǶF֖��F�r�6�FS�6�FWҒ�F�V�gV�7F��ₗ�F�7B�%&V��fVB�"����D66W72���Ґ��6F6��gV�7F���R��F�7B�R��W76vW��$6�V�B��B&V��fR�"��ғ�ТgV�7F����e6WGW�F���&WGW&�s�F�b6�73�&6&B"7G��S�'FF��s�g��Ɩ�RֆV�v�C��b#�r��s�F�b7G��S�&f��B�vV�v�C�s��&v���&�GF�ӣ��#���RV�6�6WGW7FW��F�c�r��s�6�73�&�WFVB"7G��S�&�&v��'�#�F���vR66�V�G2�B6WGF��w2�F�R�VVG26���7F�&vR&V�g&VR����R6�W6R�#�C5�FF&6S��#��"�#�b��W76S��#�(	BV�F�W"��R����r��s�F�b7G��S�&f��B�vV�v�C�c��&v��'�G�#��F���(	BC�5�FF&6R���F�c�r��s���6�73�'7FW2�WFVB#�r��s�Ɠ��6��VFf�&R��V��#�7F�&vRf��FF&6W2(i"C��#�(i"�#�7&VFS��#��v�fR�B���R���Ɠ�r��s�Ɠ��V���W"v�&�W"(i"�#�6WGF��w2(i"&��F��w3��#�(i"�#�FB&��F��s��#�(i"�#�CFF&6S��#��6WBF�Rf&�&�R��RF��6�FS�D#��6�FS��B6���6RF�RFF&6R��R�W7B�FR���Ɠ�r��s�Ɠ�FW���v���F�V�6��R&6���F�RF&�W2&R7&VFVBWF��F�6�ǒ���Ɠ�r��s�����r��s�F�b7G��S�&f��B�vV�v�C�c��&v���G�#��F���"(	B�c��F�c�r��s���6�73�'7FW2�WFVB#�r��s�Ɠ��#�7F�&vRf��FF&6W2(i"�c��#�(i"�#�7&VFR��7F�6S��#����Ɠ�r��s�Ɠ�v�&�W"(i"�#�6WGF��w2(i"&��F��w3��#�(i"�#�b��W76S��#��f&�&�R��R�6�FS夔�u��c��6�FS����Ɠ�r��s�Ɠ�FW���v�����Ɠ�r��s�����r��s�6�73�&�WFVB"7G��S�&�&v��'�#�V�F��F�V��WfW'���R6�v�2��v�F�F�R��R���77v�&B(	BF�B�VW2v�&���r������F�c�s�Р�������������F�v��7F�72���������ТgV�7F���F�t&����F��f"C�B�&F�r"���b�B�B���W$�D����F���s�F�b7G��S�&&6�w&�V�C�f"���7W&f6R��&�&FW#��6�ƖBf"���Ɩ�R��&�&FW"�&F�W3�G��FF��s�G�#�r��F�²s��F�c�s�rs�ТgV�7F���'V�6�V6����F�t&���s�7�6�73�'7���W"#���7��6�V6���~(
br���fWF6��"���6�V6�"��F�V�gV�7F���"���b�"�7FGW3���C����6F����&Vc�"�#�F�&�r�WrW'&�"�&��v��"���&WGW&�"�6�ₓ�Ғ�F�V�gV�7F���2���f"��2���Ƿ��VF���2�VF���Ƿ����v���2���v���Ƿ���յӰ���W6�����&V6�&�S���f�6S�.)��#����7FGW3���#�.)�R#�.)����"���$�W6�2�"����W'&�#�#�"�W62���W'&�"��""�����b���v���6��f�wW&VB��f�6R���W6�����v������.)�R#�.)��"��$WF����v��"����v���W'&�#�#�"�W62���v���W'&�"��"v�&�2"������W6���VF���&V6�&�S���f�6S�.)��#��VF���7FGW3���C3�.)��#�.)�R"���$VF��"��VF���7FGW3�"�"�VF���7FGW2�"�#�""���VF���W'&�#�#�"�W62�VF���W'&�"��""����f"F��2�F��V��f��W�G&�"#��b�F�bgF��72�W�G&�s�F�b7G��S�&�&v���F�����f��B�6��S��&V�"6�73�&�WFVB#�F��V�r�W62�F��72��s��F�c�s��F�t&���s�#�6���V7F�����#��F�b7G��S�&�&v���F�����Ɩ�RֆV�v�C��#�r������#�'#�"��s��F�c�r�W�G&���Ғ�6F6��gV�7F���R���b�RbfR��W76vS���&��v��"�&WGW&�F�t&���$W'&�#�"�W62�R��W76vW��R���ғ��ТgV�7F���6��u66�V����F�t&���s�7�6�73�'7���W"#���7��&VF��~(
br���fWF6��"���66�V�"��F�V�gV�7F���"��&WGW&�"�6�ₓ�Ғ�F�V�gV�7F���2���b�2�W'&�"��F�t&���$W'&�#�"�W62�2�W'&�"���&WGW&�Тf"c�2�VW'�f�V�G7�ŵӲf"G�C�%TU$�U3����"�b���gV�7F��⇂��&WGW&�"�"�����R�"�"����&w7�ŵҒ����"�"��"���"����&WGW&�7��#�"��Ғ����%���"���f"G�W3�2�G�W7�ǷӲG�B��%������E�U3����#��&�V7B�W�2�G�W2��f�$V6��gV�7F��↲��G�B�ֲ�#�"�G�W5�������"�"��%������#�ғ��v��F�r��6���G�C�F�t&���s�#��7G'V7GW&S��#��'WGF��6�73�&'F�6�"��6Ɩ6��&6��FW�B�F��2�#�6����'WGF����&RF�#�&�G""7G��S�'v��FR�76S�&R�w&�v�&B�'&V��'&V��v�&C�f��B�6��S��sW&VӶ�&v���F����#�resc(txt)+'</pre>');
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
    function probeNew(){ diagBox('<span class="spinner"></span>Checking what the server returns for new music…');
      post("/api/probe/new",{admin:_admPw}).then(function(d){ var p=(d&&d.probe)||[]; if(!p.length){ diagBox("No result."); return; }
        var txt=p.map(function(v){ if(v.error) return "• "+v.label+" → ERROR: "+v.error;
          var lines=(v.rows||[]).map(function(r){ return "    #"+r.id+"  "+(r.name||"")+"   released:"+(r.releasedAt||"-")+(r.createdAt?("   created:"+r.createdAt):""); });
          return "• "+v.label+" ("+v.count+")\\n"+lines.join("\\n"); }).join("\\n\\n");
        window._copy=txt;
        diagBox('<b>New releases (debug)</b> <button class="btn sm" onclick="copyText(this)">Copy</button><div class="muted" style="margin:6px 0">Send me this (or a screenshot) so I can fix which list the newest music comes from.</div><pre dir="ltr" style="white-space:pre-wrap;word-break:break-word;font-size:.72rem;margin-top:8px">'+esc(txt)+'</pre>');
      }).catch(function(e){ if(e&&e.message==="login")return; diagBox("Error: "+esc(e.message||e)); });
    }
    function probeAudio(){ diagBox('<span class="spinner"></span>Testing a single vs. an album on the music server…');
      post("/api/probe/audio",{admin:_admPw}).then(function(d){ if(d.error){ diagBox("Error: "+esc(d.error)); return; }
        function fmtT(x){ if(!x||!x.track){ return "(none found)"; } var t=x.track;
          var lines=(t.results||[]).map(function(r){ return "    "+r.label+" → "+(r.error?("ERROR "+r.error):("HTTP "+r.status+(r.type?(" "+r.type):"")+(r.len?(" len="+r.len):""))); });
          return x.album+"  ("+x.tracks+" tracks)\\n    id="+t.id+"  file="+(t.file||"(none)")+"\\n"+lines.join("\\n"); }
        var txt="SINGLE:\\n"+fmtT(d.single)+"\\n\\nALBUM:\\n"+fmtT(d.album);
        window._copy=txt;
        diagBox('<b>Singles (debug)</b> <button class="btn sm" onclick="copyText(this)">Copy</button><div class="muted" style="margin:6px 0">Send me this — it shows how a single differs from an album on the music server.</div><pre dir="ltr" style="white-space:pre-wrap;word-break:break-word;font-size:.72rem;margin-top:8px">'+esc(txt)+'</pre>');
      }).catch(function(e){ if(e&&e.message==="login")return; diagBox("Error: "+esc(e.message||e)); });
    }
    window.probeAudio=probeAudio;
    function copyText(btn){ var t=window._copy||""; try{ navigator.clipboard.writeText(t).then(function(){btn.textContent="Copied!";},function(){fb();}); }catch(e){ fb(); }
      function fb(){ var ta=document.createElement("textarea"); ta.value=t; document.body.appendChild(ta); ta.select(); try{document.execCommand("copy");}catch(e){} ta.remove(); btn.textContent="Copied!"; } }

    // expose
    window.go=go; window.openArtist=openArtist; window.openAlbum=openAlbum; window.openGenre=openGenre; window.openPlaylist=openPlaylist;
    window.openCategory=openCategory; window.openBannerUrl=openBannerUrl; window.openStory=openStory; window.openArticle=openArticle;
    window.browseAlbums=browseAlbums; window.loadMoreAlbums=loadMoreAlbums; window.playSearchTrack=playSearchTrack;
    window.playAlbum=playAlbum; window.playList=playList; window.downloadTrack=downloadTrack; window.downloadAlbum=downloadAlbum;
    window.togglePlay=togglePlay; window.nextTrack=nextTrack; window.prevTrack=prevTrack; window.dlCurrent=dlCurrent;
    window.showLyrics=showLyrics; window.closeOverlay=closeOverlay; window.openSettings=openSettings;
    window.runCheck=runCheck; window.showSchema=showSchema; window.showImageInfo=showImageInfo; window.copyText=copyText; window.probeNew=probeNew;
    window.showFullSchema=showFullSchema; window.downloadText=downloadText; window.showZingConfig=showZingConfig; window.showZingActions=showZingActions;
    window.openNowPlaying=openNowPlaying; window.npLyrics=npLyrics; window.npSimilar=npSimilar; window.playSimilar=playSimilar;
    window.toggleShuffle=toggleShuffle; window.cycleRepeat=cycleRepeat; window.seekTo=seekTo; window.npTab=npTab; window.jumpQueue=jumpQueue;
    window.openHistory=openHistory; window.playHistory=playHistory; window.dlFromHistory=dlFromHistory;
    window.likeCurrent=likeCurrent; window.toggleLike=toggleLike; window.openLiked=openLiked; window.playLiked=playLiked; window.unlike=unlike;
    window.openSleep=openSleep; window.setSleep=setSleep; window.setRadio=setRadio; window.clearData=clearData;
    window.playNext=playNext; window.addToQueue=addToQueue;
    window.openMyPlaylists=openMyPlaylists; window.openMyPlaylist=openMyPlaylist; window.playMyPlaylist=playMyPlaylist; window.newPlaylistPrompt=newPlaylistPrompt; window.deletePlaylist=deletePlaylist; window.removeFromPlaylist=removeFromPlaylist;
    window.choosePlaylist=choosePlaylist; window.addToPlaylistUI=addToPlaylistUI; window.newPlaylistAdd=newPlaylistAdd;
    window.songMenu=songMenu; window.songMenuAlbum=songMenuAlbum; window.menuLike=menuLike; window.menuPlaylist=menuPlaylist; window.menuPlayNext=menuPlayNext; window.menuAddQueue=menuAddQueue;
    window.browseLibrary=browseLibrary; window.saveArtist=saveArtist; window.saveAlbum=saveAlbum;
    window.setLang=setLang; window.setTheme=setTheme; window.setAutoplay=setAutoplay; window.signOut=signOut;
    window.openAccess=openAccess; window.backToSettings=backToSettings; window.unlockAccess=unlockAccess; window.addCode=addCode; window.removeCode=removeCode;
    window.cfgSet=cfgSet; window.saveAdminConfig=saveAdminConfig; window.cfgPick=cfgPick; window.cfgAccent=cfgAccent;
    window.userAction=userAction; window.userCreate=userCreate; window.userReset=userReset; window.openProfile=openProfile; window.changePw=changePw; window.loadStats=loadStats;
    window.saveMusic=saveMusic; window.testMusic=testMusic; window.clearMusic=clearMusic; window.loadMusicStatus=loadMusicStatus;
    window.pfCam=pfCam; window.pfStop=pfStop; window.pfSnap=pfSnap; window.showTakeover=showTakeover; window.hideTakeover=hideTakeover; window.claimDevice=claimDevice;


    // ---------- Recent searches, keyboard shortcuts, lock-screen seek ----------
    function getRecentQ(){ try{ var a=JSON.parse(localStorage.getItem("zing_recentq")||"[]"); return Array.isArray(a)?a.slice(0,8):[]; }catch(e){ return []; } }
    function saveRecentQ(q){ try{ var a=getRecentQ().filter(function(x){ return x.toLowerCase()!==q.toLowerCase(); }); a.unshift(q); localStorage.setItem("zing_recentq",JSON.stringify(a.slice(0,8))); }catch(e){} }
    function clearRecentQ(){ try{ localStorage.removeItem("zing_recentq"); }catch(e){} doSearch(""); }
    function pickRecentQ(i){ var v=getRecentQ()[i]; if(!v) return; var q=$("q"); if(q) q.value=v; doSearch(v); }
    window.removeFromQ=removeFromQ; window.clearUpcoming=clearUpcoming; window.clearRecentQ=clearRecentQ; window.pickRecentQ=pickRecentQ;
    document.addEventListener("keydown", function(e){
      var tg=e.target&&e.target.tagName; if(tg==="INPUT"||tg==="TEXTAREA"||tg==="SELECT"||(e.target&&e.target.isContentEditable)) return;
      if(e.ctrlKey||e.metaKey||e.altKey) return;
      var k=e.key;
      if(k===" "||k==="k"){ if(queue.length){ e.preventDefault(); togglePlay(); } }
      else if(k==="ArrowRight"){ if(queue.length){ e.preventDefault(); if(e.shiftKey) nextTrack(); else skipBy(SET.skip||15); } }
      else if(k==="ArrowLeft"){ if(queue.length){ e.preventDefault(); if(e.shiftKey) prevTrack(); else skipBy(-(SET.skip||15)); } }
      else if(k==="ArrowUp"){ if(queue.length){ e.preventDefault(); setVol(Math.min(100,(audio.volume*100)+5)); } }
      else if(k==="ArrowDown"){ if(queue.length){ e.preventDefault(); setVol(Math.max(0,(audio.volume*100)-5)); } }
      else if(k==="s"){ toggleShuffle(); }
      else if(k==="r"){ cycleRepeat(); }
      else if(k==="l"){ if(queue.length) likeCurrent(); }
      else if(k==="m"){ audio.muted=!audio.muted; toast(audio.muted?"Muted":"Unmuted"); }
      else if(k==="/"){ e.preventDefault(); go("search"); }
    });
    if("mediaSession" in navigator){ try{
      navigator.mediaSession.setActionHandler("seekto", function(d){ if(d&&d.seekTime!=null&&audio.duration){ audio.currentTime=Math.max(0,Math.min(audio.duration,d.seekTime)); } });
      navigator.mediaSession.setActionHandler("stop", function(){ audio.pause(); });
    }catch(e){} }
    var _lastPS=0;
    audio.addEventListener("timeupdate", function(){ var n=Date.now(); if(n-_lastPS<1500) return; _lastPS=n;
      try{ if("mediaSession" in navigator&&navigator.mediaSession.setPositionState&&audio.duration&&isFinite(audio.duration)){
        navigator.mediaSession.setPositionState({duration:audio.duration,playbackRate:audio.playbackRate||1,position:Math.min(audio.currentTime,audio.duration)}); } }catch(e){} });


    // ---------- Shuffle button, page title, offline notice ----------
    function shufflePlay(kind,id){
      var n=0; if(kind==="album"){ var al=(window._albums||{})[id]; n=al&&al.tracks?al.tracks.length:0; } else { n=(window._listTracks||[]).length; }
      if(!n) return; _shuffle=true; try{ localStorage.setItem("zing_shuffle","1"); }catch(e){}
      var i=Math.floor(Math.random()*n); if(kind==="album") playAlbum(id,i); else playList(i); syncSheet(); }
    function shuffleAlbum(id){ shufflePlay('album',id); } function shuffleList(){ shufflePlay('list'); }
    try{ if("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(function(){}); }catch(e){}
    window.shuffleAlbum=shuffleAlbum; window.shuffleList=shuffleList;
    var _baseTitle=document.title;
    audio.addEventListener("playing", function(){ var t=queue[qi]; if(t) document.title="\u25B6 "+(t.title||"")+(t.artist?" \u2014 "+t.artist:""); });
    audio.addEventListener("pause", function(){ document.title=_baseTitle; });
    window.addEventListener("offline", function(){ toast("You're offline. Playback will resume when you're back online."); });
    window.addEventListener("online", function(){ toast("Back online."); });

    document.addEventListener("visibilitychange", function(){ if(!document.hidden) refreshNew(); });
    hydrateIcons(); checkStatus(); sendPresence(); setInterval(sendPresence, 25000); setInterval(function(){ if(!ME.admin){ loadMe(); } }, 30000); setInterval(refreshNew, 60000);
    // Personal workspace. Device-local, with no changes to connected favorites.
    var UXKEY="zing_workspace", UX={accent:"site",density:"comfortable",motion:"system",confirmDownloads:true};
    try{Object.assign(UX,JSON.parse(localStorage.getItem(UXKEY)||"{}"));}catch(e){}
    function uxSave(){try{localStorage.setItem(UXKEY,JSON.stringify(UX));}catch(e){toast("Could not save this preference.");}}
    function applyUX(){var r=document.documentElement;r.dataset.density=UX.density;r.dataset.motion=UX.motion;var c={purple:["#7c5cff","#ff4d8d"],green:["#159c72","#29b8ca"],blue:["#3478f6","#9b5cff"],rose:["#d83d78","#a65cf5"]};if(c[UX.accent]){r.style.setProperty("--accent",c[UX.accent][0]);r.style.setProperty("--accent-2",c[UX.accent][1]);}}
    function setUX(k,v){if(k==="confirmDownloads")v=v==="on";UX[k]=v;uxSave();if(k==="accent"&&v==="site")applyConfig(CFG);applyUX();openSettings();}
    applyUX();
    function localList(k){try{var a=JSON.parse(localStorage.getItem(k)||"[]");return Array.isArray(a)?a:[];}catch(e){return [];}}
    function localWrite(k,a){try{localStorage.setItem(k,JSON.stringify(a));return true;}catch(e){toast("Storage is full or unavailable. Nothing was saved.");return false;}}
    function libraryHub(){return '<div class="workspace-banner"><div class="kicker">YOUR SPACE</div><h2>Music, your way.</h2><p class="muted">Your favorites, playlists and listening tools, one tap away.</p><div class="chips"><button class="chip" onclick="browseLibrary()">'+ic("favorite")+' Library</button><button class="chip" onclick="openMyPlaylists()">'+ic("queue_music")+' Playlists</button><button class="chip" onclick="openHistory()">'+ic("history")+' History</button><button class="chip" onclick="openSettings()">'+ic("settings")+' Settings</button></div></div>';}
    var remoteLibrary=browseLibrary;
    function browseConnectedLibrary(){remoteLibrary();}
    var _libFilter="all",_libQuery="",_libSort="name";
    browseLibrary=function(){curTab="library";setTab("");var t=$("tabLibrary");if(t)t.classList.add("active");setStatus("");
      setView('<div class="workspace-banner"><div class="kicker">YOUR MUSIC</div><h2>Library</h2><p class="muted">Saved on this browser. Not synced between devices. Export a backup in Settings.</p><div class="chips"><button class="chip" onclick="newPlaylistPrompt()">+ New playlist</button><button class="chip" onclick="openLiked()">Liked songs ('+getLiked().length+')</button><button class="chip" onclick="openHistory()">History</button><button class="chip" onclick="browseConnectedLibrary()">Connected library</button></div></div><div class="library-tools"><input class="field" id="libQ" placeholder="Filter your library..." aria-label="Filter your library" oninput="_libQuery=this.value;renderLibraryItems()"><div class="chips">'+["all","playlists","albums","artists"].map(function(k){return '<button class="chip '+(_libFilter===k?'on':'')+'" data-lib="'+k+'" onclick="setLibraryFilter(\\''+k+'\\')">'+k[0].toUpperCase()+k.slice(1)+'</button>';}).join("")+'</div></div><div id="libraryItems"></div>');_libQuery="";renderLibraryItems();};
    function setLibraryFilter(k){_libFilter=k;document.querySelectorAll("[data-lib]").forEach(function(b){b.classList.toggle("on",b.dataset.lib===k);});renderLibraryItems();}
    function renderLibraryItems(){var box=$("libraryItems");if(!box)return;var q=_libQuery.toLowerCase(),rows=[];
      getPlaylists().forEach(function(p){rows.push({type:"playlists",name:p.name,sub:p.tracks.length+" songs",action:"openMyPlaylist('"+p.id+"')"});});
      localList("zing_saved_albums").forEach(function(a){rows.push({type:"albums",name:albName(a),sub:artNames(a.artists),action:"openAlbum("+Number(a.id)+")",img:albImg(a)});});
      localList("zing_followed_artists").forEach(function(a){rows.push({type:"artists",name:pick(a.enName,a.heName)||"Artist",sub:"Following",action:"openArtist("+Number(a.id)+")",img:a.image});});
      rows=rows.filter(function(r){return (_libFilter==="all"||r.type===_libFilter)&&(r.name+" "+r.sub).toLowerCase().indexOf(q)>=0;});rows.sort(function(a,b){return a.name.localeCompare(b.name);});
      box.innerHTML=rows.length?'<div class="grid albums">'+rows.map(function(r){return '<button class="tile library-tile" onclick="'+esc(r.action)+'">'+coverHtml(r.name,{img:r.img,round:r.type==="artists"})+'<div class="c-name">'+esc(r.name)+'</div><div class="c-sub">'+esc(r.sub)+'</div><div class="kicker">'+esc(r.type)+'</div></button>';}).join("")+'</div>':'<div class="empty"><h3>'+(q?'No matches':'Make this space yours')+'</h3>'+(q?'Try another name or filter.':'Save an album, follow an artist, or make a playlist. Your liked songs and history are above.')+'</div>';}
    function savedAlbum(id){return localList("zing_saved_albums").some(function(x){return String(x.id)===String(id);});}
    function followedArtist(id){return localList("zing_followed_artists").some(function(x){return String(x.id)===String(id);});}
    function saveLocalAlbum(id){var a=(window._albums||{})[id];if(!a)return;var l=localList("zing_saved_albums"),has=savedAlbum(id);if(localWrite("zing_saved_albums",has?l.filter(function(x){return String(x.id)!==String(id);}):[a].concat(l))){toast(has?"Removed from this device":"Album saved on this device");renderAlbum(id,a);}}
    function followLocalArtist(id){var a=(window._artistRecords||{})[id]||artists.filter(function(x){return String(x.id)===String(id);})[0];if(!a)return;var l=localList("zing_followed_artists"),has=followedArtist(id);if(localWrite("zing_followed_artists",has?l.filter(function(x){return String(x.id)!==String(id);}):[a].concat(l))){toast(has?"Artist unfollowed":"Following on this device");var b=$("followArtist");if(b)b.textContent=has?"Follow artist":"Following - unfollow";}}
    function renamePlaylist(id){var l=getPlaylists(),p=l.filter(function(p){return p.id===id;})[0];if(!p)return;var n=prompt("Playlist name:",p.name);if(n===null||!n.trim())return;p.name=n.trim().slice(0,60);savePlaylists(l);openMyPlaylist(id);}
    function movePlaylistTrack(id,i,d){var l=getPlaylists(),p=l.filter(function(p){return p.id===id;})[0];if(!p||i+d<0||i+d>=p.tracks.length)return;var t=p.tracks.splice(i,1)[0];p.tracks.splice(i+d,0,t);savePlaylists(l);openMyPlaylist(id);}
    function duplicatePlaylist(id){var p=getPlaylists().filter(function(p){return p.id===id;})[0];if(!p)return;var n=createPlaylist(p.name+" (copy)"),l=getPlaylists();l[0].tracks=p.tracks.slice();savePlaylists(l);openMyPlaylist(n.id);}
    function moveQueueTrack(idx,d){var p=_order.indexOf(idx),n=p+d,c=_order.indexOf(qi);if(p<=c||n<=c||n>=_order.length)return;var t=_order[p];_order[p]=_order[n];_order[n]=t;npQueue();}
    function keyboardHelp(){overlay("Keyboard shortcuts",'<div class="card">'+[["Space / K","Play or pause"],["Left / Right","Seek backward / forward"],["Shift + Left / Right","Previous / next song"],["Up / Down","Volume"],["S / R","Shuffle / repeat"],["L / M","Like / mute"],["/","Search"],["?","This help"]].map(function(x){return row(x[0],x[1],"");}).join("")+'</div><p class="muted">Shortcuts are paused while typing in an input.</p>');}
    function sharePage(){var url=location.origin+location.pathname+location.hash;if(navigator.share){navigator.share({title:document.title,url:url}).catch(function(){});}else if(navigator.clipboard){navigator.clipboard.writeText(url).then(function(){toast("Link copied");}).catch(function(){prompt("Copy this link:",url);});}else prompt("Copy this link:",url);}
    function exportLibrary(){var keys=["zing_liked","zing_playlists","zing_hist","zing_saved_albums","zing_followed_artists","zing_settings",UXKEY],data={app:"Zing",version:1,exportedAt:new Date().toISOString(),data:{}};keys.forEach(function(k){try{var s=localStorage.getItem(k);if(s)data.data[k]=JSON.parse(s);}catch(e){}});var blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"}),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="zing-library-backup.json";a.click();setTimeout(function(){URL.revokeObjectURL(a.href);},3000);toast("Library backup downloaded. Keep it private.");}
    // (settings sections consolidated into settingsHtml)
    function setAccent(v){setUX("accent",v);}function setDensity(v){setUX("density",v);}function setMotion(v){setUX("motion",v);}function setDownloadConfirm(v){setUX("confirmDownloads",v);}
    var baseDownloadAlbum=downloadAlbum;
    downloadAlbum=function(id){var a=(window._albums||{})[id];if(!a||!dlAllowed())return;if(UX.confirmDownloads&&!confirm("Download all "+(a.tracks||[]).length+" tracks? Your browser may ask to allow multiple files."))return;baseDownloadAlbum(id);};
    document.addEventListener("keydown",function(e){if(e.key==="?"&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!/INPUT|TEXTAREA|SELECT/.test((e.target||{}).tagName||"")&&!e.target.isContentEditable){e.preventDefault();keyboardHelp();}});

    // Optional Web Audio equalizer. No second stream or upstream request.
    var EQF=[60,170,350,1000,3500,10000],EQCTX=null,EQSRC=null,EQSRC2=null,EQGAIN=null,EQNODES=[],EQON=false,EQFAILED=false;
    var EQPRESETS={flat:[0,0,0,0,0,0],bass:[6,4,1,0,-1,-1],voice:[-3,-2,1,4,3,0],soft:[0,0,-1,-2,-3,-4]};
    var EQVALUES=Array.isArray(UX.eq)&&UX.eq.length===6?UX.eq.map(function(v){return Math.max(-12,Math.min(12,Number(v)||0));}):EQPRESETS.flat.slice();
    function updateEQ(){if(!EQGAIN)return;var headroom=EQON?Math.pow(10,-Math.max.apply(null,[0].concat(EQVALUES))/20):1;EQGAIN.gain.setTargetAtTime(headroom,EQCTX.currentTime,.02);EQNODES.forEach(function(n,i){n.gain.setTargetAtTime(EQON?EQVALUES[i]:0,EQCTX.currentTime,.02);});}
    async function enableEQ(){if(EQFAILED){toast("Equalizer unavailable in this session. Reload to try again.");return;}if(EQON){EQON=false;updateEQ();openEqualizer();return;}
      var C=window.AudioContext||window.webkitAudioContext;if(!C){toast("Equalizer is not supported by this browser.");return;}
      try{if(!EQCTX)EQCTX=new C();await EQCTX.resume();if(EQCTX.state!=="running"){toast("Play a song, then enable the equalizer.");return;}
        if(!EQSRC){EQGAIN=EQCTX.createGain();EQNODES=EQF.map(function(f){var n=EQCTX.createBiquadFilter();n.type="peaking";n.frequency.value=f;n.Q.value=1;return n;});
          var last=EQGAIN;EQNODES.forEach(function(n){last.connect(n);last=n;});last.connect(EQCTX.destination);EQSRC=EQCTX.createMediaElementSource(_players[0]);EQSRC.connect(EQGAIN);EQSRC2=EQCTX.createMediaElementSource(_players[1]);EQSRC2.connect(EQGAIN);}
        EQON=true;updateEQ();openEqualizer();
      }catch(e){EQON=false;if(EQSRC){try{EQSRC.disconnect();EQSRC.connect(EQCTX.destination);if(EQSRC2){EQSRC2.disconnect();EQSRC2.connect(EQCTX.destination);}}catch(_){}EQFAILED=true;}toast("Equalizer unavailable. Standard playback remains selected.");}}
    function eqBand(i,v){EQVALUES[i]=Math.max(-12,Math.min(12,Number(v)||0));UX.eq=EQVALUES.slice();uxSave();updateEQ();var n=$("eqValue"+i);if(n)n.textContent=(EQVALUES[i]>0?"+":"")+EQVALUES[i]+" dB";}
    function eqPreset(k){if(!EQPRESETS[k])return;EQVALUES=EQPRESETS[k].slice();UX.eq=EQVALUES.slice();uxSave();updateEQ();openEqualizer();}
    function openEqualizer(){overlay("Equalizer",'<div class="workspace-banner"><div class="kicker">SOUND, YOUR WAY</div><h2>Equalizer</h2><p class="muted">Six bands with automatic headroom to reduce clipping. This changes playback on this browser, not the source file or downloads.</p><button class="btn" onclick="enableEQ()">'+(EQON?'Turn off':'Enable equalizer')+'</button></div><div class="chips">'+Object.keys(EQPRESETS).map(function(k){return '<button class="chip '+(EQVALUES.join(',')===EQPRESETS[k].join(',')?'on':'')+'" onclick="eqPreset(\\''+k+'\\')">'+k[0].toUpperCase()+k.slice(1)+'</button>';}).join("")+'</div><div class="eq-grid">'+EQF.map(function(f,i){return '<div class="eq-band"><label for="eqBand'+i+'">'+(f>=1000?f/1000+" kHz":f+" Hz")+'</label><input id="eqBand'+i+'" aria-label="'+f+' Hz gain" type="range" min="-12" max="12" step="1" value="'+EQVALUES[i]+'" oninput="eqBand('+i+',this.value)"><output id="eqValue'+i+'">'+(EQVALUES[i]>0?'+':'')+EQVALUES[i]+' dB</output></div>';}).join("")+'</div><p class="muted">'+(EQON?'Equalizer is active.':'Presets are saved; enable the equalizer to hear them. Enable again after reopening the browser.')+'</p>');}
    audio.addEventListener("play",function(){if(EQCTX&&EQCTX.state==="suspended")EQCTX.resume().catch(function(){});});
    function cleanMix(list){var seen={};return list.filter(function(t){if(!t||seen[t.id])return false;seen[t.id]=true;return true;});}
    function getPersonalMix(k){return cleanMix(k==="favorites"?getLiked():getHistory().concat(getLiked()));}
    function personalMixesHtml(){var a=getPersonalMix("rotation"),b=getPersonalMix("favorites");return '<div class="sec">'+secHead("Made from your music")+'<p class="muted" style="margin:0 18px 12px">Mixes from your likes and history on this browser. Based on songs you already played or liked.</p><div class="mix-grid">'+[["rotation","Your rotation",a.length,"Your recent songs and favorites"],["favorites","Favorites mix",b.length,"Shuffle the songs you love"]].map(function(x){return '<button class="mix-card" onclick="playPersonalMix(\\''+x[0]+'\\')"><span class="kicker">PERSONAL MIX</span><strong>'+x[1]+'</strong><span>'+x[3]+'</span><small>'+(x[2]?x[2]+' songs':'Start listening and liking songs')+'</small></button>';}).join("")+'</div></div>';}
    function playPersonalMix(k){var l=getPersonalMix(k).map(normTrack);if(!l.length){toast("Play and like songs to build your personal mixes.");return;}for(var i=l.length-1;i>0;i--){var j=Math.floor(Math.random()*(i+1)),t=l[i];l[i]=l[j];l[j]=t;}startQueue(l,0);toast(k==="favorites"?"Playing Favorites mix":"Playing Your rotation");}
    function customSleep(){var e=$("sleepMins"),n=e?Number(e.value):0;if(!Number.isInteger(n)||n<1||n>720){toast("Choose between 1 and 720 minutes.");return;}setSleep(String(n));}
    var originalSleep=openSleep;
    openSleep=function(){originalSleep();var b=$("ovlBody");if(b)b.insertAdjacentHTML("beforeend",'<div class="card" style="padding:14px;margin-top:14px"><label for="sleepMins">Custom timer (minutes)</label><div style="display:flex;gap:10px;margin-top:8px"><input class="field" id="sleepMins" type="number" min="1" max="720" value="20"><button class="btn" onclick="customSleep()">Set timer</button></div></div>');};
    function filterSongRows(input){var box=input.closest("#ovlBody");if(!box)return;var q=input.value.toLowerCase();box.querySelectorAll(".tracks .track").forEach(function(r){r.hidden=r.textContent.toLowerCase().indexOf(q)<0;});}
    function addSongFilter(){var b=$("ovlBody");if(b&&b.querySelector(".track"))b.insertAdjacentHTML("afterbegin",'<input class="field" aria-label="Filter songs" placeholder="Filter songs..." oninput="filterSongRows(this)" style="margin-bottom:14px">');}
    var originalLiked=openLiked,originalHistory=openHistory,originalPersonalPlaylist=openMyPlaylist;
    openLiked=function(){originalLiked();addSongFilter();};openHistory=function(){originalHistory();addSongFilter();};openMyPlaylist=function(id){originalPersonalPlaylist(id);addSongFilter();};
    // (equalizer and mixes live in the settings hero chips)
    function openPersonalMixes(){overlay("Personal mixes",personalMixesHtml());}

    // Merge only whitelisted, validated music data. Never execute backup fields.
    function backupText(v,n){return typeof v==="string"?v.slice(0,n||500):"";}
    function backupImage(v){return typeof v==="string"&&/^https:\\/\\//.test(v)&&!/["'<>\\\\\\x00-\\x20]/.test(v)?v.slice(0,2048):null;}
    function backupId(v){var n=Number(v);return Number.isSafeInteger(n)&&n>0?n:0;}
    function backupTrack(t){if(!t||!backupId(t.id))return null;return {id:backupId(t.id),title:backupText(t.title),artist:backupText(t.artist),file:backupText(t.file,2048),coverImg:backupImage(t.coverImg),at:Math.max(0,Math.min(Date.now(),Number(t.at)||0))};}
    function backupArtist(a){if(!a||!backupId(a.id))return null;return {id:backupId(a.id),enName:backupText(a.enName),heName:backupText(a.heName),image:backupImage(a.image)};}
    function backupAlbum(a){if(!a||!backupId(a.id))return null;var im=a.images||{};return {id:backupId(a.id),enName:backupText(a.enName),heName:backupText(a.heName),artists:Array.isArray(a.artists)?a.artists.slice(0,20).map(function(x){return {enName:backupText(x&&x.enName),heName:backupText(x&&x.heName)};}):[],images:{cdnMedium:backupImage(im.cdnMedium||im.medium||im.cdnSmall||im.small)}};}
    function validatedBackupArray(a,fn,limit){return Array.isArray(a)?a.slice(0,limit).map(fn).filter(Boolean):[];}
    function mergeBackupArray(key,a,limit){var seen={};var l=localList(key).concat(a).filter(function(x){if(!x||seen[String(x.id)])return false;seen[String(x.id)]=true;return true;});return l.slice(0,Math.max(localList(key).length,limit));}
    function pickLibraryBackup(){overlay("Restore library backup",'<div class="workspace-banner"><h2>Bring your music back</h2><p class="muted">Choose a Zing JSON backup, up to 5 MB. Songs, albums, artists and playlists are merged with this browser, never deleted. Playback and appearance preferences are restored. Backups stay on this device and are not uploaded.</p><label class="btn" for="backupFile">Choose backup</label><input id="backupFile" type="file" accept="application/json,.json" onchange="readLibraryBackup(this)" style="display:block;margin-top:14px"></div><div id="backupPreview"></div>');}
    var pendingLibraryBackup=null;
    async function readLibraryBackup(input){var f=input.files&&input.files[0];if(!f)return;var box=$("backupPreview");pendingLibraryBackup=null;
      if(f.size>5*1024*1024){box.textContent="This file is over 5 MB.";return;}
      try{var o=JSON.parse(await f.text());if(!o||o.app!=="Zing"||o.version!==1||!o.data||typeof o.data!=="object")throw new Error();var d=o.data;
        var p={liked:validatedBackupArray(d.zing_liked,backupTrack,300),history:validatedBackupArray(d.zing_hist,backupTrack,60),albums:validatedBackupArray(d.zing_saved_albums,backupAlbum,500),artists:validatedBackupArray(d.zing_followed_artists,backupArtist,1000),playlists:[]};
        if(Array.isArray(d.zing_playlists))d.zing_playlists.slice(0,100).forEach(function(x){if(!x||!backupText(x.name,60).trim())return;p.playlists.push({id:Date.now().toString(36)+Math.random().toString(36).slice(2,10),name:backupText(x.name,60),tracks:validatedBackupArray(x.tracks,backupTrack,2000)});});
        var settings=d.zing_settings||{},workspace=d[UXKEY]||{};p.settings={};p.workspace={};
        if(["en","he"].indexOf(settings.lang)>=0)p.settings.lang=settings.lang;if(["dark","light"].indexOf(settings.theme)>=0)p.settings.theme=settings.theme;
        ["autoplay","radio","resume","fade"].forEach(function(k){if(typeof settings[k]==="boolean")p.settings[k]=settings[k];});
        if([.75,1,1.25,1.5,1.75,2].indexOf(settings.speed)>=0)p.settings.speed=settings.speed;if([10,15,30].indexOf(settings.skip)>=0)p.settings.skip=settings.skip;if(typeof settings.vol==="number"&&settings.vol>=0&&settings.vol<=1)p.settings.vol=settings.vol;
        if(["site","purple","green","blue","rose"].indexOf(workspace.accent)>=0)p.workspace.accent=workspace.accent;if(["comfortable","compact"].indexOf(workspace.density)>=0)p.workspace.density=workspace.density;if(["system","reduced"].indexOf(workspace.motion)>=0)p.workspace.motion=workspace.motion;if(typeof workspace.confirmDownloads==="boolean")p.workspace.confirmDownloads=workspace.confirmDownloads;
        if(Array.isArray(workspace.eq)&&workspace.eq.length===6)p.workspace.eq=workspace.eq.map(function(v){return Math.max(-12,Math.min(12,Number(v)||0));});
        pendingLibraryBackup=p;box.innerHTML='<div class="card" style="padding:18px"><h3>Ready to merge</h3><p>'+p.liked.length+' liked songs, '+p.history.length+' history entries, '+p.albums.length+' albums, '+p.artists.length+' artists and '+p.playlists.length+' playlists.</p><p class="muted">Duplicate songs, albums and artists are skipped. Playlists with identical names and song order are skipped. Preferences in the backup replace only matching personal preferences.</p><button class="btn" onclick="restoreLibraryBackup()">Merge and restore</button></div>';
      }catch(e){box.textContent="This is not a valid Zing backup. Nothing was changed.";}}
    function restoreLibraryBackup(){var p=pendingLibraryBackup;if(!p)return;var all=getPlaylists().slice();p.playlists.forEach(function(x){var ids=x.tracks.map(function(t){return t.id;}).join(',');if(!all.some(function(y){return y.name===x.name&&y.tracks.map(function(t){return t.id;}).join(',')===ids;}))all.push(x);});
      if(all.length>300){toast("Too many playlists to restore. Nothing changed.");return;}
      var values={zing_liked:mergeBackupArray("zing_liked",p.liked,300),zing_hist:mergeBackupArray("zing_hist",p.history,60),zing_saved_albums:mergeBackupArray("zing_saved_albums",p.albums,500),zing_followed_artists:mergeBackupArray("zing_followed_artists",p.artists,1000),zing_playlists:all};values[SET_KEY]=Object.assign({},SET,p.settings);values[UXKEY]=Object.assign({},UX,p.workspace);
      var before={};try{Object.keys(values).forEach(function(k){before[k]=localStorage.getItem(k);});Object.keys(values).forEach(function(k){localStorage.setItem(k,JSON.stringify(values[k]));});}catch(e){Object.keys(before).forEach(function(k){try{if(before[k]===null)localStorage.removeItem(k);else localStorage.setItem(k,before[k]);}catch(_){}});toast("Not enough browser storage. Restore was not completed.");return;}
      Object.assign(SET,p.settings);Object.assign(UX,p.workspace);if(p.workspace.eq)EQVALUES=p.workspace.eq.slice();applyTheme();if(UX.accent==="site")applyConfig(CFG);applyUX();updateEQ();try{audio.playbackRate=SET.speed;audio.volume=SET.vol;}catch(e){}pendingLibraryBackup=null;ovlSet("Backup restored",'<div class="empty"><h2>Your library is restored</h2><p>Existing music was kept. New music was merged on this browser.</p><button class="btn" onclick="closeOverlay();browseLibrary()">Open Library</button></div>');}

    function sendShareLink(url,title){if(navigator.share){navigator.share({title:title||document.title,url:url}).catch(function(){});}else if(navigator.clipboard){navigator.clipboard.writeText(url).then(function(){toast("Link copied");}).catch(function(){prompt("Copy this link:",url);});}else prompt("Copy this link:",url);}
    function shareSong(t){if(!t||!Number.isSafeInteger(Number(t.id))||Number(t.id)<=0){toast("Choose a song first.");return;}sendShareLink(location.origin+location.pathname+"#/track/"+Number(t.id),t.title||"Song on Zing");}
    sharePage=function(){if(/!playlist\\//.test(location.hash)){toast("Personal playlists live on this browser. Export a backup to move them.");return;}if(/!np$/.test(location.hash)&&queue[qi]){shareSong(queue[qi]);return;}sendShareLink(location.origin+location.pathname+location.hash.split("!")[0]);};
    function openTrackRoute(id){id=Number(id);if(!Number.isSafeInteger(id)||id<=0){setView('<div class="empty">Song not found.</div>');return;}saveRoute("track",id);setStatus("");setView(skDetail());
      gql("query { track(where:{id:"+id+"}) { id enName heName file duration artists { enName heName } album { images { cdnSmall cdnMedium medium small } } } }").then(function(d){var t=d.track;if(!t){setView('<div class="empty">This song is not available.</div>');return;}renderTrackList(trackName(t),artNames(t.artists),[t],function(){go("home");},t.album?albImg(t.album):null,"Song");var v=$("view");if(v)v.insertAdjacentHTML("beforeend",'<div class="chips" style="margin:14px 18px"><button class="chip" onclick="shareSong(window._listTracks[0])">Share song</button></div>');}).catch(function(e){if(e.message!=="login")setView('<div class="empty">Could not load this song. Try again from Search.</div>');});}

    // ---------- Navigation history: refresh stays put, Back returns where you were ----------
    (function(){
      var cur={b:"#nil#",o:"",i:0,d:0}, applying=false, opening=0, ready=false, restoring=false, userMoved=false, lastSV=0, saveT=null;
      var BASES={track:1,home:1,albums:1,search:1,genres:1,playlists:1,artists:1,library:1,album:1,artist:1,playlist:1,genre:1,category:1,story:1};
      function enc(a){ return encodeURIComponent(a==null?"":String(a)); }
      function mkB(k,a){ return k+((a!==""&&a!=null)?"/"+enc(a):""); }
      function mkHash(b,o){ return "#/"+b+(o?"!"+o:""); }
      function parseHash(){ var h=location.hash||""; if(h.indexOf("#/")!==0) return null; var s=h.slice(2), p=s.indexOf("!"), b=p<0?s:s.slice(0,p), o=p<0?"":s.slice(p+1);
        if(!b||!BASES[b.split("/")[0]]) return null; return {b:b,o:o}; }
      function bParts(b){ var p=b.indexOf("/"); var k=p<0?b:b.slice(0,p), a=""; if(p>=0){ try{ a=decodeURIComponent(b.slice(p+1)); }catch(e){ a=b.slice(p+1); } } return [k,a]; }
      function dec(x){ try{ return decodeURIComponent(x||""); }catch(e){ return x||""; } }
      function numify(a){ return (a!==""&&!isNaN(+a)&&String(+a)===a)?+a:a; }
      function stateNow(){ var s=history.state; return (s&&typeof s.i==="number")?s:null; }
      function setState(s,b,o,replace){ try{ if(replace) history.replaceState(s,"",mkHash(b,o)); else history.pushState(s,"",mkHash(b,o)); }catch(e){} }
      function saveY(){ if(applying||restoring||!ready) return; var s=stateNow(); if(!s) return; var y=Math.round(window.pageYOffset||0); if(s.y===y) return;
        try{ history.replaceState({i:s.i,d:s.d,y:y},"",location.href); }catch(e){} }
      window.addEventListener("scroll", function(){ if(restoring) return; clearTimeout(saveT); saveT=setTimeout(saveY,200); }, {passive:true});
      ["touchstart","wheel","mousedown","keydown"].forEach(function(ev){ window.addEventListener(ev, function(){ userMoved=true; }, {passive:true,capture:true}); });
      window.addEventListener("pagehide", function(){ saveY(); });
      try{ history.scrollRestoration="manual"; }catch(e){}

      function commit(b,o,forceReplace){
        if(applying||!ready) return;
        if(b===cur.b&&o===cur.o) return;
        var sameSearch=(!o&&!cur.o&&b.split("/")[0]==="search"&&cur.b.split("/")[0]==="search");
        var d=o?(cur.o?cur.d+1:1):0;
        if(forceReplace||sameSearch){ setState({i:cur.i,d:d,y:Math.round(window.pageYOffset||0)},b,o,true); }
        else { saveY(); cur.i++; setState({i:cur.i,d:d,y:0},b,o,false); }
        cur.b=b; cur.o=o; cur.d=d;
      }
      function waitFor(test,ms,fn){ var t0=Date.now(); (function tick(){ var ok=false; try{ ok=test(); }catch(e){} if(ok){ fn(); } else if(Date.now()-t0<ms){ setTimeout(tick,150); } })(); }

      function renderBase(b){ var p=bParts(b), k=p[0], a=p[1];
        if(k==="search"){ curTab="search"; setTab("tabSearch"); window._origSaveRoute("search",a); searchView(); var q=$("q"); if(q){ q.value=a; if(a) doSearch(a); } return; }
        if(k==="library"){ browseLibrary(); return; }
        var tabs={home:1,albums:1,genres:1,playlists:1,artists:1};
        if(tabs[k]){ go(k); return; }
        var opens={track:openTrackRoute,album:openAlbum,artist:openArtist,playlist:openPlaylist,genre:openGenre,category:openCategory,story:openStory};
        if(opens[k]){ try{ opens[k](numify(a)); }catch(e){ go("home"); } return; }
        go("home"); }
      function openOverlayRoute(o){ var p=o.split("/"), k=p[0], a=dec(p.slice(1).join("/"));
        if(k==="liked") openLiked();
        else if(k==="history") openHistory();
        else if(k==="playlists") openMyPlaylists();
        else if(k==="playlist") openMyPlaylist(a);
        else if(k==="equalizer") openEqualizer();
        else if(k==="mixes") openPersonalMixes();
        else if(k==="sleep") openSleep();
        else if(k==="shortcuts") keyboardHelp();
        else if(k==="backup") pickLibraryBackup();
        else if(k==="settings") openSettings();
        else if(k==="profile") openProfile();
        else if(k==="np"){ if(queue[qi]) openNowPlaying(); }
        else if(k==="admin"){ openSettings(); openAccess();
          if(p[1]){ var sec=dec(p[1]), uid=p[1]==="user"?dec(p.slice(2).join("/")):null;
            waitFor(function(){ return _adm&&_adm.d; },8000,function(){ applying=true; try{
              if(uid!==null){ var us=(_adm.users&&_adm.users.users)||[], id=uid; us.forEach(function(u){ if(String(u.id)===uid) id=u.id; }); openUserDetail(id); }
              else adminSection(sec); }catch(e){} finally{ applying=false; } }); } } }
      function startRestore(y){ if(!y){ return; } restoring=true; userMoved=false; var t0=Date.now();
        (function tick(){ if(userMoved||Date.now()-t0>4500){ restoring=false; saveY(); return; }
          var cy=window.pageYOffset||0;
          if(y>cy+3&&(document.documentElement.scrollHeight-window.innerHeight)<y&&cur.b==="albums"&&$("albMore")&&typeof loadMoreAlbums==="function"){ try{ loadMoreAlbums(); }catch(e){} }
          if(Math.abs(cy-y)>3){ window.scrollTo(0,y); }
          else if(Date.now()-lastSV>600&&Date.now()-t0>500){ restoring=false; saveY(); return; }
          setTimeout(tick,100); })(); }
      function apply(t,y,st,force){ var wasApplying=applying; applying=true;
        try{
          var changedBase=force||t.b!==cur.b;
          if(changedBase){ if($("ovl")) origClose(true); renderBase(t.b); }
          if(!t.o){ if($("ovl")){ origClose(true); if(_dirtyView){ _dirtyView=false; go(curTab); } } }
          else if(t.o!==cur.o||!$("ovl")){ openOverlayRoute(t.o); }
          cur.b=t.b; cur.o=t.o; cur.i=st.i; cur.d=t.o?(st.d||1):0;
        } finally { applying=wasApplying; }
        if(changedBase) startRestore(y); }

      var origSave=window.saveRoute, origClose=window.closeOverlay, origSetView=window.setView, origOverlay=window.overlay;
      window._origSaveRoute=origSave;
      window.setView=function(){ lastSV=Date.now(); return origSetView.apply(this,arguments); };
      window.overlay=function(){ opening++; try{ return origOverlay.apply(this,arguments); } finally { opening--; } };
      function init(){ if(ready) return; var h=parseHash(), s=stateNow();
        if(!h){ var r=null; try{ r=JSON.parse(localStorage.getItem("zing_route")||"null"); }catch(e){}
          h=(r&&r.k&&BASES[r.k])?{b:mkB(r.k,r.a),o:""}:{b:"home",o:""}; s=null; }
        if(!s){ s={i:0,d:0,y:0}; h.o=""; }
        if(h.o==="np") h.o="";
        ready=true; cur={b:"#nil#",o:"",i:s.i,d:s.d};
        setState({i:s.i,d:h.o?s.d:0,y:s.y||0},h.b,h.o,true);
        return {h:h,s:s}; }
      window.saveRoute=function(k,a){ origSave(k,a); if(applying||!BASES[k]) return; if(!ready){ var x=init(); if(x){ cur.b=x.h.b; cur.o=x.h.o; } }
        var b=mkB(k,a), had=!!cur.o; if($("ovl")&&opening===0&&had){ origClose(true); }
        if(had){ cur.b="#nil#"; cur.o=""; cur.d=0; }
        commit(b,""); };
      var origLib=window.browseLibrary;
      window.browseLibrary=function(){ if(!applying){ window.saveRoute("library",""); } return origLib.apply(this,arguments); };
      window.restoreRoute=function(){
        if(!ready){ var x=init(); apply(x.h,x.s.y||0,x.s,true); return; }
        apply({b:cur.b,o:cur.o},Math.round(window.pageYOffset||0),{i:cur.i,d:cur.d},true); };

      function wrapO(name,routeFn){ var orig=window[name]; if(typeof orig!=="function") return;
        window[name]=function(){ if(applying||!ready){ return orig.apply(this,arguments); }
          var top=(opening===0), r=top?routeFn.apply(null,arguments):null;
          opening++; var out; try{ out=orig.apply(this,arguments); } finally { opening--; }
          if(top&&r&&$("ovl")) commit(cur.b,r);
          return out; }; }
      wrapO("openEqualizer",function(){return "equalizer";});
      wrapO("openPersonalMixes",function(){return "mixes";});
      wrapO("openSleep",function(){return "sleep";});
      wrapO("keyboardHelp",function(){return "shortcuts";});
      wrapO("pickLibraryBackup",function(){return "backup";});
      wrapO("openLiked",function(){ return "liked"; });
      wrapO("openHistory",function(){ return "history"; });
      wrapO("openMyPlaylists",function(){ return "playlists"; });
      wrapO("openMyPlaylist",function(id){ return "playlist/"+enc(id); });
      wrapO("openSettings",function(){ return "settings"; });
      wrapO("backToSettings",function(){ return "settings"; });
      wrapO("openProfile",function(){ return "profile"; });
      wrapO("openAccess",function(){ return "admin"; });
      wrapO("adminHub",function(){ return "admin"; });
      wrapO("adminSection",function(k){ return "admin/"+enc(k); });
      wrapO("openUserDetail",function(id){ return "admin/user/"+enc(id); });
      wrapO("openNowPlaying",function(){ return queue[qi]?"np":""; });

      var unwindT=null;
      window.closeOverlay=function(quiet){
        if(applying||!ready||opening>0||!cur.o) return origClose.apply(this,arguments);
        if(quiet!==true){ if(cur.d>0&&cur.i>=cur.d){ history.go(-cur.d); return; } return origClose.apply(this,arguments); }
        origClose(true); clearTimeout(unwindT);
        unwindT=setTimeout(function(){ if(!$("ovl")&&cur.o&&!applying&&cur.d>0&&cur.i>=cur.d) history.go(-cur.d); },60); };

      // In-app Back buttons follow browser history when there is a previous in-app page.
      document.addEventListener("click", function(e){ var t=e.target; var b=t&&t.closest?t.closest(".back"):null; if(!b||!ready||applying) return;
        var s=stateNow(); if(s&&s.i>0){ e.preventDefault(); e.stopPropagation(); history.back(); } }, true);

      window.addEventListener("popstate", function(e){ if(!ready) return; clearTimeout(unwindT);
        var st=(e.state&&typeof e.state.i==="number")?e.state:null, h=parseHash()||{b:"home",o:""};
        if(!st){ st={i:cur.i+1,d:0,y:0}; h.o=""; setState(st,h.b,h.o,true); }
        apply(h,st.y||0,st,false); });
    })();

    // Load who-I-am and the shared config BEFORE rendering, so download controls
    // and features are right, then restore the page you were on (refresh stays put).
    Promise.all([loadMe(), loadConfig()]).then(function(){ applyUX(); if(!$("takeover")||$("takeover").hidden){ restoreRoute(); } });
  </script>
</body>
</html>`; /* Perf split: serve the app script at /app.js?v=BUILD with an immutable per-build cache instead of 204KB inline on every load. */ const _jsTagOpen = PAGE.indexOf("<script>"); const _jsTagClose = PAGE.lastIndexOf("</" + "script>"); const PAGE_SHELL = PAGE.slice(0, _jsTagOpen) + '<script src="/app.js?v=' + BUILD + '"></' + 'script></body></html>'; const PAGE_JS = PAGE.slice(_jsTagOpen + 8, _jsTagClose); function jsResponse(request) { return maybeZip(request, PAGE_JS, { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "private, max-age=31536000, immutable" }); }


