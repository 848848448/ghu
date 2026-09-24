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
        });
      }

      // Everything below requires a login when the site is locked.
      if (!authed) {
        return json({ error: "Please log in.", needLogin: true }, 401);
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
      if (path === "/api/check") {
        return await handleCheck(env);
      }
      if (path === "/api/schema") {
        return await handleSchema(env);
      }
      if (path === "/api/query" && request.method === "POST") {
        return await handleRawQuery(request, env);
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
  const pw = (body.password || "").toString();
  if (pw && pw === env.SITE_PASSWORD) {
    const token = await authToken(env);
    const cookie =
      "auth=" + token + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000";
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", "Set-Cookie": cookie },
    });
  }
  return json({ error: "Wrong password." }, 401);
}

function logout() {
  return new Response(null, {
    status: 302,
    headers: {
      "Set-Cookie": "auth=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      Location: "/",
    },
  });
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
    "query { artist(where: { id: " + Number(id) + " }) { id enName heName image " +
    "albums { id enName heName tracks { id enName heName file duration trackNumber } } } }";
  const data = await graphql(env, query);
  const artist = data && data.data ? data.data.artist : null;
  if (!artist) return json({ error: "No details found for this artist." }, 502);
  return json({ artist });
}

async function handleNew(env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const query =
    "query { albums(take: 50) { id enName heName artists { enName heName } tracks { id enName heName file duration trackNumber } } }";
  const data = await graphql(env, query);
  if (!data || data.errors) return json({ albums: [] });
  let albums = ((data.data || {}).albums) || [];
  albums = albums
    .sort((a, b) => Number(b.id || 0) - Number(a.id || 0))
    .slice(0, 10);
  return json({ albums });
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
    headers: { "Content-Type": "text/html; charset=utf-8" },
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
  .msg{min-height:20px; margin-top:14px; font-size:.92rem; color:#fb7185;}
</style>
</head>
<body>
  <div class="box">
    <div class="logo">♪</div>
    <h1>Zing Music</h1>
    <p>Enter the password to continue.</p>
    <input id="pw" type="password" placeholder="Password" autocomplete="current-password" />
    <button id="go">Sign in</button>
    <div class="msg" id="msg"></div>
  </div>
  <script>
    var pw = document.getElementById("pw"), go = document.getElementById("go"), msg = document.getElementById("msg");
    function submit(){
      msg.textContent = "";
      fetch("/api/login", { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ password: pw.value }) })
      .then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
      .then(function(x){ if(x.ok){ location.href = "/"; } else { msg.textContent = (x.d && x.d.error) || "Wrong password."; pw.value=""; pw.focus(); } })
      .catch(function(){ msg.textContent = "Something went wrong. Try again."; });
    }
    go.onclick = submit;
    pw.addEventListener("keydown", function(e){ if(e.key === "Enter") submit(); });
    pw.focus();
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
      --text:#f4f4fb; --muted:#a3a3c2; --line:rgba(255,255,255,.08);
      --accent:#7c5cff; --accent-2:#ff4d8d; --ok:#34d399; --err:#fb7185; --warn:#fbbf24;
      --grad:linear-gradient(135deg,var(--accent),var(--accent-2));
      --font:"Plus Jakarta Sans", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      --player-h:78px;
    }
    *{box-sizing:border-box;}
    html,body{height:100%; margin:0;}
    body{
      font-family:var(--font); color:var(--text);
      background:
        radial-gradient(1000px 520px at 12% -8%, rgba(124,92,255,.20), transparent 60%),
        radial-gradient(900px 460px at 100% 0%, rgba(255,77,141,.14), transparent 55%),
        var(--bg);
      min-height:100%;
    }
    a{color:inherit;}
    button{font-family:inherit;}

    .head{
      position:sticky; top:env(safe-area-inset-top,0px); z-index:30;
      display:flex; align-items:center; gap:12px; padding:12px 18px;
      background:rgba(10,10,18,.78); backdrop-filter:blur(14px); border-bottom:1px solid var(--line);
    }
    .brand{display:flex; align-items:center; gap:10px; flex:none;}
    .logo{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:var(--grad);
      box-shadow:0 8px 18px rgba(124,92,255,.45); font-size:19px;}
    .brand .name{font-weight:800; font-size:1.12rem; line-height:1;}
    .brand .tag{display:block; font-size:.6rem; letter-spacing:2.5px; text-transform:uppercase; color:var(--muted); margin-top:3px;}
    .headsearch{flex:1; min-width:0; display:flex; align-items:center; gap:8px; background:var(--surface);
      border:1px solid var(--line); border-radius:12px; padding:6px 12px;}
    .headsearch svg{flex:none; color:var(--muted);}
    .headsearch input{flex:1; min-width:0; background:transparent; border:none; outline:none; color:var(--text);
      font-family:inherit; font-size:.98rem; padding:6px 2px;}
    .headsearch input::placeholder{color:var(--muted);}
    .badge{flex:none; font-size:.7rem; color:var(--muted); border:1px solid var(--line); padding:5px 9px; border-radius:999px;}
    .badge.ok{color:var(--ok); border-color:rgba(52,211,153,.35); background:rgba(52,211,153,.08);}

    .wrap{max-width:1080px; margin:0 auto; padding:18px 18px calc(var(--player-h) + 40px + env(safe-area-inset-bottom,0px));}

    .nav{display:flex; gap:9px; margin-bottom:18px; flex-wrap:wrap;}
    .nav button{border:1px solid var(--line); background:var(--surface); color:var(--muted); cursor:pointer;
      padding:9px 15px; border-radius:999px; font-weight:600; font-size:.9rem; transition:all .15s ease;}
    .nav button:hover{color:var(--text); background:var(--surface-2);}
    .nav button.active{background:var(--grad); color:#fff; border-color:transparent; box-shadow:0 6px 16px rgba(124,92,255,.35);}

    #status{min-height:20px; font-size:.9rem; margin:8px 2px;}
    .ok{color:var(--ok);} .err{color:var(--err);} .muted{color:var(--muted);}

    .sec{margin-top:8px;}
    .sec-head{display:flex; align-items:baseline; gap:12px; margin:10px 2px 16px;}
    .sec-head h2{margin:0; font-size:1.2rem; font-weight:800;}
    .sec-head .count{color:var(--muted); font-size:.86rem;}
    .back{display:inline-flex; align-items:center; gap:6px; cursor:pointer; color:var(--muted); font-size:.9rem; margin:2px 2px 14px;}
    .back:hover{color:var(--text);}

    .grid{display:grid; gap:16px;}
    .grid.artists{grid-template-columns:repeat(auto-fill,minmax(140px,1fr));}
    .grid.albums{grid-template-columns:repeat(auto-fill,minmax(160px,1fr));}
    .tile{background:var(--surface); border:1px solid var(--line); border-radius:16px; padding:14px; cursor:pointer;
      position:relative; overflow:hidden; transition:transform .13s ease, background .15s ease;}
    .tile:hover{transform:translateY(-4px); background:var(--surface-2);}
    .cover{width:100%; aspect-ratio:1/1; border-radius:12px; display:grid; place-items:center; margin-bottom:11px;
      color:rgba(255,255,255,.95); box-shadow:inset 0 0 46px rgba(0,0,0,.28);}
    .cover.round{border-radius:999px; width:82%; margin:0 auto 11px;}
    .cover .disc{width:32%; height:32%; border-radius:999px;
      background:radial-gradient(circle at 50% 50%, #fff 0 13%, rgba(255,255,255,.22) 14% 33%, rgba(0,0,0,.14) 34% 100%);
      box-shadow:0 6px 16px rgba(0,0,0,.4);}
    .cover .ini{font-weight:800; font-size:1.9rem;}
    .t-name{font-weight:600; font-size:.95rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
    .t-sub{color:var(--muted); font-size:.8rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:2px;}
    .tile.artist{text-align:center;}
    .fab{position:absolute; right:20px; bottom:60px; width:42px; height:42px; border-radius:999px; background:var(--grad);
      display:grid; place-items:center; color:#fff; box-shadow:0 10px 20px rgba(0,0,0,.45); opacity:0; transform:translateY(8px);
      transition:opacity .15s ease, transform .15s ease;}
    .tile.album:hover .fab{opacity:1; transform:translateY(0);}

    .album-hero{display:flex; gap:20px; align-items:flex-end; margin-bottom:20px; flex-wrap:wrap;}
    .album-hero .cover{width:160px; height:160px; aspect-ratio:auto; margin:0; flex:none;}
    .album-hero .kicker{color:var(--muted); font-size:.72rem; letter-spacing:2.5px; text-transform:uppercase;}
    .album-hero h2{margin:5px 0 6px; font-size:clamp(1.4rem,4.5vw,2rem); font-weight:800; text-wrap:balance;}
    .album-hero .sub{color:var(--muted); font-size:.9rem;}
    .album-hero .actions{margin-top:14px; display:flex; gap:10px; flex-wrap:wrap;}
    .btn{border:none; cursor:pointer; font-weight:700; font-size:.94rem; color:#fff; padding:11px 18px; border-radius:12px;
      background:var(--grad); box-shadow:0 8px 18px rgba(124,92,255,.32); display:inline-flex; align-items:center; gap:7px;}
    .btn:hover{filter:brightness(1.08);} .btn:active{transform:translateY(1px);}
    .btn.ghost{background:var(--surface-2); color:var(--text); box-shadow:none; border:1px solid var(--line); font-weight:600;}

    .tracks{border:1px solid var(--line); border-radius:16px; overflow:hidden; background:var(--surface);}
    .track{display:flex; align-items:center; gap:12px; padding:11px 14px; border-bottom:1px solid var(--line); transition:background .12s ease; cursor:pointer;}
    .track:last-child{border-bottom:none;} .track:hover{background:var(--surface-2);}
    .track.playing{background:linear-gradient(90deg, rgba(124,92,255,.16), transparent);}
    .track .num{width:26px; text-align:center; color:var(--muted); font-variant-numeric:tabular-nums; font-size:.9rem; flex:none;}
    .track.playing .num{color:var(--accent);}
    .track .tk{flex:1; min-width:0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-size:.95rem;}
    .track .time{color:var(--muted); font-size:.82rem; font-variant-numeric:tabular-nums; flex:none;}
    .track .dl{flex:none; width:38px; height:38px; border-radius:999px; border:1px solid var(--line); background:transparent;
      color:var(--muted); cursor:pointer; display:grid; place-items:center; transition:all .15s ease;}
    .track .dl:hover{color:#fff; border-color:transparent; background:var(--grad);}

    .empty{color:var(--muted); padding:40px 4px; text-align:center;}
    .filter{display:flex; align-items:center; gap:8px; background:var(--surface); border:1px solid var(--line);
      border-radius:12px; padding:8px 13px; margin-bottom:16px;}
    .filter input{flex:1; min-width:0; background:transparent; border:none; outline:none; color:var(--text); font-family:inherit; font-size:.98rem; padding:5px 2px;}
    .filter input::placeholder{color:var(--muted);}

    /* Now-playing bar */
    .player{position:fixed; left:0; right:0; bottom:0; z-index:40;
      padding:10px 16px calc(10px + env(safe-area-inset-bottom,0px));
      background:rgba(15,15,27,.92); backdrop-filter:blur(16px); border-top:1px solid var(--line);
      display:flex; align-items:center; gap:14px;}
    .player[hidden]{display:none;}
    .np-cover{width:52px; height:52px; border-radius:10px; flex:none; display:grid; place-items:center; box-shadow:inset 0 0 22px rgba(0,0,0,.3);}
    .np-cover .disc{width:34%;height:34%;border-radius:999px;background:radial-gradient(circle at 50% 50%,#fff 0 14%,rgba(255,255,255,.22) 15% 33%,rgba(0,0,0,.14) 34% 100%);}
    .np-meta{flex:1; min-width:0;}
    .np-title{font-weight:700; font-size:.95rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
    .np-artist{color:var(--muted); font-size:.8rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
    .np-ctrl{display:flex; align-items:center; gap:6px; flex:none;}
    .np-ctrl button{width:38px; height:38px; border-radius:999px; border:none; background:transparent; color:var(--text); cursor:pointer; display:grid; place-items:center;}
    .np-ctrl button:hover{background:var(--surface-3);}
    .np-ctrl .main{width:46px; height:46px; background:var(--grad); color:#fff; box-shadow:0 6px 16px rgba(124,92,255,.4);}
    .np-seek{display:flex; align-items:center; gap:9px; flex:2; min-width:120px; max-width:420px;}
    .np-seek .t{color:var(--muted); font-size:.74rem; font-variant-numeric:tabular-nums; flex:none; width:34px; text-align:center;}
    input[type=range].seek{-webkit-appearance:none; appearance:none; flex:1; height:5px; border-radius:999px; background:var(--surface-3); outline:none;}
    input[type=range].seek::-webkit-slider-thumb{-webkit-appearance:none; width:14px; height:14px; border-radius:999px; background:#fff; cursor:pointer; box-shadow:0 2px 6px rgba(0,0,0,.4);}
    input[type=range].seek::-moz-range-thumb{width:14px; height:14px; border:none; border-radius:999px; background:#fff; cursor:pointer;}
    .np-dl{flex:none; width:40px; height:40px; border-radius:999px; border:1px solid var(--line); background:transparent; color:var(--muted); cursor:pointer; display:grid; place-items:center;}
    .np-dl:hover{color:#fff; border-color:transparent; background:var(--grad);}

    @media (max-width:720px){
      .np-seek{display:none;}
      .brand .tag{display:none;}
    }
    .banner{border-radius:14px; padding:13px 15px; margin-bottom:16px; border:1px solid rgba(251,191,36,.35);
      background:rgba(251,191,36,.08); color:var(--warn); font-size:.9rem;}
    .banner code{background:rgba(255,255,255,.1); padding:1px 6px; border-radius:6px; color:var(--text);}
    .spinner{display:inline-block; width:15px; height:15px; border:2px solid var(--muted); border-top-color:transparent;
      border-radius:50%; animation:spin .7s linear infinite; vertical-align:-3px; margin-right:7px;}
    @keyframes spin{to{transform:rotate(360deg);}}
    @media (prefers-reduced-motion: reduce){ *{transition:none !important; animation-duration:.01ms !important;} }
  </style>
</head>
<body>
  <div class="head">
    <div class="brand"><span class="logo">♪</span><span><span class="name">Zing</span><span class="tag">Jewish Music</span></span></div>
    <div class="headsearch">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
      <input id="q" type="text" placeholder="Search artists…" autocomplete="off" />
    </div>
    <span class="badge" id="cfgBadge"></span>
  </div>

  <div class="wrap">
    <div class="banner" id="cfgBanner" hidden>
      ⚠️ Not configured yet. Add your <code>API_URL</code>, <code>AUDIO_API_BASE</code> and <code>USER_TOKEN</code>, then reload.
    </div>
    <div class="nav">
      <button id="navNew" class="active" onclick="doNew()">🔥 New Releases</button>
      <button id="navGenres" onclick="browseGenres()">🎼 Genres</button>
      <button id="navPlaylists" onclick="browsePlaylists()">📻 Playlists</button>
      <button id="navArtists" onclick="browseArtists()">🎤 All Artists</button>
      <button id="navCheck" onclick="runCheck(false)">🔧 Check</button>
      <button id="navSchema" onclick="showSchema()">🗺️ API</button>
    </div>
    <div id="diag"></div>
    <div id="status"></div>
    <div id="view"></div>
  </div>

  <div class="player" id="player" hidden>
    <div class="np-cover" id="npCover"><span class="disc"></span></div>
    <div class="np-meta"><div class="np-title" id="npTitle">—</div><div class="np-artist" id="npArtist"></div></div>
    <div class="np-ctrl">
      <button id="prevBtn" title="Previous"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h2v12H6zm3.5 6l8.5 6V6z"/></svg></button>
      <button id="playBtn" class="main" title="Play/Pause"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>
      <button id="nextBtn" title="Next"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M16 6h2v12h-2zM6 18l8.5-6L6 6z"/></svg></button>
    </div>
    <div class="np-seek">
      <span class="t" id="curTime">0:00</span>
      <input type="range" class="seek" id="seek" min="0" max="1000" value="0" />
      <span class="t" id="durTime">0:00</span>
    </div>
    <button class="np-dl" id="npLyrics" title="Lyrics" onclick="showLyrics()">📜</button>
    <button class="np-dl" id="npDl" title="Download"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg></button>
  </div>
  <audio id="audio" preload="none"></audio>
  <div class="toast" id="toast" style="position:fixed;left:50%;bottom:calc(var(--player-h) + 14px);transform:translateX(-50%) translateY(16px);background:var(--surface-3);color:var(--text);border:1px solid var(--line);padding:11px 16px;border-radius:11px;box-shadow:0 12px 30px rgba(0,0,0,.5);opacity:0;pointer-events:none;transition:opacity .2s,transform .2s;z-index:60;font-size:.9rem;"></div>

  <script>
    var artists = [], artistsLoaded = false;
    var CACHE_KEY = "zing_artists_cache", CACHE_TTL = 86400000;
    var queue = [], qi = -1;

    function $(id){ return document.getElementById(id); }
    function esc(s){ return (s==null?"":String(s)).replace(/[&<>"']/g, function(c){ return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]; }); }
    function hash(s){ var h=0; s=s||"?"; for(var i=0;i<s.length;i++){ h=(h*31+s.charCodeAt(i))>>>0; } return h; }
    function grad(name){ var h=hash(name); var a=h%360; var b=(a+45+(h>>3)%70)%360; return "linear-gradient(135deg, hsl("+a+",72%,56%), hsl("+b+",70%,44%))"; }
    function ini(name){ var p=(name||"?").trim().split(/\\s+/).filter(Boolean); if(!p.length) return "?"; return (p.length===1?p[0].slice(0,2):(p[0][0]+p[1][0])).toUpperCase(); }
    function fmt(sec){ if(!isFinite(sec)||sec<0) sec=0; var m=Math.floor(sec/60), s=Math.floor(sec%60); return m+":"+(s<10?"0":"")+s; }
    function trackName(t){ return (t.enName||t.heName||(t.file||"").split("/").pop()||("Track "+t.id)); }
    function albName(al){ return (al.enName||al.heName||"Unknown Album"); }
    function artNames(list){ return (list||[]).map(function(a){return a.enName||a.heName||"Unknown";}).join(", "); }

    function setStatus(h,c){ $("status").innerHTML=h; $("status").className=c||""; }
    function loading(m){ setStatus('<span class="spinner"></span>'+m,"muted"); }
    var toastT;
    function toast(m){ var t=$("toast"); t.textContent=m; t.style.opacity="1"; t.style.transform="translateX(-50%) translateY(0)";
      clearTimeout(toastT); toastT=setTimeout(function(){ t.style.opacity="0"; t.style.transform="translateX(-50%) translateY(16px)"; }, 2600); }

    function post(path,payload){
      return fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload||{})})
        .then(function(res){ return res.json().catch(function(){return {};}).then(function(d){
          if(res.status===401 && d.needLogin){ location.href="/"; throw new Error("Please log in."); }
          if(!res.ok) throw new Error(d.error||("Request failed ("+res.status+")")); return d; }); });
    }

    function checkStatus(){
      fetch("/api/status").then(function(r){return r.json();}).then(function(s){
        if(s.configured){ $("cfgBanner").hidden=true; $("cfgBadge").textContent="Connected"; $("cfgBadge").className="badge ok"; }
        else { $("cfgBanner").hidden=false; $("cfgBadge").textContent="Not configured"; $("cfgBadge").className="badge"; }
      }).catch(function(){});
    }

    function loadCache(){ try{ var o=JSON.parse(localStorage.getItem(CACHE_KEY)||"null"); if(o&&Date.now()-o.t<CACHE_TTL&&o.a&&o.a.length) return o.a; }catch(e){} return null; }
    function saveCache(a){ try{ localStorage.setItem(CACHE_KEY, JSON.stringify({t:Date.now(),a:a})); }catch(e){} }
    function ensureArtists(){
      if(artistsLoaded) return Promise.resolve(true);
      var c=loadCache(); if(c){ artists=c; artistsLoaded=true; return Promise.resolve(true); }
      loading("Loading artist catalog…");
      return post("/api/artists",{}).then(function(d){ artists=d.artists||[]; artistsLoaded=true; saveCache(artists); setStatus("",""); return true; })
        .catch(function(e){ setStatus("❌ "+e.message,"err"); runCheck(true); return false; });
    }

    var NAV_IDS=["navNew","navArtists","navGenres","navPlaylists"];
    function setNav(id){ NAV_IDS.forEach(function(n){ var el=$(n); if(el) el.classList.toggle("active", n===id); }); }
    function setView(h){ $("view").innerHTML=h; }
    function imgUrl(v){ return (typeof v==="string" && /^https?:\\/\\//.test(v)) ? v : null; }
    function coverHtml(name,opts){ opts=opts||{}; var cls="cover"+(opts.round?" round":"");
      var url=imgUrl(opts.img);
      if(url){ return '<div class="'+cls+'" style="background-image:url(\\''+esc(url)+'\\');background-size:cover;background-position:center;background-color:#161627"></div>'; }
      var inner=opts.round?'<span class="ini">'+esc(ini(name))+'</span>':'<span class="disc"></span>';
      return '<div class="'+cls+'" style="background:'+grad(name)+'">'+inner+'</div>'; }

    // Run an arbitrary GraphQL query through the server (token stays server-side).
    function gql(query, vars){
      return fetch("/api/query",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:query,variables:vars||{}})})
        .then(function(r){ if(r.status===401){ location.href="/"; throw new Error("login"); } return r.json(); })
        .then(function(d){ if(d && d.errors && d.errors.length) throw new Error(d.errors[0].message||"query error"); return (d&&d.data)||{}; });
    }

    function artistCard(a){ return '<div class="tile artist" onclick="openArtist('+a.id+')">'+coverHtml(a.enName||a.heName,{round:true,img:a.image})+
      '<div class="t-name">'+esc(a.enName||"Unknown")+'</div><div class="t-sub">'+esc(a.heName||"Artist")+'</div></div>'; }
    function albumCard(al,sub){ return '<div class="tile album" onclick="openAlbum('+al.id+')">'+coverHtml(albName(al))+
      '<div class="fab"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></div>'+
      '<div class="t-name">'+esc(albName(al))+'</div><div class="t-sub">'+esc(sub)+'</div></div>'; }

    // ---------- Views ----------
    function doNew(){
      setNav("navNew"); loading("Loading new releases…");
      post("/api/new",{}).then(function(d){
        var albums=d.albums||[]; setStatus("","");
        if(!albums.length){ setView('<div class="empty">No new releases found.</div>'); runCheck(true); return; }
        window._albums={}; window._albumBack=doNew;
        var cards=albums.map(function(al){ window._albums[al.id]=al;
          var names=artNames(al.artists)||"Various";
          return albumCard(al, names); }).join("");
        setView('<div class="sec"><div class="sec-head"><h2>🔥 New Releases</h2></div><div class="grid albums">'+cards+'</div></div>');
      }).catch(function(e){ setStatus("❌ "+e.message,"err"); runCheck(true); });
    }

    function browseArtists(){
      setNav("navArtists");
      ensureArtists().then(function(ok){ if(!ok) return;
        var sorted=artists.slice().sort(function(a,b){ return (a.enName||"").localeCompare(b.enName||""); });
        renderArtistGrid(sorted, "All Artists");
      });
    }
    function renderArtistGrid(list, title){
      window._grid=list;
      var cards=list.slice(0,600).map(artistCard).join("");
      var more = list.length>600 ? '<div class="empty">Showing first 600 of '+list.length+'. Use search to find a specific artist.</div>' : '';
      setView('<div class="sec"><div class="filter"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>'+
        '<input id="gridFilter" type="text" placeholder="Filter '+list.length+' artists…" oninput="filterGrid(this.value)" /></div>'+
        '<div class="sec-head"><h2>'+esc(title)+'</h2><span class="count">'+list.length+'</span></div>'+
        '<div class="grid artists" id="artistGrid">'+cards+'</div>'+more+'</div>');
    }
    function filterGrid(q){ q=(q||"").toLowerCase().trim();
      var list=(window._grid||[]).filter(function(a){ return !q || (a.enName||"").toLowerCase().indexOf(q)>=0 || (a.heName||"").toLowerCase().indexOf(q)>=0; });
      var g=$("artistGrid"); if(g) g.innerHTML=list.slice(0,600).map(artistCard).join(""); }

    // ---------- Genres ----------
    function browseGenres(){
      setNav("navGenres"); loading("Loading genres…");
      gql("query { genres(take: 300) { id enName heName images } }").then(function(d){
        var gs=d.genres||[]; setStatus("","");
        if(!gs.length){ setView('<div class="empty">No genres found.</div>'); return; }
        var cards=gs.map(function(g){ var nm=g.enName||g.heName||"Genre";
          return '<div class="tile album" onclick="openGenre('+g.id+')">'+coverHtml(nm,{img:g.images})+
            '<div class="t-name">'+esc(nm)+'</div><div class="t-sub">'+esc(g.heName||"Genre")+'</div></div>'; }).join("");
        setView('<div class="sec"><div class="sec-head"><h2>🎼 Genres</h2><span class="count">'+gs.length+'</span></div><div class="grid albums">'+cards+'</div></div>');
      }).catch(function(e){ if(e.message==="login")return; setStatus("❌ "+e.message,"err"); });
    }
    function openGenre(id){
      loading("Loading genre…");
      gql("query { genre(where:{id:"+Number(id)+"}) { id enName heName albums { id enName heName tracks { id enName heName file duration trackNumber } } } }").then(function(d){
        var g=d.genre; var albums=(g&&g.albums)||[]; setStatus(""); window._albumBack=browseGenres;
        var head='<div class="back" onclick="browseGenres()">‹ Back to genres</div><div class="sec-head"><h2>'+esc(g?(g.enName||g.heName):"Genre")+'</h2><span class="count">'+albums.length+' albums</span></div>';
        if(!albums.length){ setView(head+'<div class="empty">No albums in this genre.</div>'); return; }
        window._albums={}; var cards=albums.map(function(al){ window._albums[al.id]=al; return albumCard(al,(al.tracks||[]).length+" tracks"); }).join("");
        setView(head+'<div class="grid albums">'+cards+'</div>');
      }).catch(function(e){ if(e.message==="login")return; setStatus("❌ "+e.message,"err"); });
    }

    // ---------- Playlists ----------
    function browsePlaylists(){
      setNav("navPlaylists"); loading("Loading playlists…");
      gql("query { playlists(take: 300) { id name enName heName image cdnImage } }").then(function(d){
        var ps=d.playlists||[]; setStatus("","");
        if(!ps.length){ setView('<div class="empty">No playlists found.</div>'); return; }
        var cards=ps.map(function(p){ var nm=p.enName||p.name||p.heName||"Playlist";
          return '<div class="tile album" onclick="openPlaylist('+p.id+')">'+coverHtml(nm,{img:p.cdnImage||p.image})+
            '<div class="t-name">'+esc(nm)+'</div><div class="t-sub">Playlist</div></div>'; }).join("");
        setView('<div class="sec"><div class="sec-head"><h2>📻 Playlists</h2><span class="count">'+ps.length+'</span></div><div class="grid albums">'+cards+'</div></div>');
      }).catch(function(e){ if(e.message==="login")return; setStatus("❌ "+e.message,"err"); });
    }
    function openPlaylist(id){
      loading("Loading playlist…");
      gql("query { playlist(where:{id:"+Number(id)+"}) { id name enName heName image cdnImage playlistTracks { trackPosition track { id enName heName file duration trackNumber artists { enName heName } } } } }").then(function(d){
        var p=d.playlist; setStatus("","");
        var tracks=((p&&p.playlistTracks)||[]).map(function(x){return x.track;}).filter(Boolean);
        var nm=p?(p.enName||p.name||p.heName):"Playlist";
        renderTrackList(nm, "Playlist · "+tracks.length+" tracks", tracks, browsePlaylists, (p&&(p.cdnImage||p.image)));
      }).catch(function(e){ if(e.message==="login")return; setStatus("❌ "+e.message,"err"); });
    }

    // ---------- Generic track list (playlists, etc.) ----------
    function renderTrackList(title, subtitle, tracks, backFn, img){
      window._listTracks=tracks; window._listBack=backFn;
      var back='<div class="back" onclick="window._listBack&&window._listBack()">‹ Back</div>';
      var rows=tracks.map(function(t,i){ var nm=trackName(t);
        return '<div class="track" id="ltrk'+t.id+'" onclick="playList('+i+')"><div class="num">'+(i+1)+'</div>'+
          '<div class="tk">'+esc(nm)+(t.artists&&t.artists.length?' <span class="he">— '+esc(artNames(t.artists))+'</span>':'')+'</div>'+
          (t.duration?'<div class="time">'+fmt(t.duration)+'</div>':'')+
          '<button class="dl" onclick="event.stopPropagation();downloadTrack('+t.id+', '+esc(JSON.stringify(t.file||"")).replace(/"/g,"&quot;")+')"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg></button></div>'; }).join("");
      setView(back+'<div class="album-hero">'+coverHtml(title,{img:img})+
        '<div><div class="kicker">Collection</div><h2>'+esc(title)+'</h2><div class="sub">'+esc(subtitle)+'</div>'+
        '<div class="actions">'+(tracks.length?'<button class="btn" onclick="playList(0)"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg> Play all</button>':'')+'</div></div></div>'+
        (tracks.length?'<div class="tracks">'+rows+'</div>':'<div class="empty">No tracks.</div>'));
      highlightPlaying();
    }
    function playList(i){ playTracks(window._listTracks||[], i, ""); }

    function doSearch(){
      var q=$("q").value.trim().toLowerCase(); if(!q){ doNew(); return; }
      setNav("");
      ensureArtists().then(function(ok){ if(!ok) return;
        var m=artists.filter(function(a){ return (a.enName||"").toLowerCase().indexOf(q)>=0 || (a.heName||"").toLowerCase().indexOf(q)>=0; })
          .sort(function(a,b){ return (a.enName||"").localeCompare(b.enName||""); });
        if(!m.length){ setView('<div class="empty">No artists found for “'+esc(q)+'”.</div>'); return; }
        setView('<div class="sec"><div class="sec-head"><h2>Results</h2><span class="count">'+m.length+' found</span></div><div class="grid artists">'+m.map(artistCard).join("")+'</div></div>');
      });
    }

    function openArtist(id){
      loading("Loading albums…");
      post("/api/artist",{id:id}).then(function(d){
        var a=d.artist, albums=(a&&a.albums)||[]; setStatus("",""); window._curArtist=(a&&a.enName)||"";
        var head='<div class="back" onclick="doNew()">‹ Back</div><div class="sec-head"><h2>'+esc(a?a.enName:"Artist")+'</h2>'+
          (a&&a.heName?'<span class="count">'+esc(a.heName)+'</span>':'')+'</div>';
        if(!albums.length){ setView(head+'<div class="empty">No albums available for this artist.</div>'); return; }
        window._albums={}; window._albumBack=function(){ openArtist(id); };
        var cards=albums.map(function(al){ window._albums[al.id]=al; return albumCard(al, (al.tracks||[]).length+" tracks"); }).join("");
        setView(head+'<div class="grid albums">'+cards+'</div>');
      }).catch(function(e){ setStatus("❌ "+e.message,"err"); });
    }

    function openAlbum(id){
      var al=(window._albums||{})[id]; if(!al) return;
      var tracks=al.tracks||[];
      var artistName = (al.artists&&al.artists.length) ? artNames(al.artists) : (window._curArtist||"");
      var back=window._albumBack?'<div class="back" onclick="_albumBack()">‹ Back</div>':'<div class="back" onclick="doNew()">‹ Back</div>';
      var rows=tracks.map(function(t,i){ var nm=trackName(t);
        return '<div class="track" id="trk'+t.id+'" onclick="playAlbum('+id+','+i+')"><div class="num">'+(t.trackNumber||i+1)+'</div>'+
          '<div class="tk">'+esc(nm)+'</div>'+
          (t.duration?'<div class="time">'+fmt(t.duration)+'</div>':'')+
          '<button class="dl" title="Download" onclick="event.stopPropagation();downloadTrack('+t.id+', '+esc(JSON.stringify(t.file||"")).replace(/"/g,"&quot;")+')">'+
          '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg></button></div>'; }).join("");
      setView(back+'<div class="album-hero">'+coverHtml(albName(al))+
        '<div><div class="kicker">Album'+(artistName?' · '+esc(artistName):'')+'</div><h2>'+esc(albName(al))+'</h2>'+
        '<div class="sub">'+tracks.length+' tracks</div><div class="actions">'+
        (tracks.length?'<button class="btn" onclick="playAlbum('+id+',0)"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg> Play all</button>':'')+
        (tracks.length?'<button class="btn ghost" onclick="downloadAlbum('+id+')">⬇️ Download all</button>':'')+
        '</div></div></div>'+
        (tracks.length?'<div class="tracks">'+rows+'</div>':'<div class="empty">No tracks in this album.</div>'));
      highlightPlaying();
    }

    // ---------- Player ----------
    var audio=$("audio");
    function playAlbum(albumId, index){
      var al=(window._albums||{})[albumId]; if(!al) return; var tracks=al.tracks||[];
      var artistName=(al.artists&&al.artists.length)?artNames(al.artists):(window._curArtist||"");
      queue=tracks.map(function(t){ return {id:t.id, file:t.file||"", title:trackName(t), artist:artistName, cover:albName(al)}; });
      playIndex(index);
    }
    function playTracks(tracks, index, contextName){
      queue=tracks.map(function(t){ return {id:t.id, file:t.file||"", title:trackName(t), artist:(t.artists&&t.artists.length?artNames(t.artists):(contextName||"")), cover:contextName||trackName(t)}; });
      playIndex(index);
    }
    function playIndex(i){
      if(i<0||i>=queue.length) return; qi=i; var t=queue[i];
      audio.src="/api/play?trackId="+encodeURIComponent(t.id)+"&file="+encodeURIComponent(t.file);
      audio.play().catch(function(){});
      $("player").hidden=false;
      $("npTitle").textContent=t.title; $("npArtist").textContent=t.artist||"";
      $("npCover").style.background=grad(t.cover||t.title); $("npCover").innerHTML='<span class="disc"></span>';
      setPlayIcon(true); highlightPlaying();
    }
    function setPlayIcon(playing){ $("playBtn").innerHTML = playing
      ? '<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M6 5h4v14H6zm8 0h4v14h-4z"/></svg>'
      : '<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>'; }
    function highlightPlaying(){ var cur = queue[qi]; document.querySelectorAll(".track.playing").forEach(function(el){ el.classList.remove("playing"); });
      if(cur){ var el=$("trk"+cur.id)||$("ltrk"+cur.id); if(el) el.classList.add("playing"); } }
    function showLyrics(){
      var t=queue[qi]; if(!t){ toast("Play a track first."); return; }
      toast("Loading lyrics…");
      gql("query { track(where:{id:"+Number(t.id)+"}) { enName heName heLyrics enLyrics } }").then(function(d){
        var tr=d.track||{}; var lyr=tr.heLyrics||tr.enLyrics||"";
        if(!lyr){ toast("No lyrics for this track."); return; }
        var title=tr.enName||tr.heName||t.title;
        var o=document.createElement("div"); o.id="ovl";
        o.style.cssText="position:fixed;inset:0;z-index:80;background:rgba(10,10,18,.97);backdrop-filter:blur(6px);overflow:auto;padding:22px 18px calc(90px + env(safe-area-inset-bottom,0px))";
        o.innerHTML='<div style="max-width:640px;margin:0 auto"><div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:14px"><h2 style="margin:0">'+esc(title)+'</h2><button class="btn ghost" onclick="closeOverlay()">Close</button></div><pre dir="auto" style="white-space:pre-wrap;font-family:inherit;font-size:1.02rem;line-height:1.8;margin:0">'+esc(lyr)+'</pre></div>';
        document.body.appendChild(o);
      }).catch(function(e){ if(e.message==="login")return; toast("Could not load lyrics."); });
    }
    function closeOverlay(){ var d=$("ovl"); if(d) d.remove(); }
    function togglePlay(){ if(!queue.length) return; if(audio.paused) audio.play(); else audio.pause(); }
    function nextTrack(){ if(qi+1<queue.length) playIndex(qi+1); }
    function prevTrack(){ if(audio.currentTime>3){ audio.currentTime=0; return; } if(qi>0) playIndex(qi-1); }

    audio.addEventListener("play", function(){ setPlayIcon(true); });
    audio.addEventListener("pause", function(){ setPlayIcon(false); });
    audio.addEventListener("ended", function(){ nextTrack(); });
    audio.addEventListener("timeupdate", function(){
      $("curTime").textContent=fmt(audio.currentTime);
      if(audio.duration){ $("seek").value=String(Math.round(audio.currentTime/audio.duration*1000)); } });
    audio.addEventListener("loadedmetadata", function(){ $("durTime").textContent=fmt(audio.duration); });
    audio.addEventListener("error", function(){ toast("Could not play this track — running a check…"); runCheck(true); });
    $("seek").addEventListener("input", function(){ if(audio.duration){ audio.currentTime=this.value/1000*audio.duration; } });
    $("playBtn").onclick=togglePlay; $("nextBtn").onclick=nextTrack; $("prevBtn").onclick=prevTrack;
    $("npDl").onclick=function(){ var t=queue[qi]; if(t) downloadTrack(t.id, t.file); };

    // ---------- Downloads ----------
    function dlUrl(id,file){ var p=new URLSearchParams({trackId:id, file:file||""}); return "/api/download?"+p.toString(); }
    function downloadTrack(id,file){ var a=document.createElement("a"); a.href=dlUrl(id,file); a.download=""; document.body.appendChild(a); a.click(); a.remove(); toast("⬇️ Download started…"); }
    function downloadAlbum(albumId){ var al=(window._albums||{})[albumId]; if(!al) return; var tr=al.tracks||[]; var i=0;
      (function nx(){ if(i>=tr.length){ toast("✨ Started all "+tr.length+" downloads."); return; } downloadTrack(tr[i].id, tr[i].file||""); i++; setTimeout(nx,900); })(); }

    // ---------- Diagnostics ----------
    function diagBox(html){ var d=$("diag"); if(d) d.innerHTML = html ? '<div class="banner" style="border-color:rgba(124,92,255,.4);background:rgba(124,92,255,.08);color:var(--text)">'+html+'</div>' : ''; }
    function runCheck(auto){
      diagBox('<span class="spinner"></span>Checking connection…');
      fetch("/api/check").then(function(r){ if(r.status===401){ location.href="/"; throw new Error("login"); } return r.json(); }).then(function(s){
        var api=s.api||{}, audio=s.audio||{}, login=s.login||{}, lines=[], hint="";
        // API line
        if(api.configured===false) lines.push("❌ API_URL is not set.");
        else if(api.reachable===false) lines.push("❌ Can't reach your music API. Error: "+esc(api.error||"connection failed"));
        else if(api.status!==200) lines.push("⚠️ Music API answered with code "+api.status+".");
        else if(!api.hasData) lines.push("⚠️ Music API is reachable but returned no artists — check API_URL.");
        else lines.push("✅ Music API is connected.");
        // Login line (auto-login)
        if(login.configured===false) lines.push("ℹ️ Auto-login is off (using a fixed USER_TOKEN).");
        else if(login.ok) lines.push("✅ Auto-login works — the token refreshes itself.");
        else lines.push("❌ Auto-login failed. Error: "+esc(login.error||"unknown"));
        // Audio line
        if(audio.configured===false) lines.push("❌ AUDIO_API_BASE is not set.");
        else if(audio.reachable===false) lines.push("❌ Can't reach your audio server. Error: "+esc(audio.error||"connection failed"));
        else if(audio.status===403) lines.push("❌ Audio server said 403 — the login did not produce a valid token.");
        else lines.push("✅ Audio server is reachable (code "+audio.status+").");
        // Hint
        if(api.reachable===false || audio.reachable===false){
          hint='<div style="margin-top:10px">🔎 The server cannot be reached. This usually means the music server uses a self-signed certificate that Cloudflare cannot accept. The fix is to host this on a Python server instead — tell me and I will set it up.</div>';
        } else if(login.ok===false && login.configured!==false){
          hint='<div style="margin-top:10px">🔑 Auto-login failed — check the ZING_EMAIL and ZING_PASSWORD secrets, then redeploy. Send me the error above and I will adjust it.</div>';
          var am=s.authMutations;
          if(am){
            if(am.candidates && am.candidates.length){
              hint+='<div style="margin-top:10px">🔎 Found these login methods in the API — <b>send me this screenshot</b>:<br>'+am.candidates.map(function(x){ return '<code>'+esc(x)+'</code>'; }).join("<br>")+'</div>';
            } else if(am.candidates){
              hint+='<div style="margin-top:10px">🔎 No login mutation found in the schema (total mutations: '+(am.total||0)+'). Tell me and we will capture the real login request.</div>';
            } else if(am.error){
              hint+='<div style="margin-top:10px">🔎 Could not read the API schema ('+esc(am.error)+'). We will capture the real login request instead — tell me.</div>';
            }
          }
        } else if(audio.status===403 && login.configured===false){
          hint='<div style="margin-top:10px">🔑 Update the USER_TOKEN secret with a fresh token, or set up ZING_EMAIL + ZING_PASSWORD for automatic login.</div>';
        }
        // Token provider info (helps identify the auth provider)
        var ti=s.tokenInfo, tline="";
        if(ti && !ti.error){
          var when = (ti.ttlMinutes==null) ? "" : (ti.expired ? " (expired "+Math.abs(ti.ttlMinutes)+" min ago)" : " (expires in "+ti.ttlMinutes+" min)");
          tline='<div style="margin-top:10px">🪪 Token issuer: <code>'+esc(ti.iss||"unknown")+'</code>'+when+'<br><span class="muted">Send me this line — it tells me how to auto-refresh your token.</span></div>';
        }
        diagBox('<b>Connection check</b><div style="margin-top:8px;line-height:1.9">'+lines.join("<br>")+'</div>'+hint+tline);
      }).catch(function(e){ if(e&&e.message==="login") return; diagBox("❌ Could not run the check: "+esc(e.message||e)); });
    }

    function showSchema(){
      diagBox('<span class="spinner"></span>Reading API structure…');
      fetch("/api/schema").then(function(r){ if(r.status===401){location.href="/";throw new Error("login");} return r.json(); }).then(function(s){
        if(s.error){ diagBox("❌ "+esc(s.error)); return; }
        var f=s.queryFields||[];
        var rows=f.map(function(x){ return '<code>'+esc(x.name)+'('+(x.args||[]).join(", ")+') → '+esc(x.returns||"?")+'</code>'; }).join("<br>");
        var types=s.types||{}, trows="";
        Object.keys(types).forEach(function(k){
          trows+='<div style="margin-top:10px"><b>'+esc(k)+'</b><br><span style="font-size:.82rem">'+types[k].map(function(x){return esc(x);}).join(" · ")+'</span></div>';
        });
        // Plain-text version for the Copy button
        var plain="API STRUCTURE\\n\\nQUERIES:\\n";
        f.forEach(function(x){ plain+="- "+x.name+"("+(x.args||[]).join(", ")+") -> "+(x.returns||"?")+"\\n"; });
        plain+="\\nTYPES:\\n";
        Object.keys(types).forEach(function(k){ plain+=k+": "+types[k].join(", ")+"\\n\\n"; });
        window._schemaText=plain;
        diagBox('<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><b>API structure — '+f.length+' queries</b>'+
          '<button class="btn sm" style="padding:7px 13px" onclick="copySchema(this)">📋 Copy all</button></div>'+
          '<div style="margin-top:8px;line-height:1.8;font-size:.86rem">'+rows+'</div>'+
          (trows?'<div style="margin-top:14px"><b>Types (fields):</b>'+trows+'</div>':'')+
          '<div style="margin-top:10px" class="muted">Tap “Copy all”, then paste it to me — or screenshot it.</div>');
      }).catch(function(e){ if(e&&e.message==="login")return; diagBox("❌ "+esc(e.message||e)); });
    }

    function copySchema(btn){
      var txt=window._schemaText||"";
      function done(){ if(btn){ var o=btn.textContent; btn.textContent="✅ Copied!"; setTimeout(function(){ btn.textContent=o; }, 1800); } }
      try{
        if(navigator.clipboard && navigator.clipboard.writeText){
          navigator.clipboard.writeText(txt).then(done).catch(function(){ fallbackCopy(txt); done(); });
        } else { fallbackCopy(txt); done(); }
      }catch(e){ fallbackCopy(txt); done(); }
    }
    function fallbackCopy(txt){
      try{ var ta=document.createElement("textarea"); ta.value=txt; ta.style.cssText="position:fixed;left:-9999px";
        document.body.appendChild(ta); ta.focus(); ta.select(); document.execCommand("copy"); ta.remove(); }catch(e){}
    }

    // expose
    window.showSchema=showSchema; window.copySchema=copySchema;
    window.openArtist=openArtist; window.openAlbum=openAlbum; window.playAlbum=playAlbum;
    window.downloadTrack=downloadTrack; window.downloadAlbum=downloadAlbum; window.doNew=doNew;
    window.browseArtists=browseArtists; window.filterGrid=filterGrid; window.runCheck=runCheck;
    window.browseGenres=browseGenres; window.openGenre=openGenre;
    window.browsePlaylists=browsePlaylists; window.openPlaylist=openPlaylist;
    window.playList=playList; window.showLyrics=showLyrics; window.closeOverlay=closeOverlay;

    $("q").addEventListener("keydown", function(e){ if(e.key==="Enter") doSearch(); });
    $("q").addEventListener("input", function(){ if(!this.value.trim()){} });
    checkStatus();
    doNew();
  </script>
</body>
</html>`;
