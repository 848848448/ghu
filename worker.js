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
          token: !!env.USER_TOKEN,
          configured: !!(env.API_URL && env.AUDIO_API_BASE && env.USER_TOKEN),
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
      "query { artists(skip: " + skip + ", take: " + batchSize + ") { id enName heName } }";
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
    "query { artist(where: { id: " + Number(id) + " }) { id enName heName " +
    "albums { id enName tracks { id file } } } }";
  const data = await graphql(env, query);
  const artist = data && data.data ? data.data.artist : null;
  if (!artist) return json({ error: "No details found for this artist." }, 502);
  return json({ artist });
}

async function handleNew(env) {
  if (!env.API_URL) return json({ error: "Server not configured." }, 400);
  const query =
    "query { albums(take: 50) { id enName artists { enName } tracks { id file } } }";
  const data = await graphql(env, query);
  if (!data || data.errors) return json({ albums: [] });
  let albums = ((data.data || {}).albums) || [];
  albums = albums
    .sort((a, b) => Number(b.id || 0) - Number(a.id || 0))
    .slice(0, 10);
  return json({ albums });
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

  const fullUrl =
    env.AUDIO_API_BASE +
    "?trackId=" + encodeURIComponent(trackId) +
    "&token=" + encodeURIComponent(env.USER_TOKEN || "");

  const upstream = await fetch(fullUrl);
  if (upstream.status === 403) {
    return json({ error: "Access Denied (403). Your JWT token may have expired." }, 403);
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
<title>Niggun — Sign in</title>
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
    <h1>Niggun Music</h1>
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Zing — Jewish Music</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg: #0a0b14;
      --bg-2: #10121f;
      --card: #161a2c;
      --card-2: #1d2238;
      --text: #f2f3fb;
      --muted: #9aa0c0;
      --accent: #8b5cf6;
      --accent-2: #ec4899;
      --ok: #34d399;
      --err: #fb7185;
      --warn: #fbbf24;
      --border: rgba(255,255,255,.08);
      --shadow: 0 10px 30px rgba(0,0,0,.35);
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body {
      font-family: "Poppins", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background:
        radial-gradient(1100px 600px at 15% -10%, rgba(139,92,246,.22), transparent 60%),
        radial-gradient(1000px 500px at 100% 0%, rgba(236,72,153,.16), transparent 55%),
        var(--bg);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
    }
    a { color: inherit; }

    /* Top bar */
    .topbar {
      position: sticky; top: 0; z-index: 20;
      display: flex; align-items: center; gap: 14px;
      padding: 16px 22px;
      background: rgba(10,11,20,.72);
      backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--border);
    }
    .brand { display: flex; align-items: center; gap: 11px; font-weight: 800; font-size: 1.25rem; letter-spacing: .3px; }
    .logo {
      width: 38px; height: 38px; border-radius: 12px; display: grid; place-items: center;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      box-shadow: 0 6px 18px rgba(139,92,246,.5);
      font-size: 20px;
    }
    .brand small { display: block; font-weight: 500; font-size: .68rem; color: var(--muted); letter-spacing: 2px; text-transform: uppercase; }
    .badge { margin-left: auto; font-size: .78rem; padding: 6px 12px; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); }
    .badge.ok { color: var(--ok); border-color: rgba(52,211,153,.35); background: rgba(52,211,153,.08); }

    .wrap { max-width: 1080px; margin: 0 auto; padding: 26px 22px 90px; }

    /* Hero search */
    .hero { margin: 8px 0 26px; }
    .hero h1 { font-size: clamp(1.6rem, 4vw, 2.4rem); font-weight: 800; margin: 0 0 6px; }
    .hero p { color: var(--muted); margin: 0 0 20px; }
    .searchbar {
      display: flex; align-items: center; gap: 10px;
      background: var(--card); border: 1px solid var(--border);
      border-radius: 16px; padding: 8px 8px 8px 16px; box-shadow: var(--shadow);
    }
    .searchbar svg { flex: none; color: var(--muted); }
    .searchbar input {
      flex: 1; min-width: 0; background: transparent; border: none; outline: none;
      color: var(--text); font-size: 1.05rem; font-family: inherit; padding: 10px 4px;
    }
    .searchbar input::placeholder { color: var(--muted); }
    .btn {
      border: none; cursor: pointer; font-family: inherit; font-weight: 600; font-size: .98rem;
      color: #fff; padding: 12px 20px; border-radius: 12px; white-space: nowrap;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      box-shadow: 0 8px 20px rgba(139,92,246,.35);
      transition: transform .08s ease, filter .15s ease;
    }
    .btn:hover { filter: brightness(1.08); }
    .btn:active { transform: translateY(1px); }
    .btn.ghost { background: var(--card-2); color: var(--text); box-shadow: none; border: 1px solid var(--border); }
    .btn.sm { padding: 9px 14px; font-size: .88rem; }
    .chips { display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }

    #status { min-height: 20px; font-size: .92rem; margin-top: 14px; }
    .ok { color: var(--ok); } .err { color: var(--err); } .muted { color: var(--muted); }
    .hidden { display: none !important; }

    /* Section */
    .section { margin-top: 30px; }
    .section-head { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
    .section-head h2 { font-size: 1.25rem; font-weight: 700; margin: 0; }
    .back {
      display: inline-flex; align-items: center; gap: 6px; cursor: pointer; color: var(--muted);
      font-size: .9rem; margin-bottom: 14px;
    }
    .back:hover { color: var(--text); }

    /* Grids */
    .grid { display: grid; gap: 18px; }
    .grid.artists { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
    .grid.albums { grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); }

    .tile {
      background: var(--card); border: 1px solid var(--border); border-radius: 16px;
      padding: 16px; cursor: pointer; transition: transform .12s ease, background .15s ease;
      position: relative; overflow: hidden;
    }
    .tile:hover { transform: translateY(-4px); background: var(--card-2); }
    .cover {
      width: 100%; aspect-ratio: 1/1; border-radius: 12px; display: grid; place-items: center;
      font-weight: 800; font-size: 2rem; color: rgba(255,255,255,.92); margin-bottom: 12px;
      box-shadow: inset 0 0 40px rgba(0,0,0,.25);
    }
    .cover.round { border-radius: 999px; width: 84%; margin: 0 auto 12px; }
    .cover .ic { font-size: 1.7rem; opacity: .9; }
    .tile .t-name { font-weight: 600; font-size: .98rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tile .t-sub { color: var(--muted); font-size: .82rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 2px; }
    .tile.artist { text-align: center; }
    .play-fab {
      position: absolute; right: 20px; bottom: 64px; width: 42px; height: 42px; border-radius: 999px;
      background: linear-gradient(135deg, var(--accent), var(--accent-2)); display: grid; place-items: center;
      box-shadow: 0 8px 18px rgba(0,0,0,.4); opacity: 0; transform: translateY(8px);
      transition: opacity .15s ease, transform .15s ease; color: #fff;
    }
    .tile.album:hover .play-fab { opacity: 1; transform: translateY(0); }

    /* Album header */
    .album-hero { display: flex; gap: 20px; align-items: flex-end; margin-bottom: 22px; flex-wrap: wrap; }
    .album-hero .cover { width: 168px; height: 168px; aspect-ratio: auto; margin: 0; flex: none; font-size: 3rem; }
    .album-hero .meta .kicker { color: var(--muted); font-size: .78rem; letter-spacing: 2px; text-transform: uppercase; }
    .album-hero .meta h2 { font-size: clamp(1.4rem, 4vw, 2rem); margin: 4px 0 6px; font-weight: 800; }
    .album-hero .meta .sub { color: var(--muted); font-size: .92rem; }
    .album-hero .actions { margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; }

    /* Track list */
    .tracks { border: 1px solid var(--border); border-radius: 16px; overflow: hidden; background: var(--card); }
    .track {
      display: flex; align-items: center; gap: 14px; padding: 12px 16px;
      border-bottom: 1px solid var(--border); transition: background .12s ease;
    }
    .track:last-child { border-bottom: none; }
    .track:hover { background: var(--card-2); }
    .track .num { width: 26px; text-align: center; color: var(--muted); font-variant-numeric: tabular-nums; font-size: .92rem; }
    .track .tk-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: .96rem; }
    .track .dl {
      flex: none; width: 40px; height: 40px; border-radius: 999px; border: 1px solid var(--border);
      background: transparent; color: var(--muted); cursor: pointer; display: grid; place-items: center;
      transition: all .15s ease;
    }
    .track .dl:hover { color: #fff; border-color: transparent; background: linear-gradient(135deg, var(--accent), var(--accent-2)); }

    .empty { color: var(--muted); padding: 30px 4px; text-align: center; }

    .banner {
      border-radius: 14px; padding: 14px 16px; margin-bottom: 20px;
      border: 1px solid rgba(251,191,36,.35); background: rgba(251,191,36,.08); color: var(--warn); font-size: .92rem;
    }
    .banner code { background: rgba(255,255,255,.1); padding: 1px 6px; border-radius: 6px; color: var(--text); }
    .spinner {
      display: inline-block; width: 15px; height: 15px; border: 2px solid var(--muted);
      border-top-color: transparent; border-radius: 50%; animation: spin .7s linear infinite; vertical-align: -3px; margin-right: 7px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <span class="logo">🎵</span>
      <span>Zing<small>Jewish Music</small></span>
    </div>
    <span class="badge" id="cfgBadge"></span>
  </div>

  <div class="wrap">
    <div class="banner hidden" id="cfgBanner">
      ⚠️ Not configured yet. Add your <code>API_URL</code>, <code>AUDIO_API_BASE</code>
      and <code>USER_TOKEN</code> (see README), then reload.
    </div>

    <div class="hero">
      <h1>Find your music</h1>
      <p>Search thousands of artists, browse albums, and download your favorites.</p>
      <div class="searchbar">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input type="text" id="search" placeholder="Search for an artist…" autocomplete="off" />
        <button class="btn" id="searchBtn">Search</button>
      </div>
      <div class="chips">
        <button class="btn ghost sm" id="newBtn">🔥 New Releases</button>
      </div>
      <div id="status"></div>
    </div>

    <div id="view"></div>
  </div>

  <script>
    var artists = [];
    var artistsLoaded = false;
    var CACHE_KEY = "zing_artists_cache";
    var CACHE_TTL = 86400000;

    function $(id){ return document.getElementById(id); }
    function setStatus(h, c){ $("status").innerHTML = h; $("status").className = c || ""; }
    function loading(m){ setStatus('<span class="spinner"></span>' + m, "muted"); }
    function esc(s){ return (s==null?"":String(s)).replace(/[&<>"']/g, function(c){
      return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]; }); }

    // A stable gradient + initials for a name (the API has no artwork).
    function hashStr(s){ var h = 0; s = s || "?"; for (var i=0;i<s.length;i++){ h = (h*31 + s.charCodeAt(i)) >>> 0; } return h; }
    function gradient(name){
      var h = hashStr(name); var a = h % 360; var b = (a + 40 + (h>>3)%80) % 360;
      return "linear-gradient(135deg, hsl("+a+",70%,55%), hsl("+b+",72%,45%))";
    }
    function initials(name){
      name = (name || "?").trim();
      var parts = name.split(/\s+/).filter(Boolean);
      if (!parts.length) return "?";
      if (parts.length === 1) return parts[0].slice(0,2).toUpperCase();
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }

    function post(path, payload){
      return fetch(path, { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(payload||{}) })
        .then(function(res){ return res.json().catch(function(){return {};}).then(function(data){
          if(res.status===401 && data.needLogin){ location.href = "/"; throw new Error("Please log in."); }
          if(!res.ok) throw new Error(data.error || ("Request failed ("+res.status+")")); return data; }); });
    }

    function checkStatus(){
      fetch("/api/status").then(function(r){return r.json();}).then(function(s){
        if(s.configured){ $("cfgBanner").classList.add("hidden"); $("cfgBadge").textContent = "Connected"; $("cfgBadge").className = "badge ok"; }
        else { $("cfgBanner").classList.remove("hidden"); $("cfgBadge").textContent = "Not configured"; $("cfgBadge").className = "badge"; }
      }).catch(function(){});
    }

    function loadCache(){ try { var o = JSON.parse(localStorage.getItem(CACHE_KEY)||"null");
      if(o && Date.now()-o.t < CACHE_TTL && o.a && o.a.length) return o.a; } catch(e){} return null; }
    function saveCache(a){ try { localStorage.setItem(CACHE_KEY, JSON.stringify({t:Date.now(), a:a})); } catch(e){} }

    function ensureArtists(force){
      if(artistsLoaded && !force) return Promise.resolve(true);
      if(!force){ var c = loadCache(); if(c){ artists = c; artistsLoaded = true; setStatus("", ""); return Promise.resolve(true); } }
      loading("Loading artist catalog…");
      return post("/api/artists", {}).then(function(d){ artists = d.artists||[]; artistsLoaded = true; saveCache(artists);
        setStatus("", ""); return true; }).catch(function(e){ setStatus("❌ "+e.message, "err"); return false; });
    }

    function setView(h){ $("view").innerHTML = h; window.scrollTo({top:0, behavior:"smooth"}); }
    function coverHtml(name, opts){
      opts = opts || {};
      var cls = "cover" + (opts.round ? " round" : "");
      var content = opts.round ? '<span>'+esc(initials(name))+'</span>' : '<span class="ic">💿</span>';
      return '<div class="'+cls+'" style="background:'+gradient(name)+'">'+content+'</div>';
    }

    function doSearch(){
      ensureArtists(false).then(function(ok){
        if(!ok) return;
        var q = $("search").value.trim().toLowerCase();
        if(!q){ setStatus("Type part of an artist's name.", "muted"); return; }
        var matching = artists.filter(function(a){
          return ((a.enName||"").toLowerCase().indexOf(q)>=0) || ((a.heName||"").toLowerCase().indexOf(q)>=0);
        }).sort(function(a,b){ return (a.enName||"").localeCompare(b.enName||""); });
        if(!matching.length){ setView('<div class="empty">No artists found matching “'+esc(q)+'”.</div>'); return; }
        var cards = matching.map(function(a){
          return '<div class="tile artist" onclick="openArtist('+a.id+')">'+
            coverHtml(a.enName || a.heName, {round:true})+
            '<div class="t-name">'+esc(a.enName||"Unknown")+'</div>'+
            (a.heName?'<div class="t-sub">'+esc(a.heName)+'</div>':'<div class="t-sub">Artist</div>')+
          '</div>';
        }).join("");
        setView(
          '<div class="section"><div class="section-head"><h2>Artists</h2><span class="muted" style="font-size:.9rem">'+matching.length+' found</span></div>'+
          '<div class="grid artists">'+cards+'</div></div>');
        setStatus("", "");
      });
    }

    function openArtist(id){
      loading("Loading albums…");
      post("/api/artist", {id:id}).then(function(d){
        var artist = d.artist; var albums = (artist && artist.albums) || [];
        setStatus("", "");
        window._backFn = doSearch;
        var head = '<div class="back" onclick="doSearch()">‹ Back to results</div>'+
          '<div class="section-head"><h2>'+esc(artist ? artist.enName : "Artist")+'</h2>'+
          (artist && artist.heName ? '<span class="muted" style="font-size:.95rem">'+esc(artist.heName)+'</span>' : '')+'</div>';
        if(!albums.length){ setView(head + '<div class="empty">No albums available for this artist.</div>'); return; }
        window._albums = {};
        var backTo = function(){ openArtist(id); };
        window._albumBack = backTo;
        var cards = albums.map(function(al){ window._albums[al.id] = al; var n = (al.tracks||[]).length;
          return '<div class="tile album" onclick="openAlbum('+al.id+')">'+
            coverHtml(al.enName)+
            '<div class="play-fab"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></div>'+
            '<div class="t-name">'+esc(al.enName||"Unknown Album")+'</div>'+
            '<div class="t-sub">'+n+' track'+(n===1?'':'s')+'</div>'+
          '</div>'; }).join("");
        setView(head + '<div class="grid albums">'+cards+'</div>');
      }).catch(function(e){ setStatus("❌ "+e.message, "err"); });
    }

    function openAlbum(albumId){
      var al = (window._albums||{})[albumId]; if(!al) return;
      var tracks = al.tracks || [];
      var back = window._albumBack ? '<div class="back" onclick="window._albumBack()">‹ Back</div>' : '';
      var html = back + '<div class="album-hero">'+
          coverHtml(al.enName)+
          '<div class="meta"><div class="kicker">Album</div><h2>'+esc(al.enName||"Unknown")+'</h2>'+
          '<div class="sub">'+tracks.length+' track'+(tracks.length===1?'':'s')+'</div>'+
          '<div class="actions">'+
            (tracks.length ? '<button class="btn" onclick="downloadAlbum('+albumId+')">⬇️ Download all</button>' : '')+
          '</div></div></div>';
      if(!tracks.length){ setView(html + '<div class="empty">No tracks in this album.</div>'); return; }
      var rows = tracks.map(function(t,i){
        var nm = (t.file||"").split("/").pop() || ("Track "+t.id);
        return '<div class="track"><div class="num">'+(i+1)+'</div>'+
          '<div class="tk-name">'+esc(nm)+'</div>'+
          '<button class="dl" title="Download" onclick="downloadTrack('+t.id+', '+esc(JSON.stringify(t.file||"")).replace(/"/g,"&quot;")+')">'+
          '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg>'+
          '</button></div>';
      }).join("");
      setView(html + '<div class="tracks">'+rows+'</div>');
    }

    function downloadUrl(trackId, file){ var p = new URLSearchParams({ trackId: trackId, file: file||"" }); return "/api/download?"+p.toString(); }
    function downloadTrack(trackId, file){
      var a = document.createElement("a"); a.href = downloadUrl(trackId, file); a.download = "";
      document.body.appendChild(a); a.click(); a.remove(); setStatus("⬇️ Download started…", "ok");
    }
    function downloadAlbum(albumId){
      var al = (window._albums||{})[albumId]; if(!al) return; var tracks = al.tracks||[]; var i=0;
      (function next(){ if(i>=tracks.length){ setStatus("✨ Started all "+tracks.length+" downloads.", "ok"); return; }
        setStatus("⬇️ Downloading "+(i+1)+" / "+tracks.length+"…", "muted");
        downloadTrack(tracks[i].id, tracks[i].file||""); i++; setTimeout(next, 800); })();
    }

    function doNew(){
      loading("Fetching new releases…");
      post("/api/new", {}).then(function(d){
        var albums = d.albums||[]; setStatus("", "");
        if(!albums.length){ setView('<div class="empty">No new releases found.</div>'); return; }
        window._albums = {};
        window._albumBack = doNew;
        var cards = albums.map(function(al){ window._albums[al.id] = al;
          var names = (al.artists||[]).map(function(a){return a.enName||"Unknown";}).join(", ")||"Various";
          var n = (al.tracks||[]).length;
          return '<div class="tile album" onclick="openAlbum('+al.id+')">'+
            coverHtml(al.enName)+
            '<div class="play-fab"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></div>'+
            '<div class="t-name">'+esc(al.enName||"Unknown")+'</div>'+
            '<div class="t-sub">'+esc(names)+'</div>'+
          '</div>'; }).join("");
        setView('<div class="section"><div class="section-head"><h2>🔥 New Releases</h2></div><div class="grid albums">'+cards+'</div></div>');
      }).catch(function(e){ setStatus("❌ "+e.message, "err"); });
    }

    $("searchBtn").onclick = doSearch;
    $("newBtn").onclick = doNew;
    $("search").addEventListener("keydown", function(e){ if(e.key === "Enter") doSearch(); });
    checkStatus();
  </script>
</body>
</html>`;
