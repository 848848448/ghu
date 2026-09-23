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

    try {
      if (path === "/" || path === "/index.html") {
        return html(PAGE);
      }
      if (path === "/api/status") {
        return json({
          apiUrl: !!env.API_URL,
          audioBase: !!env.AUDIO_API_BASE,
          token: !!env.USER_TOKEN,
          configured: !!(env.API_URL && env.AUDIO_API_BASE && env.USER_TOKEN),
        });
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
// Frontend (served at /). Artist catalog is cached in the browser for 24h.
// --------------------------------------------------------------------------- //
const PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>🎵 Jewish Music Downloader</title>
  <style>
    :root {
      --bg: #0f1220; --panel: #191d31; --panel-2: #212640;
      --accent: #6c8cff; --accent-2: #4a68d8; --text: #e8eaf5;
      --muted: #9aa3c7; --ok: #3ecf8e; --err: #ff6b6b; --warn: #ffcc66;
      --border: #2c3352;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.5; }
    header { background: linear-gradient(135deg, #232a4a, #171a2e); padding: 20px 16px;
      border-bottom: 1px solid var(--border); display: flex; align-items: center;
      justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    header h1 { margin: 0; font-size: 1.4rem; }
    .container { max-width: 900px; margin: 0 auto; padding: 16px; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; }
    input[type="text"] { background: var(--panel-2); border: 1px solid var(--border);
      color: var(--text); padding: 11px 13px; border-radius: 10px; font-size: 1rem; width: 100%; }
    input:focus { outline: none; border-color: var(--accent); }
    button { background: var(--accent); color: white; border: none; padding: 11px 16px;
      border-radius: 10px; font-size: 1rem; cursor: pointer; font-weight: 600; white-space: nowrap; }
    button:hover { background: var(--accent-2); }
    button.ghost { background: transparent; border: 1px solid var(--border); color: var(--muted); }
    button.ghost:hover { background: var(--panel-2); color: var(--text); }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
      padding: 16px; margin-bottom: 16px; }
    .list-item { display: flex; align-items: center; justify-content: space-between; gap: 10px;
      padding: 11px 13px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 8px;
      background: var(--panel-2); cursor: pointer; }
    .list-item:hover { border-color: var(--accent); }
    .list-item .meta { color: var(--muted); font-size: .85rem; }
    .list-item.no-click { cursor: default; }
    .list-item.no-click:hover { border-color: var(--border); }
    .he { color: var(--muted); font-size: .9rem; }
    #status { min-height: 22px; font-size: .9rem; }
    .ok { color: var(--ok); } .err { color: var(--err); } .muted { color: var(--muted); }
    .hidden { display: none; }
    .breadcrumb { color: var(--muted); font-size: .9rem; margin-bottom: 10px; }
    .breadcrumb a { color: var(--accent); cursor: pointer; text-decoration: none; }
    .breadcrumb a:hover { text-decoration: underline; }
    .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--muted);
      border-top-color: transparent; border-radius: 50%; animation: spin .7s linear infinite;
      vertical-align: -2px; margin-right: 6px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    h2 { margin: 0 0 12px; font-size: 1.15rem; }
    .banner { border-radius: 12px; padding: 14px 16px; margin-bottom: 16px;
      border: 1px solid var(--warn); background: rgba(255,204,102,.08); color: var(--warn); font-size: .92rem; }
    .banner code { background: rgba(255,255,255,.08); padding: 1px 6px; border-radius: 6px; color: var(--text); }
  </style>
</head>
<body>
  <header>
    <h1>🎵 Jewish Music Downloader</h1>
    <span class="muted" id="cfgBadge"></span>
  </header>
  <div class="container">
    <div class="banner hidden" id="cfgBanner">
      ⚠️ The Worker has no configuration yet. Set the
      <code>API_URL</code>, <code>AUDIO_API_BASE</code> and <code>USER_TOKEN</code>
      secrets with <code>wrangler secret put</code>, then redeploy.
    </div>
    <div class="card">
      <div class="row">
        <input type="text" id="search" placeholder="🔍 Search for an artist by name…" style="flex:1;min-width:200px;" />
        <button id="searchBtn">Search</button>
        <button class="ghost" id="newBtn">🔥 New Releases</button>
      </div>
      <div id="status" style="margin-top:10px;"></div>
    </div>
    <div class="card hidden" id="resultsCard">
      <div class="breadcrumb" id="breadcrumb"></div>
      <h2 id="resultsTitle"></h2>
      <div id="results"></div>
    </div>
  </div>
  <script>
    var artists = [];
    var artistsLoaded = false;
    var CACHE_KEY = "jmd_artists_cache";
    var CACHE_TTL = 86400000; // 24h

    function $(id){ return document.getElementById(id); }
    function setStatus(h, c){ $("status").innerHTML = h; $("status").className = c || ""; }
    function loading(m){ setStatus('<span class="spinner"></span>' + m, "muted"); }
    function esc(s){ return (s==null?"":String(s)).replace(/[&<>"']/g,function(c){
      return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]; }); }

    function post(path, payload){
      return fetch(path, { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify(payload||{}) }).then(function(res){
        return res.json().catch(function(){return {};}).then(function(data){
          if(!res.ok) throw new Error(data.error || ("Request failed ("+res.status+")"));
          return data;
        });
      });
    }

    function checkStatus(){
      fetch("/api/status").then(function(r){return r.json();}).then(function(s){
        if(s.configured){ $("cfgBanner").classList.add("hidden");
          $("cfgBadge").textContent = "✅ configured"; $("cfgBadge").className = "ok"; }
        else { $("cfgBanner").classList.remove("hidden");
          $("cfgBadge").textContent = "⚠️ not configured"; $("cfgBadge").className = "muted"; }
      }).catch(function(){});
    }

    function loadCache(){
      try {
        var raw = localStorage.getItem(CACHE_KEY);
        if(!raw) return null;
        var obj = JSON.parse(raw);
        if(Date.now() - obj.t < CACHE_TTL && obj.a && obj.a.length) return obj.a;
      } catch(e){}
      return null;
    }
    function saveCache(a){ try { localStorage.setItem(CACHE_KEY, JSON.stringify({t:Date.now(), a:a})); } catch(e){} }

    function ensureArtists(force){
      if(artistsLoaded && !force) return Promise.resolve(true);
      if(!force){ var cached = loadCache(); if(cached){ artists = cached; artistsLoaded = true;
        setStatus("🎉 Loaded " + artists.length + " artists (from cache).", "ok"); return Promise.resolve(true); } }
      loading("Downloading artist catalog…");
      return post("/api/artists", {}).then(function(data){
        artists = data.artists || []; artistsLoaded = true; saveCache(artists);
        setStatus("🎉 Loaded " + artists.length + " artists.", "ok"); return true;
      }).catch(function(e){ setStatus("❌ " + e.message, "err"); return false; });
    }

    function showResults(title, crumb, h){
      $("resultsCard").classList.remove("hidden");
      $("resultsTitle").innerHTML = title; $("breadcrumb").innerHTML = crumb || ""; $("results").innerHTML = h;
    }

    function doSearch(){
      ensureArtists(false).then(function(ok){
        if(!ok) return;
        var q = $("search").value.trim().toLowerCase();
        if(!q){ setStatus("Type part of an artist's name.", "muted"); return; }
        var matching = artists.filter(function(a){
          var en = (a.enName||"").toLowerCase(); var he = (a.heName||"").toLowerCase();
          return en.indexOf(q) >= 0 || he.indexOf(q) >= 0;
        }).sort(function(a,b){ return (a.enName||"").localeCompare(b.enName||""); });
        if(!matching.length){ showResults("No results", "", '<p class="muted">No artists found matching “'+esc(q)+'”.</p>'); return; }
        var h = matching.map(function(a){
          return '<div class="list-item" onclick="openArtist('+a.id+')"><span>'+esc(a.enName||"Unknown")+
            (a.heName?' <span class="he">('+esc(a.heName)+')</span>':"")+'</span><span class="meta">›</span></div>';
        }).join("");
        showResults("Search results for “"+esc(q)+"” ("+matching.length+")", "", h);
        setStatus("", "");
      });
    }

    function openArtist(id){
      loading("Loading albums…");
      post("/api/artist", {id:id}).then(function(data){
        var artist = data.artist; var albums = (artist && artist.albums) || [];
        if(!albums.length){ showResults(esc(artist?artist.enName:"Artist"), backToSearch(),
          '<p class="muted">No albums available for this artist.</p>'); setStatus("",""); return; }
        window._albums = {};
        var h = albums.map(function(al){ window._albums[al.id] = al; var n = (al.tracks||[]).length;
          return '<div class="list-item" onclick="openAlbum('+al.id+')"><span>'+esc(al.enName||"Unknown Album")+
            '</span><span class="meta">'+n+' tracks ›</span></div>'; }).join("");
        showResults("Albums by "+esc(artist.enName), backToSearch(), h); setStatus("","");
      }).catch(function(e){ setStatus("❌ "+e.message, "err"); });
    }

    function backToSearch(){ return '<a onclick="doSearch()">‹ Back to results</a>'; }

    function openAlbum(albumId){
      var al = (window._albums||{})[albumId]; if(!al) return;
      var tracks = al.tracks || [];
      if(!tracks.length){ showResults(esc(al.enName), "", '<p class="muted">No tracks in this album.</p>'); return; }
      var h = '<div class="row" style="margin-bottom:12px;"><button onclick="downloadAlbum('+albumId+')">📥 Download entire album ('+tracks.length+')</button></div>';
      h += tracks.map(function(t,i){
        return '<div class="list-item no-click"><span>'+(i+1)+'. '+esc((t.file||"").split("/").pop()||("Track "+t.id))+
          '</span><button onclick="downloadTrack('+t.id+', '+esc(JSON.stringify(t.file||"")).replace(/"/g,"&quot;")+')">⬇️</button></div>';
      }).join("");
      showResults("Album: "+esc(al.enName||"Unknown"), "", h);
    }

    function downloadUrl(trackId, file){
      var p = new URLSearchParams({ trackId: trackId, file: file || "" });
      return "/api/download?" + p.toString();
    }
    function downloadTrack(trackId, file){
      var a = document.createElement("a"); a.href = downloadUrl(trackId, file); a.download = "";
      document.body.appendChild(a); a.click(); a.remove(); setStatus("⬇️ Download started…", "ok");
    }
    function downloadAlbum(albumId){
      var al = (window._albums||{})[albumId]; if(!al) return;
      var tracks = al.tracks || []; var i = 0;
      function next(){
        if(i >= tracks.length){ setStatus("✨ Started all "+tracks.length+" downloads.", "ok"); return; }
        setStatus("⬇️ Downloading "+(i+1)+" / "+tracks.length+"…", "muted");
        downloadTrack(tracks[i].id, tracks[i].file || ""); i++; setTimeout(next, 800);
      }
      next();
    }

    function doNew(){
      loading("Fetching recent releases…");
      post("/api/new", {}).then(function(data){
        var albums = data.albums || [];
        if(!albums.length){ showResults("New Releases", "", '<p class="muted">No new releases found.</p>'); setStatus("",""); return; }
        window._albums = {};
        var h = albums.map(function(al){ window._albums[al.id] = al;
          var names = (al.artists||[]).map(function(a){return a.enName||"Unknown";}).join(", ") || "Various";
          var n = (al.tracks||[]).length;
          return '<div class="list-item" onclick="openAlbum('+al.id+')"><span>'+esc(al.enName||"Unknown")+
            ' <span class="he">— '+esc(names)+'</span></span><span class="meta">'+n+' tracks ›</span></div>'; }).join("");
        showResults("🔥 Latest "+albums.length+" New Releases", "", h); setStatus("","");
      }).catch(function(e){ setStatus("❌ "+e.message, "err"); });
    }

    $("searchBtn").onclick = doSearch;
    $("newBtn").onclick = doNew;
    $("search").addEventListener("keydown", function(e){ if(e.key === "Enter") doSearch(); });
    checkStatus();
  </script>
</body>
</html>`;
