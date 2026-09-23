# 🎵 Jewish Music Downloader — Web Edition

A web version of the original command-line Python downloader. Search artists,
browse albums, view new releases, and download tracks — all from a browser.

Two ways to run it:

- **☁️ Cloudflare Workers** (`worker.js`) — host it online. **Recommended.**
- **🖥️ Local Python / Flask** (`app.py`) — run it on your own computer.

## 🔒 Your private info stays private

Your secrets (API URL, audio URL, JWT token) are **never** put in the code
and **never** uploaded to GitHub.

- On **Cloudflare**, they are stored as encrypted **Worker secrets**.
- **Locally**, they live in a git-ignored `.env` or `local_config.py`.

Either way the token stays on the server and is never sent to the browser,
so nobody reading the repository (or anyone else) ever sees your secrets.

> ⚠️ **Important:** Never paste your token into a file you commit (like
> `worker.js` or `app.py`). Anything on GitHub is visible in the repo and its
> history forever. Keep secrets only as Cloudflare secrets or in the local
> git-ignored files.

---

## ☁️ Deploy to Cloudflare (recommended)

You need a free [Cloudflare account](https://dash.cloudflare.com/sign-up) and
[Node.js](https://nodejs.org) installed. Everything below runs on **your**
computer, so your secrets are never sent to anyone else.

**1. Log in to Cloudflare**

```bash
npx wrangler login
```

**2. Add your three secrets** (encrypted at Cloudflare — never in the repo)

```bash
npx wrangler secret put API_URL
npx wrangler secret put AUDIO_API_BASE
npx wrangler secret put USER_TOKEN
```

Each command prompts you to paste the value. These are the same values as in
your original script (`API_URL`, `AUDIO_API_BASE`, `USER_TOKEN`).

**3. Deploy**

```bash
npx wrangler deploy
```

Wrangler prints your site's URL (something like
`https://jewish-music-downloader.<your-subdomain>.workers.dev`). Open it — it
just works.

To change a secret later, run the same `secret put` command again and
redeploy. To test locally first, create a `.dev.vars` file (git-ignored) with
`API_URL=…`, `AUDIO_API_BASE=…`, `USER_TOKEN=…` and run `npx wrangler dev`.

> ℹ️ Cloudflare's `fetch` verifies TLS certificates. If your music API uses a
> self-signed / invalid certificate, the Worker can't reach it — use the local
> Python option below in that case (it keeps the original `verify=False`).

---

## 🖥️ Run locally with Python (alternative)

**1. Install dependencies**

```bash
pip install -r requirements.txt
```

**2. Point it at your original script** (runs on your computer)

```bash
python configure.py
```

It copies your script in as `local_config.py` (git-ignored, never uploaded).
You can also just copy your script into this folder and rename it to
`local_config.py` yourself. Or create a `.env` file (`cp .env.example .env`)
and fill in the three values.

**3. Run**

```bash
python app.py
```

Open <http://localhost:5000>. Change the port with `PORT=8080 python app.py`.

---

## Features

- 🔍 **Search** artists by English or Hebrew name (24‑hour catalog cache)
- 🔥 **New Releases** — the latest 10 albums
- 📂 Browse an artist → albums → tracks
- ⬇️ Download a single track, or 📥 the whole album at once

## How it maps to the original script

| Original CLI | Web equivalent |
|--------------|----------------|
| `fetch_artists()` (+ cache) | `POST /api/artists` (browser cache on Cloudflare) |
| `fetch_artist_details()` | `POST /api/artist` |
| `fetch_new_releases()` | `POST /api/new` |
| `download_track()` | `GET /api/download` (streamed, token added server-side) |
| terminal menus | the web UI |
| `API_URL` / `AUDIO_API_BASE` / `USER_TOKEN` | Cloudflare secrets, or `.env` / `local_config.py` |

## Files

| File | Purpose |
|------|---------|
| `worker.js` | Cloudflare Worker (backend + web UI) |
| `wrangler.toml` | Cloudflare deploy config |
| `app.py` | Flask backend (local option) |
| `templates/index.html` | Flask web UI |
| `configure.py` | Local setup helper (copies your script to `local_config.py`) |
| `.env.example` | Template for local secrets |
