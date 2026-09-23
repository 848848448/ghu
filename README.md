# 🎵 Jewish Music Downloader — Web Edition

A web version of the original command-line Python downloader. Search artists,
browse albums, view new releases, and download tracks — all from a browser.

## 🔒 Your private info stays private

Your secrets (API URL, audio URL, JWT token) live **only** in a local
`.env` file that is **never** uploaded to GitHub (it's in `.gitignore`).

- **You** fill in the `.env` file yourself.
- The values stay on the **server** — the token is never sent to the browser.
- Nobody reading the repository ever sees your secrets.

> ⚠️ Never paste your token into a tracked file (like `app.py`) and push it —
> anything committed to GitHub is visible in the repo and its history forever.
> Always keep secrets in `.env`.

## Setup

**1. Install dependencies**

```bash
pip install -r requirements.txt
```

**2. Create your `.env` file** (copy the example and fill it in)

```bash
cp .env.example .env
```

Then open `.env` and add your own values:

```
API_URL=https://.../graphql
AUDIO_API_BASE=https://.../stream
USER_TOKEN=your-jwt-token-here
```

**3. Run**

```bash
python app.py
```

Open <http://localhost:5000>. If the `.env` is filled in, it just works —
no settings to enter in the browser. Change the port with `PORT=8080 python app.py`.

## Features

- 🔍 **Search** artists by English or Hebrew name (24‑hour local catalog cache)
- 🔥 **New Releases** — the latest 10 albums
- 📂 Browse an artist → albums → tracks
- ⬇️ Download a single track, or 📥 the whole album at once

## Deploying (optional)

If you host this somewhere, do **not** commit `.env`. Instead set the same
three values (`API_URL`, `AUDIO_API_BASE`, `USER_TOKEN`) as environment
variables / secrets in your hosting provider (or GitHub Actions secrets).
The app reads from the environment automatically.

## How it maps to the original script

| Original CLI | Web equivalent |
|--------------|----------------|
| `fetch_artists()` (+ JSON cache) | `POST /api/artists` |
| `fetch_artist_details()` | `POST /api/artist` |
| `fetch_new_releases()` | `POST /api/new` |
| `download_track()` | `GET /api/download` (streamed, token added server-side) |
| terminal menus | the web UI |
| `API_URL` / `AUDIO_API_BASE` / `USER_TOKEN` constants | `.env` file |
