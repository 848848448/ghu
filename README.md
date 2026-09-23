# 🎵 Jewish Music Downloader — Web Edition

A web version of the original command-line Python downloader. Search artists,
browse albums, view new releases, and download tracks — all from a browser.

## 🔒 Your private info stays private

Your secrets (API URL, audio URL, JWT token) stay in **one local file on
your own computer** that is **never** uploaded to GitHub. Only the website
code goes to GitHub — your secrets never do, so **nobody else (not even the
author of this code) ever sees them.**

> ⚠️ **Important:** Do NOT paste your token into a file you upload to GitHub
> (like `app.py`) and push it. Anything committed to GitHub is visible in the
> repository and its history forever. Keep secrets only in the local file
> below, which is git-ignored.

## Setup — the easy way (use your existing script)

You already have your original script with your info filled in. You don't
have to change it.

**1. Install dependencies**

```bash
pip install -r requirements.txt
```

**2. Point it at your script** (runs on your computer — your info is not sent anywhere)

```bash
python configure.py
```

It asks for the path to your original script and copies it in as
`local_config.py`. That file is git-ignored, so it is **never uploaded to
GitHub**. (You can also just copy your script into this folder and rename it
to `local_config.py` yourself — same result.)

**3. Run**

```bash
python app.py
```

Open <http://localhost:5000>. It reads `API_URL`, `AUDIO_API_BASE` and
`USER_TOKEN` straight from your script and just works — nothing to type in
the browser. Change the port with `PORT=8080 python app.py`.

### Alternative: a `.env` file

If you prefer, instead of `local_config.py` you can create a `.env` file
(also git-ignored):

```bash
cp .env.example .env
```

```
API_URL=https://.../graphql
AUDIO_API_BASE=https://.../stream
USER_TOKEN=your-jwt-token-here
```

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
| `API_URL` / `AUDIO_API_BASE` / `USER_TOKEN` constants | `local_config.py` (your script) or `.env` |
