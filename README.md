# 🎵 Jewish Music Downloader — Web Edition

A web version of the original command-line Python downloader. It does the
same things — search artists, browse albums, view new releases, and
download tracks — but through a browser instead of the terminal.

The Flask server makes all requests to the music API **server-side**, so
there are no CORS or self-signed-certificate problems, and downloads are
streamed straight to your browser.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Then open <http://localhost:5000> in your browser.

You can change the port:

```bash
PORT=8080 python app.py
```

## Configuration

On first load, click **⚙️ Settings** and fill in:

| Field | What it is |
|-------|-----------|
| **GraphQL API URL** | The `API_URL` from the original script |
| **Audio API Base URL** | The `AUDIO_API_BASE` (download endpoint) from the original script |
| **JWT Token** | Your `USER_TOKEN` |

These are saved only in your browser's `localStorage` — nothing is
hardcoded in the code and nothing is stored on the server.

## Features

- 🔍 **Search** artists by English or Hebrew name (24‑hour local catalog cache)
- 🔥 **New Releases** — the latest 10 albums
- 📂 Browse an artist → albums → tracks
- ⬇️ Download a single track, or 📥 the whole album at once

## How it maps to the original script

| Original CLI function | Web equivalent |
|-----------------------|----------------|
| `fetch_artists()` (+ JSON cache) | `POST /api/artists` (cache under `.cache/`) |
| `fetch_artist_details()` | `POST /api/artist` |
| `fetch_new_releases()` | `POST /api/new` |
| `download_track()` | `GET /api/download` (streamed) |
| terminal menus | the web UI |
