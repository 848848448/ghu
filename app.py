"""
Jewish Music Downloader — Web Edition (Flask backend)

This is a web version of the original command-line Python downloader.
The server talks to the GraphQL music API (server-side, so self-signed
certificates and CORS are not a problem) and streams downloads back to
the browser.

The API URL, audio base URL and JWT token are provided by the user in the
web UI (stored in the browser's localStorage) and sent with each request,
so no secrets are hardcoded here.
"""

import hashlib
import json
import os
import time

import requests
import urllib3
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    stream_with_context,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
CACHE_TTL = 86400  # 24 hours, same as the original script


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _cache_path(api_url):
    """A cache file per API URL, so different servers don't collide."""
    key = hashlib.sha256((api_url or "").encode("utf-8")).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"artists_{key}.json")


def graphql(api_url, query):
    """Run a GraphQL query and return the parsed JSON (or None on error)."""
    if not api_url:
        return None
    try:
        response = requests.post(
            api_url,
            json={"query": query},
            verify=False,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if response.status_code == 200:
            return response.json()
    except Exception as exc:  # noqa: BLE001
        print("GraphQL error:", exc)
    return None


def fetch_artists(api_url, force=False):
    """Fetch all artists, using a local JSON cache (< 24h) to speed things up."""
    cache_file = _cache_path(api_url)

    if not force and os.path.exists(cache_file):
        if time.time() - os.path.getmtime(cache_file) < CACHE_TTL:
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    if cached:
                        return cached, True  # (data, from_cache)
            except Exception:  # noqa: BLE001
                pass

    all_artists = []
    skip = 0
    batch_size = 500

    while True:
        query = f"""
        query {{
          artists(skip: {skip}, take: {batch_size}) {{
            id
            enName
            heName
          }}
        }}
        """
        data = graphql(api_url, query)
        if not data or "errors" in data:
            break

        batch = data.get("data", {}).get("artists", [])
        if not batch:
            break

        all_artists.extend(batch)

        if len(batch) < batch_size:
            break
        skip += batch_size

    if all_artists:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(all_artists, f, ensure_ascii=False)
        except Exception:  # noqa: BLE001
            pass

    return all_artists, False


def fetch_artist_details(api_url, artist_id):
    query = f"""
    query {{
      artist(where: {{ id: {int(artist_id)} }}) {{
        id
        enName
        heName
        albums {{
          id
          enName
          tracks {{
            id
            file
          }}
        }}
      }}
    }}
    """
    data = graphql(api_url, query)
    if data:
        return data.get("data", {}).get("artist")
    return None


def fetch_new_releases(api_url):
    query = """
    query {
      albums(take: 50) {
        id
        enName
        artists {
          enName
        }
        tracks {
          id
          file
        }
      }
    }
    """
    data = graphql(api_url, query)
    if not data or "errors" in data:
        return []
    albums = data.get("data", {}).get("albums", [])
    if albums:
        return sorted(albums, key=lambda x: int(x.get("id", 0)), reverse=True)[:10]
    return []


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/artists", methods=["POST"])
def api_artists():
    body = request.get_json(silent=True) or {}
    api_url = body.get("apiUrl", "").strip()
    force = bool(body.get("force"))
    if not api_url:
        return jsonify({"error": "Missing API URL. Open Settings and add it."}), 400

    artists, from_cache = fetch_artists(api_url, force=force)
    if not artists:
        return jsonify({"error": "No artists found. Check the API URL."}), 502
    return jsonify({"artists": artists, "fromCache": from_cache})


@app.route("/api/artist", methods=["POST"])
def api_artist():
    body = request.get_json(silent=True) or {}
    api_url = body.get("apiUrl", "").strip()
    artist_id = body.get("id")
    if not api_url or artist_id is None:
        return jsonify({"error": "Missing API URL or artist id."}), 400

    details = fetch_artist_details(api_url, artist_id)
    if not details:
        return jsonify({"error": "No details found for this artist."}), 502
    return jsonify({"artist": details})


@app.route("/api/new", methods=["POST"])
def api_new():
    body = request.get_json(silent=True) or {}
    api_url = body.get("apiUrl", "").strip()
    if not api_url:
        return jsonify({"error": "Missing API URL."}), 400

    albums = fetch_new_releases(api_url)
    return jsonify({"albums": albums})


@app.route("/api/download")
def api_download():
    """Stream a track download from the audio API back to the browser."""
    audio_base = request.args.get("audioBase", "").strip()
    token = request.args.get("token", "").strip()
    track_id = request.args.get("trackId", "").strip()
    file_path = request.args.get("file", "").strip()

    if not audio_base or not track_id:
        return jsonify({"error": "Missing audio base URL or track id."}), 400

    # Build the filename the same way the original script does.
    filename = file_path.split("/")[-1] if file_path else f"track_{track_id}.mp3"
    if not filename.endswith((".mp3", ".wav", ".m4a")):
        filename += ".mp3"

    full_url = f"{audio_base}?trackId={track_id}&token={token}"

    try:
        upstream = requests.get(full_url, verify=False, stream=True, timeout=60)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Download error: {exc}"}), 502

    if upstream.status_code == 403:
        return jsonify({"error": "Access Denied (403). Your JWT token may have expired."}), 403
    if upstream.status_code != 200:
        return jsonify({"error": f"Server returned code {upstream.status_code}."}), 502

    content_type = upstream.headers.get("Content-Type", "audio/mpeg")

    def generate():
        for chunk in upstream.iter_content(chunk_size=8192):
            if chunk:
                yield chunk

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": content_type,
    }
    if upstream.headers.get("Content-Length"):
        headers["Content-Length"] = upstream.headers["Content-Length"]

    return Response(stream_with_context(generate()), headers=headers)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
