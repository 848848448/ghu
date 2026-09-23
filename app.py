"""
Jewish Music Downloader — Web Edition (Flask backend)

Web version of the original command-line Python downloader.

All private configuration (GraphQL API URL, audio API base URL, JWT token)
is read from environment variables / a local `.env` file that is NEVER
committed to git. The values stay entirely on the server — the browser
never sends or receives the token. You fill in your own `.env`; nobody
else (and no one reading the repo) ever sees your secrets.
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

# Load a local .env file if present (optional dependency).
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # noqa: BLE001
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --------------------------------------------------------------------------- #
# Private configuration — read from the environment / .env (never committed).
# --------------------------------------------------------------------------- #
API_URL = os.environ.get("API_URL", "").strip()
AUDIO_API_BASE = os.environ.get("AUDIO_API_BASE", "").strip()
USER_TOKEN = os.environ.get("USER_TOKEN", "").strip()

CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
CACHE_TTL = 86400  # 24 hours, same as the original script


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _cache_path():
    key = hashlib.sha256((API_URL or "").encode("utf-8")).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"artists_{key}.json")


def graphql(query):
    """Run a GraphQL query and return the parsed JSON (or None on error)."""
    if not API_URL:
        return None
    try:
        response = requests.post(
            API_URL,
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


def fetch_artists(force=False):
    """Fetch all artists, using a local JSON cache (< 24h) to speed things up."""
    cache_file = _cache_path()

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
        data = graphql(query)
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


def fetch_artist_details(artist_id):
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
    data = graphql(query)
    if data:
        return data.get("data", {}).get("artist")
    return None


def fetch_new_releases():
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
    data = graphql(query)
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


@app.route("/api/status")
def api_status():
    """Report ONLY whether each secret is configured — never the values."""
    return jsonify(
        {
            "apiUrl": bool(API_URL),
            "audioBase": bool(AUDIO_API_BASE),
            "token": bool(USER_TOKEN),
            "configured": bool(API_URL and AUDIO_API_BASE and USER_TOKEN),
        }
    )


@app.route("/api/artists", methods=["POST"])
def api_artists():
    if not API_URL:
        return jsonify({"error": "Server not configured. Create a .env file (see README)."}), 400
    force = bool((request.get_json(silent=True) or {}).get("force"))
    artists, from_cache = fetch_artists(force=force)
    if not artists:
        return jsonify({"error": "No artists found. Check API_URL in your .env."}), 502
    return jsonify({"artists": artists, "fromCache": from_cache})


@app.route("/api/artist", methods=["POST"])
def api_artist():
    if not API_URL:
        return jsonify({"error": "Server not configured."}), 400
    artist_id = (request.get_json(silent=True) or {}).get("id")
    if artist_id is None:
        return jsonify({"error": "Missing artist id."}), 400
    details = fetch_artist_details(artist_id)
    if not details:
        return jsonify({"error": "No details found for this artist."}), 502
    return jsonify({"artist": details})


@app.route("/api/new", methods=["POST"])
def api_new():
    if not API_URL:
        return jsonify({"error": "Server not configured."}), 400
    return jsonify({"albums": fetch_new_releases()})


@app.route("/api/download")
def api_download():
    """Stream a track download, adding the server-side token. The browser
    never sees the token."""
    if not AUDIO_API_BASE:
        return jsonify({"error": "Server not configured (AUDIO_API_BASE)."}), 400

    track_id = request.args.get("trackId", "").strip()
    file_path = request.args.get("file", "").strip()
    if not track_id:
        return jsonify({"error": "Missing track id."}), 400

    # Build the filename the same way the original script does.
    filename = file_path.split("/")[-1] if file_path else f"track_{track_id}.mp3"
    if not filename.endswith((".mp3", ".wav", ".m4a")):
        filename += ".mp3"

    full_url = f"{AUDIO_API_BASE}?trackId={track_id}&token={USER_TOKEN}"

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
