"""Flask web app + JSON API for PhishGuard.

Run:  python app/app.py        then open http://127.0.0.1:5000

The app only analyses the URL *text*. It never visits the URL, so it cannot be
used for server-side request forgery and cannot be harmed by a malicious site.
"""

import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phishguard import __version__  # noqa: E402
from phishguard.detector import analyze  # noqa: E402
from phishguard.model import load_model  # noqa: E402

MAX_BATCH = 100


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # 256 KB request limit

    @app.get("/")
    def index():
        return render_template("index.html", version=__version__)

    @app.post("/analyze")
    def analyze_form():
        url = request.form.get("url", "")
        return render_template("index.html", version=__version__,
                               result=analyze(url), submitted=url)

    @app.post("/api/analyze")
    def api_analyze():
        data = request.get_json(silent=True) or {}
        if "urls" in data:
            urls = data["urls"]
            if not isinstance(urls, list) or len(urls) > MAX_BATCH:
                return jsonify(error=f"'urls' must be a list of at most {MAX_BATCH}"), 400
            return jsonify(results=[analyze(str(u)) for u in urls])
        url = data.get("url")
        if not isinstance(url, str):
            return jsonify(error="Send JSON like {\"url\": \"http://example.com\"}"), 400
        return jsonify(analyze(url))

    @app.get("/health")
    def health():
        return jsonify(status="ok", version=__version__, model_loaded=load_model() is not None)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
