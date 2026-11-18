import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.app import create_app  # noqa: E402


def client():
    return create_app().test_client()


def test_index_and_health():
    c = client()
    assert c.get("/").status_code == 200
    h = c.get("/health").get_json()
    assert h["status"] == "ok"


def test_api_single():
    r = client().post("/api/analyze", json={"url": "http://paypa1-login.secure.example.xyz/verify"})
    j = r.get_json()
    assert r.status_code == 200 and j["risk"] in ("MEDIUM", "HIGH") and j["findings"]


def test_api_batch_and_limits():
    c = client()
    assert len(c.post("/api/analyze", json={"urls": ["a.com", "b.com"]}).get_json()["results"]) == 2
    assert c.post("/api/analyze", json={"urls": ["x.com"] * 101}).status_code == 400
    assert c.post("/api/analyze", json={}).status_code == 400
    assert c.post("/api/analyze", data="notjson").status_code == 400


def test_form_escapes_html():
    r = client().post("/analyze", data={"url": "http://x.com/<script>alert(1)</script>"})
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and "<script>alert(1)</script>" not in body


def test_invalid_url_via_form():
    r = client().post("/analyze", data={"url": "http://"})
    assert "No hostname found" in r.get_data(as_text=True)
