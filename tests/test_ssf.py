import pytest

from ssf.app import create_app
from ssf.secrets_detector import scan_text

KEY = "test-admin-key"


@pytest.fixture
def client(tmp_path):
    (tmp_path / "bad.py").write_text('import os\neval(input())\npassword = "Zx9$kQ2!vLm8"\n')
    app = create_app({"db_path": ":memory:", "scan_root": str(tmp_path), "admin_key": KEY,
                      "external_tools": False})
    return app.test_client()


def h(key=KEY):
    return {"X-API-Key": key}


def test_secret_detection_redacts():
    f = scan_text("k = 'AKIAABCDEFGHIJKLMNOP'\nx = 'AKIAABCDEFGHIJKLMNOP'")
    assert f and "ABCDEFGHIJKLMNOP" not in str(f)


def test_auth_required(client):
    assert client.get("/api/threats/status").status_code == 401
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 200


def test_scan_and_report(client):
    r = client.post("/api/scan", json={"path": "."}, headers=h())
    assert r.status_code == 201 and r.json["vulnerabilities"] >= 1 and r.json["secrets"] >= 1
    rep = client.get("/api/reports?format=html", headers=h())
    assert b"SSF-PY001" in rep.data
    assert client.get("/api/reports", headers=h()).json["score"] < 100


def test_path_traversal_blocked(client):
    assert client.post("/api/scan", json={"path": "../.."}, headers=h()).status_code == 400


def test_rbac(client):
    r = client.post("/api/access/users", json={"name": "bob", "role": "viewer"}, headers=h())
    bob = r.json["api_key"]
    assert client.get("/api/threats/status", headers=h(bob)).status_code == 200
    assert client.post("/api/scan", json={}, headers=h(bob)).status_code == 403
    assert client.get("/api/access/audit", headers=h()).json


def test_bruteforce_detection(client):
    for _ in range(5):
        r = client.post("/api/threats/events", json={"source": "1.2.3.4", "type": "login_failed"}, headers=h())
    assert any(d["threat"] == "Brute Force" for d in r.json["detections"])
    r = client.post("/api/threats/events", json={"payload": "id=1' OR 1=1"}, headers=h())
    assert r.json["detections"][0]["threat"] == "SQL Injection"
