import os

DB_FILE = "test_aidatacheck.db"
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)
os.environ["DATABASE_URL"] = f"sqlite:///./{DB_FILE}"

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

client = TestClient(app)

USER = {
    "first_name": "Иван",
    "last_name": "Иванов",
    "username": "ivan",
    "email": "ivanov@example.com",
    "password": "12345678",
    "status": "basic",
}


def test_full_flow():
    r = client.post("/auth/register/", json=USER)
    assert r.status_code == 200, r.text

    assert client.post("/auth/register/", json=USER).status_code == 400

    r = client.post("/auth/login/", json={"username": "ivan", "password": "wrongpass"})
    assert r.status_code == 401

    r = client.post("/auth/login/", json={"username": "ivan", "password": "12345678"})
    assert r.status_code == 200, r.text
    tokens = r.json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}

    assert client.get("/auth/verify/", headers=h).status_code == 200
    assert client.get("/auth/verify/").status_code in (401, 403)

    r = client.get("/auth/me/", headers=h)
    assert r.status_code == 200 and r.json()["username"] == "ivan"
    assert "password" not in r.json()

    r = client.put("/auth/me/update/", headers=h, json={"first_name": "Пётр", "status": "pro"})
    assert r.status_code == 200
    assert r.json()["first_name"] == "Пётр" and r.json()["status"] == "pro"

    r = client.post("/auth/refresh/", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200 and "access_token" in r.json()

    r = client.post("/auth/refresh/", json={"refresh_token": tokens["access_token"]})
    assert r.status_code == 401

    r = client.post("/auth/logout/", headers=h, json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200

    r = client.post("/auth/refresh/", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401

    assert client.delete("/auth/me/delete/", headers=h).status_code == 200
    assert client.get("/auth/me/", headers=h).status_code == 401
