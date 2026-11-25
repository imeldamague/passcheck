import re
import sqlite3

from app.main import create_app

STRONG = "Zx9!kq#Lm2@vTr"


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json["status"] == "ok"


def test_security_headers(client):
    h = client.get("/").headers
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"


def test_password_form_is_masked(client):
    html = client.get("/password").data.decode()
    assert 'type="password"' in html and "localhost" not in html


def test_password_check(client):
    r = client.post("/password", data={"password": "123456"})
    assert "500 worst passwords" in r.data.decode()
    r = client.post("/password", data={"password": STRONG})
    assert "ne figure pas" in r.data.decode()
    assert STRONG not in r.data.decode()   # jamais renvoyé


def test_register_login_logout(client, app):
    r = client.post("/register", data={"username": "alice", "password": STRONG,
                                       "confirm": STRONG})
    assert r.status_code == 302
    with sqlite3.connect(app.config["DB_PATH"]) as c:
        stored = c.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$argon2id$") and STRONG not in stored
    r = client.post("/login", data={"username": "alice", "password": STRONG})
    assert r.status_code == 302 and r.headers["Location"].endswith("/account")
    assert "alice" in client.get("/account").data.decode()
    client.post("/logout")
    assert client.get("/account").status_code == 302


def test_register_rejects_weak_and_duplicate(client):
    r = client.post("/register", data={"username": "bob", "password": "password",
                                       "confirm": "password"})
    assert r.status_code == 400
    client.post("/register", data={"username": "bob", "password": STRONG, "confirm": STRONG})
    r = client.post("/register", data={"username": "BOB", "password": STRONG, "confirm": STRONG})
    assert r.status_code == 400


def test_login_generic_error(client):
    client.post("/register", data={"username": "carol", "password": STRONG, "confirm": STRONG})
    client.get("/login")                    # consomme le message flash
    a = client.post("/login", data={"username": "carol", "password": "wrong"})
    b = client.post("/login", data={"username": "nobody", "password": "wrong"})
    assert a.status_code == b.status_code == 401
    strip = re.compile(rb'name="csrf_token" value="[^"]+"')  # jeton horodaté
    assert strip.sub(b"", a.data) == strip.sub(b"", b.data)  # pas d'énumération


def test_sql_injection_attempt(client):
    r = client.post("/login", data={"username": "' OR '1'='1", "password": "x"})
    assert r.status_code == 401


def test_login_rate_limited(client):
    codes = [client.post("/login", data={"username": "x", "password": "y"}).status_code
             for _ in range(7)]
    assert 429 in codes


def test_csrf_enforced(tmp_path):
    app = create_app({"TESTING": True, "DB_PATH": str(tmp_path / "c.db")})
    r = app.test_client().post("/password", data={"password": "123456"})
    assert r.status_code == 400


def test_payload_too_large(client):
    r = client.post("/password", data={"password": "a" * 20000})
    assert r.status_code == 413


def test_production_requires_secret_key(monkeypatch):
    import pytest
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app()


def test_login_rejects_overlong_password(client):
    password = "Zx9!" * 32

    response = client.post("/register", data={
        "username": "audituser",
        "password": password,
        "confirm": password,
    })
    assert response.status_code == 302

    response = client.post("/login", data={
        "username": "audituser",
        "password": password + "extra",
    })
    assert response.status_code == 401

    with client.session_transaction() as session:
        assert "user" not in session

    response = client.post("/login", data={
        "username": "audituser",
        "password": password,
    })
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/account")


def _https_form(client, path):
    html = client.get(path, base_url="https://passcheck.test").data.decode()
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_https_forms_work_with_csrf(tmp_path):
    """Régression : en HTTPS, Flask-WTF exige un Referer de même origine."""
    app = create_app({"TESTING": True, "DB_PATH": str(tmp_path / "h.db")})
    client = app.test_client()
    assert client.get("/").headers["Referrer-Policy"] == "same-origin"
    same_origin = {"Referer": "https://passcheck.test/register"}
    r = client.post("/register", base_url="https://passcheck.test", headers=same_origin,
                    data={"csrf_token": _https_form(client, "/register"),
                          "username": "alice", "password": STRONG, "confirm": STRONG})
    assert r.status_code == 302


def test_https_cross_site_post_rejected(tmp_path):
    """Un formulaire posté depuis un autre site est refusé."""
    app = create_app({"TESTING": True, "DB_PATH": str(tmp_path / "x.db")})
    client = app.test_client()
    r = client.post("/password", base_url="https://passcheck.test",
                    headers={"Referer": "https://evil.example/attack"},
                    data={"csrf_token": _https_form(client, "/password"), "password": "x"})
    assert r.status_code == 400
