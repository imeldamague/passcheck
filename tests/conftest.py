import pytest

from app.main import create_app, limiter


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,      # CSRF testé séparément
        "DB_PATH": str(tmp_path / "test.db"),
        "SESSION_COOKIE_SECURE": False,
    })
    limiter.reset()
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()
