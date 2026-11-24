"""Accès SQLite : requêtes paramétrées uniquement (aucune concaténation SQL)."""

import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"], timeout=5)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app) -> None:
    path = Path(app.config["DB_PATH"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA journal_mode = WAL")  # lectures/écritures concurrentes
        conn.executescript(SCHEMA)
    app.teardown_appcontext(close_db)


def get_user(username: str):
    return get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def create_user(username: str, password_hash: str) -> bool:
    """Crée l'utilisateur ; False si l'identifiant existe déjà."""
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def update_hash(user_id: int, password_hash: str) -> None:
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (password_hash, user_id))
    db.commit()


def healthy() -> bool:
    try:
        get_db().execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False
