"""Application Flask : vérification de mots de passe + comptes utilisateurs.

Lancement en production : gunicorn "app.main:create_app()"
"""

import logging
import os
import re
import secrets

from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db, passwords

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

csrf = CSRFProtect()
limiter = Limiter(get_remote_address, default_limits=["120 per minute"],
                  storage_uri="memory://")
log = logging.getLogger("passcheck")


def _secret_key(env: str) -> str:
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    if env == "production":
        # Refus de démarrer sans secret : jamais de clé par défaut en prod.
        raise RuntimeError("SECRET_KEY doit être défini en production")
    log.warning("SECRET_KEY absent : clé aléatoire (développement uniquement)")
    return secrets.token_hex(32)


def create_app(test_config=None) -> Flask:
    app = Flask(__name__)
    env = os.environ.get("APP_ENV", "production")
    app.config.update(
        SECRET_KEY=_secret_key(env) if not test_config else "test",
        DB_PATH=os.environ.get("DB_PATH", "/data/app.db"),
        MAX_CONTENT_LENGTH=16 * 1024,          # requêtes > 16 Ko rejetées
        SESSION_COOKIE_HTTPONLY=True,          # cookie inaccessible au JS
        SESSION_COOKIE_SAMESITE="Lax",         # limite le CSRF inter-site
        SESSION_COOKIE_SECURE=env == "production",  # HTTPS uniquement
        PERMANENT_SESSION_LIFETIME=1800,       # 30 min
        WTF_CSRF_TIME_LIMIT=3600,
    )
    if test_config:
        app.config.update(test_config)

    # Derrière le reverse proxy Caddy : vraie IP client pour le rate limiting
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    csrf.init_app(app)
    limiter.init_app(app)
    db.init_db(app)
    _register_routes(app)
    _register_security_headers(app)
    _register_errors(app)
    return app


def _register_routes(app: Flask) -> None:

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    @limiter.exempt
    def health():
        ok = db.healthy()
        return jsonify(status="ok" if ok else "degraded"), 200 if ok else 503

    @app.route("/password", methods=["GET", "POST"])
    @limiter.limit("20 per minute", methods=["POST"])
    def password():
        if request.method == "POST":
            pwd = request.form.get("password", "")
            if not pwd or len(pwd) > passwords.MAX_LENGTH:
                return render_template("password.html",
                                       error="Saisie invalide."), 400
            found = passwords.find_in_wordlists(pwd)
            # Le mot de passe n'est jamais journalisé ni renvoyé dans la page.
            return render_template("result.html", found=found,
                                   strong=len(pwd) >= passwords.MIN_LENGTH)
        return render_template("password.html")

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            pwd = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            errors = []
            if not USERNAME_RE.fullmatch(username):
                errors.append("Identifiant : 3 à 32 caractères "
                              "(lettres, chiffres, . _ -).")
            if pwd != confirm:
                errors.append("Les mots de passe ne correspondent pas.")
            errors += passwords.policy_errors(pwd, username)
            if not errors:
                if db.create_user(username, passwords.hash_password(pwd)):
                    log.info("Compte créé : %s", username)
                    flash("Compte créé. Vous pouvez vous connecter.")
                    return redirect(url_for("login"))
                errors.append("Inscription impossible avec cet identifiant.")
            return render_template("register.html", errors=errors,
                                   username=username), 400
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])  # anti brute force
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            pwd = request.form.get("password", "")[:passwords.MAX_LENGTH]
            user = db.get_user(username) if USERNAME_RE.fullmatch(username) \
                else None
            stored = user["password_hash"] if user else None
            if passwords.verify_password(stored, pwd):
                if passwords.needs_rehash(stored):
                    db.update_hash(user["id"], passwords.hash_password(pwd))
                session.clear()  # nouvelle session : anti fixation de session
                session["user"] = user["username"]
                session.permanent = True
                log.info("Connexion réussie : %s", user["username"])
                return redirect(url_for("account"))
            log.warning("Échec de connexion depuis %s",
                        get_remote_address())
            # Message générique : ne révèle pas si le compte existe
            return render_template("login.html",
                                   error="Identifiants invalides."), 401
        return render_template("login.html")

    @app.get("/account")
    def account():
        if "user" not in session:
            return redirect(url_for("login"))
        return render_template("account.html", user=session["user"])

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'none'; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()")
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers.pop("Server", None)
        return resp


def _register_errors(app: Flask) -> None:
    def page(code, message):
        return render_template("error.html", code=code, message=message), code

    app.register_error_handler(400, lambda e: page(400, "Requête invalide."))
    app.register_error_handler(404, lambda e: page(404, "Page introuvable."))
    app.register_error_handler(413, lambda e: page(413, "Requête trop volumineuse."))
    app.register_error_handler(
        429, lambda e: page(429, "Trop de tentatives. Réessayez plus tard."))
    app.register_error_handler(500, lambda e: page(500, "Erreur interne."))
