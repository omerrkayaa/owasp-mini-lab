"""OWASP mini laboratuvarı.

Aynı uygulama iki modda çalışır:
  - vulnerable: dört açık bilerek bırakılmıştır (SQL injection, stored XSS, IDOR, kaba kuvvet)
  - secure: aynı uç noktalar, açıklar kapatılmış hâlde

Her açığın iki hâli yan yana durur; farkı görmek için `if secure:` bloklarına bakın.
YALNIZ YEREL MAKİNEDE ÇALIŞTIRIN. İnternete açmayın.
"""

import secrets
import sqlite3
import time

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

# Kaba kuvvet koruması (secure mod)
MAX_FAILED = 5
LOCK_SECONDS = 15 * 60

USERS = [
    # (kullanıcı adı, parola, rol). admin parolası her çalıştırmada rastgele üretilir.
    ("admin", None, "admin"),
    ("alice", "sunshine", "user"),
    ("bob", "bob123", "user"),
]

PAGE = """<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><title>{{ title }}</title></head>
<body>
<p>Mod: <b>{{ mode }}</b>{% if user %} · Giriş: {{ user }} · <a href="{{ url_for('logout') }}">Çıkış</a>{% endif %}</p>
<h1>{{ title }}</h1>
{{ body }}
</body></html>"""


def create_app(secure=False, db_path=":memory:"):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), SECURE=secure, DB_PATH=db_path)
    if secure:
        app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    # :memory: veritabanı bağlantı kapanınca silinir; bu yüzden tek bağlantıyı açık tutuyoruz.
    keeper = sqlite3.connect(db_path, check_same_thread=False)
    keeper.row_factory = sqlite3.Row
    _init_db(keeper, secure)
    failed_logins = {}  # kullanıcı adı -> (hata sayısı, kilit bitiş zamanı)

    def db():
        return keeper

    def page(title, body):
        return render_template_string(
            PAGE, title=title, body=body, mode="secure" if secure else "vulnerable", user=session.get("username")
        )

    def login_required():
        if "user_id" not in session:
            abort(401)

    @app.after_request
    def security_headers(resp):
        if secure:
            resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @app.route("/")
    def index():
        return page("Ana sayfa", Markup(
            '<ul><li><a href="/login">Giriş</a></li><li><a href="/notes">Notlarım</a></li>'
            '<li><a href="/board">Mesaj panosu</a></li></ul>'
        ))

    # --- 1) SQL injection + 4) kaba kuvvet ---------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return page("Giriş", Markup(
                '<form method="post"><input name="username" placeholder="kullanıcı adı">'
                '<input name="password" type="password" placeholder="parola"><button>Giriş</button></form>'
            ))

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if secure:
            count, locked_until = failed_logins.get(username, (0, 0))
            if locked_until > time.time():
                return page("Giriş", "Çok fazla hatalı deneme. Daha sonra tekrar deneyin."), 429

            # Parametreli sorgu: kullanıcı girdisi SQL'in parçası olmaz, yalnız değer olarak gider.
            row = db().execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
            ok = row is not None and check_password_hash(row["password"], password)
            if not ok:
                count += 1
                failed_logins[username] = (count, time.time() + LOCK_SECONDS if count >= MAX_FAILED else 0)
                return page("Giriş", "Kullanıcı adı ya da parola hatalı."), 401
            failed_logins.pop(username, None)
        else:
            # AÇIK: girdi doğrudan sorguya yapıştırılıyor. ' OR '1'='1' -- ile parola atlanır.
            query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                row = db().execute(query).fetchone()
            except sqlite3.Error as e:
                return page("Giriş", f"Veritabanı hatası: {e}"), 500  # AÇIK: hata ayrıntısı sızdırılıyor
            if row is None:
                return page("Giriş", "Kullanıcı adı ya da parola hatalı."), 401
            # AÇIK: deneme sınırı yok, sınırsız tahmin yapılabilir.

        session.clear()
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        return redirect(url_for("notes"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    # --- 3) IDOR ------------------------------------------------------------
    @app.route("/notes", methods=["GET", "POST"])
    def notes():
        login_required()
        if request.method == "POST":
            db().execute("INSERT INTO notes (owner_id, body) VALUES (?, ?)", (session["user_id"], request.form.get("body", "")))
            db().commit()
        rows = db().execute("SELECT id, body FROM notes WHERE owner_id = ?", (session["user_id"],)).fetchall()
        items = "".join(f'<li><a href="/notes/{r["id"]}">Not #{r["id"]}</a></li>' for r in rows)
        return page("Notlarım", Markup(f"<ul>{items}</ul>"))

    @app.route("/notes/<int:note_id>")
    def note_detail(note_id):
        login_required()
        if secure:
            # Sahiplik kontrolü sorgunun içinde: başkasının notu "yok" gibi görünür (404).
            row = db().execute(
                "SELECT id, body FROM notes WHERE id = ? AND owner_id = ?", (note_id, session["user_id"])
            ).fetchone()
        else:
            # AÇIK: yalnız giriş yapılmış mı diye bakılıyor, not kimin diye bakılmıyor.
            row = db().execute("SELECT id, body FROM notes WHERE id = ?", (note_id,)).fetchone()
        if row is None:
            abort(404)
        return page(f"Not #{row['id']}", row["body"])

    # --- 2) Stored XSS ------------------------------------------------------
    @app.route("/board", methods=["GET", "POST"])
    def board():
        if request.method == "POST":
            login_required()
            db().execute("INSERT INTO messages (author, body) VALUES (?, ?)", (session["username"], request.form.get("body", "")))
            db().commit()
        rows = db().execute("SELECT author, body FROM messages ORDER BY id").fetchall()
        if secure:
            # Jinja2 otomatik kaçışı: <script> metin olarak gösterilir, çalışmaz. CSP ikinci savunma hattı.
            body = render_template_string(
                "<ul>{% for r in rows %}<li><b>{{ r.author }}</b>: {{ r.body }}</li>{% endfor %}</ul>", rows=rows
            )
        else:
            # AÇIK: kullanıcı girdisi HTML olarak sayfaya basılıyor.
            body = "<ul>" + "".join(f"<li><b>{r['author']}</b>: {r['body']}</li>" for r in rows) + "</ul>"
        form = '<form method="post"><input name="body"><button>Gönder</button></form>' if "user_id" in session else ""
        return page("Mesaj panosu", Markup(body + form))

    return app


def _init_db(conn, secure):
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, author TEXT, body TEXT);
        """
    )
    for username, password, role in USERS:
        password = password or secrets.token_urlsafe(16)
        # Secure modda parolalar hash'lenir; vulnerable modda düz metin (bir açık daha).
        stored = generate_password_hash(password) if secure else password
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, stored, role))
    conn.execute("INSERT INTO notes (owner_id, body) VALUES (1, 'Yönetici notu: yedek sunucu şifresi rotasyonda.')")
    conn.execute("INSERT INTO notes (owner_id, body) VALUES (2, 'Alice: doktor randevusu perşembe 14.00')")
    conn.execute("INSERT INTO notes (owner_id, body) VALUES (3, 'Bob: alışveriş listesi')")
    conn.execute("INSERT INTO messages (author, body) VALUES ('alice', 'Panoya hoş geldiniz!')")
    conn.commit()
