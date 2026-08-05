"""
SimpleCMS — public site + admin content editor.
Straightforward student/vibe style: works first, minimal config.
"""

from __future__ import annotations

import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "cms.db"

app = Flask(__name__)
# local demo: keep a default so app starts without .env
app.secret_key = os.environ.get("SECRET_KEY", "simple-cms-local-dev-key")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    cur = conn.execute("SELECT COUNT(*) AS n FROM users")
    if cur.fetchone()["n"] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123")),
        )
    cur = conn.execute("SELECT COUNT(*) AS n FROM pages")
    if cur.fetchone()["n"] == 0:
        conn.execute(
            "INSERT INTO pages (slug, title, body) VALUES (?, ?, ?)",
            (
                "home",
                "Green Leaf Studio",
                "Chào mừng đến studio nhỏ của chúng tôi. "
                "Thiết kế nhận diện thương hiệu và landing page gọn nhẹ.",
            ),
        )
        conn.execute(
            "INSERT INTO pages (slug, title, body) VALUES (?, ?, ?)",
            (
                "about",
                "Về chúng tôi",
                "Đội ngũ 2 người làm design & frontend. Liên hệ qua form trên trang.",
            ),
        )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def home():
    conn = get_db()
    page = conn.execute("SELECT * FROM pages WHERE slug = ?", ("home",)).fetchone()
    about = conn.execute("SELECT * FROM pages WHERE slug = ?", ("about",)).fetchone()
    conn.close()
    return render_template("home.html", page=page, about=about)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("admin_dashboard"))
        error = "Sai tài khoản hoặc mật khẩu"
    return render_template("admin_login.html", error=error)


@app.route("/admin")
@login_required
def admin_dashboard():
    conn = get_db()
    pages = conn.execute("SELECT id, slug, title FROM pages ORDER BY id").fetchall()
    conn.close()
    return render_template("admin_dashboard.html", pages=pages, username=session.get("username"))


@app.route("/admin/edit/<slug>", methods=["GET", "POST"])
@login_required
def admin_edit(slug: str):
    conn = get_db()
    page = conn.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
    if not page:
        conn.close()
        flash("Không tìm thấy trang")
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        title = request.form.get("title", "").strip() or page["title"]
        body = request.form.get("body", "")
        conn.execute(
            "UPDATE pages SET title = ?, body = ? WHERE slug = ?",
            (title, body, slug),
        )
        conn.commit()
        conn.close()
        flash("Đã lưu thay đổi")
        return redirect(url_for("admin_edit", slug=slug))
    conn.close()
    return render_template("admin_edit.html", page=page)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5070, debug=True)
