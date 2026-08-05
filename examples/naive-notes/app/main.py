"""
MyNotes — simple note app (student-style).
Not designed for security: plaintext passwords, hardcoded secret key, debug on.
Uses parameterized SQL (no deliberate injection).
"""

import sqlite3
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, session, url_for

BASE = Path(__file__).resolve().parent.parent
DB_PATH = BASE / "mynotes.db"

app = Flask(__name__, template_folder=str(BASE / "templates"))
# typical beginner: secret written directly in source
app.secret_key = "mynotes-student-project-key"
app.config["DEBUG"] = True


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()
    db.close()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    notes = db.execute(
        "SELECT id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("index.html", notes=notes, username=session.get("username"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "Thiếu username hoặc password"
        else:
            db = get_db()
            try:
                # plaintext password — no hash / no salt
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password),
                )
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Username đã tồn tại"
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        # compare plaintext
        if row and row["password"] == password:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            return redirect(url_for("index"))
        error = "Sai tài khoản hoặc mật khẩu"
    return render_template("login.html", error=error)


@app.route("/notes/new", methods=["POST"])
def new_note():
    if "user_id" not in session:
        return redirect(url_for("login"))
    title = request.form.get("title", "Untitled")
    body = request.form.get("body", "")
    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
        (session["user_id"], title, body),
    )
    db.commit()
    return redirect(url_for("index"))


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id: int):
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    db.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    )
    db.commit()
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5055, debug=True)
