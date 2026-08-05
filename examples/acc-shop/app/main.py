"""
AccMarket — shop bán account game (INTENTIONAL VULNERABILITIES for SecureCode Copilot demo).
DO NOT deploy to production.
"""

import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)
app.secret_key = "dev-secret-key-not-for-prod"

# Hardcoded credentials / payment secret
ADMIN_PASSWORD = "Admin@123456"
STRIPE_SECRET = "sk_live_accmarket_demo_secret_key_xyz"

DB = "accmarket.db"


def get_db():
    return sqlite3.connect(DB)


@app.route("/")
def home():
    return render_template_string(
        """
        <h1>AccMarket</h1>
        <p>Mua account Liên Quân / Free Fire giá rẻ</p>
        <a href="/login">Đăng nhập</a> | <a href="/register">Đăng ký</a> | <a href="/shop">Shop</a>
        """
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # SQL Injection — string concat
        conn = get_db()
        cur = conn.cursor()
        query = f"INSERT INTO users(username, password) VALUES ('{username}', '{password}')"
        cur.execute(query)
        conn.commit()
        conn.close()
        return redirect("/login")
    return render_template_string(
        """
        <h2>Đăng ký</h2>
        <form method="post">
          <input name="username" placeholder="user"/>
          <input name="password" type="password" placeholder="pass"/>
          <button>Register</button>
        </form>
        """
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        # SQL Injection login
        sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
        cur.execute(sql)
        row = cur.fetchone()
        conn.close()
        if row:
            session["user"] = username
            # Reflected XSS welcome
            return f"<h2>Xin chào {username}</h2><a href='/shop'>Vào shop</a>"
        return "Sai tài khoản"
    return render_template_string(
        """
        <h2>Đăng nhập</h2>
        <form method="post">
          <input name="username"/>
          <input name="password" type="password"/>
          <button>Login</button>
        </form>
        """
    )


@app.route("/shop")
def shop():
    q = request.args.get("q", "")
    # XSS search
    html = f"<h2>Shop Acc</h2><p>Kết quả tìm: {q}</p>"
    conn = get_db()
    cur = conn.cursor()
    # SQL Injection search
    cur.execute(f"SELECT id, title, price FROM products WHERE title LIKE '%{q}%'")
    items = cur.fetchall()
    conn.close()
    for it in items:
        html += f"<div>{it[1]} — {it[2]}đ <a href='/buy?id={it[0]}'>Mua</a></div>"
    return html


@app.route("/buy")
def buy():
    pid = request.args.get("id", "")
    # Command Injection — ping "provider" check
    provider = request.args.get("provider", "localhost")
    os.system("ping -n 1 " + provider)
    return f"Đã đặt mua product #{pid}. Provider checked."


@app.route("/admin/backup")
def backup():
    # Path traversal via filename
    name = request.args.get("file", "users.db")
    with open("/data/backups/" + name, "rb") as f:
        data = f.read()
    return data


@app.route("/admin/import", methods=["POST"])
def import_session():
    # Insecure deserialization
    blob = request.files["session"].read()
    obj = pickle.loads(blob)
    return str(obj)


@app.route("/admin/calc")
def calc():
    # Dangerous eval
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


@app.route("/admin/shell")
def shell():
    cmd = request.args.get("cmd", "dir")
    subprocess.call(cmd, shell=True)
    return "ok"


if __name__ == "__main__":
    app.run(debug=True, port=5055)
