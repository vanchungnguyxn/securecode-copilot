"""TicketChannel — simple event ticket booking site."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for

BASE = Path(__file__).resolve().parent
DB = BASE / "tickets.db"

app = Flask(__name__)
app.secret_key = "ticket-channel-local"


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            venue TEXT NOT NULL,
            event_date TEXT NOT NULL,
            price INTEGER NOT NULL,
            seats_left INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY,
            event_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            email TEXT NOT NULL,
            qty INTEGER NOT NULL,
            FOREIGN KEY(event_id) REFERENCES events(id)
        );
        """
    )
    n = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    if n == 0:
        conn.executemany(
            "INSERT INTO events (title, venue, event_date, price, seats_left) VALUES (?,?,?,?,?)",
            [
                ("Hòa nhạc mùa hè", "Nhà hát lớn", "2026-09-12 19:30", 350000, 120),
                ("Tech Meetup HN", "CSE Space", "2026-08-20 18:00", 0, 80),
                ("Stand-up comedy", "Cine Star", "2026-08-28 20:00", 220000, 60),
            ],
        )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    conn = db()
    events = conn.execute(
        "SELECT * FROM events ORDER BY event_date"
    ).fetchall()
    conn.close()
    return render_template("index.html", events=events)


@app.route("/event/<int:event_id>")
def event_detail(event_id: int):
    conn = db()
    event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    if not event:
        flash("Không tìm thấy sự kiện")
        return redirect(url_for("index"))
    return render_template("detail.html", event=event)


@app.route("/book/<int:event_id>", methods=["POST"])
def book(event_id: int):
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    qty = int(request.form.get("qty") or "1")
    if not name or not email or qty < 1:
        flash("Vui lòng điền đủ thông tin")
        return redirect(url_for("event_detail", event_id=event_id))

    conn = db()
    event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event:
        conn.close()
        flash("Sự kiện không tồn tại")
        return redirect(url_for("index"))
    if event["seats_left"] < qty:
        conn.close()
        flash("Không đủ ghế trống")
        return redirect(url_for("event_detail", event_id=event_id))

    conn.execute(
        "INSERT INTO bookings (event_id, customer_name, email, qty) VALUES (?,?,?,?)",
        (event_id, name, email, qty),
    )
    conn.execute(
        "UPDATE events SET seats_left = seats_left - ? WHERE id = ?",
        (qty, event_id),
    )
    conn.commit()
    conn.close()
    flash(f"Đã đặt {qty} vé cho {event['title']}")
    return redirect(url_for("thanks", email=email))


@app.route("/thanks")
def thanks():
    email = request.args.get("email", "")
    conn = db()
    rows = conn.execute(
        """
        SELECT b.id, b.qty, b.customer_name, e.title, e.event_date, e.venue
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        WHERE b.email = ?
        ORDER BY b.id DESC
        """,
        (email,),
    ).fetchall()
    conn.close()
    return render_template("thanks.html", email=email, bookings=rows)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5080, debug=True)
