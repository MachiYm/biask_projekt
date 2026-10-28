"""
BEZPEČNÁ verzia tej istej aplikácie — správca produktov s loginom.

Rozdiely oproti zraniteľnej verzii:
  1. Všetky SQL dotazy používajú PARAMETRIZOVANÉ dotazy (? placeholdery),
     takže vstup používateľa sa nikdy nevloží priamo do SQL reťazca.
  2. Heslá sú uložené ako HASH (werkzeug.security), nie v otvorenom tvare.
  3. Základná VALIDÁCIA vstupu (dĺžka, povolené znaky).
"""

import os
import re
import sqlite3

from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "secure.db")

app = Flask(__name__)
app.secret_key = "demo-nepouzivajte-v-produkcii"

# Povolené znaky v používateľskom mene (jednoduchá validácia).
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Vytvorí tabuľky a naplní ich testovacími dátami (reprodukovateľne)."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role     TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT NOT NULL,
            price       REAL NOT NULL
        )
        """
    )

    # Rovnaké účty ako v zraniteľnej verzii, ale heslá sú HASHOVANÉ.
    users = [
        ("admin", "SuperTajneHeslo123", "admin"),
        ("jnovak", "jano2024", "user"),
        ("mkovac", "macka.*", "user"),
    ]
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [(u, generate_password_hash(p), r) for (u, p, r) in users],
    )

    cur.executemany(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        [
            ("Klávesnica K1", "Mechanická klávesnica", 59.90),
            ("Myš M2", "Bezdrôtová myš", 24.50),
            ("Monitor 24\"", "FullHD IPS monitor", 149.00),
            ("USB kábel", "USB-C kábel 1m", 7.90),
        ],
    )

    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 1) VALIDÁCIA vstupu — nepovolené meno rovno odmietneme.
        if not USERNAME_RE.match(username):
            error = "Neplatné používateľské meno (povolené: písmená, číslice, . _ -)."
            return render_template("login.html", error=error)

        # 2) PARAMETRIZOVANÝ dotaz — vstup ide ako parameter, nie do reťazca.
        #    Vyhľadáme len podľa mena, heslo overíme hashom v Pythone.
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        # 3) Overenie hesla cez bezpečné porovnanie hashu.
        if row and check_password_hash(row["password"], password):
            session["user"] = row["username"]
            return redirect(url_for("index"))
        else:
            error = "Nesprávne meno alebo heslo."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


@app.route("/products")
def products():
    search = request.args.get("search", "")
    rows = []

    conn = get_db()
    if search:
        # PARAMETRIZOVANÝ dotaz aj pri LIKE — placeholder ? a wildcard v hodnote.
        rows = conn.execute(
            "SELECT id, name, description, price FROM products WHERE name LIKE ?",
            (f"%{search}%",),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, name, description, price FROM products"
        ).fetchall()
    conn.close()

    return render_template(
        "products.html",
        rows=rows,
        search=search,
        user=session.get("user"),
    )


if __name__ == "__main__":
    init_db()
    print("BEZPEČNÁ appka beží na http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
