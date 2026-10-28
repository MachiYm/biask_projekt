"""
ZRANITEĽNÁ verzia aplikácie — správca produktov s loginom.

!!! POZOR: Tento kód je ZÁMERNE nebezpečný. Slúži výhradne na školskú
demonštráciu SQL injection. NIKDY ho nepoužívajte v reálnej aplikácii. !!!

Hlavná chyba: používateľský vstup sa priamo vkladá (konkatenuje) do SQL
reťazca namiesto použitia parametrizovaných dotazov.
"""

import os
import sqlite3

from flask import Flask, request, render_template, redirect, url_for, session

# Databáza sa vytvorí v priečinku tejto appky
DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable.db")

app = Flask(__name__)
app.secret_key = "demo-nepouzivajte-v-produkcii"


def get_db():
    """Vytvorí pripojenie k SQLite databáze."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Vytvorí tabuľky a naplní ich testovacími dátami (ak ešte neexistujú)."""
    # Pri každom štarte začíname načisto, aby bolo demo reprodukovateľné.
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_db()
    cur = conn.cursor()

    # Tabuľka používateľov — heslá sú v OTVORENOM TVARE (tiež zraniteľnosť).
    cur.execute(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL
        )
        """
    )

    # Tabuľka produktov — nad ňou beží zraniteľné vyhľadávanie.
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

    # Testovací admin účet + bežný používateľ.
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin", "SuperTajneHeslo123", "admin"),
            ("jnovak", "jano2024", "user"),
            ("mkovac", "macka.*", "user"),
        ],
    )

    # Pár produktov.
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
    executed_query = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ===== ZRANITEĽNÉ MIESTO =====
        # Vstup používateľa sa priamo vkladá do SQL reťazca.
        # Payload  ' OR '1'='1' --  tým pádom obíde kontrolu hesla.
        query = (
            "SELECT * FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        executed_query = query

        conn = get_db()
        try:
            # executescript sa NEpoužíva, ale použijeme priamy execute na
            # skonkatenovaný reťazec — presne to je tá chyba.
            row = conn.execute(query).fetchone()
        except sqlite3.Error as exc:
            row = None
            error = f"SQL chyba: {exc}"
        finally:
            conn.close()

        if row:
            session["user"] = row["username"]
            return redirect(url_for("index"))
        elif error is None:
            error = "Nesprávne meno alebo heslo."

    return render_template("login.html", error=error, executed_query=executed_query)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


@app.route("/products")
def products():
    search = request.args.get("search", "")
    executed_query = None
    rows = []
    error = None

    conn = get_db()
    try:
        if search:
            # ===== ZRANITEĽNÉ MIESTO =====
            # Vyhľadávanie konkatenuje vstup priamo do dotazu -> UNION injection.
            query = (
                "SELECT id, name, description, price FROM products "
                f"WHERE name LIKE '%{search}%'"
            )
        else:
            query = "SELECT id, name, description, price FROM products"

        executed_query = query
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        error = f"SQL chyba: {exc}"
    finally:
        conn.close()

    return render_template(
        "products.html",
        rows=rows,
        search=search,
        executed_query=executed_query,
        error=error,
        user=session.get("user"),
    )


if __name__ == "__main__":
    init_db()
    print("ZRANITEĽNÁ appka beží na http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
