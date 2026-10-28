# SQL Injection — demonštračný projekt

Školský demonštračný projekt pre predmet **bezpečnosť / kryptografia**.
Ukazuje reálny rozdiel medzi **zraniteľnou** a **bezpečnou** implementáciou tej
istej webovej aplikácie (interný správca produktov s prihlásením).

> ⚠️ **Upozornenie:** Priečinok `vulnerable/` obsahuje **zámerne nebezpečný kód**.
> Slúži výhradne na vzdelávacie účely na vlastnom, lokálnom počítači. Nikdy ho
> nenasadzujte na verejný server ani nepoužívajte proti cudzím systémom.

---

## 1. Čo je SQL injection a prečo funguje

**SQL injection (SQLi)** je zraniteľnosť, pri ktorej aplikácia skladá SQL dotaz
tak, že **vstup od používateľa priamo vloží (skonkatenuje) do textu dotazu**.
Databáza potom nedokáže rozlíšiť, čo je *príkaz* (napísal programátor) a čo sú
*dáta* (zadal používateľ). Útočník preto môže do vstupu napísať kúsok SQL, ktorý
sa stane súčasťou príkazu a zmení jeho význam.

Príklad zraniteľného dotazu pri prihlásení:

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

Keď používateľ zadá do mena `admin' OR '1'='1' -- `, výsledný dotaz je:

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- ' AND password = '...'
```

Podmienka `'1'='1'` je **vždy pravdivá** a `--` zakomentuje zvyšok dotazu (vrátane
kontroly hesla). Databáza vráti riadok a útočník je prihlásený bez znalosti hesla.

**Riešenie** = parametrizované (prepared) dotazy: dáta sa posielajú oddelene od
príkazu cez zástupné znaky `?`, takže vstup sa **nikdy** nestane časťou SQL kódu.

---

## 2. Štruktúra projektu

```
sql-injection-demo/
├── vulnerable/          # ZRANITEĽNÁ verzia (port 5000)
│   ├── app.py
│   └── templates/
├── secure/              # BEZPEČNÁ verzia (port 5001)
│   ├── app.py
│   └── templates/
├── attack_demo.py       # automatizovaná demonštrácia útoku
├── demo_output.txt      # uložený výstup z posledného behu
├── requirements.txt
├── .gitignore
└── README.md
```

Obe aplikácie používajú **SQLite** (súbor `*.db` sa vytvorí automaticky pri štarte)
s dvoma tabuľkami:

- `users` — `id, username, password, role` (testovací **admin** účet + 2 bežní)
- `products` — `id, name, description, price` (zopár testovacích produktov)

---

## 3. Ako to spustiť

Potrebuješ **Python 3** a nainštalované závislosti:

```bash
# (voliteľné) virtuálne prostredie
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

Spusti každú appku vo **vlastnom termináli**:

```bash
# Terminál 1 — zraniteľná appka (http://127.0.0.1:5000)
python vulnerable/app.py

# Terminál 2 — bezpečná appka (http://127.0.0.1:5001)
python secure/app.py
```

A v **treťom** termináli spusti automatizované demo:

```bash
python attack_demo.py
```

Appky vieš otvoriť aj v prehliadači a skúšať payloady ručne (login formulár aj
vyhľadávanie produktov).

**Testovací admin účet:** `admin` / `SuperTajneHeslo123`

---

## 4. Použité payloady a čo robia

### a) Obídenie prihlásenia (login bypass)

Do poľa **používateľské meno** zadaj:

```
admin' OR '1'='1' -- 
```

(do hesla čokoľvek). Apostrofom ukončíme reťazec mena, `OR '1'='1'` spraví
podmienku vždy pravdivou a `-- ` (s medzerou na konci) zakomentuje zvyšok dotazu
vrátane kontroly hesla → prihlásenie prejde bez správneho hesla.

### b) UNION-based extrakcia dát

Do poľa **vyhľadávanie produktov** zadaj:

```
' UNION SELECT id, username, password, role FROM users -- 
```

Pôvodný dotaz vyberá 4 stĺpce z `products`. Pomocou `UNION SELECT` pripojíme
4 stĺpce z tabuľky `users`, takže vo výsledkoch „produktov“ sa zobrazia
**používateľské mená a heslá**. Počet a poradie stĺpcov musí sedieť — preto
presne 4 stĺpce.

---

## 5. Porovnanie: zraniteľný vs. bezpečný kód

### Prihlásenie

**❌ Zraniteľné (`vulnerable/app.py`)** — konkatenácia vstupu do SQL:

```python
query = (
    "SELECT * FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
row = conn.execute(query).fetchone()
```

**✅ Bezpečné (`secure/app.py`)** — parametrizovaný dotaz + validácia + hash hesla:

```python
if not USERNAME_RE.match(username):          # 1) validácia vstupu
    error = "Neplatné používateľské meno."

row = conn.execute(                           # 2) parametrizovaný dotaz (?)
    "SELECT * FROM users WHERE username = ?",
    (username,),
).fetchone()

if row and check_password_hash(row["password"], password):   # 3) overenie hashu
    ...
```

### Vyhľadávanie produktov

**❌ Zraniteľné** — vstup priamo v `LIKE`:

```python
query = (
    "SELECT id, name, description, price FROM products "
    f"WHERE name LIKE '%{search}%'"
)
rows = conn.execute(query).fetchall()
```

**✅ Bezpečné** — placeholder `?`, wildcard je súčasťou hodnoty, nie SQL kódu:

```python
rows = conn.execute(
    "SELECT id, name, description, price FROM products WHERE name LIKE ?",
    (f"%{search}%",),
).fetchall()
```

Kľúčový rozdiel: v bezpečnej verzii ide vstup do databázy ako **parameter (dáta)**,
nikdy ako súčasť textu SQL príkazu. Payloady z časti 4 preto databáza vyhodnotí
len ako obyčajný hľadaný reťazec a nič neunikne.

---

## 6. Výstup z `attack_demo.py`

Uložený v súbore [`demo_output.txt`](demo_output.txt). Nový log si vygeneruješ
(pri bežiacich appkách) takto:

```bash
python attack_demo.py > demo_output.txt
```

Očakávaný výsledok:

```
  Zraniteľná — login bypass:     ÚSPEŠNÝ [OK]
  Zraniteľná — UNION extrakcia:  ÚSPEŠNÁ [OK]
  Bezpečná   — login bypass:     ODOLALA [X]
  Bezpečná   — UNION extrakcia:  ODOLALA [X]

  => Presne očakávaný výsledok: zraniteľná padla, bezpečná odolala.
```

---

## 7. Zhrnutie opatrení v bezpečnej verzii

1. **Parametrizované (prepared) dotazy** — vstup nikdy nie je súčasťou SQL kódu.
2. **Validácia vstupu** — používateľské meno musí sedieť na povolený vzor.
3. **Hashovanie hesiel** — `werkzeug.security` (`generate_password_hash` /
   `check_password_hash`), heslá nie sú v databáze v otvorenom tvare.
