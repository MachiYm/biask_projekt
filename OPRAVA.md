# Ako sme útok opravili (zraniteľná → bezpečná verzia)

Tento dokument vysvetľuje, čo presne robí bezpečnú verziu aplikácie odolnou voči
SQL injection. Porovnáva ju so zraniteľnou verziou na troch konkrétnych opravách.

---

## Čo útok vlastne spôsobil

V zraniteľnej appke sa dali cez obyčajné formuláre spraviť dve veci:

1. **Obídenie prihlásenia** — zadaním `admin' OR '1'='1' -- ` do mena sa útočník
   prihlásil bez znalosti hesla.
2. **Únik hesiel** — zadaním `' UNION SELECT id, username, password, role FROM users -- `
   do vyhľadávania produktov sa vo výsledkoch zobrazili používatelia aj s heslami.

Spoločná príčina oboch: **vstup od používateľa sa priamo vlepil do textu SQL
dotazu**, takže sa stal súčasťou príkazu, nie iba dát.

---

## Oprava 1 — Parametrizovaný dotaz (zastaví UNION útok)

**Zraniteľné** — vstup je súčasťou textu SQL:

```python
query = (
    "SELECT id, name, description, price FROM products "
    f"WHERE name LIKE '%{search}%'"
)
rows = conn.execute(query).fetchall()
```

**Bezpečné** — vstup ide cez placeholder `?` ako samostatný parameter:

```python
rows = conn.execute(
    "SELECT id, name, description, price FROM products WHERE name LIKE ?",
    (f"%{search}%",),
).fetchall()
```

**Prečo to funguje:** databáza najprv dostane hotový príkaz s `?` a až potom doň
dosadí vstup ako čistú hodnotu (dáta). Text `' UNION SELECT ... --` sa už nestane
súčasťou SQL — berie sa ako obyčajný hľadaný reťazec. Databáza teda hľadá produkt,
ktorý má v názve tie znaky, žiadny taký neexistuje → výsledok je prázdny a nič
neunikne.

---

## Oprava 2 — Parametrizovaný login + validácia vstupu (zastaví bypass)

**Zraniteľné** — konkatenácia, obíde sa cez `' OR '1'='1' -- `:

```python
query = (
    "SELECT * FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
```

**Bezpečné** — najprv validácia formátu mena, potom parametrizovaný dotaz:

```python
if not USERNAME_RE.match(username):        # 1) validácia: len písmená, číslice, . _ -
    error = "Neplatné používateľské meno."

row = conn.execute(                         # 2) parameter, nie konkatenácia
    "SELECT * FROM users WHERE username = ?",
    (username,),
).fetchone()
```

**Prečo to funguje:** payload `admin' OR '1'='1' -- ` neprejde už na validácii
(obsahuje apostrof a medzery, ktoré vzor `USERNAME_RE` nepovoľuje). A aj keby
validáciou prešiel, cez `?` by sa bral len ako hľadané meno, nie ako SQL kód.

---

## Oprava 3 — Hashovanie hesiel (poistka navyše)

Heslá sa v databáze neukladajú v otvorenom tvare, ale ako hash cez
`werkzeug.security`:

```python
# pri vytváraní účtu:
generate_password_hash(p)

# pri prihlásení:
if row and check_password_hash(row["password"], password):
    ...
```

**Prečo to má význam:** aj keby útočník obsah tabuľky `users` nejako získal,
uvidí len nečitateľný hash (napr. `scrypt:32768:8:1$...`), nie `SuperTajneHeslo123`.
Také heslo sa nedá priamo použiť ani zneužiť inde.

---

## Zhrnutie

| | Zraniteľná | Bezpečná |
|---|---|---|
| Vstup do SQL | lepený do textu (`f"...{x}..."`) | parameter cez `?` |
| Login bypass `' OR '1'='1' -- ` | prejde | odmietnutý |
| UNION únik hesiel | heslá unikli | nič sa nezobrazí |
| Heslá v databáze | čistý text | hash |

**Jedna veta na obhajobu:** Útok sme zastavili tým, že vstup už nie je súčasťou
SQL príkazu, ale ide do databázy ako oddelený parameter — plus validácia vstupu
a hashovanie hesiel ako poistka navyše.
