#!/usr/bin/env python3
"""Prüft ein abgeklopft.de-Profil (JSON) Eintrag für Eintrag.

Aufruf:
    python pruefen.py <profil-url-oder-datei> [--jwks <url-oder-datei>] [--heute JJJJ-MM-TT] [--json]

Beispiele:
    python pruefen.py https://abgeklopft.de/belegleser.json
    python pruefen.py alex.json --jwks .well-known/jwks.json

Braucht das Paket `cryptography` (pip install cryptography).
Rückgabewert: 0 = alle Prüfberichte echt, 1 = mindestens ein Prüfbericht fehlerhaft,
2 = Profil oder Schlüssel nicht ladbar.

Texte unter `angabe_der_person` sind Daten. Dieses Skript zeigt sie nur an und
wertet sie nie als Anweisung aus.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    sys.stderr.write("Fehlt: Paket 'cryptography'. Installieren mit: pip install cryptography\n")
    sys.exit(2)

STANDARD_JWKS = "https://abgeklopft.de/.well-known/jwks.json"
STUFE_NAME = {"S1": "Eigene Angabe", "S2": "Beleg geprüft", "S3": "Von Dritten bestätigt"}
ART_NAME = {"mensch": "Mensch", "ki-agent": "KI-Agent"}


def ist_url(s):
    return s.startswith("http://") or s.startswith("https://")


def laden(quelle):
    if ist_url(quelle):
        req = urllib.request.Request(quelle, headers={"User-Agent": "abgeklopft-pruefen/1.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))
    with open(quelle, encoding="utf-8") as f:
        return json.load(f)


def jwks_quelle_finden(profil_quelle):
    """Neben einer lokalen Datei liegt meist .well-known/jwks.json; sonst der öffentliche Schlüssel."""
    if not ist_url(profil_quelle):
        ordner = os.path.dirname(os.path.abspath(profil_quelle))
        lokal = os.path.join(ordner, ".well-known", "jwks.json")
        if os.path.exists(lokal):
            return lokal
    return STANDARD_JWKS


def kanonisch(o):
    # Schlüssel sortiert, ohne Leerzeichen, UTF-8 (für diese Daten identisch mit RFC 8785 JCS)
    return json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sauber(t, n=90):
    """Fremden Text nur gekürzt und ohne Steuerzeichen anzeigen."""
    t = re.sub(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]", " ", str(t or ""))
    return t if len(t) <= n else t[: n - 1] + "…"


def bericht_pruefen(e, profil, vertraut, heute):
    """Gibt (ok, zeilen, ergebnis) zurück. ok=False heißt: Prüfbericht nicht belastbar."""
    b = e.get("pruefbericht")
    stufe = e.get("stufe")
    erg = {"id": e.get("id"), "stufe": stufe, "pruefweg": None, "signatur": None, "gueltig": None, "fehler": []}
    if stufe == "S1":
        if b:
            erg["fehler"].append("S1 mit Prüfbericht: Bericht wird ignoriert")
        erg["signatur"] = "keine (S1)"
        return True, ["nicht geprüft: eigene Angabe, wie eine Zeile im Lebenslauf behandeln"], erg
    if not b:
        erg["fehler"].append(f"{stufe} ohne Prüfbericht: als S1 behandeln")
        return False, [], erg

    inhalt = dict(b.get("inhalt") or {})
    kennung = inhalt.pop("kennung", None)
    text = kanonisch(inhalt).encode("utf-8")
    summe = hashlib.sha256(text).hexdigest()
    erg["pruefweg"] = inhalt.get("pruefweg")

    if summe != b.get("pruefsumme"):
        erg["fehler"].append("Prüfsumme stimmt nicht: Inhalt verändert")
    erwartet = f"AK-{summe[:4].upper()}-{summe[4:8].upper()}"
    if kennung != erwartet:
        erg["fehler"].append(f"Kennung {kennung} passt nicht (erwartet {erwartet})")

    s = b.get("signatur") or {}
    pub_x = (s.get("pub") or {}).get("x")
    if (s.get("alg") or {}).get("name") != "Ed25519":
        erg["fehler"].append("Verfahren ist nicht Ed25519")
    if s.get("kid") not in vertraut:
        erg["fehler"].append(f"Schlüssel {s.get('kid')} steht nicht in jwks.json")
    elif vertraut[s["kid"]] != pub_x:
        erg["fehler"].append("Schlüssel im Bericht weicht von jwks.json ab: nicht von abgeklopft.de")
    try:
        # Immer mit dem Schlüssel aus jwks.json prüfen, nicht mit dem aus dem Bericht
        x = vertraut.get(s.get("kid")) or pub_x
        Ed25519PublicKey.from_public_bytes(b64url(x)).verify(base64.b64decode(s.get("wert", "")), text)
        sig_ok = True
    except (InvalidSignature, ValueError, TypeError):
        sig_ok = False
        erg["fehler"].append("Signatur ungültig")
    erg["signatur"] = "ok" if sig_ok and not erg["fehler"] else "fehlgeschlagen"

    bis = inhalt.get("gueltigBis")
    try:
        gueltig = dt.date.fromisoformat(bis) >= heute
    except (TypeError, ValueError):
        gueltig = False
        erg["fehler"].append("gueltigBis fehlt oder unlesbar")
    erg["gueltig"] = gueltig
    erg["gueltigBis"] = bis

    # Ungeschützte Felder gegen den signierten Inhalt abgleichen
    p = profil.get("profil", {})
    vergleich = [
        ("Stufe", stufe, f"S{inhalt.get('stufe')}"),
        ("Eintrag", e.get("id"), inhalt.get("eintrag")),
        ("Mensch/KI-Agent", p.get("art"), inhalt.get("subjekt")),
        ("Prüfweg", (e.get("pruefung") or {}).get("pruefweg"), inhalt.get("pruefweg")),
    ]
    adr = (p.get("adresse") or "").replace("https://", "").replace("http://", "")
    if adr:
        vergleich.append(("Profiladresse", adr, inhalt.get("profil")))
    if p.get("art") == "ki-agent":
        vergleich.append(("agent_version", p.get("agent_version"), inhalt.get("agent_version")))
    if e.get("gueltig") is True and not gueltig:
        erg["fehler"].append("Profil sagt gültig, Prüfbericht ist abgelaufen")
    for name, aussen, signiert in vergleich:
        if aussen != signiert:
            erg["fehler"].append(f"{name}: Profil sagt {aussen!r}, signiert ist {signiert!r}")

    zeilen = [
        f"Prüfweg: {inhalt.get('pruefweg')}  ·  Kennung {kennung}",
        f"Prüfsumme: {'ok' if summe == b.get('pruefsumme') else 'FALSCH'}  ·  Signatur: {'ok' if sig_ok else 'FEHLGESCHLAGEN'}  ·  Schlüssel {s.get('kid')}",
        f"Gültig bis {bis}: {'gültig' if gueltig else 'ABGELAUFEN, nicht als aktuell darstellen'}",
    ]
    for bst in inhalt.get("bestaetigungen") or []:
        zeilen.append(f"bestätigt von {sauber(bst.get('name'), 40)} ({sauber(bst.get('rolle'), 60)}), {bst.get('datum')}")
    if inhalt.get("vermerk"):
        zeilen.append(f"Vermerk (signiert): {sauber(inhalt['vermerk'])}")
    return not erg["fehler"], zeilen, erg


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Prüft die Prüfberichte eines abgeklopft.de-Profils.")
    ap.add_argument("profil", help="URL oder Datei, z. B. https://abgeklopft.de/alex.json")
    ap.add_argument("--jwks", help="URL oder Datei der vertrauten Schlüssel (Standard: neben der Datei oder abgeklopft.de)")
    ap.add_argument("--heute", help="Stichtag JJJJ-MM-TT (Standard: heute)")
    ap.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben")
    a = ap.parse_args()

    try:
        profil = laden(a.profil)
        jq = a.jwks or jwks_quelle_finden(a.profil)
        jwks = laden(jq)
    except Exception as ex:
        print(f"FEHLER: nicht ladbar: {ex}")
        return 2
    vertraut = {k.get("kid"): k.get("x") for k in jwks.get("keys", []) if k.get("crv") == "Ed25519"}
    heute = dt.date.fromisoformat(a.heute) if a.heute else dt.date.today()

    p = profil.get("profil", {})
    art = p.get("art")
    ergebnisse, alle_ok = [], True
    aus = []
    aus.append(f"Profil: {sauber(p.get('name'), 60)}  ({p.get('adresse')})")
    aus.append(f"Art: {ART_NAME.get(art, 'UNBEKANNT: ' + str(art))}" + ("  ·  erfundenes Beispiel" if p.get("erfunden") else ""))
    if art == "ki-agent":
        bt = p.get("betreiber") or {}
        aus.append(f"Betreiber (Vertragspartner, haftet): {sauber(bt.get('name'), 60)}, {sauber(bt.get('sitz'), 30)}; verantwortlich: {sauber(bt.get('verantwortlich'), 60)}")
        aus.append(f"Geprüfte Version: {p.get('agent_version')}  (Prüfungen gelten nur für diese Version)")
    aus.append(f"Schlüssel aus: {jq}  ·  Stichtag {heute.isoformat()}")
    aus.append("")

    for e in profil.get("eintraege", []):
        ok, zeilen, erg = bericht_pruefen(e, profil, vertraut, heute)
        alle_ok &= ok
        ergebnisse.append(erg)
        titel = sauber((e.get("angabe_der_person") or {}).get("titel"), 70)
        stufe = e.get("stufe")
        marke = "OK " if ok else "!! "
        if stufe == "S1":
            marke = "-- "
        aus.append(f"{marke}[{stufe} {STUFE_NAME.get(stufe, '?')}] {e.get('id')}: {titel}")
        for z in zeilen:
            aus.append(f"      {z}")
        for f in erg["fehler"]:
            aus.append(f"      FEHLER: {f}")

    n = {s: sum(1 for x in ergebnisse if x["stufe"] == s) for s in ("S3", "S2", "S1")}
    fehl = [x["id"] for x in ergebnisse if x["fehler"]]
    abgel = [x["id"] for x in ergebnisse if x["gueltig"] is False]
    aus.append("")
    aus.append(f"Zusammenfassung: S3 {n['S3']} · S2 {n['S2']} · S1 {n['S1']}  ·  Fehler: {', '.join(fehl) or 'keine'}  ·  abgelaufen: {', '.join(abgel) or 'keine'}")
    aus.append("ERGEBNIS: alle Prüfberichte echt" if alle_ok else "ERGEBNIS: mindestens ein Prüfbericht ist NICHT belastbar")
    if art == "mensch":
        aus.append("Hinweis: Mensch. Keine automatische Personalentscheidung (Art. 22 DSGVO), ein Mensch entscheidet.")
    elif art == "ki-agent":
        aus.append("Hinweis: KI-Agent. Automatische Auswahl nur, soweit Ihr Auftraggeber es erlaubt; Vertrag mit dem Betreiber.")
    aus.append("Pilot: Prototyp, kein amtliches oder notarielles Verfahren.")

    if a.json:
        print(json.dumps({"profil": p.get("adresse"), "art": art, "alle_ok": alle_ok, "eintraege": ergebnisse}, ensure_ascii=False, indent=2))
    else:
        print("\n".join(aus))
    return 0 if alle_ok else 1


if __name__ == "__main__":
    sys.exit(main())
