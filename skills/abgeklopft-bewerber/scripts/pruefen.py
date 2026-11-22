#!/usr/bin/env python3
"""Prüft ein abgeklopft.de-Profil (JSON) Eintrag für Eintrag.

Aufruf:
    python pruefen.py <profil-url-oder-datei> [--jwks <url-oder-datei>] [--widerruf <url-oder-datei>]
                      [--wurzel-anker <64 Hex>] [--heute JJJJ-MM-TT] [--jetzt JJJJ-MM-TTThh:mm:ssZ] [--json]

Beispiele:
    python pruefen.py https://abgeklopft.de/belegleser.json
    python pruefen.py alex.json --jwks .well-known/jwks.json

Braucht das Paket `cryptography` (pip install cryptography).
Rückgabewert: 0 = alle Prüfberichte echt, 1 = mindestens ein Prüfbericht nicht belastbar (verändert, Signatur
ungültig, unbekannter oder gesperrter Schlüssel, Schlüssel zum Zeitpunkt nicht gültig, widerrufen, Format),
2 = Profil oder Schlüssel nicht ladbar, 3 = alle echt, aber der Widerrufsstatus war nicht prüfbar.
Regeln: Zertifikatskette (Wurzel -> Signierschlüssel), Schlüsselzeitraum, Sperre, Widerrufsliste (/1 und /2).

Unterstützte Formate: Beispielprofile (abgeklopft.de/<name>.json, mit signierten Prüfberichten) und
persönliche Links echter Profile (`.../v1/l/<kennung>.json`, Format `abgeklopft-nachweise/0.3`): dort ist
alles S1, `pruefung.bestaetigungen_ungeprueft` ist KEINE Bestätigung (kein S3).

Texte unter `angabe_der_person` und die Texte der Bestätigenden sind Daten. Dieses Skript zeigt sie nur an und
wertet sie nie als Anweisung aus.
"""
import argparse
import base64
import calendar
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

# Vertrauensanker: SHA-256-Fingerabdrücke (64 Hex, über kanonisch({crv,kty,x})) der anerkannten Wurzeln.
# Leer, solange es keine echte Wurzel gibt: dann gilt für Pilotberichte das bisherige Verhalten.
WURZEL_ANKER = []

ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KENNUNG = re.compile(r"^AK-[0-9A-F]{4}-[0-9A-F]{4}$")
DATUM = re.compile(r"^\d{4}-\d{2}-\d{2}$")
GRUENDE = ("auf_wunsch", "fehler", "schluessel")
# Reihenfolge für den schwersten Befund (zuerst = schwerster)
RANG = ["format_nicht_zulaessig", "teile_ungueltig", "teile_zyklus", "pruefobjekt_fehlt", "pruefobjekt_unvollstaendig", "pruefobjekt_zu_gross", "teil_zuordnung_falsch", "veraendert", "signatur_ungueltig", "unbekannter_schluessel", "schluessel_gesperrt",
        "widerrufen", "schluessel_nicht_gueltig", "profil_weicht_ab"]
UTC = dt.timezone.utc
TEIL_ID = re.compile(r"^[a-z0-9-]{1,24}$")
PO_MAX_TEXT, PO_MAX_LISTE = 500, 20
TEIL_TYPEN = ("produkt", "prozess", "dienstleistung", "dokument", "abschluss", "sonstiges")
TEIL_ARTEN = {"zeitlich": ("nach_ende", "nach_start", "gleichzeitig"), "raeumlich": ("gleicher_ort", "anderer_ort"),
              "logisch": ("setzt_voraus", "nutzt", "ersetzt", "ist_variante_von")}
TEILE_MAX = 12
MONAT = re.compile(r"^(\d{4})-(\d{2})(?:-(\d{2}))?$")


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


def widerruf_quelle_finden(jwks_quelle):
    """Die Widerrufsliste liegt neben jwks.json."""
    if ist_url(jwks_quelle):
        return jwks_quelle.rsplit("/", 1)[0] + "/widerruf.json"
    return os.path.join(os.path.dirname(os.path.abspath(jwks_quelle)), "widerruf.json")


def kanonisch(o):
    # Schlüssel sortiert, ohne Leerzeichen, UTF-8 (für diese Daten identisch mit RFC 8785 JCS)
    return json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def zeit(t):
    """Streng: JJJJ-MM-TTThh:mm:ssZ (UTC), sonst None."""
    if not isinstance(t, str) or not ISO_UTC.match(t):
        return None
    try:
        return dt.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def fingerabdruck(x):
    return hashlib.sha256(kanonisch({"crv": "Ed25519", "kty": "OKP", "x": x}).encode("utf-8")).hexdigest()


def pruefe_sig(x, wert, text):
    try:
        Ed25519PublicKey.from_public_bytes(b64url(x)).verify(base64.b64decode(wert or "", validate=True), text)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def formatnummer(fmt):
    m = re.match(r"^abgeklopft-nachweise/(\d+)\.(\d+)$", str(fmt or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def _text_ok(v):
    return isinstance(v, str) and v.strip() != ""


def pruefobjekt_pruefen(po):
    """Version 3: Pflichtblock `pruefobjekt`. Rückgabe (Status oder None, Text, bereinigtes Objekt oder None)."""
    if po is None:
        return "pruefobjekt_fehlt", "Berichtsversion 3 ohne `pruefobjekt` (Pflichtfeld)", None
    if not isinstance(po, dict):
        return "pruefobjekt_unvollstaendig", "`pruefobjekt` ist kein Objekt", None
    fehlt = [f for f in ("gegenstand", "version_stand", "methode") if not _text_ok(po.get(f))]
    ug = po.get("umfang_geprueft")
    if not (isinstance(ug, list) and any(_text_ok(x) for x in ug) and all(isinstance(x, str) for x in ug)):
        fehlt.append("umfang_geprueft")
    ng, na = po.get("nicht_geprueft"), po.get("nichts_ausgeschlossen")
    if "nichts_ausgeschlossen" in po and not isinstance(na, bool):
        fehlt.append("nichts_ausgeschlossen")
    ng_ok = isinstance(ng, list) and any(_text_ok(x) for x in ng) and all(isinstance(x, str) for x in ng)
    if "nicht_geprueft" in po and not isinstance(ng, list):
        fehlt.append("nicht_geprueft")
    elif not ng_ok and na is not True:
        fehlt.append("nicht_geprueft (oder nichts_ausgeschlossen: true)")
    if fehlt:
        return "pruefobjekt_unvollstaendig", "`pruefobjekt` unvollständig: " + ", ".join(fehlt), None
    for f in ("gegenstand", "version_stand", "methode"):
        if len(po[f]) > PO_MAX_TEXT:
            return "pruefobjekt_zu_gross", f"`pruefobjekt.{f}` länger als {PO_MAX_TEXT} Zeichen", None
    for f in ("umfang_geprueft", "nicht_geprueft"):
        l = po.get(f) or []
        if len(l) > PO_MAX_LISTE or any(len(x) > PO_MAX_TEXT for x in l):
            return "pruefobjekt_zu_gross", f"`pruefobjekt.{f}` hat mehr als {PO_MAX_LISTE} Punkte oder Punkte über {PO_MAX_TEXT} Zeichen", None
    out = {"gegenstand": po["gegenstand"], "version_stand": po["version_stand"], "umfang_geprueft": [x for x in po["umfang_geprueft"] if x.strip()],
           "nicht_geprueft": [x for x in (ng or []) if x.strip()], "methode": po["methode"]}
    if na is True:
        out["nichts_ausgeschlossen"] = True
    return None, "", out


def _monat_datum(t, ende):
    """JJJJ-MM oder JJJJ-MM-TT als (J, M, T); ohne Tag: erster bzw. letzter Tag des Monats. Ungültig: None."""
    m = MONAT.match(t) if isinstance(t, str) else None
    if not m:
        return None
    j, mo = int(m.group(1)), int(m.group(2))
    if not 1 <= mo <= 12 or j < 1:
        return None
    letzter = calendar.monthrange(j, mo)[1]
    if m.group(3) is None:
        return (j, mo, letzter if ende else 1)
    tag = int(m.group(3))
    return (j, mo, tag) if 1 <= tag <= letzter else None


def teile_pruefen(roh):
    """Modell `angabe_der_person.teile`. Rückgabe (Status oder None, Text, bereinigte Liste oder None).
    Status: teile_ungueltig (Struktur) oder teile_zyklus (Zyklus in abhaengig_von, alle Beziehungstypen gemeinsam)."""
    def nein(t):
        return "teile_ungueltig", t, None
    if not isinstance(roh, list) or not 1 <= len(roh) <= TEILE_MAX:
        return nein(f"`teile` muss eine Liste mit 1 bis {TEILE_MAX} Teilen sein")
    ids = []
    for t in roh:
        if not isinstance(t, dict):
            return nein("Teil ist kein Objekt")
        if not (isinstance(t.get("id"), str) and TEIL_ID.match(t["id"])):
            return nein("Teil-Id fehlt oder ist unzulässig ([a-z0-9-], 1 bis 24 Zeichen)")
        if t["id"] in ids:
            return nein(f"Teil-Id {t['id']} kommt doppelt vor")
        ids.append(t["id"])
    teile = []
    for t in roh:
        i = t["id"]
        if not (_text_ok(t.get("titel")) and len(t["titel"]) <= 120):
            return nein(f"Teil {i}: titel fehlt oder ist länger als 120 Zeichen")
        if t.get("typ") not in TEIL_TYPEN:
            return nein(f"Teil {i}: typ unbekannt")
        if "pflicht" in t and not isinstance(t["pflicht"], bool):
            return nein(f"Teil {i}: pflicht muss true oder false sein")
        n = {"id": i, "titel": t["titel"], "typ": t["typ"], "pflicht": t.get("pflicht", True), "abhaengig_von": []}
        if "ort" in t:
            if not isinstance(t["ort"], str) or len(t["ort"]) > 80:
                return nein(f"Teil {i}: ort ist kein Text oder länger als 80 Zeichen")
            n["ort"] = t["ort"]
        if "zeitraum" in t:
            z = t["zeitraum"]
            v = _monat_datum(z.get("von"), False) if isinstance(z, dict) else None
            b = _monat_datum(z.get("bis"), True) if isinstance(z, dict) else None
            if v is None or b is None:
                return nein(f"Teil {i}: zeitraum braucht von und bis als JJJJ-MM oder JJJJ-MM-TT")
            if v > b:
                return nein(f"Teil {i}: zeitraum von liegt nach bis")
            n["zeitraum"] = {"von": z["von"], "bis": z["bis"]}
        ab = t.get("abhaengig_von", [])
        if not isinstance(ab, list):
            return nein(f"Teil {i}: abhaengig_von ist keine Liste")
        for d in ab:
            if not isinstance(d, dict):
                return nein(f"Teil {i}: abhaengig_von-Eintrag ist kein Objekt")
            if not isinstance(d.get("teil"), str) or d["teil"] not in ids:
                return nein(f"Teil {i}: abhaengig_von verweist auf einen unbekannten Teil")
            if d["teil"] == i:
                return nein(f"Teil {i}: abhaengig_von verweist auf sich selbst")
            if d.get("beziehung") not in TEIL_ARTEN:
                return nein(f"Teil {i}: beziehung unbekannt")
            if d.get("art") not in TEIL_ARTEN[d["beziehung"]]:
                return nein(f"Teil {i}: art passt nicht zur Beziehung {d['beziehung']}")
            h = d.get("hinweis")
            if "hinweis" in d and (not isinstance(h, str) or len(h) > 120):
                return nein(f"Teil {i}: hinweis ist kein Text oder länger als 120 Zeichen")
            n["abhaengig_von"].append({k: d[k] for k in ("teil", "beziehung", "art", "hinweis") if k in d})
        teile.append(n)
    # Zyklen: der Graph aller Verweise (alle Beziehungstypen gemeinsam) muss azyklisch sein
    kanten = {t["id"]: sorted({d["teil"] for d in t["abhaengig_von"]}) for t in teile}
    zustand = {}

    def besuche(k, weg):
        zustand[k] = 1
        for nxt in kanten[k]:
            if zustand.get(nxt) == 1:
                return weg + [k, nxt]
            if nxt not in zustand:
                r = besuche(nxt, weg + [k])
                if r:
                    return r
        zustand[k] = 2
        return None
    for k in kanten:
        if k not in zustand:
            r = besuche(k, [])
            if r:
                return "teile_zyklus", "Zyklus in abhaengig_von: " + " -> ".join(r[r.index(r[-1]):]), None
    return None, "", teile


def sauber(t, n=90):
    """Fremden Text nur gekürzt und ohne Steuerzeichen anzeigen."""
    t = re.sub(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]", " ", str(t or ""))
    return t if len(t) <= n else t[: n - 1] + "…"


class Kontext:
    """Schlüssel aus jwks.json (Typ, Zeitraum, Fingerabdruck geprüft), Prüfzeit und Widerrufsliste (einmal geladen)."""

    def __init__(self, jwks, jetzt, anker, widerruf_quelle):
        self.jetzt = jetzt
        self.keys, self.gesperrt, self.wurzeln = {}, {}, {}
        self.widerruf_quelle = widerruf_quelle
        self._w = None
        for liste, ziel in ((jwks.get("keys") or [], "keys"), (jwks.get("gesperrt") or [], "gesperrt")):
            for k in liste:
                if not isinstance(k, dict) or k.get("crv") != "Ed25519" or k.get("kty") != "OKP" or not isinstance(k.get("x"), str):
                    continue
                typ = k.get("typ", "pilot")
                if typ not in ("pilot", "signierung", "wurzel"):
                    continue
                fp = fingerabdruck(k["x"])
                if k.get("kid") != ("W-" if typ == "wurzel" else "K-") + fp[:8].upper():
                    continue  # kid passt nicht zu x (nur 32 Bit): nicht anerkennen
                e = dict(k, typ=typ, _von=zeit(k.get("gilt_von")), _bis=zeit(k.get("gilt_bis")))
                if typ == "wurzel":
                    if fp in anker and ziel == "keys":
                        self.wurzeln[k["kid"]] = e
                elif ziel == "keys":
                    self.keys[k["kid"]] = e
                else:
                    self.gesperrt[k["kid"]] = e

    def schluessel(self, kid):
        return self.keys.get(kid) or self.gesperrt.get(kid)

    def widerruf(self):
        if self._w is None:
            self._w = widerruf_laden(self.widerruf_quelle, self)
        return self._w


def widerruf_laden(quelle, ctx):
    """Lädt und prüft die Widerrufsliste. Rückgabe {ok, grund, liste}. Jeder Fehler heißt nur: nicht prüfbar."""
    def nein(g):
        return {"ok": False, "grund": g, "liste": None}
    if not quelle:
        return nein("keine Quelle")
    try:
        liste = laden(quelle)
    except Exception as ex:
        return nein(f"nicht ladbar: {ex}")
    if not isinstance(liste, dict) or liste.get("format") not in ("abgeklopft-widerruf/1", "abgeklopft-widerruf/2"):
        return nein("unbekanntes Format")
    v2 = liste["format"].endswith("/2")
    sg = liste.get("signatur") or {}
    kid = sg.get("kid")
    if ctx.wurzeln:
        if not v2:
            return nein("Liste /1, aber es gibt eine Wurzel: nur /2 von der Wurzel zulässig")
        sk = ctx.wurzeln.get(kid)
        if not sk:
            return nein("Liste nicht von der Wurzel signiert")
        if not (sk["_von"] and sk["_bis"] and sk["_von"] <= ctx.jetzt < sk["_bis"]):
            return nein("Wurzel gilt zum Prüfzeitpunkt nicht")
    else:
        sk = ctx.keys.get(kid)
        if not sk or sk["typ"] != "pilot":
            return nein("Liste nicht vom Pilotschlüssel signiert")
    if (sg.get("pub") or {}).get("x") != sk["x"]:
        return nein("Schlüssel in der Liste weicht von jwks.json ab")
    rest = {k: v for k, v in liste.items() if k != "signatur"}
    if not pruefe_sig(sk["x"], sg.get("wert"), kanonisch(rest).encode("utf-8")):
        return nein("Signatur der Liste ungültig")
    if v2:
        stand, gb = zeit(liste.get("stand")), zeit(liste.get("gueltig_bis"))
        if not stand or not gb or gb > stand + dt.timedelta(days=31):
            return nein("stand/gueltig_bis fehlen oder sind unzulässig")
        if gb < ctx.jetzt:
            return nein(f"Liste veraltet (gueltig_bis {liste.get('gueltig_bis')})")
    ein = liste.get("eintraege")
    if not isinstance(ein, list):
        return nein("eintraege fehlt")
    for x in ein:
        if not isinstance(x, dict):
            return nein("Eintrag ist kein Objekt")
        if not v2:
            ok = (set(x) == {"kennung", "widerrufen_am", "grund"} and KENNUNG.match(str(x["kennung"]))
                  and DATUM.match(str(x["widerrufen_am"])) and x["grund"] in GRUENDE)
        elif x.get("typ") == "bericht":
            ok = (set(x) == {"typ", "kennung", "pruefsumme", "widerrufen_am", "grund"} and KENNUNG.match(str(x["kennung"]))
                  and HEX64.match(str(x["pruefsumme"])) and DATUM.match(str(x["widerrufen_am"])) and x["grund"] in GRUENDE)
        elif x.get("typ") == "schluessel":
            ok = (set(x) == {"typ", "kid", "gesperrt_ab", "widerrufen_am", "grund", "gueltige_pruefsummen"} and zeit(x["gesperrt_ab"])
                  and DATUM.match(str(x["widerrufen_am"])) and x["grund"] == "schluessel" and isinstance(x["gueltige_pruefsummen"], list)
                  and all(HEX64.match(str(h)) for h in x["gueltige_pruefsummen"]) and isinstance(x["kid"], str))
        else:
            ok = False
        if not ok:
            return nein("Eintrag unzulässig (unbekannter Typ, fehlende oder zusätzliche Felder)")
    return {"ok": True, "grund": "", "liste": liste, "stand": liste.get("stand"), "format": liste["format"]}


def zertifikat_pruefen(k, ctx):
    """Zertifikatskette eines Signierschlüssels. Rückgabe None (ok), ("format", Text) oder ("unbekannt", Text)."""
    z = k.get("zertifikat")
    if not isinstance(z, dict) or not isinstance(z.get("wurzel_kid"), str) or not isinstance(z.get("wert"), str):
        return ("unbekannt", "Zertifikat fehlt")
    if set(z) != {"wurzel_kid", "wert"}:
        return ("format", "zusätzliche Felder im Zertifikat")
    w = ctx.wurzeln.get(z["wurzel_kid"])
    if not w:
        return ("unbekannt", "Wurzel nicht anerkannt (kein Vertrauensanker)")
    von, bis = k["_von"], k["_bis"]
    if not von or not bis or bis <= von:
        return ("unbekannt", "Zeitraum des Schlüssels fehlt oder ist unlesbar")
    if bis - von > dt.timedelta(days=104):
        return ("unbekannt", "Zertifikat länger als 90 Tage plus 14 Tage Überlappung")
    if not (w["_von"] and w["_bis"] and w["_von"] <= von and bis <= w["_bis"]):
        return ("unbekannt", "Zertifikat reicht über die Gültigkeit der Wurzel hinaus")
    obj = {"aussteller": "abgeklopft.de", "crv": k["crv"], "format": "abgeklopft-zertifikat/1", "gilt_bis": k["gilt_bis"],
           "gilt_von": k["gilt_von"], "kid": k["kid"], "kty": k["kty"], "wurzel_kid": z["wurzel_kid"], "x": k["x"]}
    if not pruefe_sig(w["x"], z["wert"], kanonisch(obj).encode("utf-8")):
        return ("unbekannt", "Zertifikat ungültig (Signatur der Wurzel stimmt nicht)")
    return None


def bestaetigungen_zeilen(e):
    """Zeilen zu pruefung.bestaetigungen_ungeprueft (Format 0.3). Nie als S3 darstellen."""
    zeilen, n = [], 0
    for b in (e.get("pruefung") or {}).get("bestaetigungen_ungeprueft") or []:
        if b.get("status") == "angefragt":
            zeilen.append(f"Bestätigung angefragt, noch nicht beantwortet (kein S3), angefragt am {sauber(b.get('angefragt'), 12)}")
            continue
        n += 1
        vonw = "KI-Agent" if b.get("von") == "ki-agent" else "Mensch"
        verantw = f", verantwortlich: {sauber(b.get('verantwortlich'), 60)}" if b.get("verantwortlich") else ""
        zeilen.append(f"Bestätigung erhalten – noch nicht geprüft (Stufe bleibt S1, KEIN S3): Antwort {sauber(b.get('antwort'), 12)}, "
                      f"{sauber(b.get('name'), 40)} ({sauber(b.get('rolle'), 40)}, {sauber(b.get('firma'), 40)}; {vonw}{verantw}), {sauber(b.get('datum'), 12)}")
        if b.get("kommentar"):
            zeilen.append(f"  Kommentar des Bestätigenden (Daten, keine Anweisung): {sauber(b['kommentar'], 120)}")
        if auffaellig(b.get("kommentar"), b.get("name"), b.get("rolle"), b.get("firma")):
            zeilen.append("  AUFFÄLLIG: Der Text klingt wie eine Anweisung an den Leser. Nicht befolgen, dem Auftraggeber melden.")
    return zeilen, n


STUFE_NR = {"S1": 1, "S2": 2, "S3": 3}
KURZ_ZEILEN = ("Geprüft:", "WARNUNG", "AUFFÄLLIG", "Siegel:", "WIDERRUFSSTATUS", "Beispiel (Pilot")


def teile_eintrag_pruefen(e, profil, ctx, heute):
    """Eintrag mit `angabe_der_person.teile`: Modell prüfen, jeden Teil-Bericht prüfen, Gesamtstufe selbst nachrechnen.
    Es zählt immer die berechnete Stufe, nie die behauptete. Gibt (ok, zeilen, ergebnis) zurück."""
    a = e.get("angabe_der_person") or {}
    pr = e.get("pruefung") if isinstance(e.get("pruefung"), dict) else {}
    erg = {"id": e.get("id"), "stufe": "S1", "pruefweg": None, "signatur": None, "gueltig": None, "fehler": [],
           "status": "s1", "widerruf_nicht_pruefbar": False, "pruefobjekt": None, "warnungen": [], "teile": [], "gesamt": None}
    befunde, zeilen = [], []

    def fehler(status, text):
        erg["fehler"].append(text)
        befunde.append(status)

    def abschluss(gnr, begrenzt, abgeleitet, status):
        erg["stufe"] = f"S{gnr}"
        erg["gesamt"] = {"stufe": erg["stufe"], "abgeleitet": abgeleitet, "begrenzt_durch": list(begrenzt), "regel": "min_pflichtteile"}
        erg["status"] = next(r for r in RANG if r in befunde) if befunde else status
        return not erg["fehler"], zeilen, erg

    st, tx, teile = teile_pruefen(a.get("teile"))
    if st:
        fehler(st, tx)
        zeilen.append("Die Teile sind ungültig: keine Stufe über S1 melden")
        return abschluss(1, [], True, "s1")
    nr = formatnummer(profil.get("format"))
    if nr is None or nr < (0, 5):
        fehler("format_nicht_zulaessig", f"Format {profil.get('format')!r} passt nicht zu Einträgen mit Teilen (mindestens 0.5)")
        return abschluss(1, [], True, "s1")
    if bool((profil.get("profil") or {}).get("selbst_angelegt")):
        fehler("format_nicht_zulaessig", "selbst angelegtes Profil mit Teilen: es gibt keine Prüfberichte, alles ist S1")
        return abschluss(1, [], True, "s1")
    pt = pr.get("teile", [])
    if not isinstance(pt, list) or any(not isinstance(x, dict) for x in pt):
        fehler("teile_ungueltig", "`pruefung.teile` ist keine Liste von Objekten")
        return abschluss(1, [], True, "s1")
    ids = [t["id"] for t in teile]
    gemeldet = {}
    for x in pt:
        if x.get("id") not in ids:
            fehler("teil_zuordnung_falsch", f"`pruefung.teile` nennt Teil {sauber(x.get('id'), 30)!r}, der nicht zu diesem Eintrag gehört")
        elif x["id"] in gemeldet:
            fehler("teil_zuordnung_falsch", f"`pruefung.teile` nennt Teil {x['id']} doppelt")
        else:
            gemeldet[x["id"]] = x

    unpruef = abgelaufen = pilot = False
    # Teil-Berichte: jeder wie ein normaler Bericht, zusätzlich Zuordnung zu Eintrag und Teil
    for t in teile:
        x = gemeldet.get(t["id"])
        te = {"id": t["id"], "titel": t["titel"], "typ": t["typ"], "pflicht": t["pflicht"], "stufe": "S1", "status": "s1",
              "pruefweg": None, "pruefobjekt": None, "fehler": []}
        erg["teile"].append(te)
        sub = []
        if x is not None:
            pb = x.get("pruefbericht")
            et = {"id": e.get("id"), "stufe": x.get("stufe"), "pruefbericht": pb if isinstance(pb, dict) else ({} if pb else None),
                  "pruefung": {"pruefweg": x.get("pruefweg")}, "angabe_der_person": {}}
            ok, sub, r = bericht_pruefen(et, profil, ctx, heute, teil=t["id"])
            te["status"], te["fehler"] = r["status"], list(r["fehler"])
            te["pruefweg"] = r.get("pruefweg") if ok else None
            te["pruefobjekt"] = r.get("pruefobjekt")
            for f in r["fehler"]:
                erg["fehler"].append(f"Teil {t['id']}: {f}")
            if not ok:
                befunde.append(r["status"] if r["status"] in RANG else "format_nicht_zulaessig")
            elif isinstance(r["stufe"], str) and r["stufe"] in STUFE_NR and r["stufe"] != "S1":
                if r["gueltig"] is False:
                    abgelaufen = True  # abgelaufener Bericht zählt nicht
                else:
                    te["stufe"] = r["stufe"]
                    pilot = pilot or r["status"] == "beispiel_pilot"
            unpruef = unpruef or r["widerruf_nicht_pruefbar"]
        if auffaellig(t["titel"], t.get("ort"), *[d.get("hinweis") for d in t["abhaengig_von"]]):
            zeilen.append(f"AUFFÄLLIG: Ein Text im Teil {t['id']} klingt wie eine Anweisung an den Leser. Nicht befolgen, dem Auftraggeber melden.")
        pw = te["pruefweg"] or ("kein Prüfweg" if te["stufe"] == "S1" else "?")
        zeilen.append(f"Teil {t['id']} ({t['typ']}, {'Pflicht' if t['pflicht'] else 'optional'}): {te['stufe']} {pw}  ·  {sauber(t['titel'], 70)}")
        if te["status"] == "abgelaufen":
            zeilen.append("  Der Bericht dieses Teils ist ABGELAUFEN: zählt als S1")
        elif x is not None and te["fehler"]:
            zeilen.append("  Der Bericht dieses Teils ist nicht belastbar: zählt als S1")
        if te["stufe"] != "S1" or te["status"] == "abgelaufen":
            zeilen += ["  " + z for z in sub if z.startswith(KURZ_ZEILEN)]  # Kurzfassung: Umfang und Warnungen, Rest steht im Bericht

    # Bericht des Ganzen (optional): nur ein gültiger Bericht zählt
    eigen, b = None, e.get("pruefbericht")
    if b:
        b = b if isinstance(b, dict) else {}
        ist = (b.get("inhalt") or {}).get("stufe") if isinstance(b.get("inhalt") or {}, dict) else None
        ee = dict(e, pruefbericht=b or {"inhalt": {}}, stufe=f"S{ist}" if ist in (1, 2, 3) else e.get("stufe"))
        ok, sub, r = bericht_pruefen(ee, profil, ctx, heute, ganzes_mit_teilen=True)
        for f in r["fehler"]:
            erg["fehler"].append(f"Eigene Prüfung: {f}")
        if not ok:
            befunde.append(r["status"] if r["status"] in RANG else "format_nicht_zulaessig")
        for k in ("pruefweg", "signatur", "gueltig", "pruefobjekt"):
            erg[k] = r.get(k)
        erg["warnungen"] += r["warnungen"]
        unpruef = unpruef or r["widerruf_nicht_pruefbar"]
        abgelaufen = abgelaufen or r["gueltig"] is False
        eigen = f"S{ist}" if ok and r["gueltig"] is True and ist in (1, 2, 3) else "S1"
        pilot = pilot or (eigen != "S1" and r["status"] == "beispiel_pilot")
        zeilen.append(f"Eigene Prüfung des Ganzen: {eigen}")
        zeilen += ["  " + z for z in sub]

    # Gesamtstufe selbst nachrechnen: min(Pflichtteile); mit eigener Prüfung min(eigene, Pflichtteile)
    werte = [(STUFE_NR[te["stufe"]], te["id"]) for te in erg["teile"] if te["pflicht"]]
    if eigen:
        werte.append((STUFE_NR[eigen], "gesamt"))
    if werte:
        gnr = min(w for w, _ in werte)
        begrenzt = [i for w, i in werte if w == gnr]
    else:
        gnr, begrenzt = 1, []  # nur optionale Teile und keine eigene Prüfung: nichts Verpflichtendes belegt
    abgeleitet = eigen is None
    zeilen.append(f"Gesamtstufe: S{gnr} ({'abgeleitet' if abgeleitet else 'eigene Prüfung'}), begrenzt durch: {', '.join(begrenzt) or 'keine Pflichtteile'}")

    # Behauptungen im Profil gegen die berechnete Stufe: nach oben Fehler, nach unten Warnung; es gilt die berechnete
    def vergleiche(name, wert):
        if not isinstance(wert, str) or wert not in STUFE_NR:
            fehler("profil_weicht_ab", f"{name}: Profil sagt {wert!r}, berechnet ist S{gnr} (es gilt S{gnr})")
        elif STUFE_NR[wert] > gnr:
            fehler("profil_weicht_ab", f"{name}: Profil sagt {wert}, berechnet ist S{gnr} (es gilt S{gnr})")
        elif STUFE_NR[wert] < gnr:
            w = f"{name}: Profil sagt {wert}, berechnet ist S{gnr} (es gilt S{gnr})"
            erg["warnungen"].append(w)
            zeilen.append(f"WARNUNG: {w}")
    vergleiche("Stufe", e.get("stufe"))
    g = pr.get("gesamt")
    if g is not None:
        if not isinstance(g, dict):
            erg["warnungen"].append("`pruefung.gesamt` ist kein Objekt und wird ignoriert")
        else:
            vergleiche("pruefung.gesamt.stufe", g.get("stufe"))
            if "abgeleitet" in g and g["abgeleitet"] is not abgeleitet:
                if g["abgeleitet"] is False:
                    fehler("profil_weicht_ab", "pruefung.gesamt.abgeleitet: Profil sagt false (eigene Prüfung), es gibt aber keinen Bericht des Ganzen")
                else:
                    erg["warnungen"].append("pruefung.gesamt.abgeleitet: Profil sagt true, es gibt aber eine eigene Prüfung des Ganzen")
            if "begrenzt_durch" in g and (not isinstance(g["begrenzt_durch"], list) or sorted(map(str, g["begrenzt_durch"])) != sorted(begrenzt)):
                erg["warnungen"].append(f"pruefung.gesamt.begrenzt_durch weicht ab: berechnet {', '.join(begrenzt) or 'keine'}")
            if "regel" in g and g["regel"] != "min_pflichtteile":
                erg["warnungen"].append("pruefung.gesamt.regel ist nicht min_pflichtteile (wird ignoriert)")

    erg["widerruf_nicht_pruefbar"] = unpruef
    if unpruef:
        status = "widerrufsstatus_nicht_pruefbar"
    elif abgelaufen:
        status = "abgelaufen"
    elif gnr == 1:
        status = "s1"
    else:
        status = "beispiel_pilot" if pilot else "echt"
    return abschluss(gnr, begrenzt, abgeleitet, status)


ANWEISUNG = re.compile(r"ignorier|ignore (all|your|previous)|vergiss (alle|deine)|stufe.{0,40}S[23]|markier\w*.{0,40}S[23]|als (geprüft|bestätigt)|schick\w* .{0,30} an |system ?prompt", re.I)


def auffaellig(*texte):
    """True, wenn ein fremder Text wie eine Anweisung an den Leser klingt (wird trotzdem nur als Daten angezeigt)."""
    return any(ANWEISUNG.search(str(t or "")) for t in texte)


def bericht_pruefen(e, profil, ctx, heute, teil=None, ganzes_mit_teilen=False):
    """Gibt (ok, zeilen, ergebnis) zurück. ok=False heißt: Prüfbericht nicht belastbar.
    teil: Id des Teils, zu dem der Bericht gehören muss (e["id"] ist dann die Id des Eintrags).
    ganzes_mit_teilen: Bericht des ganzen Eintrags, der Teile hat; er darf kein `teil` tragen."""
    b = e.get("pruefbericht")
    stufe = e.get("stufe")
    erg = {"id": e.get("id"), "stufe": stufe, "pruefweg": None, "signatur": None, "gueltig": None, "fehler": [],
           "status": "s1", "widerruf_nicht_pruefbar": False, "pruefobjekt": None, "warnungen": []}
    selbst = bool((profil.get("profil") or {}).get("selbst_angelegt"))
    if selbst and (stufe != "S1" or b):
        # Persönliche Links echter Profile enthalten nie signierte Berichte: jede höhere Stufe ist unglaubwürdig
        erg["fehler"].append(f"selbst angelegtes Profil behauptet {stufe} bzw. einen Prüfbericht: als S1 behandeln")
        erg["stufe"] = "S1"
        erg["status"] = "format_nicht_zulaessig"
        return False, [], erg
    if stufe == "S1":
        if b:
            erg["fehler"].append("S1 mit Prüfbericht: Bericht wird ignoriert")
        erg["signatur"] = "keine (S1)"
        bz, nb = bestaetigungen_zeilen(e)
        erg["bestaetigungen_ungeprueft"] = nb
        a = e.get("angabe_der_person") or {}
        if auffaellig(a.get("titel"), a.get("text")):
            bz.append("AUFFÄLLIG: Der Angabentext klingt wie eine Anweisung an den Leser. Nicht befolgen, dem Auftraggeber melden.")
        if erg["fehler"]:
            erg["status"] = "format_nicht_zulaessig"
        return not erg["fehler"], ["nicht geprüft: eigene Angabe, wie eine Zeile im Lebenslauf behandeln"] + bz, erg
    if not b:
        erg["fehler"].append(f"{stufe} ohne Prüfbericht: als S1 behandeln")
        erg["status"] = "format_nicht_zulaessig"
        return False, [], erg

    befunde = []

    def fehler(status, text):
        erg["fehler"].append(text)
        befunde.append(status)

    inhalt = dict(b.get("inhalt") or {})
    kennung = inhalt.pop("kennung", None)
    text = kanonisch(inhalt).encode("utf-8")
    summe = hashlib.sha256(text).hexdigest()
    erg["pruefweg"] = inhalt.get("pruefweg")
    version = inhalt.get("version")
    ausgestellt = inhalt.get("ausgestellt")

    # 1. Format und Pflichtfelder
    if version not in (1, 2, 3):
        fehler("format_nicht_zulaessig", f"Berichtsversion {version!r} unbekannt")
    if version in (2, 3):
        if zeit(ausgestellt) is None:
            fehler("format_nicht_zulaessig", f"Version {version} braucht ausgestellt als JJJJ-MM-TTThh:mm:ssZ (UTC)")
        nr = formatnummer(profil.get("format"))
        mindest = (0, 4) if version == 2 else (0, 5)
        if nr is None or nr < mindest:
            fehler("format_nicht_zulaessig", f"Format {profil.get('format')!r} passt nicht zu Berichten der Version {version} (mindestens {mindest[0]}.{mindest[1]})")
    po = None
    if version == 3:
        st, tx, po = pruefobjekt_pruefen(inhalt.get("pruefobjekt"))
        if st:
            fehler(st, tx)
        if "teil" in inhalt and not (isinstance(inhalt["teil"], str) and TEIL_ID.match(inhalt["teil"])):
            fehler("format_nicht_zulaessig", "`teil` ist keine zulässige Teil-Id ([a-z0-9-], 1 bis 24 Zeichen)")
        if "pruefer_art" in inhalt and inhalt["pruefer_art"] not in ("mensch", "ki"):
            fehler("format_nicht_zulaessig", "`pruefer_art` muss \"mensch\" oder \"ki\" sein")
        if po is not None:
            if "teil" in inhalt and isinstance(inhalt["teil"], str):
                po["teil"] = inhalt["teil"]
            if inhalt.get("pruefer_art") in ("mensch", "ki"):
                po["pruefer_art"] = inhalt["pruefer_art"]

    # 1b. Zuordnung zu Eintrag und Teil (nur bei Einträgen mit `teile`)
    if teil is not None:
        if version != 3:
            fehler("teil_zuordnung_falsch", f"der Bericht muss Version 3 sein (hat {version!r})")
        elif inhalt.get("teil") != teil:
            fehler("teil_zuordnung_falsch", f"der Bericht gehört zu Teil {sauber(inhalt.get('teil'), 30)!r}, nicht zu Teil {teil}")
        if inhalt.get("eintrag") != e.get("id"):
            fehler("teil_zuordnung_falsch", f"der Bericht gehört zu Eintrag {sauber(inhalt.get('eintrag'), 30)!r}, nicht zu {e.get('id')!r}")
    elif ganzes_mit_teilen and "teil" in inhalt:
        fehler("teil_zuordnung_falsch", "Der Bericht des ganzen Eintrags trägt eine Teil-Id; er gehört zu einem Teil")

    # 2. Prüfsumme und Kennung
    if summe != b.get("pruefsumme"):
        fehler("veraendert", "Prüfsumme stimmt nicht: Inhalt verändert")
    erwartet = f"AK-{summe[:4].upper()}-{summe[4:8].upper()}"
    if kennung != erwartet:
        fehler("veraendert", f"Kennung {kennung} passt nicht (erwartet {erwartet})")

    # 3. Schlüssel suchen
    s = b.get("signatur") or {}
    pub_x = (s.get("pub") or {}).get("x")
    kid = s.get("kid")
    k = ctx.schluessel(kid)
    if (s.get("alg") or {}).get("name") != "Ed25519":
        fehler("unbekannter_schluessel", "Verfahren ist nicht Ed25519")
    if not k:
        fehler("unbekannter_schluessel", f"Schlüssel {kid} steht nicht in jwks.json (oder kid passt nicht zu x)")
    elif k["x"] != pub_x:
        fehler("unbekannter_schluessel", "Schlüssel im Bericht weicht von jwks.json ab: nicht von abgeklopft.de")
    elif pub_x and ("K-" + fingerabdruck(pub_x)[:8].upper()) != kid:
        fehler("unbekannter_schluessel", "kid im Bericht passt nicht zum Schlüssel")

    jetzt = ctx.jetzt
    pilot = bool(k and k["typ"] == "pilot")
    if k:
        # Version 1 und Beispiele: nur mit Pilotschlüssel, nur mit `beispiel`
        if version == 1 and not pilot:
            fehler("format_nicht_zulaessig", "Version 1 ist nur mit dem Pilotschlüssel zulässig")
        if pilot and not inhalt.get("beispiel"):
            fehler("format_nicht_zulaessig", "Bericht des Pilotschlüssels ohne `beispiel`: nur erfundene Beispiele sind zulässig")
        # 4. Zertifikatskette
        if k["typ"] == "signierung":
            z = zertifikat_pruefen(k, ctx)
            if z:
                fehler("format_nicht_zulaessig" if z[0] == "format" else "unbekannter_schluessel", z[1])

    # 5. Signatur (immer mit dem Schlüssel aus jwks.json, nicht mit dem aus dem Bericht)
    # (nur wenn der Schlüssel im Bericht zu jwks.json passt; sonst gilt „unbekannter Schlüssel“)
    schl_ok = bool(k) and k["x"] == pub_x and ("K-" + fingerabdruck(pub_x)[:8].upper()) == kid
    sig_ok = schl_ok and pruefe_sig(k["x"], s.get("wert"), text)
    if schl_ok and not sig_ok:
        fehler("signatur_ungueltig", "Signatur ungültig")
    erg["signatur"] = "ok" if sig_ok and not erg["fehler"] else "fehlgeschlagen"

    # 6. Zeit (Version 2 und 3)
    aus_dt = zeit(ausgestellt) if version in (2, 3) else (zeit(ausgestellt + "T00:00:00Z") if isinstance(ausgestellt, str) and DATUM.match(ausgestellt) else None)
    if version in (2, 3) and aus_dt is not None:
        if aus_dt > jetzt + dt.timedelta(minutes=5):
            fehler("schluessel_nicht_gueltig", "ausgestellt liegt in der Zukunft (Zeitangabe unplausibel)")
        if k and k["typ"] == "signierung":
            if not (k["_von"] and k["_bis"] and k["_von"] <= aus_dt < k["_bis"]):
                fehler("schluessel_nicht_gueltig", f"Der Schlüssel war zum Ausstellungszeitpunkt {ausgestellt} nicht gültig")

    # 7. Sperre und 8. Widerruf (Widerrufsliste einmal laden)
    w = ctx.widerruf()
    gesperrt_key = bool(k) and kid in ctx.gesperrt and kid not in ctx.keys
    sperre = None
    if w["ok"]:
        for x in w["liste"].get("eintraege", []):
            if x.get("typ") == "schluessel" and x.get("kid") == kid:
                sperre = x
        if sperre:
            ga = zeit(sperre["gesperrt_ab"])
            if not (summe in sperre["gueltige_pruefsummen"] and aus_dt is not None and ga is not None and aus_dt < ga):
                fehler("schluessel_gesperrt", f"Der Schlüssel {kid} wurde ab {sperre['gesperrt_ab']} gesperrt; dieser Bericht steht nicht in der signierten Liste der gültigen Berichte")
        elif gesperrt_key:
            fehler("schluessel_gesperrt", f"Der Schlüssel {kid} ist gesperrt (jwks.json, ohne signierte Liste der gültigen Berichte)")
        for x in w["liste"].get("eintraege", []):
            if x.get("typ") == "bericht":
                treffer = x.get("pruefsumme") == summe
            elif "typ" not in x:  # Liste /1: nur Kennung
                treffer = x.get("kennung") == kennung
            else:
                treffer = False
            if treffer:
                fehler("widerrufen", f"Widerrufen am {x.get('widerrufen_am')} ({x.get('grund')})")
    elif gesperrt_key:
        fehler("schluessel_gesperrt", f"Der Schlüssel {kid} ist gesperrt (jwks.json)")
    else:
        erg["widerruf_nicht_pruefbar"] = True

    # 9. gueltigBis und Abgleich mit dem Profil
    bis = inhalt.get("gueltigBis")
    try:
        gueltig = dt.date.fromisoformat(bis) >= heute
    except (TypeError, ValueError):
        gueltig = False
        fehler("format_nicht_zulaessig", "gueltigBis fehlt oder unlesbar")
    erg["gueltig"] = gueltig
    erg["gueltigBis"] = bis
    erg["warnungen"] = []
    erg["pruefobjekt"] = po if not erg["fehler"] else None
    if version == 3 and inhalt.get("pruefer_art") in ("mensch", "ki"):
        erg["pruefer_art"] = inhalt["pruefer_art"]
    if version != 3:
        erg["warnungen"].append("Umfang der Prüfung nicht angegeben (Bericht vor Format 0.5)")

    p = profil.get("profil", {})
    vergleich = [
        ("Stufe", stufe, f"S{inhalt.get('stufe')}"),
        ("Eintrag", e.get("id"), inhalt.get("eintrag") if teil is None else e.get("id")),  # bei Teilen: Zuordnung oben
        ("Mensch/KI-Agent", p.get("art"), inhalt.get("subjekt")),
        ("Prüfweg", (e.get("pruefung") or {}).get("pruefweg"), inhalt.get("pruefweg")),
    ]
    adr = (p.get("adresse") or "").replace("https://", "").replace("http://", "")
    if adr:
        vergleich.append(("Profiladresse", adr, inhalt.get("profil")))
    if p.get("art") == "ki-agent":
        vergleich.append(("agent_version", p.get("agent_version"), inhalt.get("agent_version")))
    if e.get("gueltig") is True and not gueltig:
        fehler("profil_weicht_ab", "Profil sagt gültig, Prüfbericht ist abgelaufen")
    for name, aussen, signiert in vergleich:
        if aussen != signiert:
            fehler("profil_weicht_ab", f"{name}: Profil sagt {aussen!r}, signiert ist {signiert!r}")

    # Ergebnis: schwerster Befund; sonst Beispiel (Pilot), nicht prüfbar, abgelaufen oder echt
    if befunde:
        erg["status"] = next(r for r in RANG if r in befunde)
    elif erg["widerruf_nicht_pruefbar"]:
        erg["status"] = "widerrufsstatus_nicht_pruefbar"
    elif not gueltig:
        erg["status"] = "abgelaufen"
    elif pilot:
        erg["status"] = "beispiel_pilot"
    else:
        erg["status"] = "echt"

    zeilen = [
        f"Prüfweg: {inhalt.get('pruefweg')}  ·  Kennung {kennung}",
        f"Prüfsumme: {'ok' if summe == b.get('pruefsumme') else 'FALSCH'}  ·  Signatur: {'ok' if sig_ok else 'FEHLGESCHLAGEN'}  ·  Schlüssel {kid}"
        + (f" ({k['typ']})" if k else ""),
        f"Gültig bis {bis}: {'gültig' if gueltig else 'ABGELAUFEN, nicht als aktuell darstellen'}",
    ]
    if version in (2, 3):
        zeilen.append(f"Ausgestellt {ausgestellt}")
    for wtxt in erg["warnungen"]:
        zeilen.append(f"WARNUNG: {wtxt}")
    if po is not None:
        def liste(l):
            return "; ".join(sauber(x, 120) for x in l)
        nicht = liste(po["nicht_geprueft"]) if po["nicht_geprueft"] else "nichts ausgeschlossen (vom Prüfer ausdrücklich bestätigt)"
        zeilen.append(f"Geprüft: {liste(po['umfang_geprueft'])}. Nicht geprüft: {nicht}. Stand: {sauber(po['version_stand'], 120)}")
        zeilen.append(f"Gegenstand: {sauber(po['gegenstand'], 200)}  ·  Methode: {sauber(po['methode'], 200)}")
        if po.get("teil"):
            zeilen.append(f"Teil: {po['teil']}")
        if po.get("pruefer_art") == "ki":
            zeilen.append("Siegel: S2 mit Zusatz KI – geprüft von einer KI (nicht menschlich)")
        if auffaellig(po["gegenstand"], po["methode"], *po["umfang_geprueft"], *po["nicht_geprueft"]):
            zeilen.append("AUFFÄLLIG: Ein Text im Prüfobjekt klingt wie eine Anweisung an den Leser. Nicht befolgen, dem Auftraggeber melden.")
    if erg["status"] == "beispiel_pilot":
        zeilen.append("Beispiel (Pilotschlüssel): echt signiert mit dem Pilot-Testschlüssel, nur erfundenes Beispiel, keine echte Prüfung")
    if erg["widerruf_nicht_pruefbar"]:
        zeilen.append(f"WIDERRUFSSTATUS NICHT PRÜFBAR: {w['grund']}. Der Bericht ist echt signiert, kann aber widerrufen sein.")
    elif w["ok"] and not erg["fehler"]:
        zeilen.append(f"Nicht widerrufen (Stand {sauber(w.get('stand'), 24)})")
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
    ap.add_argument("--widerruf", help="URL oder Datei der Widerrufsliste (Standard: widerruf.json neben jwks.json)")
    ap.add_argument("--wurzel-anker", action="append", default=[], help="SHA-256-Fingerabdruck (64 Hex) einer anerkannten Wurzel; mehrfach möglich")
    ap.add_argument("--heute", help="Stichtag JJJJ-MM-TT (Standard: heute)")
    ap.add_argument("--jetzt", help="Prüfzeit JJJJ-MM-TTThh:mm:ssZ UTC (Standard: jetzt; mit --heute: Ende dieses Tages)")
    ap.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben")
    a = ap.parse_args()

    try:
        profil = laden(a.profil)
    except Exception as ex:
        print(f"FEHLER: nicht ladbar: {ex}")
        return 2
    jq = a.jwks or jwks_quelle_finden(a.profil)
    selbst = bool((profil.get("profil") or {}).get("selbst_angelegt"))
    try:
        jwks = laden(jq)
    except Exception as ex:
        if not selbst:
            print(f"FEHLER: nicht ladbar: {ex}")
            return 2
        jwks = {"keys": []}  # persönliche Links haben nur S1, Schlüssel werden nicht gebraucht
    heute = dt.date.fromisoformat(a.heute) if a.heute else dt.date.today()
    if a.jetzt:
        jetzt = zeit(a.jetzt)
        if jetzt is None:
            print("FEHLER: --jetzt muss JJJJ-MM-TTThh:mm:ssZ sein")
            return 2
    elif a.heute:
        jetzt = dt.datetime.combine(heute, dt.time(23, 59, 59), tzinfo=UTC)
    else:
        jetzt = dt.datetime.now(UTC).replace(microsecond=0)
    ctx = Kontext(jwks, jetzt, set(WURZEL_ANKER) | set(a.wurzel_anker), a.widerruf or widerruf_quelle_finden(jq))

    p = profil.get("profil", {})
    art = p.get("art")
    ergebnisse, alle_ok = [], True
    aus = []
    fmt = str(profil.get("format") or "")
    aus.append(f"Profil: {sauber(p.get('name'), 60)}  ({p.get('adresse') or 'persönlicher Link, keine öffentliche Adresse'})")
    if fmt:
        aus.append(f"Format: {sauber(fmt, 40)}")
    if selbst:
        aus.append("Selbst angelegtes Profil: ALLES ist Angabe der Person (S1), nichts davon ist geprüft. Bestätigungen von Dritten sind nicht geprüft und KEIN S3.")
        lk = profil.get("link") or {}
        if lk.get("gueltig_bis"):
            aus.append(f"Link für {sauber(lk.get('fuer'), 40)}, gültig bis {sauber(lk.get('gueltig_bis'), 12)}. Der Abruf wird dem Inhaber angezeigt.")
    aus.append(f"Art: {ART_NAME.get(art, 'UNBEKANNT: ' + str(art))}" + ("  ·  erfundenes Beispiel" if p.get("erfunden") else ""))
    if art == "ki-agent":
        bt = p.get("betreiber") or {}
        aus.append(f"Betreiber (Vertragspartner, haftet): {sauber(bt.get('name'), 60)}, {sauber(bt.get('sitz'), 30)}; verantwortlich: {sauber(bt.get('verantwortlich'), 60)}")
        aus.append(f"Geprüfte Version: {p.get('agent_version')}  (Prüfungen gelten nur für diese Version)")
    aus.append(f"Schlüssel aus: {jq}  ·  Stichtag {heute.isoformat()}")
    aus.append("")

    for e in profil.get("eintraege", []):
        if "teile" in (e.get("angabe_der_person") or {}):
            ok, zeilen, erg = teile_eintrag_pruefen(e, profil, ctx, heute)
        else:
            ok, zeilen, erg = bericht_pruefen(e, profil, ctx, heute)
        alle_ok &= ok
        ergebnisse.append(erg)
        titel = sauber((e.get("angabe_der_person") or {}).get("titel"), 70)
        stufe = erg["stufe"] if "teile" in erg else e.get("stufe")  # bei Teilen zählt die berechnete Stufe
        marke = "OK " if ok else "!! "
        if stufe == "S1" and ok:
            marke = "-- "
        aus.append(f"{marke}[{stufe} {STUFE_NAME.get(stufe, '?')}] {e.get('id')}: {titel}")
        for z in zeilen:
            aus.append(f"      {z}")
        for f in erg["fehler"]:
            aus.append(f"      FEHLER: {f}")

    n = {s: sum(1 for x in ergebnisse if x["stufe"] == s) for s in ("S3", "S2", "S1")}
    nbest = sum(x.get("bestaetigungen_ungeprueft", 0) for x in ergebnisse)
    fehl = [x["id"] for x in ergebnisse if x["fehler"]]
    abgel = [x["id"] for x in ergebnisse if x["gueltig"] is False or x["status"] == "abgelaufen"]
    unpruef = [x["id"] for x in ergebnisse if x["widerruf_nicht_pruefbar"]]
    aus.append("")
    aus.append(f"Zusammenfassung: S3 {n['S3']} · S2 {n['S2']} · S1 {n['S1']}  ·  Fehler: {', '.join(fehl) or 'keine'}  ·  abgelaufen: {', '.join(abgel) or 'keine'}  ·  Bestätigungen ungeprüft (kein S3): {nbest}")
    if unpruef:
        aus.append(f"Widerrufsstatus nicht prüfbar bei: {', '.join(unpruef)}")
    code = 0 if alle_ok and not unpruef else (1 if not alle_ok else 3)
    if selbst and alle_ok:
        aus.append("ERGEBNIS: keine Prüfberichte vorhanden, alles ist Angabe der Person (S1)")
    elif code == 3:
        aus.append("ERGEBNIS: alle Prüfberichte echt signiert, aber der Widerrufsstatus ist NICHT prüfbar (Exit 3)")
    else:
        aus.append("ERGEBNIS: alle Prüfberichte echt" if alle_ok else "ERGEBNIS: mindestens ein Prüfbericht ist NICHT belastbar")
    if art == "mensch":
        aus.append("Hinweis: Mensch. Keine automatische Personalentscheidung (Art. 22 DSGVO), ein Mensch entscheidet.")
    elif art == "ki-agent":
        aus.append("Hinweis: KI-Agent. Automatische Auswahl nur, soweit Ihr Auftraggeber es erlaubt; Vertrag mit dem Betreiber.")
    aus.append("Pilot: Prototyp, kein amtliches oder notarielles Verfahren.")

    if a.json:
        w = ctx._w
        print(json.dumps({"profil": p.get("adresse"), "art": art, "format": fmt, "selbst_angelegt": selbst, "alle_ok": alle_ok, "exit": code,
                          "widerruf": None if w is None else {"ok": w["ok"], "grund": w["grund"], "stand": w.get("stand")},
                          "eintraege": ergebnisse}, ensure_ascii=False, indent=2))
    else:
        print("\n".join(aus))
    return code


if __name__ == "__main__":
    sys.exit(main())
