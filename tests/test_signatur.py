#!/usr/bin/env python3
"""Test der Prüfskripte (Python und Node) gegen die Testfälle der Signatur-Spezifikation (Abschnitt 8).
Die Fälle entstehen bei jedem Lauf neu mit WEGWERF-Schlüsseln (tests/signatur_erzeugen.mjs); nichts davon ist ein echter Schlüssel.
Je Fall muss jedes Skript denselben Exit-Code und (bei --json) denselben Status liefern.
Dazu: Beide Skills müssen dieselben Skripte enthalten.
Aufruf: python tests/test_signatur.py   (ohne Netz; braucht: pip install cryptography, Node 18+)"""
import hashlib, json, os, subprocess, sys, tempfile
W = os.path.dirname(os.path.abspath(__file__)); R = os.path.dirname(W)
sys.stdout.reconfigure(encoding="utf-8")
ok = fehl = 0


def pruef(b, n, d=""):
    global ok, fehl
    if b:
        ok += 1; print("  ok  ", n)
    else:
        fehl += 1; print("  FEHL", n, d)


def skript(skill, spr):
    return os.path.join(R, "skills", skill, "scripts", "pruefen." + ("py" if spr == "py" else "mjs"))


with tempfile.TemporaryDirectory() as tmp:
    g = subprocess.run(["node", os.path.join(W, "signatur_erzeugen.mjs"), tmp], capture_output=True, text=True, encoding="utf-8")
    pruef(g.returncode == 0, "Testfälle erzeugt", g.stderr)
    faelle = sorted(d for d in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, d)))
    pruef(len(faelle) >= 58, f"mindestens 58 Fälle ({len(faelle)})")
    for d in faelle:
        pfad = os.path.join(tmp, d)
        with open(os.path.join(pfad, "fall.json"), encoding="utf-8") as f:
            fall = json.load(f)
        erw = fall["erwartung"]
        jw = os.path.join(pfad, "jwks.json")  # fehlt bei Fall 29: dann zeigt --jwks auf eine fehlende Datei
        wd = os.path.join(pfad, "widerruf.json")  # fehlt bei Fall 22
        args = [os.path.join(pfad, "profil.json"), "--jwks", jw, "--widerruf", wd, "--jetzt", fall["jetzt"], "--heute", fall["heute"], "--json"]
        for fp in fall["anker"]:
            args += ["--wurzel-anker", fp]
        for spr in ("py", "mjs"):
            cmd = ([sys.executable] if spr == "py" else ["node"]) + [skript("abgeklopft-empfaenger", spr)] + args
            p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            name = f"Fall {fall['nr']:02d} {spr}: {fall['name']}"
            status, e0 = None, {}
            if p.stdout.strip().startswith("{"):
                try:
                    e0 = json.loads(p.stdout)["eintraege"][0]
                    status = e0["status"]
                except Exception:
                    status = "?"
            pruef(p.returncode == erw["exit"] and status == erw["status"], name, f"Exit {p.returncode} (erwartet {erw['exit']}), Status {status} (erwartet {erw['status']}) {p.stderr[-200:]}")
            # Zusatzerwartungen (Version 3): Prüfobjekt, pruefer_art, Teil-Id, Warnung, Textausgabe
            if "pruefobjekt" in erw:
                po = e0.get("pruefobjekt")
                gut = bool(po) == erw["pruefobjekt"]
                if erw["pruefobjekt"] and po:
                    gut = gut and all(k in po for k in ("gegenstand", "version_stand", "umfang_geprueft", "nicht_geprueft", "methode")) and "unbekannt_x" not in po
                pruef(gut, name + " [Prüfobjekt im Ergebnis]", str(po))
            if "pruefer_art" in erw:
                pruef(e0.get("pruefer_art") == erw["pruefer_art"] and (e0.get("pruefobjekt") or {}).get("pruefer_art") == erw["pruefer_art"], name + " [pruefer_art]")
            if "teil" in erw:
                pruef((e0.get("pruefobjekt") or {}).get("teil") == erw["teil"], name + " [teil]")
            if "warnung" in erw:
                pruef(any("nicht angegeben (Bericht vor Format 0.5)" in w for w in e0.get("warnungen", [])), name + " [Warnung Umfang]")
            if erw.get("pruefobjekt") or "warnung" in erw:
                tx = subprocess.run([c for c in cmd if c != "--json"], capture_output=True, text=True, encoding="utf-8").stdout
                if erw.get("pruefobjekt"):
                    pruef("Geprüft: " in tx and "Nicht geprüft: " in tx and "Stand: " in tx, name + " [Textzeile Geprüft/Nicht geprüft/Stand]")
                if erw.get("pruefer_art") == "ki":
                    pruef("geprüft von einer KI (nicht menschlich)" in tx and "S2 mit Zusatz KI" in tx, name + " [KI-Hinweis]")
                if "warnung" in erw:
                    pruef("Umfang der Prüfung nicht angegeben (Bericht vor Format 0.5)" in tx, name + " [Warnung im Text]")

# Beide Skills müssen dieselben Skripte haben
for spr in ("py", "mjs"):
    h = [hashlib.sha256(open(skript(s, spr), "rb").read()).hexdigest() for s in ("abgeklopft-empfaenger", "abgeklopft-bewerber")]
    pruef(h[0] == h[1], f"pruefen.{spr} in beiden Skills gleich")

print(f"\n{ok}/{ok+fehl} grün")
sys.exit(1 if fehl else 0)
