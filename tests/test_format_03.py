#!/usr/bin/env python3
"""Test der Prüfskripte (Python und Node) mit einer Beispielantwort im Format abgeklopft-nachweise/0.3.
Fixture: tests/fixtures/profil_0.3.json (erfundenes Testprofil, von einem LOKALEN Server erzeugt, siehe beispiel_0.3_erzeugen.mjs).
Aufruf: python tests/test_format_03.py   (ohne Netz; braucht: pip install cryptography, Node 18+)"""
import json, os, subprocess, sys, tempfile
W = os.path.dirname(os.path.abspath(__file__)); R = os.path.dirname(W)
FIX = os.path.join(W, "fixtures", "profil_0.3.json")
JW = os.path.join(W, "fixtures", "keine_jwks.json")
ok = fehl = 0


def pruef(b, n, d=""):
    global ok, fehl
    if b:
        ok += 1; print("  ok  ", n)
    else:
        fehl += 1; print("  FEHL", n, d)


def lauf(skill, sprache, datei, jwks=JW, *extra):
    s = os.path.join(R, "skills", skill, "scripts", "pruefen." + ("py" if sprache == "py" else "mjs"))
    cmd = [sys.executable, s] if sprache == "py" else ["node", s]
    p = subprocess.run(cmd + [datei, "--jwks", jwks] + list(extra), capture_output=True, text=True, encoding="utf-8")
    return p.returncode, p.stdout


with open(JW, "w") as f:  # jwks ohne Schlüssel (für 0.3 nicht nötig)
    f.write('{"keys":[]}')
for skill in ("abgeklopft-empfaenger", "abgeklopft-bewerber"):
    for spr in ("py", "mjs"):
        t = f"{skill}/{spr}"
        code, out = lauf(skill, spr, FIX)
        pruef(code == 0, f"{t}: Rückgabe 0", code)
        pruef("Format: abgeklopft-nachweise/0.3" in out, f"{t}: Format genannt")
        pruef("S3 0 · S2 0 · S1 3" in out, f"{t}: 0×S3, 0×S2, 3×S1")
        pruef("Bestätigung erhalten – noch nicht geprüft" in out and "KEIN S3" in out, f"{t}: Bestätigung = nicht geprüft, kein S3")
        pruef("Bestätigung angefragt, noch nicht beantwortet" in out, f"{t}: Anfrage ohne Antwort genannt")
        pruef("verantwortlich: Test Verantwortliche" in out, f"{t}: verantwortliche Person beim Agenten")
        pruef(out.count("AUFFÄLLIG") == 2, f"{t}: Anweisungen in Angabe und Kommentar gemeldet", out.count("AUFFÄLLIG"))
        pruef("[S3" not in out and "[S2" not in out, f"{t}: kein Eintrag als S2/S3 dargestellt")
        pruef("alles ist Angabe der Person (S1)" in out, f"{t}: Ergebnis nennt S1")
        pruef("Bestätigungen ungeprüft (kein S3): 1" in out, f"{t}: Zählung 1 erhaltene Bestätigung")
        # Fälschung: selbst angelegtes Profil behauptet S3 mit Prüfbericht
        with open(FIX, encoding="utf-8") as f:
            j = json.load(f)
        j["eintraege"][0]["stufe"] = "S3"
        j["eintraege"][0]["pruefbericht"] = {"inhalt": {}, "pruefsumme": "x"}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(j, f)
            tmp = f.name
        code, out = lauf(skill, spr, tmp)
        os.unlink(tmp)
        pruef(code == 1 and "behauptet S3" in out and "[S1" in out, f"{t}: behauptetes S3 im 0.3-Profil wird als S1 + Fehler gemeldet", code)

# ältere Formate weiter (Beispielprofil im Hauptordner, falls vorhanden)
alex = os.path.abspath(os.path.join(R, "..", "alex.json"))
jw = os.path.abspath(os.path.join(R, "..", ".well-known", "jwks.json"))
if os.path.exists(alex) and os.path.exists(jw):
    for spr in ("py", "mjs"):
        code, out = lauf("abgeklopft-empfaenger", spr, alex, jw, "--heute", "2026-11-20")
        pruef(code == 0 and "S3 2 · S2 3 · S1 3" in out, f"älteres Format (alex.json) {spr}: weiter echt", code)
os.unlink(JW)
print(f"\n{ok}/{ok+fehl} grün")
sys.exit(1 if fehl else 0)
