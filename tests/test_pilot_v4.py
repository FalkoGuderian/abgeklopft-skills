#!/usr/bin/env python3
"""Test des Pilotberichts Version 4 (Skill abgeklopft-empfaenger): pilot_skillsatz.json im Hauptordner (GESCHRIEBEN, NOCH NICHT AUSGEFÜHRT).
Voraussetzung: Der Pilotbericht wurde vorher mit  node referenzlauf/pilot/pilotbericht_ausstellen.mjs  ausgestellt (Schritt 6, vom Manager angestoßen).
Prüft mit pruefen.py und pruefen.mjs (beide Skills müssen dieselben Skripte haben):
  1. Pilotbericht ist echt (Beispiel, Pilotschlüssel): Gesamtstufe S2, Zusatzzeile Referenzlauf, Quote, Untergrenze, Fälle, Hash, vier Standardausschlüsse;
     mit --skills stimmt der Skill-Ordner überein.
  2. Fälschungen fallen durch. Sie werden im Speicher/Temp aus dem echten Bericht abgeleitet, nie im Hauptordner geschrieben:
     Hash geändert, Zahl geändert, Schwelle unterschritten (29 Fälle, Quote 0,89), Stufe auf S3 hochgesetzt (jeweils mit alter Signatur → veraendert,
     und mit gültiger Signatur eines WEGWERF-Schlüssels, den wir selbst als Pilotschlüssel eintragen → format_nicht_zulaessig), fremder Schlüssel,
     Manifest im Profil verändert (manifest_weicht_ab), Skill-Datei im Ordner verändert (--skills).
  3. alex.json und belegleser.json sind unverändert (md5) und werden von beiden Skripten mit Exit 0 geprüft.
  4. pilot_skillsatz.json steht nicht in veroeffentlichen.ps1 und nicht in _veroeffentlichen.
Aufruf: python skills/tests/test_pilot_v4.py   (ohne Netz; braucht: pip install cryptography, Node 18+). Es wird kein Schlüssel aus schluessel/ gelesen."""
import base64, copy, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

W = os.path.dirname(os.path.abspath(__file__)); R = os.path.dirname(W); ROOT = os.path.dirname(R)
PILOT = os.path.join(ROOT, "pilot_skillsatz.json"); JWKS = os.path.join(ROOT, ".well-known", "jwks.json"); WID = os.path.join(ROOT, ".well-known", "widerruf.json")
SKILL = os.path.join(ROOT, "skills", "skills", "abgeklopft-empfaenger")
# md5 der unveränderten Beispielprofile, gemessen am 2026-11-24 im Hauptordner (die im Auftrag genannten Werte stimmten nicht mit den Dateien überein)
MD5 = {"alex.json": "92185fa84b65ad1e7bdbdd2bf72f92e6", "belegleser.json": "39c2bf4d7f83a5ffcb30126e5b5c5d5b"}
STD = ["Verhalten außerhalb der Referenzdaten (andere Eingaben, andere Aufgaben, andere Sprachen oder Formate)",
       "Verhalten mit anderen Skills, anderem Modellstand oder anderer Konfiguration als im Manifest",
       "Dauerhafte Korrektheit im Betrieb und Verhalten mit anderem Gedächtnisinhalt",
       "Sicherheit gegen gezielte Angriffe, soweit nicht durch die Fälle der Klasse Fehlfall abgedeckt"]
sys.stdout.reconfigure(encoding="utf-8")
sys.dont_write_bytecode = True   # keine __pycache__ im Skill-Ordner (er gehört zum geprüften Hash)
ok = fehl = 0
UMG = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")


def pruef(b, n, d=""):
    global ok, fehl
    if b: ok += 1; print("  ok  ", n)
    else: fehl += 1; print("  FEHL", n, d)


def skript(spr, skill="abgeklopft-empfaenger"): return os.path.join(R, "skills", skill, "scripts", "pruefen." + ("py" if spr == "py" else "mjs"))


def lauf(spr, datei, extra=(), jwks=JWKS, json_aus=True):
    cmd = ([sys.executable] if spr == "py" else ["node"]) + [skript(spr), datei, "--jwks", jwks, "--widerruf", WID] + list(extra) + (["--json"] if json_aus else [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=UMG)
    e0 = {}
    if json_aus:
        try: e0 = json.loads(p.stdout)["eintraege"][0]
        except Exception: pass
    return p.returncode, e0, p.stdout


spec = importlib.util.spec_from_file_location("pruefen_py", skript("py")); pm = importlib.util.module_from_spec(spec); spec.loader.exec_module(pm)

if not os.path.exists(PILOT):
    pruef(False, "pilot_skillsatz.json fehlt: erst referenzlauf/pilot/pilotbericht_ausstellen.mjs ausführen (Schritt 6)")
    print(f"\n{ok}/{ok + fehl} grün"); sys.exit(1)
pilot = json.load(open(PILOT, encoding="utf-8"))
tmp = tempfile.mkdtemp(prefix="pilotv4-")
wegwerf = Ed25519PrivateKey.generate()
wpub = base64.urlsafe_b64encode(wegwerf.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode().rstrip("=")
wkid = "K-" + pm.fingerabdruck(wpub)[:8].upper()


def schreibe(doc, name):
    p = os.path.join(tmp, name); json.dump(doc, open(p, "w", encoding="utf-8"), ensure_ascii=False); return p


def kopie(mut, name):
    d = copy.deepcopy(pilot); mut(d); return schreibe(d, name + ".json")


def neu_signiert(mut_inhalt, mut_doc, name):
    """Inhalt ändern und mit dem Wegwerf-Schlüssel neu signieren (gültige Signatur, Schlüssel nur in einer eigenen jwks.json bekannt, wenn bekannt=True)."""
    d = copy.deepcopy(pilot); b = d["eintraege"][0]["pruefbericht"]; inh = {k: v for k, v in b["inhalt"].items() if k != "kennung"}
    mut_inhalt(inh)
    text = pm.kanonisch(inh); h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    b["inhalt"] = {**inh, "kennung": "AK-" + h[:4].upper() + "-" + h[4:8].upper()}; b["pruefsumme"] = h
    b["signatur"] = {"alg": {"name": "Ed25519"}, "kid": wkid, "pruefer": "Wegwerf", "pub": {"crv": "Ed25519", "kty": "OKP", "x": wpub}, "wert": base64.b64encode(wegwerf.sign(text.encode("utf-8"))).decode()}
    mut_doc(d)
    return schreibe(d, name + ".json")


# jwks mit dem Wegwerf-Schlüssel als Pilotschlüssel (nur im Temp-Ordner, die echte jwks.json bleibt unberührt)
jw = json.load(open(JWKS, encoding="utf-8"))
jw["keys"].append({"kid": wkid, "typ": "pilot", "crv": "Ed25519", "kty": "OKP", "x": wpub, "use": "sig", "alg": "EdDSA", "name": "Wegwerf"})
JWKS_W = schreibe(jw, "jwks_wegwerf")
E = pilot["eintraege"][0]
manifest = E["angabe_der_person"]["agent"]["skill_satz"]
inh0 = E["pruefbericht"]["inhalt"]

# ---------- 1. Pilotbericht echt ----------
print("1. Pilotbericht")
pruef(inh0["version"] == 4 and inh0["pruefweg"] == "referenzlauf" and inh0["stufe"] == 2 and inh0["pruefer_art"] == "mensch" and inh0["ergebnis"]["auswertung"] == "skript_mit_pruefer" and "beispiel" in inh0, "Bericht: Version 4, Prüfweg referenzlauf, S2, pruefer_art mensch, skript_mit_pruefer, Beispiel gekennzeichnet")
pruef(inh0["referenz"]["faelle_geheim"] == 40 and inh0["referenz"]["faelle_oeffentlich"] == 12 and inh0["ergebnis"]["laeufe_n"] >= 3 and inh0["ergebnis"]["kritische_fehler"] == 0 and inh0["ergebnis"]["trefferquote"] >= 0.9 and inh0["ergebnis"]["bestanden"] is True, "40 geheime und 12 öffentliche Fälle, mindestens 3 Läufe, 0 kritische Fehler, Quote >= 0,90, bestanden")
pruef(inh0["pruefobjekt"]["nicht_geprueft"][:4] == STD, "die vier Standardausschlüsse stehen vorn in nicht_geprueft")
pruef(pilot["format"] == "abgeklopft-nachweise/0.6" and E["pruefung"]["skill_satz_hash_aktuell"] == inh0["skill_satz"]["manifest_sha256"], "Hülle 0.6, aktueller Hash = Hash des Berichts")
res = {}
for spr in ("py", "mjs"):
    c, e0, _ = lauf(spr, PILOT)
    res[spr] = e0
    pruef(c == 0 and e0.get("status") == "beispiel_pilot" and e0.get("stufe") == "S2", f"{spr}: Pilotbericht echt (Beispiel), Exit 0, Gesamtstufe S2", f"{c} {e0.get('status')} {e0.get('fehler')}")
    m = e0.get("manifest") or {}
    pruef(m.get("hash_nachgerechnet") is True and m.get("sha256") == inh0["skill_satz"]["manifest_sha256"] and (e0.get("ergebnis") or {}).get("trefferquote") == inh0["ergebnis"]["trefferquote"], f"{spr}: Manifest-Hash nachgerechnet, Quote im Ergebnis")
    _, _, tx = lauf(spr, PILOT, json_aus=False)
    ug = str(round(inh0["ergebnis"]["untergrenze_95"] * 100, 1)).replace(".", ",").replace(",0", "")
    pruef("Siegel: Geprüft (S2), Zusatzzeile „Referenzlauf“" in tx and "40 geheim" in tx and "öffentlich 12" in tx and f"mindestens {ug} %" in tx and inh0["skill_satz"]["manifest_sha256"] in tx and all(s in tx for s in STD[:1]), f"{spr}: Text nennt Zusatzzeile Referenzlauf, Quote, Untergrenze, Fälle, Hash, Standardausschlüsse", tx[-700:])
    c2, e2, _ = lauf(spr, PILOT, ["--skills", SKILL])
    pruef(c2 == 0 and (e2.get("manifest") or {}).get("skills_ordner") == "stimmt", f"{spr}: --skills: der Skill-Ordner stimmt mit dem Manifest überein", f"{c2} {e2.get('fehler')}")
pruef(res["py"].get("status") == res["mjs"].get("status") and res["py"].get("manifest") == res["mjs"].get("manifest"), "Python und Node: gleicher Status und gleicher Manifest-Befund")

# ---------- 2. Fälschungen ----------
print("2. Fälschungen")


def hash_aendern(d): d["eintraege"][0]["pruefbericht"]["inhalt"]["skill_satz"]["manifest_sha256"] = "0" * 64
def zahl_aendern(d): d["eintraege"][0]["pruefbericht"]["inhalt"]["ergebnis"]["faelle_bestanden"] -= 1
def schwelle29(d): d["eintraege"][0]["pruefbericht"]["inhalt"]["referenz"]["faelle_geheim"] = 29
def quote089(d): d["eintraege"][0]["pruefbericht"]["inhalt"]["ergebnis"]["trefferquote"] = 0.89
def stufe3(d): d["eintraege"][0]["pruefbericht"]["inhalt"]["stufe"] = 3; d["eintraege"][0]["stufe"] = "S3"
def manifest_aendern(d): d["eintraege"][0]["angabe_der_person"]["agent"]["skill_satz"]["dateien"][0]["sha256"] = "1" * 64
def doc_stufe3(d): d["eintraege"][0]["stufe"] = "S3"


FAELLE_ALT = [("Hash im Bericht geändert", hash_aendern), ("Zahl im Ergebnis geändert", zahl_aendern), ("Schwelle unterschritten: 29 geheime Fälle", schwelle29),
              ("Schwelle unterschritten: Quote 0,89", quote089), ("Stufe auf S3 hochgesetzt", stufe3)]
for spr in ("py", "mjs"):
    for name, mut in FAELLE_ALT:
        c, e0, _ = lauf(spr, kopie(mut, "alt_" + name[:8].replace(" ", "_").replace(":", "")))
        # der Bericht fällt durch und die Fehler nennen die Verletzung von Prüfsumme und Signatur; der Status ist der schwerste Befund nach der Rangfolge der Leser
        # (format_nicht_zulaessig und manifest_weicht_ab stehen vor veraendert, wenn die geänderte Zahl auch die Stimmigkeit bricht)
        pruef(c == 1 and e0.get("status") in ("veraendert", "format_nicht_zulaessig", "manifest_weicht_ab") and any("Prüfsumme stimmt nicht" in f for f in e0.get("fehler", [])) and any("Signatur ungültig" in f for f in e0.get("fehler", [])),
              f"{spr}: {name} (alte Signatur) → fällt durch, Prüfsumme und Signatur als verletzt gemeldet", f"{c} {e0.get('status')} {e0.get('fehler')}")
    # gültige Signatur eines Wegwerf-Schlüssels, den wir selbst als Pilotschlüssel eintragen: dann greifen die Regeln zu Stufe, Schwelle und Summen
    for name, mi, md in [("29 geheime Fälle", lambda i: i["referenz"].__setitem__("faelle_geheim", 29), lambda d: None),
                         ("Quote 0,89", lambda i: i["ergebnis"].__setitem__("trefferquote", 0.89), lambda d: None),
                         ("Stufe S3 bei Prüfweg referenzlauf", lambda i: i.__setitem__("stufe", 3), doc_stufe3)]:
        c, e0, _ = lauf(spr, neu_signiert(mi, md, "neu_" + name[:6].replace(" ", "_")), jwks=JWKS_W)
        pruef(c == 1 and e0.get("status") == "format_nicht_zulaessig", f"{spr}: {name}, gültig signiert (Wegwerf-Pilotschlüssel) → format_nicht_zulaessig", f"{c} {e0.get('status')} {e0.get('fehler')}")
    c, e0, _ = lauf(spr, neu_signiert(lambda i: None, lambda d: None, "fremd"))
    pruef(c == 1 and e0.get("status") == "unbekannter_schluessel", f"{spr}: mit fremdem Schlüssel signiert → unbekannter_schluessel", f"{c} {e0.get('status')}")
    c, e0, _ = lauf(spr, kopie(manifest_aendern, "manifest"))
    pruef(c == 1 and e0.get("status") == "manifest_weicht_ab", f"{spr}: Manifest im Profil verändert → manifest_weicht_ab", f"{c} {e0.get('status')} {e0.get('fehler')}")
    # Skill-Datei im Ordner verändert (Kopie des Ordners im Temp-Ordner, der echte Ordner bleibt unberührt)
    kopieordner = os.path.join(tmp, "skill_" + spr)
    shutil.copytree(SKILL, kopieordner, ignore=shutil.ignore_patterns("__pycache__"))
    with open(os.path.join(kopieordner, "SKILL.md"), "a", encoding="utf-8") as f: f.write("\nNachträglich eingefügte Zeile.\n")
    c, e0, _ = lauf(spr, PILOT, ["--skills", kopieordner])
    pruef(c == 1 and e0.get("status") == "manifest_weicht_ab" and any("geändert: SKILL.md" in x for x in e0.get("fehler", [])), f"{spr}: Skill-Datei verändert (--skills) → manifest_weicht_ab", f"{c} {e0.get('status')} {e0.get('fehler')}")

# ---------- 3. Beispielprofile unverändert ----------
print("3. alex.json und belegleser.json")
for n, soll in MD5.items():
    p = os.path.join(ROOT, n)
    pruef(hashlib.md5(open(p, "rb").read()).hexdigest() == soll, f"{n}: md5 unverändert", hashlib.md5(open(p, "rb").read()).hexdigest())
    for spr in ("py", "mjs"):
        c, _, _ = lauf(spr, p, json_aus=False)
        pruef(c == 0, f"{spr}: {n} wird mit Exit 0 geprüft", str(c))

# ---------- 4. nicht veröffentlichen ----------
print("4. Veröffentlichung")
ps1 = open(os.path.join(ROOT, "veroeffentlichen.ps1"), encoding="utf-8", errors="replace").read()
pruef("pilot_skillsatz" not in ps1, "pilot_skillsatz.json steht nicht in veroeffentlichen.ps1")
pruef(not os.path.exists(os.path.join(ROOT, "_veroeffentlichen", "pilot_skillsatz.json")), "pilot_skillsatz.json liegt nicht in _veroeffentlichen")

# beide Skills gleich
for spr in ("py", "mjs"):
    h = [hashlib.sha256(open(skript(spr, s), "rb").read()).hexdigest() for s in ("abgeklopft-empfaenger", "abgeklopft-bewerber")]
    pruef(h[0] == h[1], f"pruefen.{spr} in beiden Skills gleich")
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{ok}/{ok + fehl} grün")
sys.exit(1 if fehl else 0)
