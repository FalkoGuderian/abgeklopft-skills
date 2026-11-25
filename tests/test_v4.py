#!/usr/bin/env python3
"""Test der Prüfskripte 0.4.0 (Python und Node) für Berichte der Version 4 (Skill-Satz, Referenzlauf).
Alle Fälle entstehen bei jedem Lauf neu mit WEGWERF-Schlüsseln (tests/v4_erzeugen.mjs); nichts davon ist ein echter Schlüssel.
Prüft:
  1. Version-4-Fälle (echt, Fälschungen, Schwelle, Stufe, Summen, Standardausschlüsse, Manifest-Hash, --skills): je Fall müssen Python und Node
     denselben Exit-Code, Status und Manifest-Hash liefern, wie in fall.json erwartet.
  2. Hash-Vektoren aus referenzlauf/testvektoren.json (Fälle 2xx): beide Leser rechnen den Skill-Ordner nach und kommen auf den Hash des Werkzeugs.
  3. Version 1 bis 3 unverändert: die Fälle aus tests/signatur_erzeugen.mjs, die Beispielprofile alex.json/belegleser.json und die Fixtures
     liefern mit den neuen Skripten dieselbe Ausgabe (Text und JSON, Exit-Code) wie die gesicherte Fassung 0.3.0.
  4. Alter Leser (gesicherte Fassung 0.3.0 aus _screens/v4_schritt1/backup_vorher) gegen Version 4: nicht lesbar, also nie als geprüft (Exit 1, format_nicht_zulaessig).
  5. Beide Skills enthalten dieselben Skripte.
Aufruf: python tests/test_v4.py   (ohne Netz; braucht: pip install cryptography, Node 18+). Läuft einige Minuten (Abschnitt 3 startet viele Prozesse)."""
import hashlib, json, os, subprocess, sys, tempfile
W = os.path.dirname(os.path.abspath(__file__)); R = os.path.dirname(W); ROOT = os.path.dirname(R)
ALT = os.path.join(ROOT, "_screens", "v4_schritt1", "backup_vorher", "skills_skills")
sys.stdout.reconfigure(encoding="utf-8")
ok = fehl = 0
UMG = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")


def pruef(b, n, d=""):
    global ok, fehl
    if b:
        ok += 1; print("  ok  ", n)
    else:
        fehl += 1; print("  FEHL", n, d)


def skript(skill, spr, basis=None):
    return os.path.join(basis or os.path.join(R, "skills"), skill, "scripts", "pruefen." + ("py" if spr == "py" else "mjs"))


def lauf(s, spr, args):
    cmd = ([sys.executable] if spr == "py" else ["node"]) + [s] + args
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=UMG)


def eintrag0(p):
    try:
        return json.loads(p.stdout)["eintraege"][0]
    except Exception:
        return {}


# ---------- 1 und 2: Version-4-Fälle ----------
with tempfile.TemporaryDirectory() as tmp:
    g = subprocess.run(["node", os.path.join(W, "v4_erzeugen.mjs"), tmp], capture_output=True, text=True, encoding="utf-8")
    pruef(g.returncode == 0, "Version-4-Fälle erzeugt", g.stderr[-400:])
    faelle = sorted(d for d in os.listdir(tmp) if os.path.isfile(os.path.join(tmp, d, "fall.json")))
    pruef(len(faelle) >= 45 + 6, f"mindestens 51 Fälle ({len(faelle)})")
    for d in faelle:
        pfad = os.path.join(tmp, d)
        fall = json.load(open(os.path.join(pfad, "fall.json"), encoding="utf-8"))
        erw = fall["erwartung"]
        args = [os.path.join(pfad, "profil.json"), "--jwks", os.path.join(pfad, "jwks.json"), "--widerruf", os.path.join(pfad, "widerruf.json"),
                "--jetzt", fall["jetzt"], "--heute", fall["heute"]]
        for fp in fall["anker"]:
            args += ["--wurzel-anker", fp]
        if fall["skills"]:
            args += ["--skills", os.path.join(tmp, fall["skills"])]
        ergebnisse = {}
        for spr in ("py", "mjs"):
            name = f"Fall {fall['nr']:03d} {spr}: {fall['name']}"
            p = lauf(skript("abgeklopft-empfaenger", spr), spr, args + ["--json"])
            e0 = eintrag0(p)
            ergebnisse[spr] = e0
            pruef(p.returncode == erw["exit"] and e0.get("status") == erw["status"], name, f"Exit {p.returncode} (erwartet {erw['exit']}), Status {e0.get('status')} (erwartet {erw['status']}) {p.stderr[-300:]} {e0.get('fehler')}")
            if "stufe" in erw:
                pruef(e0.get("stufe") == erw["stufe"], name + " [Stufe]", str(e0.get("stufe")))
            if "fehler" in erw:
                pruef(any(erw["fehler"] in f for f in e0.get("fehler", [])), name + " [Fehlertext]", str(e0.get("fehler")))
            if "warnung_text" in erw:
                pruef(any(erw["warnung_text"] in w for w in e0.get("warnungen", [])), name + " [Warnung]", str(e0.get("warnungen")))
            m = e0.get("manifest") or {}
            for k, v in (erw.get("manifest") or {}).items():
                pruef(m.get(k) == v, name + f" [manifest.{k}]", f"{m.get(k)!r} statt {v!r}")
            if "ss" in erw:
                pruef(m.get("sha256") == erw["ss"]["hash"] and (e0.get("skill_satz") or {}).get("manifest_sha256") == erw["ss"]["hash"], name + " [Manifest-Hash wie erwartet]", str(m.get("sha256")))
            if "ergebnis" in erw:
                er = e0.get("ergebnis") or {}
                pruef(all(er.get(k) == v for k, v in erw["ergebnis"].items()), name + " [ergebnis in --json]", str(er)[:200])
                pruef(bool(e0.get("referenz")) and bool(e0.get("pruefobjekt")), name + " [referenz und pruefobjekt in --json]")
            if erw.get("ni"):
                pruef(str(m.get("ni", "")).startswith("ni:///sha-256;") and len(m.get("ni", "")) == len("ni:///sha-256;") + 43, name + " [ni-URI]", str(m.get("ni")))
            if erw["status"] not in ("echt",) and erw["exit"] == 1:
                pruef(e0.get("skill_satz") is None and e0.get("ergebnis") is None, name + " [bei Fehler kein skill_satz/ergebnis im Ergebnis]")
            if any(k in erw for k in ("text", "kein_text")):
                tx = lauf(skript("abgeklopft-empfaenger", spr), spr, args).stdout
                for t in erw.get("text", []):
                    pruef(t in tx, name + f" [Text: {t[:60]}]", tx[-600:])
                for t in erw.get("kein_text", []):
                    pruef(t not in tx, name + f" [kein Text: {t[:60]}]")
        # Node und Python müssen dasselbe Ergebnis liefern
        a, b = ergebnisse["py"], ergebnisse["mjs"]
        def norm(l): return [str(x).replace("'", '"').replace("None", "null") for x in (l or [])]   # Python schreibt !r-Texte mit ' und None, Node mit " und null (so war es schon vor Version 4)
        pruef(a.get("status") == b.get("status") and (a.get("manifest") or {}) == (b.get("manifest") or {}) and norm(a.get("fehler")) == norm(b.get("fehler")) and norm(a.get("warnungen")) == norm(b.get("warnungen")),
              f"Fall {fall['nr']:03d}: Python und Node liefern gleichen Status, Manifest-Hash, Fehler- und Warntexte", f"{a.get('fehler')} | {b.get('fehler')}")

    # ---------- 3: Version 1 bis 3 unverändert (alte Fassung gegen neue Fassung) ----------
    pruef(os.path.isdir(ALT), "gesicherte Fassung 0.3.0 vorhanden", ALT)
    if os.path.isdir(ALT):
        g = subprocess.run(["node", os.path.join(W, "signatur_erzeugen.mjs"), os.path.join(tmp, "alt")], capture_output=True, text=True, encoding="utf-8")
        pruef(g.returncode == 0, "Fälle der Versionen 1 bis 3 erzeugt (signatur_erzeugen.mjs)", g.stderr[-300:])
        altfaelle = sorted(x for x in os.listdir(os.path.join(tmp, "alt")) if os.path.isfile(os.path.join(tmp, "alt", x, "fall.json")))
        gleich = 0
        for x in altfaelle:
            pf = os.path.join(tmp, "alt", x)
            fj = json.load(open(os.path.join(pf, "fall.json"), encoding="utf-8"))
            args = [os.path.join(pf, "profil.json"), "--jwks", os.path.join(pf, "jwks.json"), "--widerruf", os.path.join(pf, "widerruf.json"), "--jetzt", fj["jetzt"], "--heute", fj["heute"]]
            for fp in fj["anker"]:
                args += ["--wurzel-anker", fp]
            for spr in ("py", "mjs"):
                n = lauf(skript("abgeklopft-empfaenger", spr), spr, args)
                o = lauf(skript("abgeklopft-empfaenger", spr, ALT), spr, args)
                n2 = lauf(skript("abgeklopft-empfaenger", spr), spr, args + ["--json"])
                o2 = lauf(skript("abgeklopft-empfaenger", spr, ALT), spr, args + ["--json"])
                # einzige gewollte Textänderung: ein Teil-Bericht darf jetzt auch Version 4 sein („Version 3 oder 4“); Status und Exit-Code bleiben gleich
                glatt = lambda t: t.replace("Version 3 oder 4 sein", "Version 3 sein")
                g1 = n.returncode == o.returncode and glatt(n.stdout) == o.stdout and glatt(n2.stdout) == o2.stdout and n2.returncode == o2.returncode
                gleich += g1
                if not g1:
                    pruef(False, f"Version 1–3 unverändert: Fall {x} {spr}", (n.stdout[:200], o.stdout[:200]))
        pruef(gleich == 2 * len(altfaelle), f"Version 1–3: alle {len(altfaelle)} Fälle in Python und Node mit neuer und alter Fassung ausgabegleich ({gleich}/{2 * len(altfaelle)})")
        beisp = [(os.path.join(ROOT, "alex.json"), os.path.join(ROOT, ".well-known", "jwks.json")), (os.path.join(ROOT, "belegleser.json"), os.path.join(ROOT, ".well-known", "jwks.json")),
                 (os.path.join(W, "fixtures", "alex_0.2.json"), os.path.join(ROOT, ".well-known", "jwks.json")), (os.path.join(W, "fixtures", "profil_0.3.json"), os.path.join(tmp, "keine_jwks.json"))]
        open(os.path.join(tmp, "keine_jwks.json"), "w").write('{"keys":[]}')
        for datei, jw in beisp:
            if not os.path.exists(datei):
                pruef(False, f"Beispiel fehlt: {datei}"); continue
            for spr in ("py", "mjs"):
                a = ["--jwks", jw, "--heute", "2026-11-24"]
                n = lauf(skript("abgeklopft-empfaenger", spr), spr, [datei] + a)
                o = lauf(skript("abgeklopft-empfaenger", spr, ALT), spr, [datei] + a)
                pruef(n.returncode == o.returncode and n.stdout == o.stdout, f"{os.path.basename(datei)} {spr}: Ausgabe und Exit-Code gleich wie 0.3.0", (n.stdout[:200], o.stdout[:200]))
                n = lauf(skript("abgeklopft-empfaenger", spr), spr, [datei] + a + ["--json"])
                o = lauf(skript("abgeklopft-empfaenger", spr, ALT), spr, [datei] + a + ["--json"])
                pruef(n.stdout == o.stdout, f"{os.path.basename(datei)} {spr}: --json gleich wie 0.3.0")

        # ---------- 4: alter Leser gegen Version 4 ----------
        for nr in ("101", "102"):
            pf = os.path.join(tmp, nr)
            fj = json.load(open(os.path.join(pf, "fall.json"), encoding="utf-8"))
            args = [os.path.join(pf, "profil.json"), "--jwks", os.path.join(pf, "jwks.json"), "--widerruf", os.path.join(pf, "widerruf.json"), "--jetzt", fj["jetzt"], "--heute", fj["heute"], "--wurzel-anker", fj["anker"][0]]
            for spr in ("py", "mjs"):
                for skill in ("abgeklopft-empfaenger", "abgeklopft-bewerber"):
                    if not os.path.exists(skript(skill, spr, ALT)):
                        pruef(False, f"alte Fassung fehlt: {skill} {spr}"); continue
                    p = lauf(skript(skill, spr, ALT), spr, args + ["--json"])
                    e0 = eintrag0(p)
                    name = f"Alter Leser 0.3.0 ({skill}, {spr}) gegen Version 4, Fall {nr}"
                    pruef(p.returncode == 1 and e0.get("status") == "format_nicht_zulaessig", name + ": nicht lesbar, Exit 1", f"{p.returncode} {e0.get('status')}")
                    pruef(any("Berichtsversion 4 unbekannt" in f for f in e0.get("fehler", [])), name + ": Meldung „Berichtsversion 4 unbekannt“", str(e0.get("fehler")))
                    t = lauf(skript(skill, spr, ALT), spr, args).stdout
                    pruef("!! [" in t and "mindestens ein Prüfbericht ist NICHT belastbar" in t and "ERGEBNIS: alle Prüfberichte echt" not in t, name + ": Text nennt den Bericht nicht belastbar, nie als geprüft")
                    pruef("Referenzlauf" not in t and "Trefferquote" not in t, name + ": keine Kennzahlen als Prüfaussage angezeigt")

# ---------- 5: beide Skills gleich ----------
for spr in ("py", "mjs"):
    h = [hashlib.sha256(open(skript(s, spr), "rb").read()).hexdigest() for s in ("abgeklopft-empfaenger", "abgeklopft-bewerber")]
    pruef(h[0] == h[1], f"pruefen.{spr} in beiden Skills gleich")
for dat in (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"):
    pruef('"version": "0.4.0"' in open(os.path.join(R, dat), encoding="utf-8").read(), f"{dat}: Version 0.4.0")

print(f"\n{ok}/{ok+fehl} grün")
sys.exit(1 if fehl else 0)
