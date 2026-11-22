// Erzeugt die Testfälle für test_signatur.py (Spezifikation Abschnitt 8) mit WEGWERF-Schlüsseln, die hier neu entstehen.
// Es wird kein echter Schlüssel und nicht der Pilotschlüssel verwendet.
// Aufruf: node tests/signatur_erzeugen.mjs <ausgabeordner>
// Je Fall ein Ordner: profil.json, jwks.json (fehlt bei Fall 29), widerruf.json (fehlt bei Fall 22), fall.json (Erwartung, Argumente).
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const out = process.argv[2];
if (!out) { console.error("Aufruf: node signatur_erzeugen.mjs <ausgabeordner>"); process.exit(2); }
fs.mkdirSync(out, { recursive: true });

const kan = o => Array.isArray(o) ? "[" + o.map(kan).join(",") + "]" : o && typeof o === "object" ? "{" + Object.keys(o).sort().map(k => JSON.stringify(k) + ":" + kan(o[k])).join(",") + "}" : JSON.stringify(o);
const sha = t => crypto.createHash("sha256").update(t, "utf8").digest("hex");
const TAG = 86400000, T = s => Date.parse(s), iso = ms => new Date(ms).toISOString().slice(0, 19) + "Z";
const JETZT = "2027-01-20T10:00:00Z", AUSG = "2027-01-10T09:00:00Z", HEUTE = "2027-01-20";
const hex = n => crypto.randomBytes(n).toString("hex");

function schluessel(typ, name, von, bis) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const j = publicKey.export({ format: "jwk" });
  const pub = { crv: j.crv, kty: j.kty, x: j.x };
  const fp = sha(kan(pub));
  return { typ, name, privateKey, pub, fp, kid: (typ === "wurzel" ? "W-" : "K-") + fp.slice(0, 8).toUpperCase(), von, bis };
}
const sign = (k, text) => crypto.sign(null, Buffer.from(text, "utf8"), k.privateKey).toString("base64");
function jwkEintrag(k, extra = {}) {
  const e = { kid: k.kid, typ: k.typ, ...k.pub, use: "sig", alg: "EdDSA", name: k.name };
  if (k.von) { e.gilt_von = k.von; e.gilt_bis = k.bis; }
  if (k.typ === "pilot") e.gilt_fuer = "Pilot: nur erfundene Beispielprofile";
  return { ...e, ...extra };
}
function zertifikat(w, k, ueber = {}, zusatz = {}) {
  const obj = { aussteller: "abgeklopft.de", crv: k.pub.crv, format: "abgeklopft-zertifikat/1", gilt_bis: k.bis, gilt_von: k.von, kid: k.kid, kty: k.pub.kty, wurzel_kid: w.kid, x: k.pub.x, ...ueber };
  return { wurzel_kid: obj.wurzel_kid, wert: sign(w, kan(obj)), ...zusatz };
}
function mitZert(w, k, ueber, zusatz) { return jwkEintrag(k, { zertifikat: zertifikat(w, k, ueber, zusatz) }); }

function bericht(k, ueber = {}, opt = {}) {
  const inhalt = { aussteller: "abgeklopft.de", version: 2, subjekt: "mensch", person: "Test Person", profil: "abgeklopft.de/test", eintrag: "e1", art: "Erfahrung",
    anspruch: "Testanspruch", belege: ["https://example.org/b"], pruefweg: "auftraggeber", stufe: 3, ausgestellt: AUSG, gueltigBis: "2027-12-31",
    bestaetigungen: [{ name: "Test Bestätigende", rolle: "Leitung", datum: "2027-01-10", kommentar: "ok" }] };
  if (k.typ === "pilot") inhalt.beispiel = "Erfundene Person, nur zur Vorführung";
  Object.assign(inhalt, ueber);
  for (const key of Object.keys(inhalt)) if (inhalt[key] === undefined) delete inhalt[key];
  const text = kan(inhalt), hash = sha(text), kennung = "AK-" + hash.slice(0, 4).toUpperCase() + "-" + hash.slice(4, 8).toUpperCase();
  return { summe: hash, kennung, b: { inhalt: { ...inhalt, kennung }, pruefsumme: hash,
    signatur: { alg: { name: "Ed25519" }, kid: opt.kid ?? k.kid, pruefer: k.name, pub: opt.pub ?? k.pub, wert: sign(opt.signierer ?? k, opt.signText ?? text) } } };
}
function neuHashen(b) { const { kennung, ...inh } = b.inhalt; const h = sha(kan(inh)); b.pruefsumme = h; b.inhalt.kennung = "AK-" + h.slice(0, 4).toUpperCase() + "-" + h.slice(4, 8).toUpperCase(); }

function profil(b, { format = "abgeklopft-nachweise/0.4", gueltig = true } = {}) {
  return { format, profil: { art: "mensch", name: "Test Person", adresse: "https://abgeklopft.de/test", erfunden: true },
    eintraege: [{ id: "e1", stufe: "S3", gueltig, angabe_der_person: { titel: "Testeintrag" }, pruefung: { pruefweg: "auftraggeber" }, pruefbericht: b }] };
}
function liste(signer, eintraege, { format = "abgeklopft-widerruf/2", stand, gueltigBis, zusatz = {} } = {}) {
  stand = stand ?? iso(T(JETZT) - 5 * TAG);
  const inh = { format, aussteller: "abgeklopft.de", stand, eintraege, ...zusatz };
  if (format.endsWith("/2")) inh.gueltig_bis = gueltigBis ?? iso(T(stand) + 30 * TAG);
  return { ...inh, signatur: { alg: { name: "Ed25519" }, kid: signer.kid, pruefer: signer.name, pub: signer.pub, wert: sign(signer, kan(inh)) } };
}
const sperrEintrag = (k, summen, ab = "2027-01-14T18:30:00Z") => ({ typ: "schluessel", kid: k.kid, gesperrt_ab: ab, widerrufen_am: "2027-01-15", grund: "schluessel", gueltige_pruefsummen: summen });

const P = schluessel("pilot", "Wegwerf-Pilot", null, null);
const W = schluessel("wurzel", "Wegwerf-Wurzel", "2026-11-01T00:00:00Z", "2031-11-01T00:00:00Z");
const W2 = schluessel("wurzel", "Fremde Wurzel", "2026-11-01T00:00:00Z", "2031-11-01T00:00:00Z");
const S1 = schluessel("signierung", "Wegwerf-Signierschlüssel 1", "2026-12-01T00:00:00Z", "2027-03-01T00:00:00Z");
const S2 = schluessel("signierung", "Wegwerf-Signierschlüssel 2", "2027-02-15T00:00:00Z", "2027-05-16T00:00:00Z");
const welt = (extra = {}) => ({ format: "abgeklopft-jwks/2", keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W, S1), mitZert(W, S2)], gesperrt: [], ...extra });

const faelle = [];
// bau() -> { profil, jwks (oder null), liste (oder null), anker (Standard: [W.fp]) }
function fall(nr, name, erwartung, bau) { faelle.push({ nr, name, erwartung, bau }); }
const E = (exit, status) => ({ exit, status });
const leer = () => liste(W, []);

fall(1, "echt (S1, Fenster, Zertifikat, leere Liste)", E(0, "echt"), () => ({ profil: profil(bericht(S1).b), jwks: welt(), liste: leer() }));
fall(2, "Inhalt geändert → verändert", E(1, "veraendert"), () => { const r = bericht(S1); r.b.inhalt.anspruch = "Geändert"; return { profil: profil(r.b), jwks: welt(), liste: leer() }; });
fall(3, "Prüfsumme neu berechnet, Signatur alt → Signatur ungültig", E(1, "signatur_ungueltig"), () => { const r = bericht(S1); r.b.inhalt.anspruch = "Geändert"; neuHashen(r.b); return { profil: profil(r.b), jwks: welt(), liste: leer() }; });
fall(4, "Schlüssel nicht in jwks → unbekannter Schlüssel", E(1, "unbekannter_schluessel"), () => { const S9 = schluessel("signierung", "Unbekannt", S1.von, S1.bis); return { profil: profil(bericht(S9).b), jwks: welt(), liste: leer() }; });
fall(5, "x im Bericht weicht von jwks ab → unbekannter Schlüssel", E(1, "unbekannter_schluessel"), () => { const S9 = schluessel("signierung", "Fremd", S1.von, S1.bis); return { profil: profil(bericht(S9, {}, { kid: S1.kid }).b), jwks: welt(), liste: leer() }; });
fall(6, "Zertifikat von nicht gepinnter Wurzel → unbekannter Schlüssel", E(1, "unbekannter_schluessel"), () => ({ profil: profil(bericht(S1).b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W2, S1)] }), liste: leer() }));
fall(7, "ausgestellt nach gilt_bis des Schlüssels → nicht gültig", E(1, "schluessel_nicht_gueltig"), () => ({ profil: profil(bericht(S1, { ausgestellt: "2027-03-05T09:00:00Z" }).b), jwks: welt(), liste: liste(W, [], { stand: "2027-03-08T10:00:00Z" }), jetzt: "2027-03-10T10:00:00Z", heute: "2027-03-10" }));
fall(8, "ausgestellt vor gilt_von → nicht gültig", E(1, "schluessel_nicht_gueltig"), () => ({ profil: profil(bericht(S1, { ausgestellt: "2026-11-30T09:00:00Z" }).b), jwks: welt(), liste: leer() }));
fall(9, "ausgestellt einen Tag in der Zukunft → nicht gültig", E(1, "schluessel_nicht_gueltig"), () => ({ profil: profil(bericht(S1, { ausgestellt: "2027-01-21T10:00:00Z" }).b), jwks: welt(), liste: leer() }));
fall(10, "Zertifikat mit 200 Tagen → unbekannter Schlüssel", E(1, "unbekannter_schluessel"), () => { const L = schluessel("signierung", "Lang", "2026-12-01T00:00:00Z", iso(T("2026-12-01T00:00:00Z") + 200 * TAG)); return { profil: profil(bericht(L).b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W, L)] }), liste: leer() }; });
fall(11, "Version 2 ohne ausgestellt → Format nicht zulässig", E(1, "format_nicht_zulaessig"), () => ({ profil: profil(bericht(S1, { ausgestellt: undefined }).b), jwks: welt(), liste: leer() }));
fall(12, "Version 1 (Datum) von Signierschlüssel → Format nicht zulässig", E(1, "format_nicht_zulaessig"), () => ({ profil: profil(bericht(S1, { version: 1, ausgestellt: "2027-01-10" }).b, { format: "abgeklopft-nachweise/0.3" }), jwks: welt(), liste: leer() }));
fall(13, "Version 1 vom Pilot mit beispiel → Beispiel", E(0, "beispiel_pilot"), () => ({ profil: profil(bericht(P, { version: 1, ausgestellt: "2027-01-10" }).b, { format: "abgeklopft-nachweise/0.3" }), jwks: welt(), liste: leer() }));
fall(14, "Version 1 vom Pilot ohne beispiel → Format nicht zulässig", E(1, "format_nicht_zulaessig"), () => ({ profil: profil(bericht(P, { version: 1, ausgestellt: "2027-01-10", beispiel: undefined }).b, { format: "abgeklopft-nachweise/0.3" }), jwks: welt(), liste: leer() }));
fall(15, "Version 2 vom Pilot mit beispiel → Beispiel", E(0, "beispiel_pilot"), () => ({ profil: profil(bericht(P).b), jwks: welt(), liste: leer() }));
fall(16, "S1 gesperrt, Bericht in der Liste, davor ausgestellt → echt", E(0, "echt"), () => { const r = bericht(S1); return { profil: profil(r.b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W, S2)], gesperrt: [mitZert(W, S1, {}, {})] }), liste: liste(W, [sperrEintrag(S1, [r.summe])]) }; });
fall(17, "S1 gesperrt, Bericht nicht in der Liste (zurückdatiert) → gesperrt", E(1, "schluessel_gesperrt"), () => { const echt = bericht(S1), fake = bericht(S1, { anspruch: "Zurückdatiert", ausgestellt: "2027-01-05T09:00:00Z" }); return { profil: profil(fake.b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W, S2)], gesperrt: [mitZert(W, S1)] }), liste: liste(W, [sperrEintrag(S1, [echt.summe])]) }; });
fall(18, "S1 gesperrt, in der Liste, aber ausgestellt nach gesperrt_ab → gesperrt", E(1, "schluessel_gesperrt"), () => { const r = bericht(S1, { ausgestellt: "2027-01-16T09:00:00Z" }); return { profil: profil(r.b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W, S2)], gesperrt: [mitZert(W, S1)] }), liste: liste(W, [sperrEintrag(S1, [r.summe])]) }; });
fall(19, "S1 nur in jwks.gesperrt, Liste ohne Eintrag → gesperrt", E(1, "schluessel_gesperrt"), () => ({ profil: profil(bericht(S1).b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W, S2)], gesperrt: [mitZert(W, S1)] }), liste: leer() }));
fall(20, "Bericht in der Widerrufsliste → widerrufen", E(1, "widerrufen"), () => { const r = bericht(S1); return { profil: profil(r.b), jwks: welt(), liste: liste(W, [{ typ: "bericht", kennung: r.kennung, pruefsumme: r.summe, widerrufen_am: "2027-01-12", grund: "auf_wunsch" }]) }; });
fall(21, "gleiche Kennung, andere Prüfsumme in der Liste → echt", E(0, "echt"), () => { const r = bericht(S1); return { profil: profil(r.b), jwks: welt(), liste: liste(W, [{ typ: "bericht", kennung: r.kennung, pruefsumme: hex(32), widerrufen_am: "2027-01-12", grund: "fehler" }]) }; });
fall(22, "Widerrufsliste fehlt → nicht prüfbar", E(3, "widerrufsstatus_nicht_pruefbar"), () => ({ profil: profil(bericht(S1).b), jwks: welt(), liste: null }));
fall(23, "Widerrufsliste mit ungültiger Signatur → nicht prüfbar", E(3, "widerrufsstatus_nicht_pruefbar"), () => { const l = leer(); l.stand = iso(T(l.stand) + 60000); return { profil: profil(bericht(S1).b), jwks: welt(), liste: l }; });
fall(24, "Widerrufsliste vom Signierschlüssel statt von der Wurzel → nicht prüfbar", E(3, "widerrufsstatus_nicht_pruefbar"), () => ({ profil: profil(bericht(S1).b), jwks: welt(), liste: liste(S1, []) }));
fall(25, "Widerrufsliste abgelaufen (gueltig_bis überschritten) → nicht prüfbar", E(3, "widerrufsstatus_nicht_pruefbar"), () => ({ profil: profil(bericht(S1).b), jwks: welt(), liste: liste(W, [], { stand: "2026-12-10T10:00:00Z", gueltigBis: "2027-01-09T10:00:00Z" }) }));
fall(26, "Widerrufsliste mit zusätzlichem Feld im Eintrag → nicht prüfbar", E(3, "widerrufsstatus_nicht_pruefbar"), () => ({ profil: profil(bericht(S1).b), jwks: welt(), liste: liste(W, [{ typ: "bericht", kennung: "AK-AAAA-BBBB", pruefsumme: hex(32), widerrufen_am: "2027-01-12", grund: "fehler", name: "Zusatz" }]) }));
fall(27, "Liste /1 vom Pilot, jwks ohne Wurzel → gilt wie heute", E(0, "beispiel_pilot"), () => ({ profil: profil(bericht(P, { version: 1, ausgestellt: "2027-01-10" }).b, { format: "abgeklopft-nachweise/0.3" }), jwks: { keys: [jwkEintrag(P)] }, liste: liste(P, [], { format: "abgeklopft-widerruf/1" }), anker: [] }));
fall(28, "Liste /1 vom Pilot, jwks mit Wurzel → nicht prüfbar", E(3, "widerrufsstatus_nicht_pruefbar"), () => ({ profil: profil(bericht(P, { version: 1, ausgestellt: "2027-01-10" }).b, { format: "abgeklopft-nachweise/0.3" }), jwks: welt(), liste: liste(P, [], { format: "abgeklopft-widerruf/1" }) }));
fall(29, "jwks nicht ladbar → Exit 2", E(2, null), () => ({ profil: profil(bericht(S1).b), jwks: null, liste: leer() }));
fall(30, "Hülle 0.3 mit Bericht Version 2 → Format nicht zulässig", E(1, "format_nicht_zulaessig"), () => ({ profil: profil(bericht(S1).b, { format: "abgeklopft-nachweise/0.3" }), jwks: welt(), liste: leer() }));
fall(31, "gueltigBis überschritten → abgelaufen", E(0, "abgelaufen"), () => ({ profil: profil(bericht(S1, { gueltigBis: "2027-01-10" }).b, { gueltig: false }), jwks: welt(), liste: leer() }));
fall(32, "kid im Bericht passt nicht zu x → unbekannter Schlüssel", E(1, "unbekannter_schluessel"), () => ({ profil: profil(bericht(S1, {}, { kid: "K-ZZZZZZZZ" }).b), jwks: welt(), liste: leer() }));
fall(33, "Zertifikat mit zusätzlichem Feld → Format nicht zulässig", E(1, "format_nicht_zulaessig"), () => ({ profil: profil(bericht(S1).b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), mitZert(W, S1, {}, { extra: 1 })] }), liste: leer() }));
fall(34, "jwks-Eintrag mit kid, die nicht zu x passt → unbekannter Schlüssel", E(1, "unbekannter_schluessel"), () => ({ profil: profil(bericht(S1).b), jwks: welt({ keys: [jwkEintrag(P), jwkEintrag(W), { ...mitZert(W, S1), kid: "K-00000000" }] }), liste: leer() }));
fall(35, "zweiter Signierschlüssel (Rotation) im Fenster → echt", E(0, "echt"), () => ({ profil: profil(bericht(S2, { ausgestellt: "2027-02-20T09:00:00Z" }).b), jwks: welt(), liste: liste(W, [], { stand: "2027-02-18T10:00:00Z" }), jetzt: "2027-02-21T10:00:00Z", heute: "2027-02-21" }));
fall(36, "alter Bericht nach Rotation (S1, Überlappung) → echt", E(0, "echt"), () => ({ profil: profil(bericht(S1, { ausgestellt: "2027-02-20T09:00:00Z" }).b), jwks: welt(), liste: liste(W, [], { stand: "2027-02-18T10:00:00Z" }), jetzt: "2027-02-21T10:00:00Z", heute: "2027-02-21" }));

// ---- Berichtsversion 3 (Hülle 0.5): Prüfobjekt Pflicht ----
const PO = (x = {}) => ({ gegenstand: "Android-App Netzlast, Paket de.beispiel.netzlast", version_stand: "Version 2.3.1, Store-Stand 2027-01-09", umfang_geprueft: ["Inhaberschaft des Store-Eintrags", "App läuft auf Pixel 8"], nicht_geprueft: ["Qualität des Codes", "Datenschutzkonformität"], methode: "Abgleich mit Store-Konsole, App 10 Minuten benutzt", ...x });
const V3 = (po, extra = {}) => ({ version: 3, ...(po === undefined ? {} : { pruefobjekt: po }), ...extra });
const hue5 = { format: "abgeklopft-nachweise/0.5" };
const E3 = (exit, status, extra = {}) => ({ exit, status, ...extra });
const v3fall = (nr, name, erw, ueber, po, opt = hue5) => fall(nr, name, erw, () => ({ profil: profil(bericht(S1, V3(po, ueber)).b, opt), jwks: welt(), liste: leer() }));
const ohne = (o, k) => { const c = { ...o }; delete c[k]; return c; };
v3fall(37, "v3 vollständiges Prüfobjekt → echt", E3(0, "echt", { pruefobjekt: true }), {}, PO());
v3fall(38, "v3 ohne Prüfobjekt → pruefobjekt_fehlt", E3(1, "pruefobjekt_fehlt", { pruefobjekt: false }), {}, undefined);
v3fall(39, "v3 mit leerem umfang_geprueft → unvollständig", E3(1, "pruefobjekt_unvollstaendig", { pruefobjekt: false }), {}, PO({ umfang_geprueft: [] }));
v3fall(40, "v3 ohne nicht_geprueft und ohne nichts_ausgeschlossen → unvollständig", E3(1, "pruefobjekt_unvollstaendig"), {}, ohne(PO(), "nicht_geprueft"));
v3fall(41, "v3 mit nichts_ausgeschlossen true → echt", E3(0, "echt", { pruefobjekt: true }), {}, ohne({ ...PO(), nichts_ausgeschlossen: true }, "nicht_geprueft"));
v3fall(42, "v3 mit Teil-Id und pruefer_art ki → echt, Zusatz KI", E3(0, "echt", { pruefobjekt: true, pruefer_art: "ki", teil: "frontend-1" }), { teil: "frontend-1", pruefer_art: "ki" }, PO());
fall(43, "v3 Prüfobjekt nachträglich geändert → verändert", E3(1, "veraendert"), () => { const r = bericht(S1, V3(PO())); r.b.inhalt.pruefobjekt.nicht_geprueft = ["nichts Wesentliches"]; return { profil: profil(r.b, hue5), jwks: welt(), liste: leer() }; });
fall(44, "v3 Prüfobjekt geändert, Prüfsumme neu → Signatur ungültig", E3(1, "signatur_ungueltig"), () => { const r = bericht(S1, V3(PO())); r.b.inhalt.pruefobjekt.nicht_geprueft = []; r.b.inhalt.pruefobjekt.nichts_ausgeschlossen = true; neuHashen(r.b); return { profil: profil(r.b, hue5), jwks: welt(), liste: leer() }; });
v3fall(45, "v3 mit Hülle 0.4 → Format nicht zulässig", E3(1, "format_nicht_zulaessig"), {}, PO(), { format: "abgeklopft-nachweise/0.4" });
v3fall(46, "v3 mit Hülle 0.6 → echt (höhere Minor-Zahl)", E3(0, "echt", { pruefobjekt: true }), {}, PO(), { format: "abgeklopft-nachweise/0.6" });
v3fall(47, "v3 Text über 500 Zeichen → zu groß", E3(1, "pruefobjekt_zu_gross"), {}, PO({ methode: "x".repeat(501) }));
v3fall(48, "v3 mehr als 20 Punkte → zu groß", E3(1, "pruefobjekt_zu_gross"), {}, PO({ umfang_geprueft: Array.from({ length: 21 }, (_, i) => "Punkt " + i) }));
v3fall(49, "v3 genau 500 Zeichen und 20 Punkte → echt", E3(0, "echt"), {}, PO({ methode: "x".repeat(500), nicht_geprueft: Array.from({ length: 20 }, (_, i) => "Nicht " + i) }));
v3fall(50, "v3 mit weiteren Feldern (beobachtungszeitraum, stichprobe, fremdpruefung, unbekannt) → echt", E3(0, "echt", { pruefobjekt: true }), { beobachtungszeitraum: "2026-10-01/2026-12-31", stichprobe: "30 von 400", fremdpruefung: "TÜV-123", unbekannt_x: "egal" }, PO());
v3fall(51, "v3 Teil-Id ungültig → Format nicht zulässig", E3(1, "format_nicht_zulaessig"), { teil: "Teil 1!" }, PO());
v3fall(52, "v3 pruefer_art ungültig → Format nicht zulässig", E3(1, "format_nicht_zulaessig"), { pruefer_art: "roboter" }, PO());
v3fall(53, "v3 Prüfobjekt ist kein Objekt → unvollständig", E3(1, "pruefobjekt_unvollstaendig"), {}, "alles geprüft");
v3fall(54, "v3 nichts_ausgeschlossen false und leere Liste → unvollständig", E3(1, "pruefobjekt_unvollstaendig"), {}, PO({ nicht_geprueft: [], nichts_ausgeschlossen: false }));
fall(55, "v2 mit Feld pruefobjekt (wird ignoriert) → echt, Umfang nicht angegeben", E3(0, "echt", { pruefobjekt: false, warnung: true }), () => ({ profil: profil(bericht(S1, { pruefobjekt: PO() }).b), jwks: welt(), liste: leer() }));
fall(56, "v2 unverändert → echt, Warnung Umfang nicht angegeben", E3(0, "echt", { pruefobjekt: false, warnung: true }), () => ({ profil: profil(bericht(S1).b), jwks: welt(), liste: leer() }));
fall(57, "v3 mit pruefung.gesamt im Profil → ignoriert, nur Stufe und Bericht", E3(0, "echt", { pruefobjekt: true }), () => { const p = profil(bericht(S1, V3(PO())).b, hue5); p.eintraege[0].pruefung.gesamt = { stufe: "S1", begrenzt_durch: "teil-x" }; p.eintraege[0].pruefung.teile = [{ id: "a" }]; return { profil: p, jwks: welt(), liste: leer() }; });
v3fall(58, "v3 in Hülle 0.3 → Format nicht zulässig", E3(1, "format_nicht_zulaessig"), {}, PO(), { format: "abgeklopft-nachweise/0.3" });

for (const f of faelle) {
  const d = path.join(out, String(f.nr).padStart(2, "0"));
  fs.mkdirSync(d, { recursive: true });
  const r = f.bau();
  fs.writeFileSync(path.join(d, "profil.json"), JSON.stringify(r.profil, null, 2));
  if (r.jwks) fs.writeFileSync(path.join(d, "jwks.json"), JSON.stringify(r.jwks, null, 2));
  if (r.liste) fs.writeFileSync(path.join(d, "widerruf.json"), JSON.stringify(r.liste, null, 2));
  fs.writeFileSync(path.join(d, "fall.json"), JSON.stringify({ nr: f.nr, name: f.name, erwartung: f.erwartung, jetzt: r.jetzt ?? JETZT, heute: r.heute ?? HEUTE, anker: r.anker ?? [W.fp] }, null, 2));
}
console.log(`${faelle.length} Fälle in ${out}`);
