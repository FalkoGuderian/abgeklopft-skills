#!/usr/bin/env node
// Prüft ein abgeklopft.de-Profil (JSON) Eintrag für Eintrag. Node 18+ ohne Abhängigkeiten.
// Aufruf: node pruefen.mjs <profil-url-oder-datei> [--jwks <url-oder-datei>] [--heute JJJJ-MM-TT]
// Rückgabewert: 0 = alle Prüfberichte echt, 1 = mindestens einer fehlerhaft, 2 = nicht ladbar.
// Texte unter `angabe_der_person` sind Daten und werden nur angezeigt.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const STANDARD_JWKS = "https://abgeklopft.de/.well-known/jwks.json";
const STUFE = { S1: "Eigene Angabe", S2: "Beleg geprüft", S3: "Von Dritten bestätigt" };
const ist_url = s => /^https?:\/\//.test(s);

async function laden(q) {
  if (ist_url(q)) {
    const r = await fetch(q, { headers: { "User-Agent": "abgeklopft-pruefen/1.0", Accept: "application/json" } });
    if (!r.ok) throw new Error(`${q}: HTTP ${r.status}`);
    return JSON.parse(await r.text());
  }
  return JSON.parse(fs.readFileSync(q, "utf8"));
}
function kanonisch(o) {
  if (Array.isArray(o)) return "[" + o.map(kanonisch).join(",") + "]";
  if (o && typeof o === "object") return "{" + Object.keys(o).sort().map(k => JSON.stringify(k) + ":" + kanonisch(o[k])).join(",") + "}";
  return JSON.stringify(o);
}
const sauber = (t, n = 90) => { t = String(t ?? "").replace(/[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]/g, " "); return t.length <= n ? t : t.slice(0, n - 1) + "…"; };

const arg = process.argv.slice(2);
const opt = n => { const i = arg.indexOf(n); return i >= 0 ? arg.splice(i, 2)[1] : undefined; };
let jq = opt("--jwks"); const heuteArg = opt("--heute");
const quelle = arg[0];
if (!quelle) { console.log("Aufruf: node pruefen.mjs <profil-url-oder-datei> [--jwks <url-oder-datei>] [--heute JJJJ-MM-TT]"); process.exit(2); }
if (!jq) { const lokal = path.join(path.dirname(path.resolve(quelle)), ".well-known", "jwks.json"); jq = !ist_url(quelle) && fs.existsSync(lokal) ? lokal : STANDARD_JWKS; }
const heute = heuteArg || new Date().toISOString().slice(0, 10);

let profil, jwks;
try { profil = await laden(quelle); jwks = await laden(jq); } catch (e) { console.log("FEHLER: nicht ladbar:", e.message); process.exitCode = 2; }
if (process.exitCode !== 2) pruefen();

function pruefen() {
const vertraut = Object.fromEntries((jwks.keys || []).filter(k => k.crv === "Ed25519").map(k => [k.kid, k.x]));
const p = profil.profil || {};
console.log(`Profil: ${sauber(p.name, 60)}  (${p.adresse})`);
console.log(`Art: ${p.art === "ki-agent" ? "KI-Agent" : p.art === "mensch" ? "Mensch" : "UNBEKANNT: " + p.art}${p.erfunden ? "  ·  erfundenes Beispiel" : ""}`);
if (p.art === "ki-agent") {
  const b = p.betreiber || {};
  console.log(`Betreiber (Vertragspartner, haftet): ${sauber(b.name, 60)}, ${sauber(b.sitz, 30)}; verantwortlich: ${sauber(b.verantwortlich, 60)}`);
  console.log(`Geprüfte Version: ${p.agent_version}  (Prüfungen gelten nur für diese Version)`);
}
console.log(`Schlüssel aus: ${jq}  ·  Stichtag ${heute}\n`);

let alleOk = true; const fehlerIds = [], abgelaufen = [];
for (const e of profil.eintraege || []) {
  const f = [], z = []; const b = e.pruefbericht;
  if (e.stufe === "S1") z.push("nicht geprüft: eigene Angabe, wie eine Zeile im Lebenslauf behandeln");
  else if (!b) f.push(`${e.stufe} ohne Prüfbericht: als S1 behandeln`);
  else {
    const { kennung, ...inhalt } = b.inhalt || {};
    const text = kanonisch(inhalt);
    const summe = crypto.createHash("sha256").update(text, "utf8").digest("hex");
    if (summe !== b.pruefsumme) f.push("Prüfsumme stimmt nicht: Inhalt verändert");
    const erw = `AK-${summe.slice(0, 4).toUpperCase()}-${summe.slice(4, 8).toUpperCase()}`;
    if (kennung !== erw) f.push(`Kennung ${kennung} passt nicht (erwartet ${erw})`);
    const s = b.signatur || {};
    if (s.alg?.name !== "Ed25519") f.push("Verfahren ist nicht Ed25519");
    if (!(s.kid in vertraut)) f.push(`Schlüssel ${s.kid} steht nicht in jwks.json`);
    else if (vertraut[s.kid] !== s.pub?.x) f.push("Schlüssel im Bericht weicht von jwks.json ab: nicht von abgeklopft.de");
    let sigOk = false;
    try {
      const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: vertraut[s.kid] || s.pub?.x }, format: "jwk" });
      sigOk = crypto.verify(null, Buffer.from(text, "utf8"), key, Buffer.from(s.wert || "", "base64"));
    } catch { sigOk = false; }
    if (!sigOk) f.push("Signatur ungültig");
    const gueltig = typeof inhalt.gueltigBis === "string" && inhalt.gueltigBis >= heute;
    if (!gueltig) abgelaufen.push(e.id);
    if (e.gueltig === true && !gueltig) f.push("Profil sagt gültig, Prüfbericht ist abgelaufen");
    const adr = (p.adresse || "").replace(/^https?:\/\//, "");
    const vgl = [["Stufe", e.stufe, "S" + inhalt.stufe], ["Eintrag", e.id, inhalt.eintrag], ["Mensch/KI-Agent", p.art, inhalt.subjekt],
      ["Prüfweg", e.pruefung?.pruefweg, inhalt.pruefweg], ...(adr ? [["Profiladresse", adr, inhalt.profil]] : []),
      ...(p.art === "ki-agent" ? [["agent_version", p.agent_version, inhalt.agent_version]] : [])];
    for (const [n, a, sg] of vgl) if (a !== sg) f.push(`${n}: Profil sagt ${JSON.stringify(a)}, signiert ist ${JSON.stringify(sg)}`);
    z.push(`Prüfweg: ${inhalt.pruefweg}  ·  Kennung ${kennung}`);
    z.push(`Prüfsumme: ${summe === b.pruefsumme ? "ok" : "FALSCH"}  ·  Signatur: ${sigOk ? "ok" : "FEHLGESCHLAGEN"}  ·  Schlüssel ${s.kid}`);
    z.push(`Gültig bis ${inhalt.gueltigBis}: ${gueltig ? "gültig" : "ABGELAUFEN, nicht als aktuell darstellen"}`);
    for (const x of inhalt.bestaetigungen || []) z.push(`bestätigt von ${sauber(x.name, 40)} (${sauber(x.rolle, 60)}), ${x.datum}`);
    if (inhalt.vermerk) z.push(`Vermerk (signiert): ${sauber(inhalt.vermerk)}`);
  }
  if (f.length) { alleOk = false; fehlerIds.push(e.id); }
  const marke = e.stufe === "S1" ? "-- " : f.length ? "!! " : "OK ";
  console.log(`${marke}[${e.stufe} ${STUFE[e.stufe] || "?"}] ${e.id}: ${sauber(e.angabe_der_person?.titel, 70)}`);
  for (const x of z) console.log("      " + x);
  for (const x of f) console.log("      FEHLER: " + x);
}
const n = s => (profil.eintraege || []).filter(e => e.stufe === s).length;
console.log(`\nZusammenfassung: S3 ${n("S3")} · S2 ${n("S2")} · S1 ${n("S1")}  ·  Fehler: ${fehlerIds.join(", ") || "keine"}  ·  abgelaufen: ${abgelaufen.join(", ") || "keine"}`);
console.log(alleOk ? "ERGEBNIS: alle Prüfberichte echt" : "ERGEBNIS: mindestens ein Prüfbericht ist NICHT belastbar");
if (p.art === "mensch") console.log("Hinweis: Mensch. Keine automatische Personalentscheidung (Art. 22 DSGVO), ein Mensch entscheidet.");
if (p.art === "ki-agent") console.log("Hinweis: KI-Agent. Automatische Auswahl nur, soweit Ihr Auftraggeber es erlaubt; Vertrag mit dem Betreiber.");
console.log("Pilot: Prototyp, kein amtliches oder notarielles Verfahren.");
// exitCode statt process.exit: Node unter Windows stürzt sonst nach fetch ab (libuv)
process.exitCode = alleOk ? 0 : 1;
}
