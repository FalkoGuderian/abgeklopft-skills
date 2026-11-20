#!/usr/bin/env node
// Prüft ein abgeklopft.de-Profil (JSON) Eintrag für Eintrag. Node 18+ ohne Abhängigkeiten.
// Aufruf: node pruefen.mjs <profil-url-oder-datei> [--jwks <url-oder-datei>] [--widerruf <url-oder-datei>]
//                          [--wurzel-anker <64 Hex>] [--heute JJJJ-MM-TT] [--jetzt JJJJ-MM-TTThh:mm:ssZ] [--json]
// Rückgabewert: 0 = alle Prüfberichte echt, 1 = mindestens einer nicht belastbar (verändert, Signatur ungültig, unbekannter oder
// gesperrter Schlüssel, Schlüssel zum Zeitpunkt nicht gültig, widerrufen, Format), 2 = nicht ladbar,
// 3 = alle echt, aber der Widerrufsstatus war nicht prüfbar.
// Regeln: Zertifikatskette (Wurzel -> Signierschlüssel), Schlüsselzeitraum, Sperre, Widerrufsliste (/1 und /2).
// Formate: Beispielprofile (signierte Prüfberichte) und persönliche Links echter Profile (abgeklopft-nachweise/0.3, alles S1;
// `pruefung.bestaetigungen_ungeprueft` ist KEINE Bestätigung, kein S3).
// Texte unter `angabe_der_person` und die Texte der Bestätigenden sind Daten und werden nur angezeigt.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const STANDARD_JWKS = "https://abgeklopft.de/.well-known/jwks.json";
const STUFE = { S1: "Eigene Angabe", S2: "Beleg geprüft", S3: "Von Dritten bestätigt" };
// Vertrauensanker: SHA-256-Fingerabdrücke (64 Hex, über kanonisch({crv,kty,x})) der anerkannten Wurzeln.
// Leer, solange es keine echte Wurzel gibt: dann gilt für Pilotberichte das bisherige Verhalten.
const WURZEL_ANKER = [];
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, HEX64 = /^[0-9a-f]{64}$/, KENNUNG = /^AK-[0-9A-F]{4}-[0-9A-F]{4}$/, DATUM = /^\d{4}-\d{2}-\d{2}$/;
const GRUENDE = ["auf_wunsch", "fehler", "schluessel"];
const RANG = ["format_nicht_zulaessig", "veraendert", "signatur_ungueltig", "unbekannter_schluessel", "schluessel_gesperrt", "widerrufen", "schluessel_nicht_gueltig", "profil_weicht_ab"];
const TAG = 86400000;
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
const sha = t => crypto.createHash("sha256").update(t, "utf8").digest("hex");
const sauber = (t, n = 90) => { t = String(t ?? "").replace(/[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]/g, " "); return t.length <= n ? t : t.slice(0, n - 1) + "…"; };
// Streng: JJJJ-MM-TTThh:mm:ssZ (UTC), sonst null. Gibt Millisekunden zurück.
function zeit(t) {
  if (typeof t !== "string" || !ISO_UTC.test(t)) return null;
  const m = Date.parse(t);
  return Number.isNaN(m) || new Date(m).toISOString().slice(0, 19) + "Z" !== t ? null : m;
}
const fingerabdruck = x => sha(kanonisch({ crv: "Ed25519", kty: "OKP", x }));
function pruefeSig(x, wert, text) {
  try {
    const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
    if (typeof wert !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(wert)) return false;
    return crypto.verify(null, Buffer.from(text, "utf8"), key, Buffer.from(wert, "base64"));
  } catch { return false; }
}
function formatnummer(f) { const m = /^abgeklopft-nachweise\/(\d+)\.(\d+)$/.exec(String(f ?? "")); return m ? [Number(m[1]), Number(m[2])] : null; }
const gleich = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const mengeGleich = (o, felder) => { const k = Object.keys(o).sort(); return gleich(k, [...felder].sort()); };

const arg = process.argv.slice(2);
const opt = n => { const i = arg.indexOf(n); return i >= 0 ? arg.splice(i, 2)[1] : undefined; };
const optAlle = n => { const r = []; for (let i; (i = arg.indexOf(n)) >= 0;) r.push(arg.splice(i, 2)[1]); return r; };
const alsJson = arg.includes("--json"); if (alsJson) arg.splice(arg.indexOf("--json"), 1);
let jq = opt("--jwks"); const widerrufArg = opt("--widerruf"), heuteArg = opt("--heute"), jetztArg = opt("--jetzt");
const ankerArg = optAlle("--wurzel-anker");
const quelle = arg[0];
if (!quelle) { console.log("Aufruf: node pruefen.mjs <profil-url-oder-datei> [--jwks <url-oder-datei>] [--widerruf <url-oder-datei>] [--wurzel-anker <64 Hex>] [--heute JJJJ-MM-TT] [--jetzt JJJJ-MM-TTThh:mm:ssZ] [--json]"); process.exit(2); }
if (!jq) { const lokal = path.join(path.dirname(path.resolve(quelle)), ".well-known", "jwks.json"); jq = !ist_url(quelle) && fs.existsSync(lokal) ? lokal : STANDARD_JWKS; }
const heute = heuteArg || new Date().toISOString().slice(0, 10);
let jetzt;
if (jetztArg) { jetzt = zeit(jetztArg); if (jetzt === null) { console.log("FEHLER: --jetzt muss JJJJ-MM-TTThh:mm:ssZ sein"); process.exit(2); } }
else if (heuteArg) jetzt = Date.parse(heuteArg + "T23:59:59Z");
else jetzt = Math.floor(Date.now() / 1000) * 1000;
const widerrufQuelle = widerrufArg || (ist_url(jq) ? jq.slice(0, jq.lastIndexOf("/")) + "/widerruf.json" : path.join(path.dirname(path.resolve(jq)), "widerruf.json"));

const ANWEISUNG = /ignorier|ignore (all|your|previous)|vergiss (alle|deine)|stufe.{0,40}S[23]|markier\w*.{0,40}S[23]|als (geprüft|bestätigt)|schick\w* .{0,30} an |system ?prompt/i;
const auffaellig = (...t) => t.some(x => ANWEISUNG.test(String(x ?? "")));

// Schlüssel aus jwks.json (Typ, Zeitraum, Fingerabdruck geprüft)
function schluesselLaden(jwks, anker) {
  const keys = {}, gesperrt = {}, wurzeln = {};
  for (const [liste, ziel] of [[jwks.keys || [], "keys"], [jwks.gesperrt || [], "gesperrt"]]) {
    for (const k of Array.isArray(liste) ? liste : []) {
      if (!k || k.crv !== "Ed25519" || k.kty !== "OKP" || typeof k.x !== "string") continue;
      const typ = k.typ ?? "pilot";
      if (!["pilot", "signierung", "wurzel"].includes(typ)) continue;
      const fp = fingerabdruck(k.x);
      if (k.kid !== (typ === "wurzel" ? "W-" : "K-") + fp.slice(0, 8).toUpperCase()) continue; // kid passt nicht zu x (nur 32 Bit)
      const e = { ...k, typ, _von: zeit(k.gilt_von), _bis: zeit(k.gilt_bis) };
      if (typ === "wurzel") { if (anker.has(fp) && ziel === "keys") wurzeln[k.kid] = e; }
      else if (ziel === "keys") keys[k.kid] = e; else gesperrt[k.kid] = e;
    }
  }
  return { keys, gesperrt, wurzeln };
}

// Widerrufsliste laden und prüfen. Jeder Fehler heißt nur: nicht prüfbar.
async function widerrufLaden(q, ctx) {
  const nein = grund => ({ ok: false, grund, liste: null });
  if (!q) return nein("keine Quelle");
  let liste; try { liste = await laden(q); } catch (e) { return nein("nicht ladbar: " + e.message); }
  if (!liste || typeof liste !== "object" || !["abgeklopft-widerruf/1", "abgeklopft-widerruf/2"].includes(liste.format)) return nein("unbekanntes Format");
  const v2 = liste.format.endsWith("/2"), sg = liste.signatur || {}, kid = sg.kid;
  let sk;
  if (Object.keys(ctx.wurzeln).length) {
    if (!v2) return nein("Liste /1, aber es gibt eine Wurzel: nur /2 von der Wurzel zulässig");
    sk = ctx.wurzeln[kid];
    if (!sk) return nein("Liste nicht von der Wurzel signiert");
    if (!(sk._von !== null && sk._bis !== null && sk._von <= jetzt && jetzt < sk._bis)) return nein("Wurzel gilt zum Prüfzeitpunkt nicht");
  } else {
    sk = ctx.keys[kid];
    if (!sk || sk.typ !== "pilot") return nein("Liste nicht vom Pilotschlüssel signiert");
  }
  if (sg.pub?.x !== sk.x) return nein("Schlüssel in der Liste weicht von jwks.json ab");
  const { signatur, ...rest } = liste;
  if (!pruefeSig(sk.x, sg.wert, kanonisch(rest))) return nein("Signatur der Liste ungültig");
  if (v2) {
    const stand = zeit(liste.stand), gb = zeit(liste.gueltig_bis);
    if (stand === null || gb === null || gb > stand + 31 * TAG) return nein("stand/gueltig_bis fehlen oder sind unzulässig");
    if (gb < jetzt) return nein(`Liste veraltet (gueltig_bis ${liste.gueltig_bis})`);
  }
  if (!Array.isArray(liste.eintraege)) return nein("eintraege fehlt");
  for (const x of liste.eintraege) {
    if (!x || typeof x !== "object" || Array.isArray(x)) return nein("Eintrag ist kein Objekt");
    let ok;
    if (!v2) ok = mengeGleich(x, ["kennung", "widerrufen_am", "grund"]) && KENNUNG.test(String(x.kennung)) && DATUM.test(String(x.widerrufen_am)) && GRUENDE.includes(x.grund);
    else if (x.typ === "bericht") ok = mengeGleich(x, ["typ", "kennung", "pruefsumme", "widerrufen_am", "grund"]) && KENNUNG.test(String(x.kennung)) && HEX64.test(String(x.pruefsumme)) && DATUM.test(String(x.widerrufen_am)) && GRUENDE.includes(x.grund);
    else if (x.typ === "schluessel") ok = mengeGleich(x, ["typ", "kid", "gesperrt_ab", "widerrufen_am", "grund", "gueltige_pruefsummen"]) && zeit(x.gesperrt_ab) !== null && DATUM.test(String(x.widerrufen_am)) && x.grund === "schluessel" && Array.isArray(x.gueltige_pruefsummen) && x.gueltige_pruefsummen.every(h => HEX64.test(String(h))) && typeof x.kid === "string";
    else ok = false;
    if (!ok) return nein("Eintrag unzulässig (unbekannter Typ, fehlende oder zusätzliche Felder)");
  }
  return { ok: true, grund: "", liste, stand: liste.stand, format: liste.format };
}

// Zertifikatskette eines Signierschlüssels: null (ok) oder ["format"|"unbekannt", Text]
function zertifikatPruefen(k, ctx) {
  const z = k.zertifikat;
  if (!z || typeof z !== "object" || typeof z.wurzel_kid !== "string" || typeof z.wert !== "string") return ["unbekannt", "Zertifikat fehlt"];
  if (!mengeGleich(z, ["wurzel_kid", "wert"])) return ["format", "zusätzliche Felder im Zertifikat"];
  const w = ctx.wurzeln[z.wurzel_kid];
  if (!w) return ["unbekannt", "Wurzel nicht anerkannt (kein Vertrauensanker)"];
  const von = k._von, bis = k._bis;
  if (von === null || bis === null || bis <= von) return ["unbekannt", "Zeitraum des Schlüssels fehlt oder ist unlesbar"];
  if (bis - von > 104 * TAG) return ["unbekannt", "Zertifikat länger als 90 Tage plus 14 Tage Überlappung"];
  if (!(w._von !== null && w._bis !== null && w._von <= von && bis <= w._bis)) return ["unbekannt", "Zertifikat reicht über die Gültigkeit der Wurzel hinaus"];
  const obj = { aussteller: "abgeklopft.de", crv: k.crv, format: "abgeklopft-zertifikat/1", gilt_bis: k.gilt_bis, gilt_von: k.gilt_von, kid: k.kid, kty: k.kty, wurzel_kid: z.wurzel_kid, x: k.x };
  if (!pruefeSig(w.x, z.wert, kanonisch(obj))) return ["unbekannt", "Zertifikat ungültig (Signatur der Wurzel stimmt nicht)"];
  return null;
}

let profil, jwks, selbst = false, ausgabe = null;
try { profil = await laden(quelle); } catch (e) { console.log("FEHLER: nicht ladbar:", e.message); process.exitCode = 2; }
if (process.exitCode !== 2) {
  selbst = !!(profil.profil || {}).selbst_angelegt;
  try { jwks = await laden(jq); } catch (e) { if (!selbst) { console.log("FEHLER: nicht ladbar:", e.message); process.exitCode = 2; } else jwks = { keys: [] }; } // persönliche Links: nur S1, kein Schlüssel nötig
}
if (process.exitCode !== 2) await pruefen();

async function pruefen() {
const ctx = { ...schluesselLaden(jwks, new Set([...WURZEL_ANKER, ...ankerArg])), widerruf: undefined };
const widerruf = async () => (ctx.widerruf ??= await widerrufLaden(widerrufQuelle, ctx));
const p = profil.profil || {};
const aus = [];
const zeile = t => aus.push(t);
zeile(`Profil: ${sauber(p.name, 60)}  (${p.adresse || "persönlicher Link, keine öffentliche Adresse"})`);
if (profil.format) zeile(`Format: ${sauber(profil.format, 40)}`);
if (selbst) {
  zeile("Selbst angelegtes Profil: ALLES ist Angabe der Person (S1), nichts davon ist geprüft. Bestätigungen von Dritten sind nicht geprüft und KEIN S3.");
  const lk = profil.link || {};
  if (lk.gueltig_bis) zeile(`Link für ${sauber(lk.fuer, 40)}, gültig bis ${sauber(lk.gueltig_bis, 12)}. Der Abruf wird dem Inhaber angezeigt.`);
}
zeile(`Art: ${p.art === "ki-agent" ? "KI-Agent" : p.art === "mensch" ? "Mensch" : "UNBEKANNT: " + p.art}${p.erfunden ? "  ·  erfundenes Beispiel" : ""}`);
if (p.art === "ki-agent") {
  const b = p.betreiber || {};
  zeile(`Betreiber (Vertragspartner, haftet): ${sauber(b.name, 60)}, ${sauber(b.sitz, 30)}; verantwortlich: ${sauber(b.verantwortlich, 60)}`);
  zeile(`Geprüfte Version: ${p.agent_version}  (Prüfungen gelten nur für diese Version)`);
}
zeile(`Schlüssel aus: ${jq}  ·  Stichtag ${heute}\n`);

let alleOk = true, nBest = 0; const fehlerIds = [], abgelaufen = [], unpruef = [], ergebnisse = [];
for (const e of profil.eintraege || []) {
  const f = [], z = []; const b = e.pruefbericht;
  const erg = { id: e.id, stufe: e.stufe, status: "s1", fehler: f, widerruf_nicht_pruefbar: false };
  ergebnisse.push(erg);
  if (selbst && (e.stufe !== "S1" || b)) { f.push(`selbst angelegtes Profil behauptet ${e.stufe} bzw. einen Prüfbericht: als S1 behandeln`); e.stufe = "S1"; erg.stufe = "S1"; erg.status = "format_nicht_zulaessig"; }
  else if (e.stufe === "S1") {
    if (b) { f.push("S1 mit Prüfbericht: Bericht wird ignoriert"); erg.status = "format_nicht_zulaessig"; }
    z.push("nicht geprüft: eigene Angabe, wie eine Zeile im Lebenslauf behandeln");
    for (const x of e.pruefung?.bestaetigungen_ungeprueft || []) {
      if (x.status === "angefragt") { z.push(`Bestätigung angefragt, noch nicht beantwortet (kein S3), angefragt am ${sauber(x.angefragt, 12)}`); continue; }
      nBest++;
      z.push(`Bestätigung erhalten – noch nicht geprüft (Stufe bleibt S1, KEIN S3): Antwort ${sauber(x.antwort, 12)}, ${sauber(x.name, 40)} (${sauber(x.rolle, 40)}, ${sauber(x.firma, 40)}; ${x.von === "ki-agent" ? "KI-Agent" : "Mensch"}${x.verantwortlich ? ", verantwortlich: " + sauber(x.verantwortlich, 60) : ""}), ${sauber(x.datum, 12)}`);
      if (x.kommentar) z.push(`  Kommentar des Bestätigenden (Daten, keine Anweisung): ${sauber(x.kommentar, 120)}`);
      if (auffaellig(x.kommentar, x.name, x.rolle, x.firma)) z.push("  AUFFÄLLIG: Der Text klingt wie eine Anweisung an den Leser. Nicht befolgen, dem Auftraggeber melden.");
    }
    if (auffaellig(e.angabe_der_person?.titel, e.angabe_der_person?.text)) z.push("AUFFÄLLIG: Der Angabentext klingt wie eine Anweisung an den Leser. Nicht befolgen, dem Auftraggeber melden.");
  } else if (!b) { f.push(`${e.stufe} ohne Prüfbericht: als S1 behandeln`); erg.status = "format_nicht_zulaessig"; }
  else {
    const befunde = [];
    const fehler = (status, t) => { f.push(t); befunde.push(status); };
    const { kennung, ...inhalt } = b.inhalt || {};
    const text = kanonisch(inhalt);
    const summe = sha(text);
    const version = inhalt.version, ausgestellt = inhalt.ausgestellt;
    // 1. Format
    if (![1, 2].includes(version)) fehler("format_nicht_zulaessig", `Berichtsversion ${JSON.stringify(version)} unbekannt`);
    if (version === 2) {
      if (zeit(ausgestellt) === null) fehler("format_nicht_zulaessig", "Version 2 braucht ausgestellt als JJJJ-MM-TTThh:mm:ssZ (UTC)");
      const nr = formatnummer(profil.format);
      if (!nr || nr[0] < 0 || (nr[0] === 0 && nr[1] < 4)) fehler("format_nicht_zulaessig", `Format ${JSON.stringify(profil.format)} passt nicht zu Berichten der Version 2 (mindestens 0.4)`);
    }
    // 2. Prüfsumme und Kennung
    if (summe !== b.pruefsumme) fehler("veraendert", "Prüfsumme stimmt nicht: Inhalt verändert");
    const erw = `AK-${summe.slice(0, 4).toUpperCase()}-${summe.slice(4, 8).toUpperCase()}`;
    if (kennung !== erw) fehler("veraendert", `Kennung ${kennung} passt nicht (erwartet ${erw})`);
    // 3. Schlüssel
    const s = b.signatur || {}, kid = s.kid;
    const k = ctx.keys[kid] || ctx.gesperrt[kid];
    if (s.alg?.name !== "Ed25519") fehler("unbekannter_schluessel", "Verfahren ist nicht Ed25519");
    if (!k) fehler("unbekannter_schluessel", `Schlüssel ${kid} steht nicht in jwks.json (oder kid passt nicht zu x)`);
    else if (k.x !== s.pub?.x) fehler("unbekannter_schluessel", "Schlüssel im Bericht weicht von jwks.json ab: nicht von abgeklopft.de");
    else if ("K-" + fingerabdruck(s.pub.x).slice(0, 8).toUpperCase() !== kid) fehler("unbekannter_schluessel", "kid im Bericht passt nicht zum Schlüssel");
    const pilot = !!(k && k.typ === "pilot");
    if (k) {
      if (version === 1 && !pilot) fehler("format_nicht_zulaessig", "Version 1 ist nur mit dem Pilotschlüssel zulässig");
      if (pilot && !inhalt.beispiel) fehler("format_nicht_zulaessig", "Bericht des Pilotschlüssels ohne `beispiel`: nur erfundene Beispiele sind zulässig");
      // 4. Zertifikatskette
      if (k.typ === "signierung") { const zr = zertifikatPruefen(k, ctx); if (zr) fehler(zr[0] === "format" ? "format_nicht_zulaessig" : "unbekannter_schluessel", zr[1]); }
    }
    // 5. Signatur (mit dem Schlüssel aus jwks.json)
    // (nur wenn der Schlüssel im Bericht zu jwks.json passt; sonst gilt „unbekannter Schlüssel“)
    const schlOk = !!k && k.x === s.pub?.x && "K-" + fingerabdruck(s.pub.x).slice(0, 8).toUpperCase() === kid;
    const sigOk = schlOk && pruefeSig(k.x, s.wert, text);
    if (schlOk && !sigOk) fehler("signatur_ungueltig", "Signatur ungültig");
    // 6. Zeit
    const ausMs = version === 2 ? zeit(ausgestellt) : (typeof ausgestellt === "string" && DATUM.test(ausgestellt) ? Date.parse(ausgestellt + "T00:00:00Z") : null);
    if (version === 2 && ausMs !== null) {
      if (ausMs > jetzt + 5 * 60000) fehler("schluessel_nicht_gueltig", "ausgestellt liegt in der Zukunft (Zeitangabe unplausibel)");
      if (k && k.typ === "signierung" && !(k._von !== null && k._bis !== null && k._von <= ausMs && ausMs < k._bis)) fehler("schluessel_nicht_gueltig", `Der Schlüssel war zum Ausstellungszeitpunkt ${ausgestellt} nicht gültig`);
    }
    // 7. Sperre, 8. Widerruf
    const w = await widerruf();
    const gesperrtKey = !!k && kid in ctx.gesperrt && !(kid in ctx.keys);
    if (w.ok) {
      const sperre = w.liste.eintraege.filter(x => x.typ === "schluessel" && x.kid === kid).pop();
      if (sperre) {
        const ga = zeit(sperre.gesperrt_ab);
        if (!(sperre.gueltige_pruefsummen.includes(summe) && ausMs !== null && ga !== null && ausMs < ga)) fehler("schluessel_gesperrt", `Der Schlüssel ${kid} wurde ab ${sperre.gesperrt_ab} gesperrt; dieser Bericht steht nicht in der signierten Liste der gültigen Berichte`);
      } else if (gesperrtKey) fehler("schluessel_gesperrt", `Der Schlüssel ${kid} ist gesperrt (jwks.json, ohne signierte Liste der gültigen Berichte)`);
      for (const x of w.liste.eintraege) {
        const treffer = x.typ === "bericht" ? x.pruefsumme === summe : (!("typ" in x) ? x.kennung === kennung : false);
        if (treffer) fehler("widerrufen", `Widerrufen am ${x.widerrufen_am} (${x.grund})`);
      }
    } else if (gesperrtKey) fehler("schluessel_gesperrt", `Der Schlüssel ${kid} ist gesperrt (jwks.json)`);
    else erg.widerruf_nicht_pruefbar = true;
    // 9. gueltigBis und Abgleich mit dem Profil
    const gueltig = typeof inhalt.gueltigBis === "string" && DATUM.test(inhalt.gueltigBis) && inhalt.gueltigBis >= heute;
    if (!(typeof inhalt.gueltigBis === "string" && DATUM.test(inhalt.gueltigBis))) fehler("format_nicht_zulaessig", "gueltigBis fehlt oder unlesbar");
    if (!gueltig) abgelaufen.push(e.id);
    if (e.gueltig === true && !gueltig) fehler("profil_weicht_ab", "Profil sagt gültig, Prüfbericht ist abgelaufen");
    const adr = (p.adresse || "").replace(/^https?:\/\//, "");
    const vgl = [["Stufe", e.stufe, "S" + inhalt.stufe], ["Eintrag", e.id, inhalt.eintrag], ["Mensch/KI-Agent", p.art, inhalt.subjekt],
      ["Prüfweg", e.pruefung?.pruefweg, inhalt.pruefweg], ...(adr ? [["Profiladresse", adr, inhalt.profil]] : []),
      ...(p.art === "ki-agent" ? [["agent_version", p.agent_version, inhalt.agent_version]] : [])];
    for (const [n, a, sg] of vgl) if (a !== sg) fehler("profil_weicht_ab", `${n}: Profil sagt ${JSON.stringify(a)}, signiert ist ${JSON.stringify(sg)}`);
    erg.status = befunde.length ? RANG.find(r => befunde.includes(r)) : erg.widerruf_nicht_pruefbar ? "widerrufsstatus_nicht_pruefbar" : !gueltig ? "abgelaufen" : pilot ? "beispiel_pilot" : "echt";
    z.push(`Prüfweg: ${inhalt.pruefweg}  ·  Kennung ${kennung}`);
    z.push(`Prüfsumme: ${summe === b.pruefsumme ? "ok" : "FALSCH"}  ·  Signatur: ${sigOk ? "ok" : "FEHLGESCHLAGEN"}  ·  Schlüssel ${kid}${k ? ` (${k.typ})` : ""}`);
    z.push(`Gültig bis ${inhalt.gueltigBis}: ${gueltig ? "gültig" : "ABGELAUFEN, nicht als aktuell darstellen"}`);
    if (version === 2) z.push(`Ausgestellt ${ausgestellt}`);
    if (erg.status === "beispiel_pilot") z.push("Beispiel (Pilotschlüssel): echt signiert mit dem Pilot-Testschlüssel, nur erfundenes Beispiel, keine echte Prüfung");
    if (erg.widerruf_nicht_pruefbar) z.push(`WIDERRUFSSTATUS NICHT PRÜFBAR: ${w.grund}. Der Bericht ist echt signiert, kann aber widerrufen sein.`);
    else if (w.ok && !f.length) z.push(`Nicht widerrufen (Stand ${sauber(w.stand, 24)})`);
    for (const x of inhalt.bestaetigungen || []) z.push(`bestätigt von ${sauber(x.name, 40)} (${sauber(x.rolle, 60)}), ${x.datum}`);
    if (inhalt.vermerk) z.push(`Vermerk (signiert): ${sauber(inhalt.vermerk)}`);
  }
  if (erg.widerruf_nicht_pruefbar) unpruef.push(e.id);
  if (f.length) { alleOk = false; fehlerIds.push(e.id); }
  const marke = e.stufe === "S1" && !f.length ? "-- " : f.length ? "!! " : "OK ";
  zeile(`${marke}[${e.stufe} ${STUFE[e.stufe] || "?"}] ${e.id}: ${sauber(e.angabe_der_person?.titel, 70)}`);
  for (const x of z) zeile("      " + x);
  for (const x of f) zeile("      FEHLER: " + x);
}
const n = s => (profil.eintraege || []).filter(e => e.stufe === s).length;
zeile(`\nZusammenfassung: S3 ${n("S3")} · S2 ${n("S2")} · S1 ${n("S1")}  ·  Fehler: ${fehlerIds.join(", ") || "keine"}  ·  abgelaufen: ${abgelaufen.join(", ") || "keine"}  ·  Bestätigungen ungeprüft (kein S3): ${nBest}`);
if (unpruef.length) zeile(`Widerrufsstatus nicht prüfbar bei: ${unpruef.join(", ")}`);
const code = alleOk && !unpruef.length ? 0 : !alleOk ? 1 : 3;
zeile(selbst && alleOk ? "ERGEBNIS: keine Prüfberichte vorhanden, alles ist Angabe der Person (S1)"
  : code === 3 ? "ERGEBNIS: alle Prüfberichte echt signiert, aber der Widerrufsstatus ist NICHT prüfbar (Exit 3)"
  : alleOk ? "ERGEBNIS: alle Prüfberichte echt" : "ERGEBNIS: mindestens ein Prüfbericht ist NICHT belastbar");
if (p.art === "mensch") zeile("Hinweis: Mensch. Keine automatische Personalentscheidung (Art. 22 DSGVO), ein Mensch entscheidet.");
if (p.art === "ki-agent") zeile("Hinweis: KI-Agent. Automatische Auswahl nur, soweit Ihr Auftraggeber es erlaubt; Vertrag mit dem Betreiber.");
zeile("Pilot: Prototyp, kein amtliches oder notarielles Verfahren.");
if (alsJson) {
  const w = ctx.widerruf;
  console.log(JSON.stringify({ profil: p.adresse, art: p.art, format: profil.format || "", selbst_angelegt: selbst, alle_ok: alleOk, exit: code,
    widerruf: w ? { ok: w.ok, grund: w.grund, stand: w.stand } : null, eintraege: ergebnisse }, null, 2));
} else console.log(aus.join("\n"));
// exitCode statt process.exit: Node unter Windows stürzt sonst nach fetch ab (libuv)
process.exitCode = code;
}
