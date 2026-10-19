/**
 * LA SONDE DE LA SORTIE RÉSEAU — vague 11, fil F, TR-146 (EX-SEC-150, 160, 170, EX-NET-760).
 *
 * Une application sans dépendance, déployée trois fois dans l'organisation `v11-f` (sortie fermée,
 * restreinte à example.com, ouverte). GET /essais joue chaque tentative depuis la charge et rend ce
 * qu'elle a vu, tel quel : « joint », « refus » (code d'erreur), « délai » (rien en 4 s). Rien n'est
 * jugé ici : le verdict se lit à côté de l'audit du locataire (agent.egress.refused).
 *   /essais            toutes les tentatives
 *   /reseau            /etc/resolv.conf, interfaces et passerelle par défaut
 *   /                  « sonde-sortie » et la release servie
 */
import dgram from "node:dgram";
import { promises as dns } from "node:dns";
import { readFile } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";

const PORT = Number(process.env.PORT ?? 3000);
const RELEASE = process.env.BASTIDE_RELEASE_ID ?? process.env.RELEASE ?? "inconnue";
const DELAI_MS = 4_000;

const avecDelai = (p) =>
  Promise.race([p, new Promise((_, r) => setTimeout(() => r(Object.assign(new Error("délai"), { code: "DELAI" })), DELAI_MS))]);

function tcp(hote, port) {
  return new Promise((ok) => {
    const t0 = Date.now();
    const s = net.connect({ host: hote, port, timeout: DELAI_MS });
    const fin = (r) => {
      s.destroy();
      ok({ ...r, ms: Date.now() - t0 });
    };
    s.once("connect", () => fin({ issue: "joint" }));
    s.once("timeout", () => fin({ issue: "délai" }));
    s.once("error", (e) => fin({ issue: "refus", code: e.code }));
  });
}

/** Une question DNS brute (A example.com) envoyée en UDP à un autre résolveur que celui du nœud. */
function dnsBrut(serveur) {
  return new Promise((ok) => {
    const t0 = Date.now();
    const q = Buffer.from("abcd01000001000000000000076578616d706c6503636f6d0000010001", "hex");
    const s = dgram.createSocket("udp4");
    const minuteur = setTimeout(() => {
      s.close();
      ok({ issue: "délai", ms: Date.now() - t0 });
    }, DELAI_MS);
    s.once("message", (m) => {
      clearTimeout(minuteur);
      s.close();
      ok({ issue: "joint", octets: m.length, ms: Date.now() - t0 });
    });
    s.once("error", (e) => {
      clearTimeout(minuteur);
      s.close();
      ok({ issue: "refus", code: e.code, ms: Date.now() - t0 });
    });
    s.send(q, 53, serveur);
  });
}

async function resoudre(nom) {
  const t0 = Date.now();
  try {
    const a = await avecDelai(dns.resolve4(nom));
    return { issue: "résolu", adresses: a, ms: Date.now() - t0 };
  } catch (e) {
    return { issue: "refus", code: e.code, ms: Date.now() - t0 };
  }
}

async function passerelle() {
  try {
    const lignes = (await readFile("/proc/net/route", "utf8")).trim().split("\n").slice(1);
    for (const l of lignes) {
      const c = l.split(/\s+/);
      if (c[1] === "00000000") {
        const h = c[2];
        return [3, 2, 1, 0].map((i) => Number.parseInt(h.slice(i * 2, i * 2 + 2), 16)).join(".");
      }
    }
  } catch {}
  return null;
}

async function essais() {
  const gw = await passerelle();
  // Les adresses littérales sont celles que le nuage résolvait le 17/10/2026 : elles servent quand
  // le résolveur du projet refuse (sortie fermée), pour que le refus mesuré soit celui du réseau.
  // EN PARALLÈLE : une sortie filtrée JETTE les paquets (aucun refus immédiat), chaque essai
  // attend donc son délai de 4 s ; en série, la réponse dépassait le délai de l'edge (19/10).
  const [declare, nonDeclare, smtp, local, meta, g8, c1] = await Promise.all([
    resoudre("example.com"),
    resoudre("wikipedia.org"),
    resoudre("gmail-smtp-in.l.google.com"),
    resoudre("localhost.bastide.internal"),
    resoudre("metadata.google.internal"),
    dnsBrut("8.8.8.8"),
    dnsBrut("1.1.1.1"),
  ]);
  const ipDeclare = declare.adresses?.[0] ?? "104.20.23.154";
  const ipNonDeclare = nonDeclare.adresses?.[0] ?? "185.15.58.224";
  const ipSmtp = smtp.adresses?.[0] ?? "74.125.69.26";
  const r = {
    a: new Date().toISOString(),
    release: RELEASE,
    passerelle: gw,
    dns: {
      "example.com (déclaré)": declare,
      "wikipedia.org (non déclaré)": nonDeclare,
      "gmail-smtp-in.l.google.com": smtp,
      "localhost.bastide.internal": local,
      "metadata.google.internal": meta,
    },
    tcp: {},
    autreResolveur: {
      "8.8.8.8 udp/53": g8,
      "1.1.1.1 udp/53": c1,
    },
  };
  const cibles = [
    [`example.com ${ipDeclare}:443 (déclaré)`, ipDeclare, 443],
    [`wikipedia.org ${ipNonDeclare}:443 (non déclaré)`, ipNonDeclare, 443],
    ["8.8.8.8:53 tcp", "8.8.8.8", 53],
    [`smtp ${ipSmtp}:25`, ipSmtp, 25],
    [`smtp ${ipSmtp}:465`, ipSmtp, 465],
    [`smtp ${ipSmtp}:587`, ipSmtp, 587],
    [`smtp ${ipSmtp}:2525`, ipSmtp, 2525],
    ["169.254.169.254:80 (métadonnées)", "169.254.169.254", 80],
    ["10.0.0.1:22 (privé)", "10.0.0.1", 22],
    ["192.168.1.1:80 (privé)", "192.168.1.1", 80],
    ["172.17.0.1:22 (pont docker)", "172.17.0.1", 22],
    ["127.0.0.1:4100 (bouclage)", "127.0.0.1", 4100],
  ];
  if (gw) cibles.push([`passerelle ${gw}:22 (hôte)`, gw, 22], [`passerelle ${gw}:4100 (hôte)`, gw, 4100]);
  const issues = await Promise.all(cibles.map(([, h, p]) => tcp(h, p)));
  cibles.forEach(([nom], i) => (r.tcp[nom] = issues[i]));
  return r;
}

async function reseau() {
  let resolv = null;
  try {
    resolv = await readFile("/etc/resolv.conf", "utf8");
  } catch {}
  return { resolv, interfaces: os.networkInterfaces(), passerelle: await passerelle(), serveursDns: dns.getServers?.() };
}

http
  .createServer(async (req, rep) => {
    const url = new URL(req.url, "http://sonde");
    const json = (corps) => {
      rep.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      rep.end(JSON.stringify(corps, null, 1));
    };
    try {
      if (url.pathname === "/essais") return json(await essais());
      if (url.pathname === "/reseau") return json(await reseau());
      return json({ sonde: "sonde-sortie", release: RELEASE });
    } catch (e) {
      rep.writeHead(500, { "content-type": "text/plain" });
      rep.end(String(e?.stack ?? e));
    }
  })
  .listen(PORT, "0.0.0.0");
