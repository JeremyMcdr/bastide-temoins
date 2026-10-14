/**
 * L'APPLICATION TÉMOIN DES SONDES DE L'EDGE — vague 9, fil B.
 *
 * Une seule application, sans dépendance, déployée dans l'organisation `v9-b`, qui donne à chaque
 * sonde ce qu'il lui faut voir DERRIÈRE l'edge :
 *   /etiquette/<t>  une réponse en cache une heure, étiquetée <t>, qui porte un compteur : une
 *                   valeur neuve prouve que la purge a atteint l'edge (EX-NET-140, 430).
 *   /froide?k=<k>   300 ms de travail, en cache une minute ; /compte?k=<k> dit combien de fois
 *                   l'origine l'a fait (EX-NET-450 : mille requêtes, un appel).
 *   /ws             un écho WebSocket, pour tenir cent connexions une heure (EX-NET-260).
 *   /octets?n=<n>   n octets jamais en cache, pour saturer un plafond de débit (EX-NET-530).
 *   /release        l'identifiant de la release servie, pour dater les commutations.
 * Une instance seule : les compteurs sont en mémoire, et c'est voulu — l'origine compte ce
 * qu'elle a fait, pas ce que l'edge croit lui avoir demandé.
 */
import { createHash } from "node:crypto";
import http from "node:http";

const PORT = Number(process.env.PORT ?? 3000);
const RELEASE = process.env.BASTIDE_RELEASE_ID ?? process.env.RELEASE ?? `local-${Date.now()}`;
const compteurs = new Map();
const compter = (k) => {
  const n = (compteurs.get(k) ?? 0) + 1;
  compteurs.set(k, n);
  return n;
};

const serveur = http.createServer(async (req, rep) => {
  const url = new URL(req.url, "http://temoin");
  const json = (statut, corps, entetes = {}) => {
    rep.writeHead(statut, { "content-type": "application/json", ...entetes });
    rep.end(JSON.stringify(corps));
  };
  if (url.pathname.startsWith("/etiquette/")) {
    const t = url.pathname.slice("/etiquette/".length);
    return json(
      200,
      { t, n: compter(`etiquette:${t}`), release: RELEASE, a: Date.now() },
      {
        "cache-control": "public, max-age=0, s-maxage=3600",
        "glowsoft-cache-tag": t,
      },
    );
  }
  if (url.pathname === "/froide") {
    const k = url.searchParams.get("k") ?? "";
    const n = compter(`froide:${k}`);
    await new Promise((r) => setTimeout(r, 300));
    return json(200, { k, n }, { "cache-control": "public, s-maxage=60" });
  }
  if (url.pathname === "/compte") {
    const k = url.searchParams.get("k") ?? "";
    return json(200, { k, n: compteurs.get(`froide:${k}`) ?? 0 }, { "cache-control": "no-store" });
  }
  if (url.pathname === "/octets") {
    const n = Math.min(Number(url.searchParams.get("n") ?? 1_048_576), 104_857_600);
    rep.writeHead(200, {
      "content-type": "application/octet-stream",
      "content-length": n,
      "cache-control": "no-store",
    });
    const bloc = Buffer.alloc(65_536, 0x61);
    let reste = n;
    const pousser = () => {
      while (reste > 0) {
        const m = bloc.subarray(0, Math.min(reste, bloc.length));
        reste -= m.length;
        if (!rep.write(m)) return rep.once("drain", pousser);
      }
      rep.end();
    };
    return pousser();
  }
  if (url.pathname === "/release")
    return json(200, { release: RELEASE }, { "cache-control": "no-store" });
  return json(200, { temoin: "edge", release: RELEASE }, { "cache-control": "no-store" });
});

/** Un écho WebSocket écrit à la main (RFC 6455, trames texte et ping), faute de dépendance. */
serveur.on("upgrade", (req, socket) => {
  const cle = req.headers["sec-websocket-key"];
  if (!cle || new URL(req.url, "http://temoin").pathname !== "/ws") return socket.destroy();
  const accepte = createHash("sha1")
    .update(`${cle}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accepte}\r\n\r\n`,
  );
  const trame = (op, charge) => {
    const l = charge.length;
    const tete =
      l < 126 ? Buffer.from([0x80 | op, l]) : Buffer.from([0x80 | op, 126, l >> 8, l & 255]);
    socket.write(Buffer.concat([tete, charge]));
  };
  let tampon = Buffer.alloc(0);
  socket.on("data", (d) => {
    tampon = Buffer.concat([tampon, d]);
    while (tampon.length >= 2) {
      const op = tampon[0] & 0x0f;
      let l = tampon[1] & 0x7f;
      let i = 2;
      if (l === 126) {
        if (tampon.length < 4) return;
        l = tampon.readUInt16BE(2);
        i = 4;
      } else if (l === 127) return socket.destroy();
      const masque = (tampon[1] & 0x80) !== 0;
      if (tampon.length < i + (masque ? 4 : 0) + l) return;
      const m = masque ? tampon.subarray(i, i + 4) : null;
      i += masque ? 4 : 0;
      const charge = Buffer.from(tampon.subarray(i, i + l));
      if (m) for (let j = 0; j < charge.length; j++) charge[j] ^= m[j % 4];
      tampon = tampon.subarray(i + l);
      if (op === 0x8) return socket.end(Buffer.from([0x88, 0]));
      if (op === 0x9) trame(0xa, charge);
      if (op === 0x1) trame(0x1, Buffer.from(`${RELEASE} ${charge.toString()}`));
    }
  });
  socket.on("error", () => {});
});

serveur.listen(PORT, () =>
  console.log(`témoin de l'edge à l'écoute sur ${PORT}, release ${RELEASE}`),
);
