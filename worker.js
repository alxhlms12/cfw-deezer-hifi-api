// =========================================================================
// Cloudflare Worker: Deezer High-Speed Playback Streamer & Deep Resolver
// =========================================================================

const DEEZER_GW = "https://www.deezer.com/ajax/gw-light.php";
const DEEZER_MEDIA_API = "https://media.deezer.com/v1/get_url";
const DEEZER_PIPE_GQL = "https://pipe.deezer.com/api";
const DEEZER_AUTH_RENEW = "https://auth.deezer.com/login/renew?jo=p&rto=c&i=c";

// Cloudflare KV binding:
//   GENERAL_MUSIC_CACHE
// This namespace can be shared with the Qobuz worker. Deezer keys are
// automatically prefixed with music:deezer: to prevent collisions.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Range",
  "Access-Control-Expose-Headers": "Content-Length, Content-Type, Accept-Ranges, Content-Range",
};

const BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Accept-Language": "en-US,en;q=0.9",
  "Origin": "https://www.deezer.com",
  "Referer": "https://www.deezer.com/",
  "Sec-Fetch-Dest": "empty",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Site": "same-origin",
  "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
  "sec-ch-ua-mobile": "?0",
  "sec-ch-ua-platform": '"Windows"',
};

const QUALITY_MAP = {
  "flac": { format: "FLAC", audioFormat: "FLAC", mime: "audio/flac", sampleRate: 44100, bitDepth: 16, bitrate: null, lossless: true, label: "16-bit / 44.1kHz Lossless", badge: "LOSSLESS" },
  "lossless": { format: "FLAC", audioFormat: "FLAC", mime: "audio/flac", sampleRate: 44100, bitDepth: 16, bitrate: null, lossless: true, label: "16-bit / 44.1kHz Lossless", badge: "LOSSLESS" },
  "hifi": { format: "FLAC", audioFormat: "FLAC", mime: "audio/flac", sampleRate: 44100, bitDepth: 16, bitrate: null, lossless: true, label: "16-bit / 44.1kHz Lossless", badge: "LOSSLESS" },
  "320": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "320k": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "mp3_320": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "hq": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "128": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, lossless: false, label: "128kbps MP3", badge: "LOW" },
  "128k": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, lossless: false, label: "128kbps MP3", badge: "LOW" },
  "mp3_128": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, lossless: false, label: "128kbps MP3", badge: "LOW" },
  "standard": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, lossless: false, label: "128kbps MP3", badge: "LOW" },
};

const sessionCache = new Map();
const jwtCache = new Map();

// Shared Cloudflare KV namespace used by both Deezer and Qobuz workers.
// Keys are provider-prefixed so the two providers never overwrite each other.
const GENERAL_CACHE_PREFIX = "music:deezer:";

function sharedCacheKey(type, id) {
  return `${GENERAL_CACHE_PREFIX}${type}:${String(id)}`;
}

async function getSharedCache(env, key) {
  if (!env.GENERAL_MUSIC_CACHE) return null;
  try {
    return await env.GENERAL_MUSIC_CACHE.get(key, { type: "json" });
  } catch (_) {
    return null;
  }
}

async function putSharedCache(env, key, value, ttlSeconds = 2592000) {
  if (!env.GENERAL_MUSIC_CACHE) return;
  try {
    await env.GENERAL_MUSIC_CACHE.put(
      key,
      JSON.stringify(value),
      { expirationTtl: Math.max(60, Math.floor(ttlSeconds)) }
    );
  } catch (_) {}
}

function normalizeSharedIsrc(isrc) {
  return String(isrc || "").replace(/[^A-Za-z0-9]/g, "").toUpperCase();
}

function clearArlCache(arl) {
  sessionCache.delete(arl);
  jwtCache.delete(arl);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

async function readResponse(response) {
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: response.status, ok: response.ok, text, json };
}

// -------------------------------------------------------------------------
// SESSION & AUTHENTICATION (GATEWAY + PIPE GRAPHQL JWT)
// -------------------------------------------------------------------------

async function getOrRenewSession(arl, forceRefresh = false) {
  const now = Date.now();
  const cached = sessionCache.get(arl);

  if (!forceRefresh && cached?.sid && cached.expiresAt > now) {
    return cached;
  }

  const pingResp = await fetch(`${DEEZER_GW}?method=deezer.ping&input=3&api_version=1.0&api_token=`, {
    method: "POST",
    headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
    body: "{}",
  });

  const pingResult = await readResponse(pingResp);
  const sid = pingResult.json?.results?.SESSION;
  if (!sid) throw new Error("Deezer ping failed: Could not establish session.");

  const userResp = await fetch(`${DEEZER_GW}?method=deezer.getUserData&input=3&api_version=1.0&api_token=null`, {
    method: "POST",
    headers: {
      ...BROWSER_HEADERS,
      "Content-Type": "application/json",
      Cookie: `sid=${sid}; arl=${arl}`,
    },
    body: "{}",
  });

  const userResult = await readResponse(userResp);
  const apiToken = userResult.json?.results?.checkForm;
  const licenseToken = userResult.json?.results?.USER?.OPTIONS?.license_token;
  const canLossless = userResult.json?.results?.USER?.OPTIONS?.can_stream_lossless;

  if (!apiToken || !licenseToken) {
    clearArlCache(arl);
    throw new Error("Invalid or expired DEEZER_ARL cookie.");
  }

  const session = {
    arl,
    sid,
    apiToken,
    licenseToken,
    canLossless: Boolean(canLossless),
    expiresAt: now + 1000 * 60 * 60 * 2,
  };

  sessionCache.set(arl, session);
  return session;
}

async function getPipeJwt(arl, forceRefresh = false) {
  const now = Date.now();
  const cached = jwtCache.get(arl);

  if (!forceRefresh && cached?.jwt && cached.expiresAt > now) {
    return cached.jwt;
  }

  try {
    const renewResp = await fetch(DEEZER_AUTH_RENEW, {
      method: "POST",
      headers: {
        ...BROWSER_HEADERS,
        "Cookie": `arl=${arl}`,
      },
    });

    const result = await readResponse(renewResp);
    const jwt = result.json?.jwt;
    if (jwt) {
      jwtCache.set(arl, {
        jwt,
        expiresAt: now + 1000 * 60 * 45,
      });
      return jwt;
    }
  } catch {}

  jwtCache.delete(arl);
  return null;
}

// -------------------------------------------------------------------------
// BLOWFISH STREAM CIPHER ENGINE
// -------------------------------------------------------------------------

function md5(str) {
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
  }

  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];

  const n = str.length;
  const bitLen = n * 8;
  const padLen = (((n + 8) >> 6) + 1) * 64;
  const msg = new Uint8Array(padLen);
  for (let i = 0; i < n; i++) msg[i] = str.charCodeAt(i);
  msg[n] = 0x80;

  const view = new DataView(msg.buffer);
  view.setUint32(padLen - 8, bitLen >>> 0, true);
  view.setUint32(padLen - 4, Math.floor(bitLen / 0x100000000) >>> 0, true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  for (let offset = 0; offset < padLen; offset += 64) {
    let a = a0, b = b0, c = c0, d = d0;
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) {
      M[j] = view.getUint32(offset + j * 4, true);
    }

    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) {
        f = (b & c) | ((~b) & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | ((~d) & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | (~d));
        g = (7 * i) % 16;
      }

      const temp = (a + f + K[i] + M[g]) >>> 0;
      a = d;
      d = c;
      c = b;
      const s = S[i];
      const rotated = ((temp << s) | (temp >>> (32 - s))) >>> 0;
      b = (b + rotated) >>> 0;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const out = new DataView(new ArrayBuffer(16));
  out.setUint32(0, a0, true);
  out.setUint32(4, b0, true);
  out.setUint32(8, c0, true);
  out.setUint32(12, d0, true);

  let hex = "";
  for (let i = 0; i < 16; i++) {
    hex += out.getUint8(i).toString(16).padStart(2, "0");
  }
  return hex;
}

function deriveTrackKey(trackId) {
  const md5Hex = md5(String(trackId));
  const secret = "g4el58wc0zvf9na1";
  const key = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    key[i] = md5Hex.charCodeAt(i) ^ md5Hex.charCodeAt(i + 16) ^ secret.charCodeAt(i);
  }
  return key;
}

const BF_P_INIT = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
  0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
];

const BF_S_BOXES_B64 = `
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
`;

function decodeBase64(value) {
  const normalized = String(value)
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error("Invalid BF_S_BOXES_B64: unexpected Base64 character");
  }

  if (normalized.length % 4 === 1) {
    throw new Error("Invalid BF_S_BOXES_B64: invalid Base64 length");
  }

  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return atob(padded);
}

const GLOBAL_TABLES = (function () {
  const binary = decodeBase64(BF_S_BOXES_B64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
  const view = new DataView(buffer.buffer);
  const sBoxes = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
  let offset = 0;
  for (let b = 0; b < 4; b++) {
    for (let i = 0; i < 256; i++) {
      sBoxes[b][i] = view.getUint32(offset, false);
      offset += 4;
    }
  }
  return { pArray: new Uint32Array(BF_P_INIT), sBoxes };
})();

class FastBlowfish {
  constructor(keyBytes) {
    this.p = new Uint32Array(GLOBAL_TABLES.pArray);
    this.s0 = new Uint32Array(GLOBAL_TABLES.sBoxes[0]);
    this.s1 = new Uint32Array(GLOBAL_TABLES.sBoxes[1]);
    this.s2 = new Uint32Array(GLOBAL_TABLES.sBoxes[2]);
    this.s3 = new Uint32Array(GLOBAL_TABLES.sBoxes[3]);
    this.initKey(keyBytes);
  }

  encBlock(xl, xr) {
    const s0 = this.s0, s1 = this.s1, s2 = this.s2, s3 = this.s3, p = this.p;
    for (let i = 0; i < 16; i++) {
      xl ^= p[i];
      const a = (xl >>> 24) & 0xff, b = (xl >>> 16) & 0xff, c = (xl >>> 8) & 0xff, d = xl & 0xff;
      const f = (((s0[a] + s1[b]) ^ s2[c]) + s3[d]) >>> 0;
      xr = (f ^ xr) >>> 0;
      const tmp = xl; xl = xr; xr = tmp;
    }
    const tmp = xl; xl = xr; xr = tmp;
    return [(xl ^ p[17]) >>> 0, (xr ^ p[16]) >>> 0];
  }

  initKey(key) {
    let keyIdx = 0;
    for (let i = 0; i < 18; i++) {
      let data = 0;
      for (let k = 0; k < 4; k++) {
        data = ((data << 8) | key[keyIdx]) >>> 0;
        keyIdx = (keyIdx + 1) % key.length;
      }
      this.p[i] ^= data;
    }
    let block = [0, 0];
    for (let i = 0; i < 18; i += 2) {
      block = this.encBlock(block[0], block[1]);
      this.p[i] = block[0]; this.p[i + 1] = block[1];
    }
    for (let s = 0; s < 4; s++) {
      const currentS = s === 0 ? this.s0 : s === 1 ? this.s1 : s === 2 ? this.s2 : this.s3;
      for (let i = 0; i < 256; i += 2) {
        block = this.encBlock(block[0], block[1]);
        currentS[i] = block[0]; currentS[i + 1] = block[1];
      }
    }
  }

  decryptCBC(view, offset) {
    let ivL = 0x00010203, ivR = 0x04050607;
    const p = this.p;
    const s0 = this.s0, s1 = this.s1, s2 = this.s2, s3 = this.s3;

    for (let i = 0; i < 2048; i += 8) {
      const pos = offset + i;
      const cL = view.getUint32(pos, false);
      const cR = view.getUint32(pos + 4, false);

      let A = cL ^ p[17];
      let B = cR ^ p[16];

      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[15];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[14];
      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[13];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[12];
      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[11];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[10];
      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[9];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[8];
      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[7];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[6];
      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[5];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[4];
      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[3];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[2];
      B = ((((s0[(A >>> 24) & 0xff] + s1[(A >>> 16) & 0xff]) ^ s2[(A >>> 8) & 0xff]) + s3[A & 0xff]) ^ B) >>> 0; A ^= p[1];
      A = ((((s0[(B >>> 24) & 0xff] + s1[(B >>> 16) & 0xff]) ^ s2[(B >>> 8) & 0xff]) + s3[B & 0xff]) ^ A) >>> 0; B ^= p[0];

      view.setUint32(pos, ((B ^ ivL) >>> 0), false);
      view.setUint32(pos + 4, ((A ^ ivR) >>> 0), false);
      ivL = cL; ivR = cR;
    }
  }
}

function decryptAlignedBuffer(cipher, buffer, startBlock) {
  const numBlocks = Math.floor(buffer.length / 2048);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  for (let i = 0; i < numBlocks; i++) {
    const currentBlock = startBlock + i;
    if (currentBlock % 3 === 0) {
      cipher.decryptCBC(view, i * 2048);
    }
  }
}

// -------------------------------------------------------------------------
// ARTWORK HELPER (UP TO 1900x1900 ULTRA HD)
// -------------------------------------------------------------------------

function buildArtworkUrls(rawIdOrUrl, type = "cover") {
  if (!rawIdOrUrl) return null;
  let md5Hash = String(rawIdOrUrl);

  const hashMatch = md5Hash.match(/([a-f0-9]{32})/i);
  if (hashMatch) {
    md5Hash = hashMatch[1];
  } else if (rawIdOrUrl.startsWith("http")) {
    return {
      ultra: rawIdOrUrl.replace(/\/\d+x\d+-/, "/1900x1900-"),
      xl: rawIdOrUrl.replace(/\/\d+x\d+-/, "/1000x1000-"),
      large: rawIdOrUrl.replace(/\/\d+x\d+-/, "/500x500-"),
      medium: rawIdOrUrl.replace(/\/\d+x\d+-/, "/250x250-"),
      small: rawIdOrUrl.replace(/\/\d+x\d+-/, "/56x56-"),
      default: rawIdOrUrl.replace(/\/\d+x\d+-/, "/1000x1000-"),
    };
  } else {
    return null;
  }

  const endpoint = type === "artist" ? "artist" : "cover";
  return {
    ultra: `https://e-cdns-images.dzcdn.net/images/${endpoint}/${md5Hash}/1900x1900-000000-80-0-0.jpg`,
    xl: `https://e-cdns-images.dzcdn.net/images/${endpoint}/${md5Hash}/1000x1000-000000-80-0-0.jpg`,
    large: `https://e-cdns-images.dzcdn.net/images/${endpoint}/${md5Hash}/500x500-000000-80-0-0.jpg`,
    medium: `https://e-cdns-images.dzcdn.net/images/${endpoint}/${md5Hash}/250x250-000000-80-0-0.jpg`,
    small: `https://e-cdns-images.dzcdn.net/images/${endpoint}/${md5Hash}/56x56-000000-80-0-0.jpg`,
    default: `https://e-cdns-images.dzcdn.net/images/${endpoint}/${md5Hash}/1000x1000-000000-80-0-0.jpg`,
  };
}

// -------------------------------------------------------------------------
// TRACK DISCOVERY (ID / ISRC / QUERY + ARTIST)
// -------------------------------------------------------------------------

async function discoverTrack({ id, isrc, query, artist }, env = null) {
  const cleanId = id ? String(id).trim() : "";
  const cleanIsrc = normalizeSharedIsrc(isrc);
  const cleanQuery = query ? String(query).trim() : "";
  const cleanArtist = artist ? String(artist).trim() : "";

  // Stable track metadata can safely live in the shared KV. Signed playback
  // URLs are never stored here.
  const cacheId = cleanId
    ? sharedCacheKey("track", `id:${cleanId}`)
    : cleanIsrc
      ? sharedCacheKey("track", `isrc:${cleanIsrc}`)
      : null;

  if (cacheId) {
    const cached = await getSharedCache(env, cacheId);
    if (cached?.id) return cached;
  }

  let found = null;

  if (cleanId) {
    const resp = await fetch(`https://api.deezer.com/track/${encodeURIComponent(cleanId)}`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    });
    const result = await readResponse(resp);
    if (result.json?.id) found = result.json;
  }

  if (!found && cleanIsrc) {
    const resp = await fetch(`https://api.deezer.com/track/isrc:${encodeURIComponent(cleanIsrc)}`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    });
    const result = await readResponse(resp);
    if (result.json?.id) found = result.json;
  }

  if (!found && (cleanQuery || cleanArtist)) {
    let qTerm = "";
    if (cleanQuery && cleanArtist) {
      qTerm = `track:"${cleanQuery}" artist:"${cleanArtist}"`;
    } else if (cleanQuery) {
      qTerm = cleanQuery;
    } else {
      qTerm = `artist:"${cleanArtist}"`;
    }

    let resp = await fetch(`https://api.deezer.com/search?q=${encodeURIComponent(qTerm)}`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    });
    let result = await readResponse(resp);
    if (result.json?.data?.length > 0) found = result.json.data[0];

    if (!found && cleanQuery && cleanArtist) {
      resp = await fetch(`https://api.deezer.com/search?q=${encodeURIComponent(`${cleanQuery} ${cleanArtist}`)}`, {
        headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
      });
      result = await readResponse(resp);
      if (result.json?.data?.length > 0) found = result.json.data[0];
    }
  }

  if (found?.id) {
    if (cacheId) await putSharedCache(env, cacheId, found);
    const foundIsrc = normalizeSharedIsrc(found.isrc || found.ISRC || cleanIsrc);
    if (foundIsrc) {
      await putSharedCache(env, sharedCacheKey("track", `isrc:${foundIsrc}`), found);
    }
    await putSharedCache(env, sharedCacheKey("track", `id:${found.id}`), found);
  }

  return found;
}

// -------------------------------------------------------------------------
// DEEZER GRAPHQL LYRICS (WORD-BY-WORD & LINE-BY-LINE)
// -------------------------------------------------------------------------

const GQL_LYRICS_QUERY = `
query GetLyrics($trackId: String!) {
  track(trackId: $trackId) {
    id
    lyrics {
      id
      text
      copyright
      writers
      synchronizedLines {
        lrcTimestamp
        line
        lineTranslated
        milliseconds
        duration
      }
      synchronizedWordByWordLines {
        start
        end
        words {
          start
          end
          word
        }
      }
    }
  }
}
`;

function normalizeLyricsLines(lines) {
  if (!Array.isArray(lines)) return null;
  return lines.map((line) => ({
    ...line,
    milliseconds: Number.isFinite(Number(line?.milliseconds)) ? Number(line.milliseconds) : null,
    duration: Number.isFinite(Number(line?.duration)) ? Number(line.duration) : null,
  }));
}

function normalizeWordSync(lines) {
  if (!Array.isArray(lines)) return null;
  return lines.map((line) => ({
    start: Number.isFinite(Number(line?.start)) ? Number(line.start) : line?.start ?? null,
    end: Number.isFinite(Number(line?.end)) ? Number(line.end) : line?.end ?? null,
    words: Array.isArray(line?.words) ? line.words.map((word) => ({
      start: Number.isFinite(Number(word?.start)) ? Number(word.start) : word?.start ?? null,
      end: Number.isFinite(Number(word?.end)) ? Number(word.end) : word?.end ?? null,
      word: word?.word ?? "",
    })) : [],
  }));
}

function wordSyncToLrc(wordLines) {
  if (!Array.isArray(wordLines) || !wordLines.length) return null;
  const lines = [];
  for (const line of wordLines) {
    const words = Array.isArray(line.words) ? line.words : [];
    if (!words.length) continue;
    const start = Number(line.start);
    const ms = Number.isFinite(start) ? start : Number(words[0]?.start);
    const timestamp = Number.isFinite(ms) ? `[${Math.floor(ms / 60000).toString().padStart(2, "0")}:${((ms % 60000) / 1000).toFixed(2).padStart(5, "0")}]` : "";
    lines.push(`${timestamp}${words.map(w => w.word || "").join("")}`);
  }
  return lines.length ? lines.join("\n") : null;
}

async function getLyricsFromPipeGQL(arl, trackId) {
  const jwt = await getPipeJwt(arl);
  if (!jwt) return null;

  try {
    const resp = await fetch(DEEZER_PIPE_GQL, {
      method: "POST",
      headers: {
        ...BROWSER_HEADERS,
        "Content-Type": "application/json",
        "Authorization": `Bearer ${jwt}`,
      },
      body: JSON.stringify({
        operationName: "GetLyrics",
        variables: { trackId: String(trackId) },
        query: GQL_LYRICS_QUERY,
      }),
    });

    const result = await readResponse(resp);
    const lyricsObj = result.json?.data?.track?.lyrics;
    if (!lyricsObj) return null;

    const wordSync = normalizeWordSync(lyricsObj.synchronizedWordByWordLines);
    const lineSync = normalizeLyricsLines(lyricsObj.synchronizedLines);
    let lrc = null;

    // Word-level timing is the most precise representation. Prefer it over
    // line timing so clients that only consume `lrc` still receive the most
    // detailed timing available from Deezer.
    if (wordSync?.length) {
      lrc = wordSyncToLrc(wordSync);
    } else if (lineSync?.length) {
      lrc = lineSync.map(l => `${l.lrcTimestamp || ""}${l.line || ""}`).join("\n");
    }

    return {
      source: "deezer_graphql",
      id: lyricsObj.id ?? null,
      syncType: wordSync?.length ? "WORD_BY_WORD" : lineSync?.length ? "LINE_BY_LINE" : "UNSYNCED",
      hasWordSync: Boolean(wordSync?.length),
      hasLineSync: Boolean(lineSync?.length),
      writers: lyricsObj.writers ?? null,
      copyright: lyricsObj.copyright ?? null,
      plain: lyricsObj.text ?? null,
      lrc,
    };
  } catch {
    return null;
  }
}

async function getLyricsFromLRCLIB(title, artist, duration, isrc) {
  try {
    const params = new URLSearchParams();
    if (isrc) params.set("isrc", isrc);
    if (title) params.set("track_name", title);
    if (artist) params.set("artist_name", artist);
    if (duration) params.set("duration", Math.round(duration));

    const resp = await fetch(`https://lrclib.net/api/get?${params.toString()}`, {
      headers: { "User-Agent": "CloudflareWorker-DeezerStreamer/2.0" },
    });

    const result = await readResponse(resp);
    if (result.json?.id) {
      const synced = result.json.syncedLyrics || null;
      return {
        source: "lrclib",
        id: result.json.id,
        syncType: synced ? "LINE_BY_LINE" : "UNSYNCED",
        hasWordSync: false,
        hasLineSync: Boolean(synced),
        writers: result.json.writers ?? null,
        copyright: result.json.copyright ?? null,
        plain: result.json.plainLyrics || null,
        lrc: synced,
      };
    }
  } catch {}
  return null;
}

// -------------------------------------------------------------------------
// AUTOPLAY & RADIO ENGINE
// -------------------------------------------------------------------------

async function getAutoplayRadio(artistId, currentTrackId, reqOrigin, currentQuality) {
  if (!artistId) return [];

  let rawTracks = [];

  // 1. Fetch artist radio (mixes artist tracks + similar artists)
  try {
    const radioResp = await fetch(`https://api.deezer.com/artist/${artistId}/radio`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    });
    const result = await readResponse(radioResp);
    if (Array.isArray(result.json?.data) && result.json.data.length > 0) {
      rawTracks = result.json.data;
    }
  } catch {}

  // 2. Fallback: Artist Top Tracks
  if (rawTracks.length === 0) {
    try {
      const topResp = await fetch(`https://api.deezer.com/artist/${artistId}/top?limit=25`, {
        headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
      });
      const result = await readResponse(topResp);
      if (Array.isArray(result.json?.data)) {
        rawTracks = result.json.data;
      }
    } catch {}
  }

  // Filter out the currently playing track
  const filtered = rawTracks.filter(t => String(t.id) !== String(currentTrackId));

  return filtered.map(item => ({
    id: String(item.id),
    title: item.title,
    artist: {
      id: String(item.artist?.id),
      name: item.artist?.name,
      artwork: buildArtworkUrls(item.artist?.picture_xl || item.artist?.picture, "artist"),
    },
    album: {
      id: String(item.album?.id),
      title: item.album?.title,
      artwork: buildArtworkUrls(item.album?.cover_xl || item.album?.cover, "cover"),
    },
    duration: item.duration,
    explicit: Boolean(item.explicit_lyrics),
    streamUrl: `${reqOrigin}/stream-track?id=${item.id}&quality=${encodeURIComponent(currentQuality || "flac")}`,
    resolveUrl: `${reqOrigin}/?id=${item.id}&quality=${encodeURIComponent(currentQuality || "flac")}`,
  }));
}

// -------------------------------------------------------------------------
// TRACK TOKENS & STREAM RESOLUTION
// -------------------------------------------------------------------------

async function getTrackTokens(arl, session, trackId) {
  const idNum = parseInt(trackId, 10) || trackId;
  const listUrl = `${DEEZER_GW}?method=song.getListData&input=3&api_version=1.0&api_token=${session.apiToken}`;

  const response = await fetch(listUrl, {
    method: "POST",
    headers: {
      ...BROWSER_HEADERS,
      "Content-Type": "application/json",
      Cookie: `sid=${session.sid}; arl=${arl}`,
    },
    body: JSON.stringify({ sng_ids: [idNum] }),
  });

  const result = await readResponse(response);
  let trackData = result.json?.results?.data?.[0];
  if (trackData?.FALLBACK) trackData = { ...trackData, ...trackData.FALLBACK };
  return trackData;
}

async function resolveMediaStream(licenseToken, trackToken, targetFormat) {
  const payload = {
    license_token: licenseToken,
    media: [
      {
        type: "FULL",
        formats: [{ cipher: "BF_CBC_STRIPE", format: targetFormat }],
      },
    ],
    track_tokens: [trackToken],
  };

  const response = await fetch(DEEZER_MEDIA_API, {
    method: "POST",
    headers: {
      ...BROWSER_HEADERS,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const result = await readResponse(response);
  const mediaItem = result.json?.data?.[0]?.media?.[0];
  if (mediaItem?.sources?.[0]?.url) {
    return {
      directCdnUrl: mediaItem.sources[0].url,
      format: mediaItem.format,
    };
  }

  const rawError = result.json?.data?.[0]?.errors?.[0] || result.json || result.text;
  throw new Error(`Media resolution for ${targetFormat} failed: ${typeof rawError === "object" ? JSON.stringify(rawError) : rawError}`);
}

function firstValue(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && String(value).trim() !== "") return value;
  }
  return null;
}

function toNumber(value) {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function normalizeContributors(raw) {
  if (!raw) return [];
  const result = [];

  // Deezer REST Track objects return contributors as an array of artist objects.
  if (Array.isArray(raw)) {
    for (const item of raw) {
      if (!item) continue;
      if (typeof item === "object") {
        result.push({ ...item, role: item.role || "artist" });
      } else if (String(item).trim()) {
        result.push({ role: "artist", name: String(item) });
      }
    }
    return result;
  }

  if (typeof raw !== "object") return [];

  // song.getListData may return contributors grouped by role.
  for (const [role, names] of Object.entries(raw)) {
    if (Array.isArray(names)) {
      for (const item of names) {
        if (!item) continue;
        if (typeof item === "object") {
          result.push({ role, ...item });
        } else if (String(item).trim()) {
          result.push({ role, name: String(item) });
        }
      }
    } else if (names !== null && names !== undefined && String(names).trim()) {
      result.push({ role, name: String(names) });
    }
  }
  return result;
}

function contributorNamesForRole(contributors, rolePattern) {
  if (!Array.isArray(contributors)) return [];
  const pattern = rolePattern instanceof RegExp ? rolePattern : new RegExp(String(rolePattern), "i");
  return contributors
    .filter(c => pattern.test(String(c?.role || c?.ROLE || "")))
    .map(c => c?.name || c?.ART_NAME || c?.artist?.name)
    .filter(Boolean)
    .map(String);
}

async function getAlbumMetadata(albumId) {
  if (!albumId) return null;
  try {
    const resp = await fetch(`https://api.deezer.com/album/${encodeURIComponent(albumId)}`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    });
    const result = await readResponse(resp);
    if (result.json?.id) return result.json;
  } catch {}
  return null;
}

function buildRichMetadata(trackData, track, albumData, finalLyrics) {
  const rawContributors = firstValue(
    trackData?.SNG_CONTRIBUTORS,
    trackData?.CONTRIBUTORS,
    trackData?.contributors,
    track?.contributors
  );
  const contributors = normalizeContributors(rawContributors);
  const contributorText = contributors
    .map(c => c?.name || c?.ART_NAME || c?.artist?.name)
    .filter(Boolean)
    .map(String);

  const writerValue = firstValue(
    trackData?.SNG_WRITERS,
    trackData?.WRITERS,
    trackData?.writers,
    track?.writers,
    finalLyrics?.writers,
    contributorNamesForRole(contributors, /writer|songwriter|composer|lyricist|author/i)
  );

  const copyright = firstValue(
    trackData?.COPYRIGHT,
    trackData?.SNG_COPYRIGHT,
    trackData?.COPYRIGHT_TEXT,
    trackData?.COPYRIGHT_HOLDER,
    trackData?.copyright,
    track?.copyright,
    albumData?.copyright,
    finalLyrics?.copyright
  );

  const label = firstValue(
    trackData?.LABEL_NAME,
    trackData?.LABEL,
    trackData?.label,
    trackData?.ALB_LABEL,
    trackData?.ALBUM_LABEL,
    albumData?.label
  );

  const distributor = firstValue(
    trackData?.DISTRIBUTOR,
    trackData?.DISTRIBUTOR_NAME,
    trackData?.distribution,
    trackData?.DISTRIBUTION,
    track?.distributor,
    albumData?.distributor
  );

  const publisher = firstValue(
    trackData?.PUBLISHER,
    trackData?.PUBLISHER_NAME,
    trackData?.publishing,
    trackData?.PUBLISHING,
    track?.publisher,
    albumData?.publisher
  );

  const authorNotes = firstValue(
    trackData?.AUTHOR_NOTES,
    trackData?.AUTHORS_NOTES,
    trackData?.AUTHOR_NOTE,
    trackData?.NOTES,
    trackData?.NOTE,
    trackData?.authorNotes,
    trackData?.notes,
    track?.authorsNotes,
    albumData?.authorsNotes
  );

  return {
    contributors: contributors.length ? contributors : null,
    writers: Array.isArray(writerValue) ? writerValue : (writerValue ?? (contributorText.length ? contributorText : null)),
    copyright: copyright ?? null,
    label: label ?? null,
    distributor: distributor ?? null,
    publisher: publisher ?? null,
    authorsNotes: authorNotes ?? null,
    rawCredits: rawContributors ?? null,
  };
}

function sanitizeSourceMetadata(value) {
  if (!value || typeof value !== "object") return null;
  const blocked = /(token|jwt|arl|password|secret|license|credential|cookie|authorization)/i;
  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (blocked.test(key)) continue;
    if (typeof val === "function") continue;
    out[key] = val;
  }
  return out;
}

// -------------------------------------------------------------------------
// ARL HEALTH / PING
// -------------------------------------------------------------------------

function getConfiguredArls(env) {
  const arls = [];
  for (let i = 0; i < 10; i++) {
    const name = i === 0 ? "DEEZER_ARL" : `DEEZER_ARL_${i + 1}`;
    const value = env[name]?.trim();
    if (value) {
      arls.push({ slot: i + 1, name, value });
    }
  }
  return arls;
}

async function pingArlDirect(arl, slot, variableName) {
  const started = Date.now();

  try {
    // Create a brand-new Deezer session for THIS environment variable.
    // This deliberately bypasses the playback session cache, so every ARL is
    // actually tested independently.
    const pingResp = await fetch(
      `${DEEZER_GW}?method=deezer.ping&input=3&api_version=1.0&api_token=`,
      {
        method: "POST",
        headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
        body: "{}",
      }
    );

    const pingResult = await readResponse(pingResp);
    const sid = pingResult.json?.results?.SESSION;
    if (!sid) {
      return {
        slot,
        variable: variableName,
        status: "failed",
        latency_ms: Date.now() - started,
        error: "Deezer session could not be created",
      };
    }

    const userResp = await fetch(
      `${DEEZER_GW}?method=deezer.getUserData&input=3&api_version=1.0&api_token=null`,
      {
        method: "POST",
        headers: {
          ...BROWSER_HEADERS,
          "Content-Type": "application/json",
          Cookie: `sid=${sid}; arl=${arl}`,
        },
        body: "{}",
      }
    );

    const userResult = await readResponse(userResp);
    const user = userResult.json?.results?.USER;
    const apiToken = userResult.json?.results?.checkForm;
    const licenseToken = user?.OPTIONS?.license_token;
    const ok = Boolean(user && apiToken && licenseToken);

    if (!ok) {
      return {
        slot,
        variable: variableName,
        status: "expired_or_invalid",
        latency_ms: Date.now() - started,
        can_lossless: false,
        lossless_check: "authentication_failed",
        user_id: user?.USER_ID ?? user?.id ?? null,
        error: "Invalid or expired Deezer ARL",
      };
    }

    // Real lossless capability test. Authenticate this ARL, obtain the
    // playback token for a known Deezer FLAC track, then ask Deezer's media
    // endpoint for FLAC. We only mark the account as lossless-capable when
    // Deezer actually returns a FLAC source for the test track.
    let canLossless = false;
    let losslessCheck = "flac_test_failed";
    let losslessError = null;

    try {
      const testTrackData = await getTrackTokens(arl, {
        sid,
        apiToken,
        licenseToken,
      }, "819736552");

      if (!testTrackData?.TRACK_TOKEN) {
        throw new Error("Could not obtain TRACK_TOKEN for lossless test track");
      }

      const flacResult = await resolveMediaStream(
        licenseToken,
        testTrackData.TRACK_TOKEN,
        "FLAC"
      );

      const returnedFormat = String(flacResult?.format || "").toUpperCase();
      canLossless = returnedFormat === "FLAC" && Boolean(flacResult?.directCdnUrl);
      losslessCheck = canLossless ? "flac_authorized" : "flac_not_authorized";

      if (!canLossless) {
        losslessError = `Deezer returned ${returnedFormat || "no format"} instead of FLAC`;
      }
    } catch (error) {
      losslessError = error?.message || "FLAC authorization test failed";
    }

    return {
      slot,
      variable: variableName,
      status: "active",
      latency_ms: Date.now() - started,
      can_lossless: canLossless,
      lossless_check: losslessCheck,
      lossless_test_track: "819736552",
      user_id: user?.USER_ID ?? user?.id ?? null,
      error: losslessError,
    };
  } catch (error) {
    return {
      slot,
      variable: variableName,
      status: "failed",
      latency_ms: Date.now() - started,
      can_lossless: null,
      lossless_check: "not_tested",
      error: error?.message || "Authentication request failed",
    };
  }
}

async function pingAllArls(env) {
  const configured = getConfiguredArls(env);

  if (!configured.length) {
    return {
      configured: 0,
      active: 0,
      expired_or_invalid: 0,
      failed: 0,
      checked_at: new Date().toISOString(),
      results: [],
      error: "No DEEZER_ARL environment variables are configured.",
    };
  }

  const results = await Promise.all(
    configured.map(item => pingArlDirect(item.value, item.slot, item.name))
  );

  const active = results.filter(r => r.status === "active").length;
  const expired = results.filter(r => r.status === "expired_or_invalid").length;
  const failed = results.filter(r => r.status === "failed").length;

  return {
    configured: configured.length,
    active,
    expired_or_invalid: expired,
    failed,
    checked_at: new Date().toISOString(),
    results,
  };
}

// -------------------------------------------------------------------------
// PUBLIC CATALOG API HELPERS
// -------------------------------------------------------------------------

const PUBLIC_API_BASE = "https://api.deezer.com";
const API_VERSION = "3.0-deezer-hifi";

function clampInt(value, fallback, min, max) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function catalogHeaders() {
  return {
    "User-Agent": BROWSER_HEADERS["User-Agent"],
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
  };
}

async function publicApi(path, params = {}, timeoutMs = 8000) {
  const url = new URL(`${PUBLIC_API_BASE}/${String(path).replace(/^\//, "")}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
  }

  let lastError = null;
  const maxAttempts = 3;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url.toString(), {
        headers: catalogHeaders(),
        signal: controller.signal,
      });
      const result = await readResponse(response);

      if (result.ok && !result.json?.error) return result.json;

      const apiError = result.json?.error;
      const message = apiError?.message || `Deezer catalog request failed (${result.status})`;
      const error = new Error(message);
      error.status = result.status || 502;
      error.apiError = apiError || null;
      lastError = error;

      const retryable = result.status === 429 || result.status >= 500;
      if (!retryable || attempt === maxAttempts) throw error;
    } catch (error) {
      lastError = error;
      const retryable = error?.name === "AbortError" || !error?.status || error.status === 429 || error.status >= 500;
      if (!retryable || attempt === maxAttempts) throw error;
    } finally {
      clearTimeout(timer);
    }

    await new Promise(resolve => setTimeout(resolve, 150 * (2 ** (attempt - 1))));
  }

  throw lastError || new Error("Deezer catalog request failed");
}

function catalogResponse(data, status = 200, maxAge = 60) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${Math.max(0, maxAge)}, stale-while-revalidate=300`,
      "X-Voria-API-Version": API_VERSION,
    },
  });
}

function apiErrorResponse(message, status = 400, details = null) {
  return catalogResponse({
    error: message,
    status,
    ...(details ? { details } : {}),
    api: API_VERSION,
  }, status, 0);
}

function normalizeLimitOffset(url, defaultLimit = 25, maxLimit = 100) {
  return {
    limit: clampInt(url.searchParams.get("limit"), defaultLimit, 1, maxLimit),
    offset: clampInt(url.searchParams.get("offset") ?? url.searchParams.get("index"), 0, 0, 1000000),
  };
}

function normalizeTrack(track) {
  if (!track) return null;
  const artwork = buildArtworkUrls(track.album?.cover_xl || track.album?.cover, "cover");
  const artistArtwork = buildArtworkUrls(track.artist?.picture_xl || track.artist?.picture, "artist");
  return {
    id: track.id ?? null,
    title: track.title ?? null,
    title_short: track.title_short ?? null,
    version: track.version ?? null,
    duration: toNumber(track.duration),
    rank: toNumber(track.rank),
    explicit: Boolean(track.explicit_lyrics),
    explicit_content_lyrics: track.explicit_content_lyrics ?? null,
    explicit_content_cover: track.explicit_content_cover ?? null,
    preview: track.preview ?? null,
    bpm: toNumber(track.bpm),
    gain: toNumber(track.gain),
    isrc: track.isrc ?? null,
    readable: track.readable ?? null,
    link: track.link ?? null,
    artist: track.artist ? {
      id: track.artist.id ?? null,
      name: track.artist.name ?? null,
      link: track.artist.link ?? null,
      artwork: artistArtwork,
    } : null,
    album: track.album ? {
      id: track.album.id ?? null,
      title: track.album.title ?? null,
      link: track.album.link ?? null,
      release_date: track.album.release_date ?? null,
      artwork,
    } : null,
    artwork,
  };
}

function normalizeAlbum(album) {
  if (!album) return null;
  const artwork = buildArtworkUrls(album.cover_xl || album.cover, "cover");
  return {
    id: album.id ?? null,
    title: album.title ?? null,
    upc: album.upc ?? null,
    link: album.link ?? null,
    release_date: album.release_date ?? null,
    record_type: album.record_type ?? null,
    genre_id: album.genre_id ?? null,
    nb_tracks: toNumber(album.nb_tracks),
    duration: toNumber(album.duration),
    fans: toNumber(album.fans),
    rating: toNumber(album.rating),
    explicit_lyrics: album.explicit_lyrics ?? null,
    label: album.label ?? null,
    available: album.available ?? null,
    artwork,
    artist: album.artist ? {
      id: album.artist.id ?? null,
      name: album.artist.name ?? null,
      link: album.artist.link ?? null,
      artwork: buildArtworkUrls(album.artist.picture_xl || album.artist.picture, "artist"),
    } : null,
  };
}

function normalizeArtist(artist) {
  if (!artist) return null;
  return {
    id: artist.id ?? null,
    name: artist.name ?? null,
    link: artist.link ?? null,
    nb_album: toNumber(artist.nb_album),
    nb_fan: toNumber(artist.nb_fan),
    radio: artist.radio ?? null,
    tracklist: artist.tracklist ?? null,
    artwork: buildArtworkUrls(artist.picture_xl || artist.picture, "artist"),
  };
}

function normalizePlaylist(playlist) {
  if (!playlist) return null;
  return {
    id: playlist.id ?? null,
    title: playlist.title ?? null,
    description: playlist.description ?? null,
    public: playlist.public ?? null,
    is_loved_track: playlist.is_loved_track ?? null,
    nb_tracks: toNumber(playlist.nb_tracks),
    fans: toNumber(playlist.fans),
    duration: toNumber(playlist.duration),
    link: playlist.link ?? null,
    creation_date: playlist.creation_date ?? null,
    modification_date: playlist.modification_date ?? null,
    picture: buildArtworkUrls(playlist.picture_xl || playlist.picture, "cover"),
    creator: playlist.creator ? {
      id: playlist.creator.id ?? null,
      name: playlist.creator.name ?? null,
    } : null,
  };
}

function normalizeCollection(result, normalizer) {
  const items = Array.isArray(result?.data) ? result.data.map(normalizer).filter(Boolean) : [];
  return {
    data: items,
    total: toNumber(result?.total),
    next: result?.next ?? null,
    previous: result?.prev ?? result?.previous ?? null,
  };
}

async function handleCatalogRoute(requestUrl) {
  const path = requestUrl.pathname.replace(/\/+$/, "") || "/";
  const { limit, offset } = normalizeLimitOffset(requestUrl);

  if (path === "/" || path === "/info-api") {
    return catalogResponse({
      version: API_VERSION,
      provider: "deezer",
      name: "Voria Deezer HiFi API",
      cache: { namespace: "GENERAL_MUSIC_CACHE", keyPrefix: "music:deezer:" },
      compatibleStyle: "hifi-api",
      capabilities: {
        info: true,
        track: true,
        stream: true,
        search: true,
        album: true,
        artist: true,
        playlist: true,
        lyrics: true,
        cover: true,
        recommendations: true,
        radio: true,
        similarArtists: true,
        similarAlbums: true,
      },
      endpoints: ["/info", "/track", "/stream", "/search", "/album", "/artist", "/playlist", "/lyrics", "/cover", "/recommendations", "/radio", "/artist/similar", "/album/similar", "/chart", "/genre", "/ping"],
    }, 200, 30);
  }

  if (path === "/info") {
    const id = requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    const isrc = requestUrl.searchParams.get("isrc");
    if (!id && !isrc) return apiErrorResponse("Missing id or isrc", 400);
    const track = await discoverTrack({ id, isrc }, env);
    if (!track?.id) return apiErrorResponse("Track not found", 404);
    return catalogResponse({ version: API_VERSION, data: normalizeTrack(track) }, 200, 30);
  }

  if (path === "/search") {
    const isrc = requestUrl.searchParams.get("i");
    const q = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("s") || requestUrl.searchParams.get("a") || requestUrl.searchParams.get("al") || requestUrl.searchParams.get("p");
    let type = (requestUrl.searchParams.get("type") || "").toLowerCase();
    if (!type) {
      if (requestUrl.searchParams.has("a")) type = "artist";
      else if (requestUrl.searchParams.has("al")) type = "album";
      else if (requestUrl.searchParams.has("p")) type = "playlist";
      else type = "track";
    }
    if (!q && !isrc) return apiErrorResponse("Missing q", 400);
    const allowed = new Set(["track", "album", "artist", "playlist", "podcast", "radio"]);
    if (!allowed.has(type)) return apiErrorResponse(`Unsupported search type: ${type}`, 400, { supported: [...allowed] });

    if (isrc) {
      const track = await discoverTrack({ isrc }, env);
      const items = track ? [normalizeTrack(track)] : [];
      return catalogResponse({ version: API_VERSION, type: "track", query: isrc, data: items, total: items.length, next: null, previous: null }, 200, 30);
    }

    const params = {
      q,
      limit,
      index: offset,
      ...(requestUrl.searchParams.get("order") ? { order: requestUrl.searchParams.get("order") } : {}),
      ...(requestUrl.searchParams.has("strict") ? { strict: requestUrl.searchParams.get("strict") } : {}),
    };
    const result = await publicApi(`search/${type}`, params);
    const normalizer = type === "track" ? normalizeTrack : type === "album" ? normalizeAlbum : type === "artist" ? normalizeArtist : type === "playlist" ? normalizePlaylist : x => x;
    return catalogResponse({ version: API_VERSION, type, query: q, ...normalizeCollection(result, normalizer) }, 200, 30);
  }

  if (path === "/album") {
    const id = requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id", 400);
    const album = await publicApi(`album/${encodeURIComponent(id)}`);
    const tracks = await publicApi(`album/${encodeURIComponent(id)}/tracks`, { limit, index: offset });
    const normalizedTracks = normalizeCollection(tracks, normalizeTrack);
    return catalogResponse({ version: API_VERSION, data: normalizeAlbum(album), tracks: normalizedTracks.data, pagination: { total: normalizedTracks.total, next: normalizedTracks.next, previous: normalizedTracks.previous, limit, offset } }, 200, 120);
  }

  if (path === "/artist") {
    const id = requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id", 400);
    const artist = await publicApi(`artist/${encodeURIComponent(id)}`);
    const mode = (requestUrl.searchParams.get("include") || "profile").toLowerCase();
    const data = { version: API_VERSION, artist: normalizeArtist(artist) };
    if (mode === "top" || mode === "all") {
      const top = await publicApi(`artist/${encodeURIComponent(id)}/top`, { limit, index: offset });
      data.top_tracks = normalizeCollection(top, normalizeTrack);
    }
    if (mode === "albums" || mode === "all") {
      const albums = await publicApi(`artist/${encodeURIComponent(id)}/albums`, { limit, index: offset });
      data.albums = normalizeCollection(albums, normalizeAlbum);
    }
    if (mode === "radio" || mode === "all") {
      const radio = await publicApi(`artist/${encodeURIComponent(id)}/radio`, { limit, index: offset });
      data.radio = normalizeCollection(radio, normalizeTrack);
    }
    if (mode === "related" || mode === "all") {
      const related = await publicApi(`artist/${encodeURIComponent(id)}/related`, { limit, index: offset });
      data.related = normalizeCollection(related, normalizeArtist);
    }
    return catalogResponse(data, 200, 120);
  }

  if (path === "/playlist") {
    const id = requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id", 400);
    const playlist = await publicApi(`playlist/${encodeURIComponent(id)}`);
    const trackResult = await publicApi(`playlist/${encodeURIComponent(id)}/tracks`, { limit, index: offset });
    const normalizedTracks = normalizeCollection(trackResult, normalizeTrack);
    return catalogResponse({ version: API_VERSION, data: normalizePlaylist(playlist), tracks: normalizedTracks.data, pagination: { total: normalizedTracks.total ?? toNumber(playlist?.nb_tracks), next: normalizedTracks.next, previous: normalizedTracks.previous, limit, offset } }, 200, 120);
  }

  if (path === "/cover") {
    const id = requestUrl.searchParams.get("id");
    const q = requestUrl.searchParams.get("q");
    let track = null;
    if (id) track = await discoverTrack({ id }, env);
    else if (q) track = await discoverTrack({ query: q }, env);
    else return apiErrorResponse("Missing id or q", 400);
    if (!track?.id) return apiErrorResponse("Track not found", 404);
    return catalogResponse({ version: API_VERSION, covers: [{ id: track.album?.id ?? null, name: track.album?.title ?? null, ...buildArtworkUrls(track.album?.cover_xl || track.album?.cover, "cover") }] }, 200, 300);
  }

  if (path === "/recommendations") {
    const id = requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    if (!id) return apiErrorResponse("Missing id", 400);
    const track = await discoverTrack({ id }, env);
    if (!track?.id) return apiErrorResponse("Track not found", 404);
    const artistId = track.artist?.id;
    const result = artistId ? await publicApi(`artist/${encodeURIComponent(artistId)}/radio`, { limit, index: offset }) : { data: [] };
    const items = (result?.data || []).filter(x => String(x.id) !== String(track.id)).map(normalizeTrack).filter(Boolean);
    return catalogResponse({ version: API_VERSION, data: { limit, offset, total: items.length, items } }, 200, 30);
  }

  if (path === "/radio") {
    const artistId = requestUrl.searchParams.get("artist_id") || requestUrl.searchParams.get("id");
    if (!artistId) return apiErrorResponse("Missing artist_id", 400);
    const result = await publicApi(`artist/${encodeURIComponent(artistId)}/radio`, { limit, index: offset });
    return catalogResponse({ version: API_VERSION, data: { ...normalizeCollection(result, normalizeTrack), limit, offset } }, 200, 30);
  }

  if (path === "/artist/similar") {
    const id = requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id", 400);
    const result = await publicApi(`artist/${encodeURIComponent(id)}/related`, { limit, index: offset });
    return catalogResponse({ version: API_VERSION, ...normalizeCollection(result, normalizeArtist) }, 200, 300);
  }

  if (path === "/chart") {
    const genre = requestUrl.searchParams.get("genre") || requestUrl.searchParams.get("genre_id") || 0;
    const result = await publicApi("chart", { limit, index: offset, genre });
    return catalogResponse({
      version: API_VERSION,
      genre_id: Number(genre) || 0,
      tracks: normalizeCollection(result?.tracks || {}, normalizeTrack),
      albums: normalizeCollection(result?.albums || {}, normalizeAlbum),
      artists: normalizeCollection(result?.artists || {}, normalizeArtist),
      playlists: normalizeCollection(result?.playlists || {}, normalizePlaylist),
    }, 200, 60);
  }

  if (path === "/genre") {
    const id = requestUrl.searchParams.get("id");
    if (id) {
      const genre = await publicApi(`genre/${encodeURIComponent(id)}`);
      return catalogResponse({ version: API_VERSION, data: genre }, 200, 3600);
    }
    const genres = await publicApi("genre");
    return catalogResponse({ version: API_VERSION, ...normalizeCollection(genres, x => x) }, 200, 3600);
  }

  if (path === "/album/similar") {
    const id = requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id", 400);
    const album = await publicApi(`album/${encodeURIComponent(id)}`);
    const artistId = album?.artist?.id;
    if (!artistId) return catalogResponse({ version: API_VERSION, data: [] }, 200, 300);
    const albums = await publicApi(`artist/${encodeURIComponent(artistId)}/albums`, { limit: Math.min(100, limit + 10), index: 0 });
    const data = (albums?.data || []).filter(x => String(x.id) !== String(id)).slice(0, limit).map(normalizeAlbum).filter(Boolean);
    return catalogResponse({ version: API_VERSION, data, total: data.length }, 200, 300);
  }

  return null;
}

// -------------------------------------------------------------------------
// MAIN FETCH HANDLER
// -------------------------------------------------------------------------

const worker = {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const requestUrl = new URL(request.url);
    const routePath = requestUrl.pathname.replace(/\/+$/, "") || "/";

    // --- DEEZER ARL HEALTH CHECK ---
    // GET /ping or /?ping=1
    if (routePath === "/ping" || requestUrl.searchParams.has("ping")) {
      try {
        const result = await pingAllArls(env);
        return jsonResponse(result, result.error && !result.results?.length ? 500 : 200);
      } catch (error) {
        return jsonResponse({
          error: "ARL ping failed",
          message: error?.message || "Unknown error",
        }, 500);
      }
    }

    if (!["GET", "HEAD"].includes(request.method)) {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { ...corsHeaders, "Allow": "GET, HEAD, OPTIONS" },
      });
    }

    // --- HIFI-STYLE PUBLIC CATALOG API ---
    // These routes are deliberately independent of ARL playback auth. They use
    // Deezer's public catalog API, giving Voria a stable browser-facing API for
    // metadata, discovery and artwork even when no playback account is usable.
    if (routePath !== "/" && ["/info-api", "/info", "/track", "/search", "/album", "/artist", "/playlist", "/cover", "/recommendations", "/radio", "/artist/similar", "/album/similar", "/chart", "/genre"].includes(routePath)) {
      // /track is an explicit alias for the normal rich playback pipeline.
      if (routePath === "/track") {
        // /track is an explicit alias for the existing rich playback response.
        // Fall through to the normal playback pipeline below.
      } else {
        try {
          const catalogResult = await handleCatalogRoute(requestUrl);
          if (catalogResult) {
            if (request.method === "HEAD") return new Response(null, { status: catalogResult.status, headers: catalogResult.headers });
            return catalogResult;
          }
        } catch (error) {
          return apiErrorResponse(error?.message || "Catalog request failed", error?.status >= 400 ? error.status : 502, error?.apiError || null);
        }
      }
    }

    // --- RANGE-AWARE CHUNKED STREAM ENGINE ---
    if (routePath === "/stream") {
      if (request.method === "HEAD") {
        return new Response(null, {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type": "audio/flac",
            "Accept-Ranges": "bytes",
          },
        });
      }

      try {
        const trackId = requestUrl.searchParams.get("id");
        const cdnUrl = requestUrl.searchParams.get("url");
        const format = (requestUrl.searchParams.get("format") || "FLAC").toUpperCase();

        if (!trackId || !cdnUrl) {
          return new Response("Missing id or url parameter", { status: 400 });
        }

        const mimeType = format.startsWith("MP3") ? "audio/mpeg" : "audio/flac";
        const cipher = new FastBlowfish(deriveTrackKey(trackId));

        const rangeHeader = request.headers.get("Range");

        let reqStart = 0;
        let reqEnd = null;
        let hasRange = false;

        if (rangeHeader) {
          const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
          if (match) {
            hasRange = true;
            reqStart = parseInt(match[1], 10);
            if (match[2].length > 0) {
              reqEnd = parseInt(match[2], 10);
            }
          }
        }

        const MAX_CHUNK = 6 * 1024 * 1024;
        if (reqEnd === null || reqEnd - reqStart + 1 > MAX_CHUNK) {
          reqEnd = reqStart + MAX_CHUNK - 1;
        }

        const startBlock = Math.floor(reqStart / 2048);
        const alignedStart = startBlock * 2048;
        const endBlock = Math.floor(reqEnd / 2048);
        const alignedEnd = (endBlock + 1) * 2048 - 1;

        const cdnResp = await fetch(cdnUrl, {
          headers: {
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "Range": `bytes=${alignedStart}-${alignedEnd}`,
          },
        });

        if (!cdnResp.ok && cdnResp.status !== 206) {
          return new Response(`CDN error: ${cdnResp.status}`, { status: cdnResp.status });
        }

        const contentRange = cdnResp.headers.get("content-range") || "";
        const totalMatch = contentRange.match(/\/(\d+)/);
        const totalSize = totalMatch ? parseInt(totalMatch[1], 10) : (alignedEnd + 1);

        const rawBytes = new Uint8Array(await cdnResp.arrayBuffer());

        decryptAlignedBuffer(cipher, rawBytes, startBlock);

        const offsetInFirstBlock = reqStart - alignedStart;
        const actualEnd = Math.min(reqEnd, totalSize - 1);
        const sliceLength = Math.max(0, actualEnd - reqStart + 1);
        const clientSlice = rawBytes.subarray(offsetInFirstBlock, offsetInFirstBlock + sliceLength);

        const headers = new Headers(corsHeaders);
        headers.set("Content-Type", mimeType);
        headers.set("Content-Length", clientSlice.length.toString());
        headers.set("Accept-Ranges", "bytes");
        headers.set("Cache-Control", "public, max-age=3600");

        if (hasRange) {
          headers.set("Content-Range", `bytes ${reqStart}-${actualEnd}/${totalSize}`);
          return new Response(clientSlice, { status: 206, headers });
        } else {
          return new Response(clientSlice, { status: 200, headers });
        }
      } catch (streamErr) {
        return new Response(`Stream error: ${streamErr.message}`, { status: 500, headers: corsHeaders });
      }
    }

    // --- PARAMETER PARSING ---
    const paramId = requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    const paramIsrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
    const paramQuery = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("track");
    const paramArtist = requestUrl.searchParams.get("artist");
    if (!paramId && !paramIsrc && !paramQuery && !paramArtist) {
      try {
        return await handleCatalogRoute(requestUrl);
      } catch (error) {
        return apiErrorResponse(error?.message || "Catalog request failed", error?.status >= 400 ? error.status : 502, error?.apiError || null);
      }
    }

    const hasExplicitQuality = requestUrl.searchParams.has("quality") || requestUrl.searchParams.has("format");
    const rawQuality = (requestUrl.searchParams.get("quality") || requestUrl.searchParams.get("format") || "best").toLowerCase().trim();

    if (hasExplicitQuality && rawQuality !== "best" && !QUALITY_MAP[rawQuality]) {
      return jsonResponse(
        {
          error: `Invalid quality requested: "${rawQuality}"`,
          supported_qualities: ["best", "flac", "320", "128"],
        },
        400
      );
    }

    // Automatic playback uses a strict two-stage fallback across ALL ARLs:
    //   1. Try FLAC on every configured account.
    //   2. Only if every account fails FLAC, try MP3_128 on every account.
    //
    // This is intentionally different from trying FLAC -> 320 -> 128 on ARL #1
    // before ever checking ARL #2. A lossy ARL must not prevent a later HiFi ARL
    // from being selected.
    const formatsToTry = hasExplicitQuality
      ? [rawQuality === "best" ? "flac" : rawQuality]
      : ["flac", "128"];
    const arls = Array.from({ length: 10 }, (_, i) =>
      env[`DEEZER_ARL${i ? `_${i + 1}` : ""}`]?.trim()
    ).filter(Boolean);

    if (!arls.length) {
      return jsonResponse({ error: "Missing DEEZER_ARL environment variable(s)" }, 500);
    }

    try {
      // Track discovery is provider-level and does not require an ARL.
      // Track discovery
      const track = await discoverTrack({
        id: paramId,
        isrc: paramIsrc,
        query: paramQuery,
        artist: paramArtist,
      }, env);

      if (!track?.id) {
        return jsonResponse({ error: "Track not found" }, 404);
      }

      // Do NOT trust USER.OPTIONS.can_stream_lossless for playback selection.
      // Deezer can report that flag as false even when the ARL can actually
      // resolve FLAC. The real test is whether the media endpoint accepts a
      // FLAC request for this account and this track.
      //
      // Authenticate all ARLs first. We then try them in slot order and let the
      // actual FLAC media request decide whether the account is lossless-capable.
      // If ARL #1 is lossy and ARL #2 is lossless, #1's FLAC request fails and
      // #2's FLAC request succeeds, so #2 is selected automatically.
      const candidates = await Promise.all(arls.map(async (candidateArl, index) => {
        try {
          const candidateSession = await getOrRenewSession(candidateArl);
          return {
            arl: candidateArl,
            slot: index + 1,
            session: candidateSession,
          };
        } catch (err) {
          clearArlCache(candidateArl);
          return {
            arl: candidateArl,
            slot: index + 1,
            session: null,
          };
        }
      }));

      let session = null;
      let arl = null;
      let selectedArlSlot = null;
      let selectedArlTier = null;
      let trackData = null;
      let mediaResult = null;
      let selectedProfile = null;
      let lastMediaError = null;

      // Automatic mode is intentionally account-first by quality tier:
      // check FLAC against every authenticated ARL before allowing a lossy
      // fallback. This makes ARL #2 capable of winning even when ARL #1 is
      // valid but only has 128 kbps access.
      const qualityStages = hasExplicitQuality
        ? [[rawQuality === "best" ? "flac" : rawQuality]]
        : [["flac"], ["128"]];

      let selected = false;

      for (const stage of qualityStages) {
        if (selected) break;

        for (const candidate of candidates) {
          if (!candidate.session) continue;

          try {
            const candidateArl = candidate.arl;
            const candidateSession = candidate.session;
            const candidateTrackData = await getTrackTokens(
              candidateArl,
              candidateSession,
              track.id
            );

            if (!candidateTrackData?.TRACK_TOKEN) {
              throw new Error("No playable TRACK_TOKEN");
            }

            const requestedKey = stage[0];
            const requestedProfile = QUALITY_MAP[requestedKey];
            const resolved = await resolveMediaStream(
              candidateSession.licenseToken,
              candidateTrackData.TRACK_TOKEN,
              requestedProfile.format
            );

            // Never accept a silent downgrade as a successful FLAC attempt.
            // If Deezer returns MP3_128 for a FLAC request, this account has
            // not actually satisfied the FLAC stage, so we continue to the
            // next ARL instead of selecting it prematurely.
            const actualFormat = String(
              resolved.format || requestedProfile.format
            ).toUpperCase();

            const actualKey = actualFormat === "FLAC"
              ? "flac"
              : actualFormat === "MP3_320"
                ? "320"
                : actualFormat === "MP3_128"
                  ? "128"
                  : null;

            if (!actualKey) {
              throw new Error(`Unsupported media format returned by Deezer: ${actualFormat}`);
            }

            if (actualKey !== requestedKey) {
              throw new Error(
                `Deezer returned ${actualFormat} for requested ${requestedProfile.format}`
              );
            }

            const actualProfile = QUALITY_MAP[actualKey];

            arl = candidateArl;
            session = candidateSession;
            selectedArlSlot = candidate.slot;
            selectedArlTier = actualProfile.lossless ? "lossless" : "lossy";
            trackData = candidateTrackData;
            mediaResult = resolved;
            selectedProfile = actualProfile;
            selected = true;
            break;
          } catch (err) {
            lastMediaError = err;
            // Keep the ARL available for the next quality stage. A failed FLAC
            // authorization does NOT mean the ARL itself is dead because the
            // same account may still be perfectly valid for MP3_128.
          }
        }
      }

      if (!trackData?.TRACK_TOKEN || !mediaResult || !selectedProfile) {
        throw lastMediaError || new Error("All configured Deezer ARLs failed to resolve the track.");
      }

      const songId = String(trackData.SNG_ID || track.id);
      const cleanStreamUrl = `${requestUrl.origin}/stream?id=${songId}&format=${mediaResult.format}&url=${encodeURIComponent(mediaResult.directCdnUrl)}`;

      // Immediate redirect if stream=1
      if (requestUrl.searchParams.get("stream") === "1" && !requestUrl.searchParams.has("json")) {
        return Response.redirect(cleanStreamUrl, 302);
      }

      // Optional Features: Lyrics and Autoplay
      const wantLyrics = requestUrl.searchParams.has("lyrics") || routePath === "/lyrics";
      const wantRadio = requestUrl.searchParams.has("radio") || requestUrl.searchParams.has("autoplay") || routePath === "/radio";
      const wantDebug = requestUrl.searchParams.has("debug");

      const artistId = String(trackData.ART_ID || track.artist?.id);

      // Parallel feature retrieval
      const [pipeLyrics, radioTracks, albumData] = await Promise.all([
        wantLyrics ? getLyricsFromPipeGQL(arl, songId) : Promise.resolve(null),
        wantRadio ? getAutoplayRadio(artistId, songId, requestUrl.origin, rawQuality) : Promise.resolve(null),
        getAlbumMetadata(trackData.ALB_ID || track.album?.id),
      ]);

      // Fallback to LRCLIB if Deezer GraphQL has no lyrics
      let finalLyrics = pipeLyrics;
      if (wantLyrics && (!finalLyrics || !finalLyrics.plain || !finalLyrics.lrc)) {
        const fallback = await getLyricsFromLRCLIB(
          trackData.SNG_TITLE || track.title,
          trackData.ART_NAME || track.artist?.name,
          toNumber(trackData.DURATION) ?? toNumber(track.duration),
          trackData.ISRC || track.isrc
        );
        if (fallback) {
          if (!finalLyrics) {
            finalLyrics = fallback;
          } else {
            finalLyrics = {
              ...fallback,
              ...finalLyrics,
              plain: finalLyrics.plain || fallback.plain,
              lrc: finalLyrics.lrc || fallback.lrc,
              writers: finalLyrics.writers || fallback.writers,
              copyright: finalLyrics.copyright || fallback.copyright,
            };
          }
        }
      }

      // Direct route endpoints
      if (routePath === "/lyrics") {
        return jsonResponse({ track_id: songId, lyrics: finalLyrics });
      }
      if (routePath === "/radio") {
        return jsonResponse({ track_id: songId, radio: radioTracks });
      }

      // Artwork generators
      const albumArtwork = buildArtworkUrls(trackData.ALB_PICTURE || track.album?.cover_xl || track.album?.cover, "cover");
      const artistArtwork = buildArtworkUrls(trackData.ART_PICTURE || track.artist?.picture_xl || track.artist?.picture, "artist");

      const richMetadata = buildRichMetadata(trackData, track, albumData, finalLyrics);
      const version = firstValue(
        trackData.VERSION,
        trackData.SNG_VERSION,
        trackData.TRACK_VERSION,
        trackData.version,
        track.version
      );
      const bpm = toNumber(firstValue(
        track.bpm,
        trackData.BPM,
        trackData.SNG_BPM,
        trackData.TRACK_BPM,
        trackData.bpm
      ));

      // Final rich JSON response
      const responsePayload = {
        provider: "deezer",
        id: songId,
        isrc: trackData.ISRC || track.isrc || null,
        title: trackData.SNG_TITLE || track.title,
        version,
        duration: Number(trackData.DURATION) || track.duration || null,
        track_number: Number(trackData.TRACK_NUMBER) || track.track_position || null,
        disc_number: Number(trackData.DISK_NUMBER) || track.disk_number || null,
        bpm,
        gain: trackData.GAIN ? parseFloat(trackData.GAIN) : null,
        explicit: Boolean(Number(trackData.EXPLICIT_LYRICS) || track.explicit_lyrics),
        release_date: trackData.PHYSICAL_RELEASE_DATE || track.release_date || null,

        // High quality artwork suite (up to 1900x1900)
        artwork: albumArtwork,

        artist: {
          id: artistId,
          name: trackData.ART_NAME || track.artist?.name || "Unknown",
          artwork: artistArtwork,
        },

        album: {
          id: String(trackData.ALB_ID || track.album?.id),
          title: trackData.ALB_TITLE || track.album?.title || null,
          release_date: track.album?.release_date || trackData.PHYSICAL_RELEASE_DATE || null,
          track_count: toNumber(firstValue(
            albumData?.nb_tracks,
            trackData?.ALB_NB_TRACKS,
            trackData?.ALBUM_NB_TRACKS,
            track?.album?.nb_tracks
          )),
          artwork: albumArtwork,
        },

        // Audio specifications
        audio: {
          format: selectedProfile.audioFormat,           // "FLAC" or "MP3"
          bitrate: selectedProfile.bitrate,               // 320, 128, or null
          sampleRate: selectedProfile.sampleRate,         // 44100
          bitDepth: selectedProfile.bitDepth,             // 16 or null
          lossless: selectedProfile.lossless,             // true / false
          audioQuality: selectedProfile.badge,            // "LOSSLESS", "HIGH", or "LOW"
          qualityLabel: selectedProfile.label,
          mimeType: selectedProfile.mime,
          rawProfile: mediaResult.format,
        },

        // Top-level aliases
        format: selectedProfile.audioFormat,
        bitrate: selectedProfile.bitrate,
        sampleRate: selectedProfile.sampleRate,
        bitDepth: selectedProfile.bitDepth,
        audioQuality: selectedProfile.badge,
        quality: selectedProfile.label,
        deliveredQuality: selectedProfile.audioFormat === "FLAC" ? "16-bit / 44.1kHz" : selectedProfile.label,

        contributors: richMetadata.contributors,
        writers: richMetadata.writers,
        copyright: richMetadata.copyright,
        label: richMetadata.label,
        distributor: richMetadata.distributor,
        publisher: richMetadata.publisher,
        authorsNotes: richMetadata.authorsNotes,
        credits: richMetadata.rawCredits,

        deezerAccount: {
          variable: selectedArlSlot === 1 ? "DEEZER_ARL" : `DEEZER_ARL_${selectedArlSlot}`,
          slot: selectedArlSlot,
          tier: selectedArlTier,
          canLossless: Boolean(selectedProfile?.lossless),
        },

        sourceMetadata: sanitizeSourceMetadata(trackData),
        streamUrl: cleanStreamUrl,
        rawCdnUrl: mediaResult.directCdnUrl,
      };

      if (wantLyrics) {
        responsePayload.lyrics = finalLyrics;
      }

      if (wantRadio) {
        responsePayload.radio = radioTracks;
      }

      if (wantDebug) {
        responsePayload.debug = {
          session: {
            canLossless: session.canLossless,
            jwtActive: Boolean(jwtCache.get(arl)?.jwt),
            tokenExpiry: new Date(session.expiresAt).toISOString(),
          },
          metadataSources: {
            restTrack: Boolean(track),
            trackBpm: track?.bpm ?? null,
            trackContributors: Array.isArray(track?.contributors) ? track.contributors.length : 0,
            albumMetadata: Boolean(albumData),
            pipeLyrics: Boolean(pipeLyrics),
          },
          serverAvailableFormats: {
            flac: Number(trackData.FILESIZE_FLAC) > 0,
            mp3_320: Number(trackData.FILESIZE_MP3_320) > 0,
            mp3_128: Number(trackData.FILESIZE_MP3_128) > 0,
          },
          filesizes: {
            flac: Number(trackData.FILESIZE_FLAC) || 0,
            mp3_320: Number(trackData.FILESIZE_MP3_320) || 0,
            mp3_128: Number(trackData.FILESIZE_MP3_128) || 0,
          },
        };
      }

      return jsonResponse(responsePayload);
    } catch (error) {
      return jsonResponse(
        {
          error: "Deezer media resolution failed",
          message: error.message,
        },
        502
      );
    }
  },
};

export default worker;a
