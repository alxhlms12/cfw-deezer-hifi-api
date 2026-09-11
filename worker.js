/*
 * Qobuz HiFi API
 *
 * Drop-in, hifi-api-style Qobuz worker with:
 * - Multiple Qobuz user auth tokens
 * - Token failover / cooldown
 * - Catalog search
 * - Track / album / artist / playlist metadata
 * - ISRC -> exact Qobuz track resolution
 * - Qobuz stream URL resolution with 24/192 -> 24/96 -> CD -> MP3 fallback
 * - Short-lived stream URL memory cache only
 * - Long-lived metadata KV cache (shared GENERAL_MUSIC_CACHE)
 * - Request coalescing
 * - Retry/backoff for transient API failures
 * - CORS + HEAD + OPTIONS
 * - Artwork URL normalization
 * - Verified Qobuz catalog endpoints only
 * - Generated radio built from verified Qobuz catalog endpoints
 * - Explicit 501 responses for capabilities without a verified endpoint
 * - /ping token health testing
 *
 * Environment variables:
 *   QOBUZ_APP_ID
 *   QOBUZ_APP_SECRET
 *   QOBUZ_USER_AUTH_TOKEN
 *   QOBUZ_USER_AUTH_TOKEN_2 ... _10
 *   QOBUZ_APP_ID / QOBUZ_APP_ID_2 ... _10
 *   QOBUZ_APP_SECRET / QOBUZ_APP_SECRET_2 ... _10
 *
 * Required/optional KV:
 *   GENERAL_MUSIC_CACHE (shared with the Deezer worker)
 *
 * Notes:
 *   Qobuz stream URLs are signed/time-limited. Do NOT persist them in KV.
 *   Metadata is safe to cache for much longer.
 */

const API_VERSION = "4.0.0";
const QOBUZ_BASE = "https://www.qobuz.com/api.json/0.2";
const GENERAL_CACHE_PREFIX = "music:qobuz:";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Range",
  "Access-Control-Expose-Headers":
    "Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag, Server-Timing, X-Qobuz-Token, X-Qobuz-Format, X-Qobuz-Cache",
};

const MAX_TOKENS = 10;
const MEMORY_TRACK_CACHE_TTL = 30 * 60 * 1000;
const STREAM_URL_CACHE_TTL = 20 * 1000;
const TOKEN_COOLDOWN_MS = 30 * 1000;
const MAX_MEMORY_TRACK_CACHE = 1000;
const MAX_MEMORY_STREAM_CACHE = 250;
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

const memoryTrackCache = new Map();
const memoryStreamCache = new Map();
const pendingLookups = new Map();
const pendingStreams = new Map();
const tokenState = new Map();
const qobuzSessionCache = new Map();
const QOBUZ_SESSION_TTL_MS = 20 * 60 * 1000;

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function apiError(message, status = 400, extra = {}) {
  return jsonResponse(
    {
      error: message,
      status,
      provider: "qobuz",
      ...extra,
    },
    status
  );
}

function headResponse(response) {
  return new Response(null, {
    status: response.status,
    headers: response.headers,
  });
}

function normalizePath(pathname) {
  return pathname.replace(/\/+$/, "") || "/";
}

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function getLimitOffset(url) {
  return {
    limit: clamp(url.searchParams.get("limit") || DEFAULT_LIMIT, 1, MAX_LIMIT),
    offset: Math.max(0, Number(url.searchParams.get("offset") || url.searchParams.get("index") || 0) || 0),
  };
}

function normalizeIsrc(value) {
  return String(value || "").trim().toUpperCase();
}

function cleanString(value) {
  if (value == null) return null;
  const s = String(value).trim();
  return s || null;
}

function numberOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function boolOrNull(value) {
  if (value == null) return null;
  return Boolean(value);
}

function memorySet(map, key, value, maxSize) {
  if (map.has(key)) map.delete(key);
  while (map.size >= maxSize) {
    map.delete(map.keys().next().value);
  }
  map.set(key, value);
  return value;
}

function memoryGet(map, key, ttl) {
  const item = map.get(key);
  if (!item) return null;
  if (Date.now() - item.savedAt > ttl) {
    map.delete(key);
    return null;
  }
  return item.value;
}

/* =========================================================
 * MD5
 * ========================================================= */

function safeAdd(x, y) {
  const lsw = (x & 0xffff) + (y & 0xffff);
  const msw = (x >>> 16) + (y >>> 16) + (lsw >>> 16);
  return (msw << 16) | (lsw & 0xffff);
}

function bitRotateLeft(num, cnt) {
  return (num << cnt) | (num >>> (32 - cnt));
}

function md5cmn(q, a, b, x, s, t) {
  return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}

function md5ff(a, b, c, d, x, s, t) {
  return md5cmn((b & c) | (~b & d), a, b, x, s, t);
}

function md5gg(a, b, c, d, x, s, t) {
  return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
}

function md5hh(a, b, c, d, x, s, t) {
  return md5cmn(b ^ c ^ d, a, b, x, s, t);
}

function md5ii(a, b, c, d, x, s, t) {
  return md5cmn(c ^ (b | ~d), a, b, x, s, t);
}

function utf8Bytes(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code < 0x80) bytes.push(code);
    else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(++i);
      const cp = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    } else {
      bytes.push(
        0xe0 | (code >> 12),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f)
      );
    }
  }
  return bytes;
}

function md5(input) {
  const bytes = utf8Bytes(String(input));
  const originalLength = bytes.length;

  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);

  const bitLengthLow = (originalLength * 8) >>> 0;
  const bitLengthHigh = Math.floor(originalLength / 0x20000000) >>> 0;

  bytes.push(
    bitLengthLow & 0xff,
    (bitLengthLow >>> 8) & 0xff,
    (bitLengthLow >>> 16) & 0xff,
    (bitLengthLow >>> 24) & 0xff,
    bitLengthHigh & 0xff,
    (bitLengthHigh >>> 8) & 0xff,
    (bitLengthHigh >>> 16) & 0xff,
    (bitLengthHigh >>> 24) & 0xff
  );

  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;

  for (let offset = 0; offset < bytes.length; offset += 64) {
    const oldA = a;
    const oldB = b;
    const oldC = c;
    const oldD = d;

    const x = new Array(16);
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      x[i] =
        (bytes[j] |
          (bytes[j + 1] << 8) |
          (bytes[j + 2] << 16) |
          (bytes[j + 3] << 24)) |
        0;
    }

    a = md5ff(a, b, c, d, x[0], 7, -680876936);
    d = md5ff(d, a, b, c, x[1], 12, -389564586);
    c = md5ff(c, d, a, b, x[2], 17, 606105819);
    b = md5ff(b, c, d, a, x[3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[4], 7, -176418897);
    d = md5ff(d, a, b, c, x[5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[7], 22, -45705983);
    a = md5ff(a, b, c, d, x[8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[10], 17, -42063);
    b = md5ff(b, c, d, a, x[11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[13], 12, -40341101);
    c = md5ff(c, d, a, b, x[14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[15], 22, 1236535329);

    a = md5gg(a, b, c, d, x[1], 5, -165796510);
    d = md5gg(d, a, b, c, x[6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[11], 14, 643717713);
    b = md5gg(b, c, d, a, x[0], 20, -373897302);
    a = md5gg(a, b, c, d, x[5], 5, -701558691);
    d = md5gg(d, a, b, c, x[10], 9, 38016083);
    c = md5gg(c, d, a, b, x[15], 14, -660478335);
    b = md5gg(b, c, d, a, x[4], 20, -405537848);
    a = md5gg(a, b, c, d, x[9], 5, 568446438);
    d = md5gg(d, a, b, c, x[14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[3], 14, -187363961);
    b = md5gg(b, c, d, a, x[8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[2], 9, -51403784);
    c = md5gg(c, d, a, b, x[7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[12], 20, -1926607734);

    a = md5hh(a, b, c, d, x[5], 4, -378558);
    d = md5hh(d, a, b, c, x[8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[14], 23, -35309556);
    a = md5hh(a, b, c, d, x[1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[7], 16, -155497632);
    b = md5hh(b, c, d, a, x[10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[13], 4, 681279174);
    d = md5hh(d, a, b, c, x[0], 11, -358537222);
    c = md5hh(c, d, a, b, x[3], 16, -722521979);
    b = md5hh(b, c, d, a, x[6], 23, 76029189);
    a = md5hh(a, b, c, d, x[9], 4, -640364487);
    d = md5hh(d, a, b, c, x[12], 11, -421815835);
    c = md5hh(c, d, a, b, x[15], 16, 530742520);
    b = md5hh(b, c, d, a, x[2], 23, -995338651);

    a = md5ii(a, b, c, d, x[0], 6, -198630844);
    d = md5ii(d, a, b, c, x[7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[5], 21, -57434055);
    a = md5ii(a, b, c, d, x[12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[10], 15, -1051523);
    b = md5ii(b, c, d, a, x[1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[15], 10, -30611744);
    c = md5ii(c, d, a, b, x[6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[4], 6, -145523070);
    d = md5ii(d, a, b, c, x[11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[2], 15, 718787259);
    b = md5ii(b, c, d, a, x[9], 21, -343485551);

    a = safeAdd(a, oldA);
    b = safeAdd(b, oldB);
    c = safeAdd(c, oldC);
    d = safeAdd(d, oldD);
  }

  const words = [a, b, c, d];
  let output = "";
  for (const word of words) {
    for (let j = 0; j < 4; j++) {
      output += ((word >>> (j * 8)) & 0xff).toString(16).padStart(2, "0");
    }
  }
  return output;
}

/* =========================================================
 * HTTP helpers
 * ========================================================= */

async function readResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  let json = null;
  let text = "";

  if (contentType.includes("json")) {
    try {
      json = await response.json();
    } catch (_) {}
  } else {
    try {
      text = await response.text();
      json = JSON.parse(text);
    } catch (_) {}
  }

  return {
    status: response.status,
    ok: response.ok,
    headers: response.headers,
    json,
    text,
  };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

function isTransientStatus(status) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

async function qobuzRequest(path, {
  token,
  appId,
  method = "GET",
  query = {},
  headers = {},
  body,
  timeoutMs = 8000,
  retries = 2,
} = {}) {
  const url = new URL(`${QOBUZ_BASE}/${String(path).replace(/^\/+/, "")}`);

  // Qobuz requires app_id on the API request URL for signed playback
  // endpoints. Keep it OUT of request_sig generation, because the signing
  // algorithm signs the endpoint parameters, not app_id itself.
  const finalQuery = { ...query };
  if (appId && finalQuery.app_id === undefined) {
    finalQuery.app_id = appId;
  }

  for (const [key, value] of Object.entries(finalQuery)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }

  const requestHeaders = {
    Accept: "application/json",
    "User-Agent": "Qobuz-HiFi-API/2.0",
    ...headers,
  };

  if (appId) requestHeaders["X-App-Id"] = appId;
  if (token) {
    requestHeaders["X-User-Auth-Token"] = token;
    requestHeaders.Authorization = `Bearer ${token}`;
  }

  let lastError = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetchWithTimeout(
        url,
        {
          method,
          headers: requestHeaders,
          body,
        },
        timeoutMs
      );

      if (!isTransientStatus(response.status) || attempt === retries) {
        return response;
      }

      await new Promise((resolve) => setTimeout(resolve, 150 * 2 ** attempt));
    } catch (error) {
      lastError = error;
      if (attempt === retries) throw error;
      await new Promise((resolve) => setTimeout(resolve, 150 * 2 ** attempt));
    }
  }

  throw lastError || new Error("Qobuz request failed");
}

/* =========================================================
 * Token pool
 * ========================================================= */

function credentialKey(prefix, slot) {
  return slot === 1 ? prefix : `${prefix}_${slot}`;
}

function getCredentials(env, slot) {
  const appId =
    cleanString(env[credentialKey("QOBUZ_APP_ID", slot)]) ||
    (slot !== 1 ? cleanString(env.QOBUZ_APP_ID) : "");

  const appSecret =
    cleanString(env[credentialKey("QOBUZ_APP_SECRET", slot)]) ||
    (slot !== 1 ? cleanString(env.QOBUZ_APP_SECRET) : "");

  return {
    appId,
    appSecret,
    credential_source:
      cleanString(env[credentialKey("QOBUZ_APP_ID", slot)]) &&
      cleanString(env[credentialKey("QOBUZ_APP_SECRET", slot)])
        ? "slot"
        : "default_fallback",
  };
}

function getCredentialPairs(env) {
  const pairs = [];
  const seen = new Set();

  for (let i = 1; i <= MAX_TOKENS; i++) {
    const credentials = getCredentials(env, i);
    if (!credentials.appId || !credentials.appSecret) continue;

    const key = `${credentials.appId}|${credentials.appSecret}`;
    if (seen.has(key)) continue;
    seen.add(key);

    pairs.push({
      credential_slot: i,
      appId: credentials.appId,
      appSecret: credentials.appSecret,
      credential_source: credentials.credential_source,
    });
  }

  return pairs;
}

function getTokens(env) {
  const tokens = [];
  const credentialPairs = getCredentialPairs(env);

  for (let i = 1; i <= MAX_TOKENS; i++) {
    const key = credentialKey("QOBUZ_USER_AUTH_TOKEN", i);
    const token = cleanString(env[key]);
    if (!token) continue;

    const credentials = getCredentials(env, i);
    const ownKey = credentials.appId && credentials.appSecret
      ? `${credentials.appId}|${credentials.appSecret}`
      : null;

    const candidates = credentialPairs
      .slice()
      .sort((a, b) => {
        const aOwn = `${a.appId}|${a.appSecret}` === ownKey ? 0 : 1;
        const bOwn = `${b.appId}|${b.appSecret}` === ownKey ? 0 : 1;
        return aOwn - bOwn || a.credential_slot - b.credential_slot;
      });

    tokens.push({
      slot: i,
      token,
      appId: credentials.appId,
      appSecret: credentials.appSecret,
      credential_source: credentials.credential_source,
      credential_candidates: candidates,
    });
  }

  return tokens;
}

function tokenKey(slot) {
  return `qobuz:${slot}`;
}

function getTokenState(slot) {
  const key = tokenKey(slot);
  if (!tokenState.has(key)) {
    tokenState.set(key, {
      failures: 0,
      lastFailure: 0,
      lastSuccess: 0,
      lastStatus: null,
      lastError: null,
    });
  }
  return tokenState.get(key);
}

function tokenAvailable(slot) {
  const state = getTokenState(slot);
  return Date.now() - state.lastFailure >= TOKEN_COOLDOWN_MS;
}

function markTokenSuccess(slot) {
  const state = getTokenState(slot);
  state.failures = 0;
  state.lastSuccess = Date.now();
  state.lastStatus = 200;
  state.lastError = null;
}

function markTokenFailure(slot, status, error) {
  const state = getTokenState(slot);
  state.failures++;
  state.lastFailure = Date.now();
  state.lastStatus = status ?? null;
  state.lastError = error ? String(error).slice(0, 300) : null;
}

function orderedTokens(env, preferredSlot = null) {
  const tokens = getTokens(env);
  if (!tokens.length) return [];

  const preferred = preferredSlot
    ? tokens.find((x) => x.slot === Number(preferredSlot))
    : null;

  const rest = tokens.filter((x) => !preferred || x.slot !== preferred.slot);

  rest.sort((a, b) => {
    const aa = getTokenState(a.slot);
    const bb = getTokenState(b.slot);

    const aAvailable = tokenAvailable(a.slot) ? 0 : 1;
    const bAvailable = tokenAvailable(b.slot) ? 0 : 1;
    if (aAvailable !== bAvailable) return aAvailable - bAvailable;

    if (aa.lastSuccess !== bb.lastSuccess) {
      return bb.lastSuccess - aa.lastSuccess;
    }

    return a.slot - b.slot;
  });

  return preferred ? [preferred, ...rest] : rest;
}

async function withTokenFailover(env, operation, preferredSlot = null) {
  const tokens = orderedTokens(env, preferredSlot);
  if (!tokens.length) {
    throw Object.assign(new Error("No Qobuz auth tokens configured"), { status: 500 });
  }

  const errors = [];

  for (const entry of tokens) {
    if (!entry.appId || !entry.appSecret) {
      markTokenFailure(entry.slot, 500, "Missing App ID or App Secret for this token slot");
      errors.push({
        slot: entry.slot,
        status: 500,
        error: "Missing Qobuz App ID or App Secret for this token slot",
      });
      continue;
    }

    if (!tokenAvailable(entry.slot) && tokens.length > 1) continue;

    try {
      const result = await operation({
        token: entry.token,
        slot: entry.slot,
        appId: entry.appId,
        appSecret: entry.appSecret,
        credential_source: entry.credential_source,
      });

      if (result?.response?.status === 401 || result?.response?.status === 403) {
        const message =
          result.response.headers.get("www-authenticate") ||
          `HTTP ${result.response.status}`;
        markTokenFailure(entry.slot, result.response.status, message);
        errors.push({ slot: entry.slot, status: result.response.status, error: message });
        continue;
      }

      markTokenSuccess(entry.slot);
      return {
        ...result,
        tokenSlot: entry.slot,
        token: entry.token,
      };
    } catch (error) {
      markTokenFailure(entry.slot, error?.status, error?.message);
      errors.push({
        slot: entry.slot,
        status: error?.status || null,
        error: error?.message || String(error),
      });
    }
  }

  throw Object.assign(new Error("All configured Qobuz tokens failed"), {
    status: 502,
    tokenErrors: errors,
  });
}

/* =========================================================
 * Artwork / normalization
 * ========================================================= */

function normalizeImageUrl(value, size = null) {
  if (!value) return null;
  let url = String(value);

  if (size && /_(small|medium|large|extralarge|max)\.(jpg|jpeg|png)$/i.test(url)) {
    url = url.replace(/_(small|medium|large|extralarge|max)(\.[a-z]+)$/i, `_${size}$2`);
  }

  if (size && /\/(small|medium|large)\//i.test(url)) {
    url = url.replace(/\/(small|medium|large)\//i, `/${size}/`);
  }

  return url;
}

function artworkSet(image) {
  if (!image) {
    return {
      small: null,
      medium: null,
      large: null,
      extraLarge: null,
      max: null,
    };
  }

  if (typeof image === "string") {
    return {
      small: normalizeImageUrl(image, "small"),
      medium: normalizeImageUrl(image, "medium"),
      large: normalizeImageUrl(image, "large"),
      extraLarge: normalizeImageUrl(image, "extralarge"),
      max: normalizeImageUrl(image, "max"),
    };
  }

  const source =
    image.original ||
    image.max ||
    image.large ||
    image.medium ||
    image.small ||
    image;

  return {
    small: image.small || normalizeImageUrl(source, "small"),
    medium: image.medium || normalizeImageUrl(source, "medium"),
    large: image.large || normalizeImageUrl(source, "large"),
    extraLarge:
      image.extralarge ||
      image.extra_large ||
      normalizeImageUrl(source, "extralarge"),
    max: image.max || normalizeImageUrl(source, "max"),
  };
}

function normalizeArtist(artist) {
  if (!artist) return null;
  return {
    id: artist.id ?? null,
    name: artist.name ?? null,
    slug: artist.slug ?? null,
    picture: artworkSet(artist.image || artist.picture || artist.picture_url),
    albums_count: numberOrNull(
      artist.albums_count ?? artist.albums_count_total ?? artist.nb_album
    ),
    biography: artist.biography ?? artist.bio ?? null,
    link: artist.url ?? artist.link ?? null,
  };
}

function normalizeAlbum(album) {
  if (!album) return null;

  return {
    id: album.id ?? null,
    title: album.title ?? null,
    subtitle: album.subtitle ?? null,
    version: album.version ?? null,
    artist: normalizeArtist(album.artist),
    artists: Array.isArray(album.artists)
      ? album.artists.map(normalizeArtist).filter(Boolean)
      : [],
    image: artworkSet(album.image || album.images),
    release_date:
      album.release_date_original ||
      album.release_date ||
      album.released_at ||
      null,
    genre: album.genre ?? null,
    genres: Array.isArray(album.genres) ? album.genres : [],
    tracks_count:
      numberOrNull(album.tracks_count) ??
      numberOrNull(album.tracks?.total) ??
      null,
    duration: numberOrNull(album.duration),
    hires: Boolean(
      album.hires ||
      album.hires_streamable ||
      album.maximum_bit_depth >= 24 ||
      album.maximum_sampling_rate > 44100
    ),
    maximum_bit_depth: numberOrNull(album.maximum_bit_depth),
    maximum_sampling_rate: numberOrNull(album.maximum_sampling_rate),
    maximum_channel_count: numberOrNull(album.maximum_channel_count),
    streamable: album.streamable ?? null,
    purchasable: album.purchasable ?? null,
    url: album.url ?? album.link ?? null,
  };
}

function normalizeTrack(track) {
  if (!track) return null;

  const album = track.album || null;
  const performer = track.performer || track.artist || null;

  return {
    id: track.id ?? null,
    title: track.title ?? null,
    version: track.version ?? null,
    subtitle: track.subtitle ?? null,
    isrc: track.isrc ?? null,
    artist: normalizeArtist(performer),
    artists: Array.isArray(track.artists)
      ? track.artists.map(normalizeArtist).filter(Boolean)
      : performer
        ? [normalizeArtist(performer)]
        : [],
    album: normalizeAlbum(album),
    image: artworkSet(
      track.image ||
      album?.image ||
      album?.images
    ),
    duration: numberOrNull(track.duration),
    track_number: numberOrNull(track.track_number),
    media_number: numberOrNull(track.media_number),
    copyright: track.copyright ?? null,
    label: track.label ?? null,
    genre: track.genre ?? null,
    genres: Array.isArray(track.genres) ? track.genres : [],
    release_date:
      track.release_date_original ||
      track.release_date ||
      album?.release_date_original ||
      album?.release_date ||
      null,
    maximum_bit_depth: numberOrNull(track.maximum_bit_depth),
    maximum_sampling_rate: numberOrNull(track.maximum_sampling_rate),
    maximum_channel_count: numberOrNull(track.maximum_channel_count),
    hires: Boolean(
      track.hires ||
      track.maximum_bit_depth >= 24 ||
      track.maximum_sampling_rate > 44100
    ),
    streamable: track.streamable ?? null,
    purchasable: track.purchasable ?? null,
    url: track.url ?? track.link ?? null,
  };
}

function normalizePlaylist(playlist) {
  if (!playlist) return null;

  return {
    id: playlist.id ?? null,
    name: playlist.name ?? playlist.title ?? null,
    title: playlist.title ?? playlist.name ?? null,
    description: playlist.description ?? null,
    image: artworkSet(playlist.image || playlist.images),
    tracks_count:
      numberOrNull(playlist.tracks_count) ??
      numberOrNull(playlist.tracks?.total) ??
      null,
    duration: numberOrNull(playlist.duration),
    owner: normalizeArtist(playlist.owner || playlist.creator),
    is_public: playlist.is_public ?? playlist.public ?? null,
    url: playlist.url ?? playlist.link ?? null,
  };
}

function normalizeCollection(payload, key, normalizer) {
  const collection = payload?.[key] || payload;
  const items = Array.isArray(collection?.items)
    ? collection.items.map(normalizer).filter(Boolean)
    : Array.isArray(collection)
      ? collection.map(normalizer).filter(Boolean)
      : [];

  return {
    data: items,
    total:
      numberOrNull(collection?.total) ??
      numberOrNull(payload?.total) ??
      items.length,
    offset:
      numberOrNull(collection?.offset) ??
      numberOrNull(payload?.offset) ??
      0,
    limit:
      numberOrNull(collection?.limit) ??
      numberOrNull(payload?.limit) ??
      items.length,
    next: collection?.next ?? payload?.next ?? null,
    previous:
      collection?.previous ??
      collection?.prev ??
      payload?.previous ??
      payload?.prev ??
      null,
  };
}

/* =========================================================
 * Metadata cache
 * ========================================================= */

function cacheKey(type, id) {
  return `qobuz:${type}:${String(id)}`;
}

function cacheMemoryTrack(key, value) {
  memorySet(
    memoryTrackCache,
    key,
    { savedAt: Date.now(), value },
    MAX_MEMORY_TRACK_CACHE
  );
}

function getMemoryTrack(key) {
  return memoryGet(memoryTrackCache, key, MEMORY_TRACK_CACHE_TTL);
}

function sharedMetadataKey(key) {
  return `${GENERAL_CACHE_PREFIX}${key}`;
}

function saveMetadata(env, ctx, key, value, ttlSeconds = 2592000) {
  if (!env.GENERAL_MUSIC_CACHE) return;

  const task = env.GENERAL_MUSIC_CACHE
    .put(
      sharedMetadataKey(key),
      JSON.stringify(value),
      { expirationTtl: Math.max(60, Math.floor(ttlSeconds)) }
    )
    .catch(() => {});

  if (ctx?.waitUntil) ctx.waitUntil(task);
}

async function getCachedMetadata(env, key) {
  if (!env.GENERAL_MUSIC_CACHE) return null;

  try {
    return await env.GENERAL_MUSIC_CACHE.get(sharedMetadataKey(key), { type: "json" });
  } catch (_) {
    return null;
  }
}

/* =========================================================
 * Search / catalog
 * ========================================================= */

async function catalogRequest(env, path, query, preferredSlot = null) {
  return withTokenFailover(
    env,
    async ({ token, appId, slot }) => {
      const requestQuery = { ...(query || {}) };

      // App credentials are slot-specific. Never leak the global App ID
      // into a request when a different token slot is being used.
      requestQuery.app_id = appId;

      const response = await qobuzRequest(path, {
        token,
        appId,
        query: requestQuery,
      });

      return {
        response,
        slot,
        token,
      };
    },
    preferredSlot
  );
}

async function catalogJson(env, path, query, preferredSlot = null) {
  const result = await catalogRequest(env, path, query, preferredSlot);
  const parsed = await readResponse(result.response);

  if (!parsed.ok || !parsed.json) {
    const error = new Error(
      parsed.json?.message ||
      parsed.json?.error ||
      parsed.text ||
      `Qobuz API returned HTTP ${parsed.status}`
    );
    error.status = parsed.status;
    error.api = parsed.json;
    error.tokenSlot = result.tokenSlot;
    throw error;
  }

  return {
    json: parsed.json,
    tokenSlot: result.tokenSlot,
    response: result.response,
  };
}

async function searchCatalog(env, url) {
  const isrc =
    cleanString(url.searchParams.get("i")) ||
    cleanString(url.searchParams.get("isrc"));

  const q =
    cleanString(url.searchParams.get("q")) ||
    cleanString(url.searchParams.get("query")) ||
    cleanString(url.searchParams.get("s")) ||
    cleanString(url.searchParams.get("a")) ||
    cleanString(url.searchParams.get("al")) ||
    cleanString(url.searchParams.get("p"));

  const { limit, offset } = getLimitOffset(url);
  let type = cleanString(url.searchParams.get("type"));

  if (!type) {
    if (url.searchParams.has("a")) type = "artist";
    else if (url.searchParams.has("al")) type = "album";
    else if (url.searchParams.has("p")) type = "playlist";
    else type = "track";
  }

  if (isrc) {
    const found = await findTrackByIsrc(env, isrc, null, null);
    const item = found?.track ? normalizeTrack(found.track) : null;
    return {
      version: API_VERSION,
      provider: "qobuz",
      type: "track",
      query: isrc,
      data: item ? [item] : [],
      total: item ? 1 : 0,
      next: null,
      previous: null,
      tokenSlot: found?.tokenSlot || null,
    };
  }

  if (!q) throw Object.assign(new Error("Missing q/query"), { status: 400 });

  const t = String(type).toLowerCase();
  const aliases = {
    track: "tracks", tracks: "tracks", song: "tracks", songs: "tracks",
    album: "albums", albums: "albums",
    artist: "artists", artists: "artists",
    playlist: "playlists", playlists: "playlists",
    all: "all",
  };
  const normalizedType = aliases[t];

  if (!normalizedType) {
    throw Object.assign(new Error("Invalid type. Use track, album, artist, playlist, or all."), { status: 400 });
  }

  // These are separate, verified Qobuz catalog methods. `all` uses the
  // documented catalog/search aggregator. This avoids inventing resource
  // names such as `catalog/search?type=...` for endpoints that have their own
  // stable search methods.
  const requests = {
    tracks: () => catalogJson(env, "track/search", { query: q, limit, offset }),
    albums: () => catalogJson(env, "album/search", { query: q, limit, offset }),
    artists: () => catalogJson(env, "artist/search", { query: q, limit, offset }),
    playlists: () => catalogJson(env, "playlist/search", { query: q, limit, offset }),
    all: () => catalogJson(env, "catalog/search", { query: q, limit, offset }),
  };

  const result = await requests[normalizedType]();
  const json = result.json || {};

  let data = [];
  let total = 0;

  if (normalizedType === "tracks") {
    data = json?.tracks?.items || [];
    total = numberOrNull(json?.tracks?.total) ?? data.length;
  } else if (normalizedType === "albums") {
    data = json?.albums?.items || [];
    total = numberOrNull(json?.albums?.total) ?? data.length;
  } else if (normalizedType === "artists") {
    data = json?.artists?.items || [];
    total = numberOrNull(json?.artists?.total) ?? data.length;
  } else if (normalizedType === "playlists") {
    data = json?.playlists?.items || [];
    total = numberOrNull(json?.playlists?.total) ?? data.length;
  } else {
    data = json?.tracks?.items || [];
    total = numberOrNull(json?.tracks?.total) ?? data.length;
  }

  const normalizer = normalizedType === "albums" ? normalizeAlbum
    : normalizedType === "artists" ? normalizeArtist
    : normalizedType === "playlists" ? normalizePlaylist
    : normalizeTrack;

  let normalizedData = data.map(normalizer).filter(Boolean);

  // Track search may optionally enrich each result with a direct legacy
  // streamUrl. The endpoint is verified and returns a direct URL, unlike the
  // modern /file/url segmented descriptor. `include_stream=0` skips this
  // expensive enrichment when a caller only wants catalog search.
  const includeStream = normalizedType === "tracks" &&
    url.searchParams.get("include_stream") !== "0";

  if (includeStream) {
    const searchQuality =
      cleanString(url.searchParams.get("quality") || url.searchParams.get("format")) || "best";

    const searchTokens = orderedTokens(env, result.tokenSlot || null);
    const searchToken = searchTokens[0] || null;
    const searchCredential = searchToken?.credential_candidates?.[0] || null;

    const enrich = async (track, normalized) => {
      const key = `stream:${String(track.id)}:${String(searchQuality).toLowerCase()}`;
      const cached = memoryGet(memoryStreamCache, key, STREAM_URL_CACHE_TTL);
      if (cached?.url) {
        return applyResolvedPlayback(normalized, cached, "memory");
      }

      if (!searchToken || !searchCredential) {
        return { ...normalized, streamUrl: null, playback_error: "No Qobuz playback credentials configured" };
      }

      const formats = qualityPlan(track, searchQuality);
      for (const fmt of formats) {
        try {
          const legacy = await resolveLegacyFileUrl(env, {
            trackId: String(track.id),
            formatId: fmt.id,
            intent: "stream",
            token: searchToken.token,
            appId: searchCredential.appId,
            appSecret: searchCredential.appSecret,
          });

          if (!legacy.parsed.ok || !legacy.url) continue;

          const playback = {
            ...legacy,
            token_slot: searchToken.slot,
            credential_slot: searchCredential.credential_slot,
            credential_source: searchCredential.credential_slot === searchToken.slot
              ? searchCredential.credential_source
              : "cross_slot_fallback",
            format_name: fmt.name,
            mime_type: legacy.parsed.json?.mime_type || (String(fmt.id) === "5" ? "audio/mpeg" : "audio/flac"),
            bit_depth: numberOrNull(legacy.parsed.json?.bit_depth) ?? (String(fmt.id) === "5" ? null : String(fmt.id) === "6" ? 16 : 24),
            sampling_rate: numberOrNull(legacy.parsed.json?.sampling_rate) ?? (String(fmt.id) === "5" ? null : String(fmt.id) === "6" ? 44100 : null),
            bitrate: numberOrNull(legacy.parsed.json?.bitrate) ?? (String(fmt.id) === "5" ? 320 : null),
          };

          memorySet(memoryStreamCache, key, playback, MAX_MEMORY_STREAM_CACHE);
          markTokenSuccess(searchToken.slot);
          return applyResolvedPlayback(normalized, playback, "miss");
        } catch (_) {}
      }

      // If the first catalog-authenticated token cannot resolve a direct URL,
      // let the normal token/credential failover try the track. This is only
      // done for failed results, keeping the common search path fast.
      try {
        const playback = await resolveDirectLegacyStream(env, {
          track,
          trackId: String(track.id),
          quality: searchQuality,
          preferredTokenSlot: result.tokenSlot || null,
        });
        return applyResolvedPlayback(normalized, playback, "fallback");
      } catch (error) {
        return { ...normalized, streamUrl: null, playback_error: error?.message || String(error) };
      }
    };

    normalizedData = await Promise.all(
      data.map((track, index) => enrich(track, normalizedData[index]))
    );
  }

  const envelope = {
    version: API_VERSION,
    provider: "qobuz",
    query: q,
    type: normalizedType,
    tokenSlot: result.tokenSlot,
    data: normalizedData,
    total,
    offset,
    limit,
    next: null,
    previous: offset > 0 ? Math.max(0, offset - limit) : null,
  };

  if (normalizedType === "all") {
    envelope.tracks = normalizeCollection(json?.tracks || {}, "items", normalizeTrack);
    envelope.albums = normalizeCollection(json?.albums || {}, "items", normalizeAlbum);
    envelope.artists = normalizeCollection(json?.artists || {}, "items", normalizeArtist);
    envelope.playlists = normalizeCollection(json?.playlists || {}, "items", normalizePlaylist);
  }

  return envelope;
}

function applyResolvedPlayback(normalized, playback, cacheState) {
  const bitDepth = playback.bit_depth ?? null;
  const samplingRate = playback.sampling_rate ?? null;
  return {
    ...normalized,
    streamUrl: playback.url || null,
    stream_type: playback.url ? "direct_url" : null,
    stream_url_template: null,
    stream_segments: null,
    format_id: playback.format_id || null,
    format: playback.format_name || null,
    mime_type: playback.mime_type || null,
    bit_depth: bitDepth,
    sampling_rate: samplingRate,
    bitrate: playback.bitrate ?? null,
    maximum_bit_depth: bitDepth ?? normalized.maximum_bit_depth ?? null,
    maximum_sampling_rate: samplingRate ?? normalized.maximum_sampling_rate ?? null,
    hires: bitDepth >= 24 || samplingRate > 44100 ? true : normalized.hires,
    playback_token_slot: playback.token_slot || null,
    playback_credential_slot: playback.credential_slot || null,
    playback_credential_source: playback.credential_source || null,
    playback_signing_mode: playback.signing_mode || "legacy_track_getFileUrl",
    stream_cache: cacheState,
  };
}

async function findTrackByIsrc(env, isrc, preferredSlot = null, ctx = null) {
  const normalized = normalizeIsrc(isrc);
  if (!normalized) return null;

  const memoryKey = cacheKey("isrc", normalized);
  const memoryHit = getMemoryTrack(memoryKey);
  if (memoryHit) return { track: memoryHit, source: "memory", tokenSlot: null };

  const pending = pendingLookups.get(normalized);
  if (pending) {
    const result = await pending;
    return { ...result, source: "coalesced" };
  }

  const lookup = (async () => {
    const kv = await getCachedMetadata(env, memoryKey);
    if (kv?.id) {
      cacheMemoryTrack(memoryKey, kv);
      return { track: kv, source: "kv", tokenSlot: null };
    }

    const result = await catalogJson(env, "catalog/search", {
      query: normalized,
      limit: 10,
      offset: 0,
    }, preferredSlot);

    const tracks = result.json?.tracks?.items || [];
    const exact =
      tracks.find((track) => normalizeIsrc(track?.isrc) === normalized) ||
      null;

    if (!exact) {
      return {
        track: null,
        source: "miss",
        tokenSlot: result.tokenSlot,
      };
    }

    cacheMemoryTrack(memoryKey, exact);
    saveMetadata(env, ctx, memoryKey, exact, 2592000);

    return {
      track: exact,
      source: "miss",
      tokenSlot: result.tokenSlot,
    };
  })();

  pendingLookups.set(normalized, lookup);

  try {
    return await lookup;
  } finally {
    pendingLookups.delete(normalized);
  }
}

/* =========================================================
 * Signed stream URL
 * ========================================================= */

function qualityPlan(track, requestedQuality = "best") {
  const q = String(requestedQuality || "best").toLowerCase();

  if (q === "mp3" || q === "320" || q === "mp3_320") {
    return [{ id: "5", name: "mp3_320" }];
  }

  if (q === "cd" || q === "flac" || q === "16" || q === "lossless") {
    return [{ id: "6", name: "flac_16_44" }, { id: "5", name: "mp3_320" }];
  }

  if (q === "96" || q === "hires96" || q === "hires_96") {
    return [
      { id: "7", name: "flac_24_96" },
      { id: "6", name: "flac_16_44" },
      { id: "5", name: "mp3_320" },
    ];
  }

  if (q === "192" || q === "hires192" || q === "hires_192") {
    return [
      { id: "27", name: "flac_24_192" },
      { id: "7", name: "flac_24_96" },
      { id: "6", name: "flac_16_44" },
      { id: "5", name: "mp3_320" },
    ];
  }

  // Qobuz format_id is a requested maximum, not a promise about the
  // catalog metadata returned by search. For `best`, ask for the highest
  // available format first, then gracefully fall back if that release does
  // not actually have Hi-Res. This is important for /search because search
  // metadata can report only CD-quality fields even when playback can return
  // a Hi-Res master.
  return [
    { id: "27", name: "flac_24_192" },
    { id: "7", name: "flac_24_96" },
    { id: "6", name: "flac_16_44" },
    { id: "5", name: "mp3_320" },
  ];
}

function signedRequestParams(objectMethod, params, appSecret) {
  const requestTs = Math.floor(Date.now() / 1000).toString();
  const keys = Object.keys(params || {}).sort();
  let signatureInput = objectMethod;

  for (const key of keys) {
    const value = params[key];
    if (value === undefined || value === null) continue;
    signatureInput += `${key}${value}`;
  }

  signatureInput += `${requestTs}${appSecret}`;

  return {
    ...params,
    request_ts: requestTs,
    request_sig: md5(signatureInput),
  };
}

function signedFileUrlParams(trackId, formatId, appSecret, intent = "stream") {
  return signedRequestParams(
    "trackgetFileUrl",
    {
      format_id: String(formatId),
      intent,
      track_id: String(trackId),
    },
    appSecret
  );
}

function signedSessionStartParams(appSecret) {
  return signedRequestParams(
    "sessionstart",
    { profile: "qbz-1" },
    appSecret
  );
}

function signedModernFileUrlParams(trackId, formatId, appSecret, intent = "stream") {
  return signedRequestParams(
    "fileurl",
    {
      format_id: String(formatId),
      intent,
      track_id: String(trackId),
    },
    appSecret
  );
}

async function getQobuzSession(env, { token, appId, appSecret, slot }) {
  const cacheKey = `${slot}:${appId}`;
  const cached = qobuzSessionCache.get(cacheKey);

  if (cached && cached.expiresAt > Date.now() + 30_000) {
    return cached;
  }

  const query = signedSessionStartParams(appSecret);
  const response = await qobuzRequest("session/start", {
    token,
    appId,
    query,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    timeoutMs: 7000,
    retries: 1,
  });

  const parsed = await readResponse(response);
  const sessionId = parsed.json?.session_id || parsed.json?.sessionId || null;

  if (!parsed.ok || !sessionId) {
    const error = new Error(
      parsed.json?.message ||
      parsed.json?.error ||
      `Qobuz session/start failed with HTTP ${parsed.status}`
    );
    error.status = parsed.status;
    error.qobuz = parsed.json;
    throw error;
  }

  const expiresAt = Number(parsed.json?.expires_at || 0) * 1000;
  const session = {
    sessionId,
    infos: parsed.json?.infos || null,
    expiresAt: expiresAt > Date.now() ? expiresAt : Date.now() + QOBUZ_SESSION_TTL_MS,
  };

  qobuzSessionCache.set(cacheKey, session);
  return session;
}

async function resolveModernFileUrl(env, {
  trackId,
  formatId,
  intent,
  token,
  appId,
  appSecret,
  slot,
}) {
  const session = await getQobuzSession(env, {
    token,
    appId,
    appSecret,
    slot,
  });
  const sessionId = session.sessionId;

  const query = signedModernFileUrlParams(trackId, formatId, appSecret, intent);

  const response = await qobuzRequest("file/url", {
    token,
    appId,
    query,
    headers: {
      "X-Session-Id": sessionId,
    },
    timeoutMs: 7000,
    retries: 1,
  });

  const parsed = await readResponse(response);
  const streamUrl =
    parsed.json?.url ||
    parsed.json?.streamUrl ||
    parsed.json?.stream_url ||
    parsed.json?.file_url ||
    parsed.json?.fileUrl ||
    null;

  return {
    response,
    parsed,
    url: streamUrl,
    url_template: parsed.json?.url_template || null,
    n_segments: Number(parsed.json?.n_segments || 0) || null,
    encryption_key: parsed.json?.key || null,
    session_id: sessionId,
    session_infos: session.infos || null,
    format_id: String(formatId),
    signing_mode: "modern_session_file_url",
  };
}

async function resolveLegacyFileUrl(env, {
  trackId,
  formatId,
  intent,
  token,
  appId,
  appSecret,
}) {
  const query = signedFileUrlParams(trackId, formatId, appSecret, intent);

  const response = await qobuzRequest("track/getFileUrl", {
    token,
    appId,
    query,
    timeoutMs: 7000,
    retries: 1,
  });

  const parsed = await readResponse(response);
  const streamUrl =
    parsed.json?.url ||
    parsed.json?.streamUrl ||
    parsed.json?.stream_url ||
    parsed.json?.file_url ||
    parsed.json?.fileUrl ||
    null;

  return {
    response,
    parsed,
    url: streamUrl,
    format_id: String(formatId),
    signing_mode: "legacy_track_getFileUrl",
  };
}


async function resolveDirectLegacyStream(env, {
  track,
  trackId,
  quality = "best",
  preferredTokenSlot = null,
}) {
  const formats = qualityPlan(track, quality);
  const tokens = orderedTokens(env, preferredTokenSlot);
  let lastError = null;

  for (const tokenEntry of tokens) {
    if (!tokenAvailable(tokenEntry.slot) && tokens.length > 1) continue;

    const candidates = tokenEntry.credential_candidates?.length
      ? tokenEntry.credential_candidates
      : [{
          credential_slot: tokenEntry.slot,
          appId: tokenEntry.appId,
          appSecret: tokenEntry.appSecret,
          credential_source: tokenEntry.credential_source,
        }];

    for (const credentials of candidates) {
      for (const fmt of formats) {
        try {
          const legacy = await resolveLegacyFileUrl(env, {
            trackId,
            formatId: fmt.id,
            intent: "stream",
            token: tokenEntry.token,
            appId: credentials.appId,
            appSecret: credentials.appSecret,
          });

          if (legacy.parsed.ok && legacy.url) {
            markTokenSuccess(tokenEntry.slot);
            return {
              ...legacy,
              token_slot: tokenEntry.slot,
              credential_slot: credentials.credential_slot,
              credential_source: credentials.credential_slot === tokenEntry.slot
                ? credentials.credential_source
                : "cross_slot_fallback",
              format_name: fmt.name || null,
              mime_type: legacy.parsed.json?.mime_type ||
                (String(fmt.id) === "5" ? "audio/mpeg" : "audio/flac"),
              bit_depth: numberOrNull(legacy.parsed.json?.bit_depth) ??
                (String(fmt.id) === "5" ? null : String(fmt.id) === "6" ? 16 : 24),
              sampling_rate: numberOrNull(legacy.parsed.json?.sampling_rate) ??
                (String(fmt.id) === "5" ? null : String(fmt.id) === "6" ? 44100 : null),
              bitrate: numberOrNull(legacy.parsed.json?.bitrate) ??
                (String(fmt.id) === "5" ? 320 : null),
            };
          }

          lastError = new Error(
            legacy.parsed.json?.message ||
            legacy.parsed.json?.error ||
            `Qobuz legacy playback failed with HTTP ${legacy.parsed.status}`
          );
          lastError.status = legacy.parsed.status;
          lastError.qobuz = legacy.parsed.json;
        } catch (error) {
          lastError = error;
        }
      }
    }
  }

  throw lastError || new Error("Qobuz direct stream URL could not be resolved");
}

async function resolveOneFormat(env, {
  trackId,
  formatId,
  intent,
  token,
  appId,
  appSecret,
  slot,
  allowLegacy = false,
}) {
  let modernError = null;

  try {
    const modern = await resolveModernFileUrl(env, {
      trackId,
      formatId,
      intent,
      token,
      appId,
      appSecret,
      slot,
    });

    if (modern.parsed.ok && (modern.url || modern.url_template)) {
      return modern;
    }

    modernError = new Error(
      modern.parsed.json?.message ||
      modern.parsed.json?.error ||
      `Qobuz file/url failed with HTTP ${modern.parsed.status}`
    );
    modernError.status = modern.parsed.status;
    modernError.qobuz = modern.parsed.json;
  } catch (error) {
    modernError = error;
  }

  if (!allowLegacy) {
    throw modernError || new Error("Qobuz modern playback failed");
  }

  const legacy = await resolveLegacyFileUrl(env, {
    trackId,
    formatId,
    intent,
    token,
    appId,
    appSecret,
  });

  if (legacy.parsed.ok && legacy.url) {
    return legacy;
  }

  const error = new Error(
    legacy.parsed.json?.message ||
    legacy.parsed.json?.error ||
    modernError?.message ||
    `Qobuz playback failed with HTTP ${legacy.parsed.status}`
  );
  error.status = legacy.parsed.status || modernError?.status;
  error.qobuz = legacy.parsed.json || modernError?.qobuz;
  throw error;
}

async function resolveStream(env, {
  track,
  trackId,
  quality = "best",
  preferredTokenSlot = null,
}) {
  const cacheKeyValue =
    `stream:${trackId}:${String(quality).toLowerCase()}`;

  const cached = memoryGet(
    memoryStreamCache,
    cacheKeyValue,
    STREAM_URL_CACHE_TTL
  );

  if (cached) {
    return { ...cached, cache: "memory" };
  }

  const pending = pendingStreams.get(cacheKeyValue);
  if (pending) {
    const value = await pending;
    return { ...value, cache: "coalesced" };
  }

  const task = (async () => {
    const formats = qualityPlan(track, quality);
    const attempts = [];

    const tokens = orderedTokens(env, preferredTokenSlot);
    if (!tokens.length) {
      throw Object.assign(new Error("No Qobuz auth tokens configured"), { status: 500 });
    }

    for (const tokenEntry of tokens) {
      if (!tokenAvailable(tokenEntry.slot) && tokens.length > 1) continue;

      for (const fmt of formats) {
        const started = Date.now();

        try {
          const candidates = tokenEntry.credential_candidates?.length
            ? tokenEntry.credential_candidates
            : [{
                credential_slot: tokenEntry.slot,
                appId: tokenEntry.appId,
                appSecret: tokenEntry.appSecret,
                credential_source: tokenEntry.credential_source,
              }];

          let result = null;
          let lastError = null;

          for (const credentials of candidates) {
            try {
              result = await resolveOneFormat(env, {
                trackId,
                formatId: fmt.id,
                intent: "stream",
                token: tokenEntry.token,
                appId: credentials.appId,
                appSecret: credentials.appSecret,
                slot: tokenEntry.slot,
                allowLegacy: true,
              });

              if (result.parsed.ok && (result.url || result.url_template)) {
                result.credential_slot = credentials.credential_slot;
                result.credential_source = credentials.credential_slot === tokenEntry.slot
                  ? credentials.credential_source
                  : "cross_slot_fallback";
                break;
              }
            } catch (error) {
              lastError = error;
              if (error?.code !== "INVALID_REQUEST_SIGNATURE") throw error;
            }
          }

          if (!result || !result.parsed?.ok || (!result.url && !result.url_template)) {
            if (lastError) throw lastError;
            throw new Error("Qobuz modern playback failed for every configured App ID/App Secret pair");
          }

          const status = result.parsed.status;

          attempts.push({
            token_slot: tokenEntry.slot,
            credential_slot: result.credential_slot ?? tokenEntry.slot,
            credential_source: result.credential_source || tokenEntry.credential_source,
            format_id: fmt.id,
            status,
            ok: result.parsed.ok,
            has_url: Boolean(result.url),
            has_segmented_stream: Boolean(result.url_template),
            signing_mode: result.signing_mode || null,
            error:
              result.parsed.json?.message ||
              result.parsed.json?.error ||
              null,
            duration_ms: Date.now() - started,
          });

          if (result.parsed.ok && (result.url || result.url_template)) {
            markTokenSuccess(tokenEntry.slot);

            const json = result.parsed.json || {};
            const value = {
              url: result.url || null,
              url_template: result.url_template || null,
              n_segments: result.n_segments || null,
              encryption_key: result.encryption_key || null,
              session_id: result.session_id || null,
              format_id: String(result.format_id),
              mime_type:
                json.mime_type ||
                (String(fmt.id) === "5" ? "audio/mpeg" : "audio/flac"),
              bit_depth:
                numberOrNull(json.bit_depth) ??
                (String(fmt.id) === "5" ? null : String(fmt.id) === "6" ? 16 : 24),
              sampling_rate:
                numberOrNull(json.sampling_rate) ??
                (String(fmt.id) === "5" ? null : String(fmt.id) === "6" ? 44100 : null),
              bitrate:
                numberOrNull(json.bitrate) ??
                (String(fmt.id) === "5" ? 320 : null),
              duration:
                numberOrNull(json.duration) ??
                numberOrNull(track?.duration),
              restrictions: json.restrictions || [],
              sample: Boolean(json.sample),
              file_type: json.file_type || "full",
              format_name: fmt.name,
              token_slot: tokenEntry.slot,
              credential_slot: result.credential_slot ?? tokenEntry.slot,
              credential_source: result.credential_source || tokenEntry.credential_source,
              attempts,
            };

            memorySet(
              memoryStreamCache,
              cacheKeyValue,
              { savedAt: Date.now(), value },
              MAX_MEMORY_STREAM_CACHE
            );

            return { ...value, cache: "miss" };
          }

          if (status === 401 || status === 403) {
            markTokenFailure(
              tokenEntry.slot,
              status,
              result.parsed.json?.message || `HTTP ${status}`
            );
            break;
          }

          if (!isTransientStatus(status)) {
            // A format-specific failure can be legitimate, so continue
            // to the next quality before abandoning the token.
          }
        } catch (error) {
          attempts.push({
            token_slot: tokenEntry.slot,
            format_id: fmt.id,
            status: error?.status || null,
            ok: false,
            has_url: false,
            error: error?.message || String(error),
            duration_ms: Date.now() - started,
          });
        }
      }
    }

    const error = new Error("No Qobuz stream URL could be resolved");
    error.status = 502;
    error.attempts = attempts;
    throw error;
  })();

  pendingStreams.set(cacheKeyValue, task);

  try {
    return await task;
  } finally {
    pendingStreams.delete(cacheKeyValue);
  }
}

/* =========================================================
 * Track response
 * ========================================================= */

async function getTrackById(env, id, ctx) {
  const key = cacheKey("track", id);
  const memoryHit = getMemoryTrack(key);
  if (memoryHit) return { track: memoryHit, source: "memory", tokenSlot: null };

  const kv = await getCachedMetadata(env, key);
  if (kv?.id) {
    cacheMemoryTrack(key, kv);
    return { track: kv, source: "kv", tokenSlot: null };
  }

  const result = await catalogJson(env, "track/get", {
    track_id: id,
  });

  const track = result.json?.track || result.json;
  if (!track?.id) return { track: null, source: "miss", tokenSlot: result.tokenSlot };

  cacheMemoryTrack(key, track);
  saveMetadata(env, ctx, key, track);

  return { track, source: "miss", tokenSlot: result.tokenSlot };
}

async function richTrackResponse(env, ctx, url) {
  const id = cleanString(url.searchParams.get("id") || url.searchParams.get("track_id"));
  const isrc = normalizeIsrc(url.searchParams.get("isrc") || url.searchParams.get("i"));
  const query = cleanString(
    url.searchParams.get("q") ||
    url.searchParams.get("query") ||
    url.searchParams.get("track")
  );
  const artist = cleanString(url.searchParams.get("artist"));
  const quality = url.searchParams.get("quality") || url.searchParams.get("format") || "best";
  const startedAt = Date.now();

  let lookup;
  let track;

  if (id) {
    lookup = await getTrackById(env, id, ctx);
    track = lookup.track;
  } else if (isrc) {
    lookup = await findTrackByIsrc(env, isrc, null, ctx);
    track = lookup.track;
  } else if (query) {
    const searchUrl = new URL("https://internal/search");
    searchUrl.searchParams.set("q", query);
    const result = await searchCatalog(env, searchUrl);
    const candidates = result?.data || [];
    track = candidates.find((x) => {
      if (!artist) return true;
      return String(x?.artist?.name || "").toLowerCase() === artist.toLowerCase();
    }) || candidates[0] || null;
    lookup = { track, source: "search", tokenSlot: result?.tokenSlot || null };
  } else {
    throw Object.assign(
      new Error("Missing id, track_id, isrc, q, query, or track"),
      { status: 400 }
    );
  }

  if (!track?.id) {
    throw Object.assign(new Error("Track not found"), { status: 404 });
  }

  const normalized = normalizeTrack(track);
  const playback = await resolveStream(env, {
    track,
    trackId: String(track.id),
    quality,
    preferredTokenSlot:
      Number(url.searchParams.get("token")) || lookup?.tokenSlot || null,
  });

  const total = Date.now() - startedAt;

  return {
    version: API_VERSION,
    provider: "qobuz",
    id: String(track.id),
    track_id: String(track.id),
    isrc: normalizeIsrc(track.isrc || isrc) || null,
    title: track.title || null,
    artist:
      track.performer?.name ||
      track.artist?.name ||
      normalized.artist?.name ||
      "Unknown",
    album: track.album?.title || null,

    // Rich normalized metadata
    metadata: normalized,

    // Playback
    format_id: playback.format_id,
    format: playback.format_name,
    mime_type: playback.mime_type,
    streamUrl: playback.url,
    stream_url_template: playback.url_template || null,
    stream_segments: playback.n_segments || null,
    stream_type: playback.url ? "direct_url" : playback.url_template ? "segmented" : null,
    bitrate: playback.bitrate,
    bit_depth: playback.bit_depth,
    sampling_rate: playback.sampling_rate,
    duration: playback.duration,
    sample: playback.sample,
    file_type: playback.file_type,
    restrictions: playback.restrictions,

    // Diagnostics
    token_slot: playback.token_slot || lookup?.tokenSlot || null,
    diagnostics: {
      cache: {
        metadata: lookup?.source || "miss",
        stream: playback.cache || "miss",
      },
      formats_tried: playback.attempts || [],
      elapsed_ms: total,
    },
  };
}

/* =========================================================
 * Qobuz catalog routes
 * ========================================================= */

async function routeSearch(env, url) {
  return searchCatalog(env, url);
}

async function routeAlbum(env, url, ctx) {
  const id = cleanString(url.searchParams.get("id") || url.searchParams.get("album_id"));
  if (!id) throw Object.assign(new Error("Missing album id"), { status: 400 });

  const { limit, offset } = getLimitOffset(url);
  const key = cacheKey("album", `${id}:${offset}:${limit}`);

  const cached = await getCachedMetadata(env, key);
  if (cached) return { version: API_VERSION, provider: "qobuz", data: cached, cache: "kv" };

  const result = await catalogJson(env, "album/get", {
    album_id: id,
    offset,
    limit,
    extra: url.searchParams.get("extra") || "track_ids",
  });

  const album = result.json?.album || result.json;
  const normalized = normalizeAlbum(album);

  let tracks = null;
  if (Array.isArray(album?.tracks?.items)) {
    tracks = {
      data: album.tracks.items.map(normalizeTrack).filter(Boolean),
      total: numberOrNull(album.tracks.total) ?? album.tracks.items.length,
      offset: numberOrNull(album.tracks.offset) ?? offset,
      limit: numberOrNull(album.tracks.limit) ?? limit,
    };
  }

  const data = {
    ...normalized,
    token_slot: result.tokenSlot,
    tracks,
    raw_streamable: album?.streamable ?? null,
  };

  saveMetadata(env, ctx, key, data);
  return { version: API_VERSION, provider: "qobuz", data, cache: "miss" };
}

async function routeArtist(env, url, ctx) {
  const id = cleanString(url.searchParams.get("id") || url.searchParams.get("artist_id"));
  if (!id) throw Object.assign(new Error("Missing artist id"), { status: 400 });

  const { limit, offset } = getLimitOffset(url);

  const result = await catalogJson(env, "artist/page", {
    artist_id: id,
  });

  const page = result.json;
  const artist = page?.artist || page;
  const releases =
    page?.albums ||
    page?.releases ||
    page?.discography ||
    null;

  return {
    version: API_VERSION,
    provider: "qobuz",
    data: {
      ...normalizeArtist(artist),
      token_slot: result.tokenSlot,
      biography: artist?.biography || page?.biography || null,
      albums: releases
        ? normalizeCollection({ albums: releases }, "albums", normalizeAlbum)
        : null,
      similar_artists:
        page?.similar_artists ||
        page?.similarArtists ||
        null,
    },
  };
}

async function routePlaylist(env, url, ctx) {
  const id = cleanString(url.searchParams.get("id") || url.searchParams.get("playlist_id"));
  if (!id) throw Object.assign(new Error("Missing playlist id"), { status: 400 });

  const { limit, offset } = getLimitOffset(url);

  const result = await catalogJson(env, "playlist/get", {
    playlist_id: id,
    offset,
    limit,
    extra: "tracks",
  });

  const playlist = result.json?.playlist || result.json;

  return {
    version: API_VERSION,
    provider: "qobuz",
    data: {
      ...normalizePlaylist(playlist),
      token_slot: result.tokenSlot,
      tracks: normalizeCollection(playlist, "tracks", normalizeTrack),
    },
  };
}

async function routeCover(env, url) {
  const id =
    cleanString(url.searchParams.get("id")) ||
    cleanString(url.searchParams.get("album_id")) ||
    cleanString(url.searchParams.get("track_id")) ||
    cleanString(url.searchParams.get("i"));

  if (!id) throw Object.assign(new Error("Missing id"), { status: 400 });

  let data;

  if (url.searchParams.get("track_id")) {
    const result = await catalogJson(env, "track/get", { track_id: id });
    data = normalizeTrack(result.json?.track || result.json)?.image;
  } else {
    const result = await catalogJson(env, "album/get", { album_id: id });
    data = normalizeAlbum(result.json?.album || result.json)?.image;
  }

  if (!data) throw Object.assign(new Error("Artwork not found"), { status: 404 });

  return {
    version: API_VERSION,
    provider: "qobuz",
    id,
    image: data,
    urls: data,
  };
}

async function routeSimilarArtist(env, url) {
  const id = cleanString(url.searchParams.get("id") || url.searchParams.get("artist_id"));
  if (!id) throw Object.assign(new Error("Missing artist id"), { status: 400 });

  const result = await catalogJson(env, "artist/getSimilarArtists", { artist_id: id });
  const collection = result.json?.artists || result.json?.similar_artists || result.json;
  const items = Array.isArray(collection?.items) ? collection.items : Array.isArray(collection) ? collection : [];

  return {
    version: API_VERSION,
    provider: "qobuz",
    route_used: "artist/getSimilarArtists",
    data: items.map(normalizeArtist).filter(Boolean),
    total: numberOrNull(collection?.total) ?? items.length,
    token_slot: result.tokenSlot,
  };
}

async function routeAlbumSimilar(env, url) {
  return apiError(
    "Qobuz does not expose a verified album-similarity endpoint in the API surface used by this worker.",
    501,
    {
      capability: "album_similar",
      supported: false,
      alternatives: ["/artist/similar", "/radio"],
    }
  );
}

async function routeRecommendations(env, url) {
  const { limit, offset } = getLimitOffset(url);
  const q = cleanString(url.searchParams.get("q") || url.searchParams.get("query"));

  // Verified Qobuz discovery endpoint. This is a popularity/discovery feed,
  // not a fake native personalized-recommendations endpoint.
  if (q) {
    const result = await catalogJson(env, "most-popular/get", {
      query: q,
      offset,
      limit,
    });

    return {
      version: API_VERSION,
      provider: "qobuz",
      route_used: "most-popular/get",
      mode: "most_popular",
      token_slot: result.tokenSlot,
      data: result.json?.tracks || result.json?.items || result.json,
    };
  }

  return apiError(
    "Qobuz's verified personalized recommendation endpoint requires a POST dynamic/suggest request with listening context. Use /recommendations with q for the verified most-popular discovery feed.",
    501,
    {
      capability: "recommendations",
      supported: false,
      verified_dynamic_endpoint: "dynamic/suggest",
      usage: "/recommendations?q=artist-or-query",
    }
  );
}

async function routeRadio(env, url) {
  const requestedLimit = getLimitOffset(url).limit;
  const limit = Math.min(Math.max(requestedLimit || 20, 1), 50);
  const seedTrackId = cleanString(url.searchParams.get("id") || url.searchParams.get("track_id"));
  const seedArtistId = cleanString(url.searchParams.get("artist_id"));

  if (!seedTrackId && !seedArtistId) {
    throw Object.assign(new Error("Radio requires id/track_id or artist_id"), { status: 400 });
  }

  let seedTrack = null;
  let seedArtist = null;
  let tokenSlot = null;

  if (seedTrackId) {
    const seed = await catalogJson(env, "track/get", { track_id: seedTrackId });
    tokenSlot = seed.tokenSlot;
    seedTrack = seed.json?.track || seed.json;
    seedArtist = seedTrack?.performer || seedTrack?.artist || null;
  } else {
    const artist = await catalogJson(env, "artist/page", { artist_id: seedArtistId });
    tokenSlot = artist.tokenSlot;
    const page = artist.json;
    seedArtist = page?.artist || page;
  }

  const artistId = cleanString(seedArtist?.id || seedArtistId);
  const artistName = cleanString(seedArtist?.name);
  if (!artistId || !artistName) {
    throw Object.assign(new Error("Qobuz radio seed did not contain a usable artist"), { status: 404 });
  }

  const similarResult = await catalogJson(env, "artist/getSimilarArtists", { artist_id: artistId }, tokenSlot);
  const similarCollection = similarResult.json?.artists || similarResult.json?.similar_artists || similarResult.json;
  const similarArtists = (Array.isArray(similarCollection?.items) ? similarCollection.items : Array.isArray(similarCollection) ? similarCollection : [])
    .map(normalizeArtist)
    .filter((artist) => artist?.id && String(artist.id) !== String(artistId));

  const artistSeeds = [{ id: artistId, name: artistName, seed: true }];
  for (const artist of similarArtists.slice(0, 10)) artistSeeds.push({ id: artist.id, name: artist.name, seed: false });

  const perArtist = Math.max(2, Math.ceil(limit / Math.max(artistSeeds.length, 1)) + 1);
  const searches = await Promise.all(artistSeeds.map(async (artist) => {
    try {
      const result = await catalogJson(env, "catalog/search", {
        query: artist.name,
        type: "tracks",
        limit: perArtist,
        offset: 0,
      }, tokenSlot);
      return (result.json?.tracks?.items || []).map(normalizeTrack).filter(Boolean);
    } catch (_) {
      return [];
    }
  }));

  const tracks = [];
  const seen = new Set();
  const seedId = seedTrack?.id != null ? String(seedTrack.id) : null;

  for (let index = 0; tracks.length < limit; index++) {
    let added = false;
    for (const bucket of searches) {
      const track = bucket[index];
      if (!track || track.id == null) continue;
      const id = String(track.id);
      if (seen.has(id) || id === seedId) continue;
      seen.add(id);
      tracks.push(track);
      added = true;
      if (tracks.length >= limit) break;
    }
    if (!added) break;
  }

  return {
    version: API_VERSION,
    provider: "qobuz",
    route_used: "artist/getSimilarArtists + catalog/search",
    radio_type: "generated_from_qobuz_catalog",
    token_slot: tokenSlot,
    seed: {
      track: seedTrack ? normalizeTrack(seedTrack) : null,
      artist: normalizeArtist(seedArtist),
    },
    similar_artists: similarArtists.slice(0, 10),
    data: tracks,
    total: tracks.length,
  };
}

async function routeChart(env, url) {
  const { limit, offset } = getLimitOffset(url);
  const type = cleanString(url.searchParams.get("type")) || "new-releases";
  const genreId = cleanString(url.searchParams.get("genre_id"));

  const query = { type, limit, offset };
  if (genreId) query.genre_id = genreId;

  const result = await catalogJson(env, "album/getFeatured", query);
  return {
    version: API_VERSION,
    provider: "qobuz",
    route_used: "album/getFeatured",
    type,
    genre_id: genreId,
    token_slot: result.tokenSlot,
    data: result.json?.albums || result.json?.items || result.json,
  };
}

async function routeGenre(env, url) {
  const result = await catalogJson(env, "genre/list", {});
  return {
    version: API_VERSION,
    provider: "qobuz",
    route_used: "genre/list",
    token_slot: result.tokenSlot,
    data: result.json?.genres || result.json,
  };
}

async function routeLyrics(env, url) {
  /*
   * Qobuz's documented v0.2 catalog surface does not expose a stable
   * lyrics endpoint equivalent to Deezer's synchronized lyrics API.
   * Keep the route for API parity, but fail honestly.
   */
  return apiError(
    "Qobuz does not expose a stable lyrics endpoint through the catalog API.",
    501,
    {
      capability: "lyrics",
      supported: false,
      provider: "qobuz",
    }
  );
}

/* =========================================================
 * Token ping
 * ========================================================= */

async function pingTokens(env) {
  const tokens = getTokens(env);

  if (!tokens.length) {
    return {
      provider: "qobuz",
      version: API_VERSION,
      configured_tokens: 0,
      lossless_probe_track_id: null,
      results: [],
    };
  }

  const results = [];

  for (const entry of tokens) {
    const started = Date.now();

    if (!entry.appId || !entry.appSecret) {
      markTokenFailure(entry.slot, 500, "Missing App ID or App Secret for this token slot");
      results.push({
        slot: entry.slot,
        status: "misconfigured",
        http_status: 500,
        elapsed_ms: Date.now() - started,
        can_catalog: false,
        can_lossless: false,
        credential_source: entry.credential_source,
        has_app_id: Boolean(entry.appId),
        has_app_secret: Boolean(entry.appSecret),
        error: "Missing Qobuz App ID or App Secret for this token slot",
      });
      continue;
    }

    try {
      // Do not use a hard-coded Deezer track ID here. Search Qobuz itself
      // for a known track, then use the returned Qobuz track ID for the
      // optional lossless entitlement probe.
      const catalog = await catalogJson(
        env,
        "catalog/search",
        {
          query: "Blinding Lights The Weeknd",
          type: "tracks",
          limit: 1,
          offset: 0,
        },
        entry.slot
      );

      const tracks = catalog.json?.tracks?.items || catalog.json?.tracks?.data || [];
      const probeTrack = tracks[0] || null;
      const probeTrackId = probeTrack?.id ? String(probeTrack.id) : null;

      if (!probeTrackId) {
        markTokenFailure(entry.slot, 404, "Qobuz catalog returned no probe track");
        results.push({
          slot: entry.slot,
          status: "failed",
          http_status: 404,
          elapsed_ms: Date.now() - started,
          can_catalog: false,
          can_lossless: false,
          credential_source: entry.credential_source,
          error: "Qobuz catalog returned no track for the ping probe",
        });
        continue;
      }

      markTokenSuccess(entry.slot);
      const result = {
        slot: entry.slot,
        status: "active",
        http_status: catalog.response?.status || 200,
        elapsed_ms: Date.now() - started,
        can_catalog: true,
        can_playback: false,
        credential_source: entry.credential_source,
        probe_track_id: probeTrackId,
        probe_track_title: probeTrack?.title || null,
        probe_track_artist: probeTrack?.artist?.name || null,
      };

      try {
        const candidates = entry.credential_candidates?.length
          ? entry.credential_candidates
          : [{
              credential_slot: entry.slot,
              appId: entry.appId,
              appSecret: entry.appSecret,
              credential_source: entry.credential_source,
            }];

        let stream = null;
        let lastError = null;

        for (const credentials of candidates) {
          try {
            stream = await resolveOneFormat(env, {
              trackId: probeTrackId,
              formatId: "6",
              intent: "stream",
              token: entry.token,
              appId: credentials.appId,
              appSecret: credentials.appSecret,
              slot: entry.slot,
              allowLegacy: false,
            });

            if (stream.parsed.ok && (stream.url || stream.url_template)) {
              stream.credential_slot = credentials.credential_slot;
              stream.credential_source = credentials.credential_slot === entry.slot
                ? credentials.credential_source
                : "cross_slot_fallback";
              break;
            }
          } catch (error) {
            lastError = error;
            if (error?.code !== "INVALID_REQUEST_SIGNATURE") throw error;
          }
        }

        if (!stream || !stream.parsed?.ok || (!stream.url && !stream.url_template)) {
          if (lastError) throw lastError;
          throw new Error("Qobuz playback failed for every configured App ID/App Secret pair");
        }

        const playbackSucceeded = Boolean(
          stream.parsed.ok && (stream.url || stream.url_template)
        );
        result.can_playback = playbackSucceeded;
        result.playback_check = playbackSucceeded
          ? "signed_playback_authorized"
          : "playback_test_failed";
        result.playback_http_status = stream.parsed.status;
        result.playback_signing_mode = stream.signing_mode || null;
        result.playback_stream_type = stream.url
          ? "direct_url"
          : stream.url_template
            ? "segmented"
            : null;
        result.playback_segments = stream.n_segments || null;
        result.playback_credential_slot = stream.credential_slot ?? entry.slot;
        result.playback_credential_source = stream.credential_source || entry.credential_source;
        result.playback_error =
          stream.parsed.json?.message ||
          stream.parsed.json?.error ||
          null;

        // A successful format-6 request proves signed lossless playback.
        result.can_lossless = playbackSucceeded ? true : null;
        result.lossless_check = playbackSucceeded
          ? "flac_authorized"
          : "unknown_due_to_playback_failure";
        result.lossless_http_status = stream.parsed.status;
        result.lossless_error = playbackSucceeded
          ? null
          : (stream.parsed.json?.message || stream.parsed.json?.error || null);
      } catch (error) {
        result.can_playback = false;
        result.playback_check = "playback_test_error";
        result.playback_error = error?.message || String(error);
        result.playback_error_code = error?.code || null;

        // Do not call this a lossless entitlement failure. We could not
        // establish a valid signed playback request in the first place.
        result.can_lossless = null;
        result.lossless_check = error?.code === "INVALID_REQUEST_SIGNATURE"
          ? "invalid_request_signature"
          : "unknown_due_to_playback_failure";
        result.lossless_error = error?.message || String(error);
        if (error?.code === "INVALID_REQUEST_SIGNATURE") {
          result.lossless_error_code = error.code;
        }
      }

      results.push(result);
    } catch (error) {
      const status = error?.status || null;
      markTokenFailure(entry.slot, status, error?.message);
      results.push({
        slot: entry.slot,
        status:
          status === 401 || status === 403
            ? "expired_or_invalid"
            : "failed",
        http_status: status,
        elapsed_ms: Date.now() - started,
        can_catalog: false,
        can_lossless: false,
        credential_source: entry.credential_source,
        error: error?.message || String(error),
      });
    }
  }

  const probe = results.find((x) => x.probe_track_id);

  return {
    provider: "qobuz",
    version: API_VERSION,
    configured_tokens: tokens.length,
    lossless_probe_track_id: probe?.probe_track_id || null,
    results,
  };
}

/* =========================================================
 * Root / info
 * ========================================================= */

function rootInfo(env) {
  const tokens = getTokens(env);

  return {
    version: API_VERSION,
    provider: "qobuz",
    name: "Qobuz HiFi API",
      cache: { namespace: "GENERAL_MUSIC_CACHE", keyPrefix: "music:qobuz:" },
    compatibleStyle: "hifi-api",
    base: QOBUZ_BASE,
    configured_tokens: tokens.length,
    capabilities: {
      info: true,
      track: true,
      stream: true,
      search: true,
      album: true,
      artist: true,
      playlist: true,
      cover: true,
      lyrics: false,
      recommendations: true,
      recommendations_mode: "most-popular (GET) or dynamic/suggest (POST, listening context)",
      radio: "generated",
      nativeRadio: false,
      similarArtists: true,
      similarAlbums: false,
      chart: true,
      genre: true,
      multiToken: true,
      tokenFailover: true,
      isrcLookup: true,
      hires192: true,
      hires96: true,
      cdQuality: true,
      mp3320: true,
      metadataCache: true,
      streamUrlCache: true,
    },
    verified_qobuz_methods: [
      "track/search",
      "album/search",
      "artist/search",
      "playlist/search",
      "catalog/search",
      "track/get",
      "album/get",
      "artist/page",
      "artist/getSimilarArtists",
      "artist/getReleasesList",
      "playlist/get",
      "playlist/getUserPlaylists",
      "genre/list",
      "album/getFeatured",
      "most-popular/get",
      "session/start",
      "file/url",
      "track/getFileUrl"
    ],
    endpoints: [
      "/",
      "/info-api",
      "/info",
      "/track",
      "/stream",
      "/search",
      "/album",
      "/artist",
      "/playlist",
      "/cover",
      "/lyrics",
      "/recommendations",
      "/radio",
      "/artist/similar",
      "/chart",
      "/genre",
      "/ping",
    ],
    token_environment: [
      "QOBUZ_USER_AUTH_TOKEN",
      "QOBUZ_USER_AUTH_TOKEN_2",
      "...",
      "QOBUZ_USER_AUTH_TOKEN_10",
    ],
  };
}

/* =========================================================
 * Optional direct CDN proxy
 * ========================================================= */

async function proxyAudio(request, url) {
  let sourceUrl = url.searchParams.get("url");

  if (!sourceUrl) {
    throw Object.assign(new Error("Missing url parameter"), { status: 400 });
  }

  try {
    sourceUrl = decodeURIComponent(sourceUrl);
  } catch (_) {}

  let source;
  try {
    source = new URL(sourceUrl);
  } catch (_) {
    throw Object.assign(new Error("Invalid stream URL"), { status: 400 });
  }

  if (!/^https?:$/.test(source.protocol)) {
    throw Object.assign(new Error("Unsupported stream URL protocol"), { status: 400 });
  }

  const headers = new Headers();
  const range = request.headers.get("Range");
  if (range) headers.set("Range", range);

  const upstream = await fetch(source.toString(), {
    method: request.method === "HEAD" ? "HEAD" : "GET",
    headers,
    redirect: "follow",
  });

  const outHeaders = new Headers(corsHeaders);
  for (const name of [
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "etag",
    "last-modified",
  ]) {
    const value = upstream.headers.get(name);
    if (value) outHeaders.set(name, value);
  }

  outHeaders.set("Cache-Control", "no-store");

  return new Response(
    request.method === "HEAD" ? null : upstream.body,
    {
      status: upstream.status,
      headers: outHeaders,
    }
  );
}

/* =========================================================
 * Main router
 * ========================================================= */

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    if (!["GET", "HEAD"].includes(request.method)) {
      return apiError("Method not allowed", 405, {
        allowedMethods: ["GET", "HEAD", "OPTIONS"],
      });
    }

    const url = new URL(request.url);
    const path = normalizePath(url.pathname);

    // Health / token diagnostics
    if (path === "/ping" || url.searchParams.has("ping")) {
      try {
        const result = await pingTokens(env);
        return request.method === "HEAD"
          ? new Response(null, {
              status: 200,
              headers: {
                ...corsHeaders,
                "Content-Type": "application/json",
              },
            })
          : jsonResponse(result, 200);
      } catch (error) {
        return apiError(error?.message || "Qobuz ping failed", 500);
      }
    }

    // Root / capability information
    if (path === "/" || path === "/info-api") {
      const response = jsonResponse(rootInfo(env), 200, {
        "Cache-Control": "public, max-age=30",
        "X-Qobuz-API-Version": API_VERSION,
      });
      return request.method === "HEAD" ? headResponse(response) : response;
    }

    try {
      if (path === "/info") {
        const data = await richTrackResponse(env, ctx, url);
        const response = jsonResponse(data, 200, {
          "Cache-Control": "no-store",
          "X-Qobuz-Token": String(data.token_slot || "unknown"),
          "X-Qobuz-Format": String(data.format_id || "unknown"),
        });
        return request.method === "HEAD" ? headResponse(response) : response;
      }

      if (path === "/track") {
        const data = await richTrackResponse(env, ctx, url);
        const response = jsonResponse(data, 200, {
          "Cache-Control": "no-store",
          "X-Qobuz-Token": String(data.token_slot || "unknown"),
          "X-Qobuz-Format": String(data.format_id || "unknown"),
        });
        return request.method === "HEAD" ? headResponse(response) : response;
      }

      if (path === "/stream") {
        /*
         * /stream?isrc=... or /stream?id=...
         * returns a fresh signed URL.
         *
         * /stream?url=...&proxy=1
         * proxies an already-resolved Qobuz CDN URL and honors Range.
         */
        if (url.searchParams.get("proxy") === "1" || url.searchParams.has("url")) {
          const response = await proxyAudio(request, url);
          return response;
        }

        const data = await richTrackResponse(env, ctx, url);

        // Mirror the Deezer worker's convenient redirect mode.
        // stream=1 returns the fresh signed Qobuz CDN URL directly.
        if (url.searchParams.get("stream") === "1" && !url.searchParams.has("json")) {
          if (!data.streamUrl) {
            return jsonResponse({
              error: "Qobuz returned a segmented modern stream",
              code: "SEGMENTED_STREAM",
              stream_type: data.stream_type,
              url_template: data.stream_url_template,
              n_segments: data.stream_segments,
            }, 409);
          }
          return Response.redirect(data.streamUrl, 302);
        }

        return jsonResponse(data, 200, {
          "Cache-Control": "no-store",
          "X-Qobuz-Token": String(data.token_slot || "unknown"),
          "X-Qobuz-Format": String(data.format_id || "unknown"),
          "X-Qobuz-Cache": data.diagnostics?.cache?.stream || "miss",
          "Server-Timing": `total;dur=${data.diagnostics?.elapsed_ms || 0}`,
        });
      }

      if (path === "/search") {
        const data = await routeSearch(env, url);
        const response = jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=30",
        });
        return request.method === "HEAD" ? headResponse(response) : response;
      }

      if (path === "/album") {
        const data = await routeAlbum(env, url, ctx);
        const response = jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=60",
        });
        return request.method === "HEAD" ? headResponse(response) : response;
      }

      if (path === "/artist") {
        const data = await routeArtist(env, url, ctx);
        const response = jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=60",
        });
        return request.method === "HEAD" ? headResponse(response) : response;
      }

      if (path === "/playlist") {
        const data = await routePlaylist(env, url, ctx);
        const response = jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=30",
        });
        return request.method === "HEAD" ? headResponse(response) : response;
      }

      if (path === "/cover") {
        const data = await routeCover(env, url);
        const response = jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=86400",
        });
        return request.method === "HEAD" ? headResponse(response) : response;
      }

      if (path === "/lyrics") {
        const response = await routeLyrics(env, url);
        return response;
      }

      if (path === "/recommendations") {
        const data = await routeRecommendations(env, url);
        if (data instanceof Response) return data;
        return jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=60",
        });
      }

      if (path === "/radio") {
        const data = await routeRadio(env, url);
        return jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=30",
        });
      }

      if (path === "/artist/similar") {
        const data = await routeSimilarArtist(env, url);
        return jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=300",
        });
      }

      if (path === "/album/similar") {
        const data = await routeAlbumSimilar(env, url);
        if (data instanceof Response) return data;
        return jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=300",
        });
      }

      if (path === "/chart") {
        const data = await routeChart(env, url);
        return jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=60",
        });
      }

      if (path === "/genre") {
        const data = await routeGenre(env, url);
        return jsonResponse(data, 200, {
          "Cache-Control": "public, max-age=300",
        });
      }

      return apiError("Not found", 404, {
        available: rootInfo(env).endpoints,
      });
    } catch (error) {
      const status =
        Number(error?.status) >= 400 && Number(error?.status) < 600
          ? Number(error.status)
          : 502;

      return apiError(
        error?.message || "Qobuz request failed",
        status,
        {
          attempts: error?.attempts || error?.tokenErrors || undefined,
        }
      );
    }
  },
};
