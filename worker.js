// cfw-deezer-hifi-api-v1.2.4-final-sweep
// Leech-resistance hardening: authenticated playback entry points require one-use
// bootstrap tokens by default; same-isolate replay races are serialized; optional
// Durable Object coordination provides globally atomic token consumption.
// Production optimization pass: cached hot-path crypto, in-flight upstream
// coalescing, compact JSON by default, strict bootstrap/session token typing,
// and unique non-coalesced 256-bit bootstrap nonces.
// Derived from cfw-deezer-hifi-api-v11-random-nonce.
import { DurableObject } from "cloudflare:workers";

const DEEZER_GW = "https://www.deezer.com/ajax/gw-light.php";
const DEEZER_MEDIA_API = "https://media.deezer.com/v1/get_url";
const DEEZER_PIPE_GQL = "https://pipe.deezer.com/api";
const DEEZER_AUTH_ARL = "https://auth.deezer.com/login/arl?jo=p&rto=c&i=c";
const DEEZER_AUTH_RENEW = "https://auth.deezer.com/login/renew?jo=p&rto=c&i=c";
const PUBLIC_API_BASE = "https://api.deezer.com";
const API_VERSION = "1.2.4";
const GITHUB_REPOSITORY_URL = "https://github.com/alxhlms12/cfw-deezer-hifi-api/";
const SERVICE_NAME = "cfw-deezer-hifi-api";




const SAFE_DEFAULT_CHUNK = 512 * 1024;
const SAFE_MAX_CHUNK = 512 * 1024;

function getCorsHeaders(env) {
  const origin = env?.CORS_ALLOW_ORIGIN?.trim() || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Range, X-Chunk-Size, X-API-Key, X-Request-ID",
    "Access-Control-Expose-Headers": "Content-Length, Content-Type, Accept-Ranges, Content-Range, Server-Timing, X-Timing-Fetch-Ms, X-Timing-Process-Ms, X-Timing-Total-Ms, X-CPU-Safety, X-ARL-Slot, X-ARL-Tier, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset-Ms",
  };
}

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
  "flac": { format: "FLAC", audioFormat: "FLAC", mime: "audio/flac", sampleRate: 44100, bitDepth: 16, bitrate: null, bitrateUncompressed: 1411, lossless: true, label: "Lossless FLAC", badge: "LOSSLESS" },
  "lossless": { format: "FLAC", audioFormat: "FLAC", mime: "audio/flac", sampleRate: 44100, bitDepth: 16, bitrate: null, bitrateUncompressed: 1411, lossless: true, label: "Lossless FLAC", badge: "LOSSLESS" },
  "hifi": { format: "FLAC", audioFormat: "FLAC", mime: "audio/flac", sampleRate: 44100, bitDepth: 16, bitrate: null, bitrateUncompressed: 1411, lossless: true, label: "Lossless FLAC", badge: "LOSSLESS" },
  "320": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, bitrateUncompressed: null, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "320k": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, bitrateUncompressed: null, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "mp3_320": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, bitrateUncompressed: null, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "hq": { format: "MP3_320", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 320, bitrateUncompressed: null, lossless: false, label: "320kbps MP3", badge: "HIGH" },
  "128": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, bitrateUncompressed: null, lossless: false, label: "128kbps MP3", badge: "LOW" },
  "128k": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, bitrateUncompressed: null, lossless: false, label: "128kbps MP3", badge: "LOW" },
  "mp3_128": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, bitrateUncompressed: null, lossless: false, label: "128kbps MP3", badge: "LOW" },
  "standard": { format: "MP3_128", audioFormat: "MP3", mime: "audio/mpeg", sampleRate: 44100, bitDepth: null, bitrate: 128, bitrateUncompressed: null, lossless: false, label: "128kbps MP3", badge: "LOW" },
};




class BoundedMap {
  constructor(maxSize = 256) {
    this.maxSize = maxSize;
    this.map = new Map();
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt && entry.expiresAt <= Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value;
  }

  set(key, value, ttlMs = 0) {
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxSize) {
      const oldestKey = this.map.keys().next().value;
      this.map.delete(oldestKey);
    }
    this.map.set(key, {
      value,
      expiresAt: ttlMs > 0 ? Date.now() + ttlMs : 0,
    });
  }

  delete(key) {
    return this.map.delete(key);
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  get size() {
    return this.map.size;
  }
}

const sessionCache = new BoundedMap(64);
const jwtCache = new BoundedMap(64);
const cipherCache = new BoundedMap(128);
const trackMemoryCache = new BoundedMap(512);
const albumMemoryCache = new BoundedMap(256);
const lyricsMemoryCache = new BoundedMap(256);
const searchMemoryCache = new BoundedMap(256);
const catalogMemoryCache = new BoundedMap(128);

// Hot-path crypto caches. CryptoKey import and repeated API-key hashing are
// surprisingly expensive when a catalog response contains many stream URLs.
const streamHmacKeyCache = new BoundedMap(8);
const clientApiKeyHashCache = new BoundedMap(128);
const clientUserAgentHashCache = new BoundedMap(64);
const mediaInflight = new BoundedMap(256);
const trackTokenInflight = new BoundedMap(256);
const catalogInflight = new BoundedMap(128);
const GENERAL_CACHE_PREFIX = "music:deezer:";

function sharedCacheKey(type, id) {
  return `${GENERAL_CACHE_PREFIX}${type}:${String(id)}`;
}

async function getSharedCache(env, key) {
  if (!env?.GENERAL_MUSIC_CACHE) return null;
  try {
    return await env.GENERAL_MUSIC_CACHE.get(key, { type: "json" });
  } catch (_) {
    return null;
  }
}

async function putSharedCache(env, key, value, ttlSeconds = null) {
  if (!env?.GENERAL_MUSIC_CACHE) return;
  const days = Number(env?.CACHE_TTL_DAYS) || 30;
  const ttl = ttlSeconds || Math.floor(days * 86400);
  try {
    await env.GENERAL_MUSIC_CACHE.put(
      key,
      JSON.stringify(value),
      { expirationTtl: Math.max(60, ttl) }
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

function serializeJson(data, env = null) {
  const pretty = String(env?.PRETTY_JSON || "false").trim().toLowerCase();
  return JSON.stringify(data, null, ["1", "true", "yes", "on"].includes(pretty) ? 2 : 0);
}

function jsonResponse(data, status = 200, headers = {}, env = null) {
  return new Response(serializeJson(data, env), {
    status,
    headers: { ...getCorsHeaders(env), "Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff", ...headers },
  });
}

async function readResponse(response) {
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: response.status, ok: response.ok, text, json };
}

function shuffleArray(arr) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
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




const DEFAULT_UPSTREAM_TIMEOUT_MS = 8000;
const MAX_UPSTREAM_TIMEOUT_MS = 20000;
const MAX_UPSTREAM_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_REQUEST_URL_LENGTH = 8192;
const MAX_QUERY_VALUE_LENGTH = 2048;

function getUpstreamTimeoutMs(env = null, fallback = DEFAULT_UPSTREAM_TIMEOUT_MS) {
  const value = Number(env?.UPSTREAM_TIMEOUT_MS);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.max(1000, Math.min(MAX_UPSTREAM_TIMEOUT_MS, Math.floor(value)));
}

async function fetchWithTimeout(input, init = {}, env = null, timeoutMs = null) {
  const controller = new AbortController();
  const callerSignal = init?.signal || null;
  const effectiveTimeout = Math.max(1000, Math.min(MAX_UPSTREAM_TIMEOUT_MS, Number(timeoutMs) || getUpstreamTimeoutMs(env)));
  let timer = null;

  const abortFromCaller = () => controller.abort(callerSignal?.reason || "caller-aborted");
  if (callerSignal) {
    if (callerSignal.aborted) abortFromCaller();
    else callerSignal.addEventListener("abort", abortFromCaller, { once: true });
  }

  timer = setTimeout(() => controller.abort("upstream-timeout"), effectiveTimeout);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
    if (callerSignal) callerSignal.removeEventListener("abort", abortFromCaller);
  }
}

async function readResponseLimited(response, maxBytes = MAX_UPSTREAM_RESPONSE_BYTES) {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    try { await response.body?.cancel(); } catch (_) {}
    const error = new Error(`Upstream response exceeded ${maxBytes} bytes`);
    error.code = "UPSTREAM_RESPONSE_TOO_LARGE";
    error.status = 502;
    throw error;
  }

  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      const error = new Error(`Upstream response exceeded ${maxBytes} bytes`);
      error.code = "UPSTREAM_RESPONSE_TOO_LARGE";
      error.status = 502;
      throw error;
    }
    let json = null;
    try { json = JSON.parse(text); } catch (_) {}
    return { status: response.status, ok: response.ok, text, json };
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel("response-too-large"); } catch (_) {}
        const error = new Error(`Upstream response exceeded ${maxBytes} bytes`);
        error.code = "UPSTREAM_RESPONSE_TOO_LARGE";
        error.status = 502;
        throw error;
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    try { reader.releaseLock(); } catch (_) {}
  }

  let json = null;
  try { json = JSON.parse(text); } catch (_) {}
  return { status: response.status, ok: response.ok, text, json };
}

function validateRequestEnvelope(requestUrl) {
  if (requestUrl.toString().length > MAX_REQUEST_URL_LENGTH) {
    return { ok: false, error: "REQUEST_URL_TOO_LONG" };
  }
  for (const [key, value] of requestUrl.searchParams) {
    if (String(value).length > MAX_QUERY_VALUE_LENGTH) {
      return { ok: false, error: `QUERY_PARAMETER_TOO_LONG:${key}` };
    }
  }
  return { ok: true };
}






const rateLimitMap = new BoundedMap(5000);

async function checkRateLimit(request, env, authToken = "anonymous") {
  const route = new URL(request.url).pathname || "/";
  const key = `${authToken || "anonymous"}:${route.split("/")[1] || "root"}`;

  if (env?.RATE_LIMITER?.limit) {
    try {
      const result = await env.RATE_LIMITER.limit({ key });
      if (!result.success) return { limited: true, distributed: true };
      return { limited: false, distributed: true };
    } catch (_) {


      if (String(env?.RATE_LIMIT_FAIL_CLOSED || "false").toLowerCase() === "true") {
        return { limited: true, distributed: true, bindingError: true };
      }
    }
  }

  const rpsStr = env?.RATE_LIMIT?.trim();
  if (!rpsStr) return { limited: false, distributed: false };
  const rps = Number(rpsStr);
  if (!Number.isFinite(rps) || rps <= 0) return { limited: false, distributed: false };

  const windowMs = 2500;
  const maxRequests = Math.max(1, Math.round(rps * 2.5));
  const now = Date.now();
  let record = rateLimitMap.get(key);
  if (!record || now >= record.resetAt) {
    record = { count: 1, resetAt: now + windowMs };
    rateLimitMap.set(key, record, windowMs);
    return { limited: false, remaining: maxRequests - 1, resetInMs: windowMs, limit: maxRequests, rps, distributed: false };
  }
  record.count++;
  const remaining = Math.max(0, maxRequests - record.count);
  const resetInMs = Math.max(0, record.resetAt - now);
  if (record.count > maxRequests) return { limited: true, remaining: 0, resetInMs, limit: maxRequests, rps, distributed: false };
  return { limited: false, remaining, resetInMs, limit: maxRequests, rps, distributed: false };
}




let memoizedEnvRef = null;
let memoizedConfiguredArls = null;
let memoizedKeyMappings = null;

function getMemoizedConfig(env) {
  if (memoizedConfiguredArls && memoizedKeyMappings && memoizedEnvRef === env) {
    return { arls: memoizedConfiguredArls, mappings: memoizedKeyMappings };
  }

  const arls = [];
  for (let i = 1; i <= 50; i++) {
    const name = i === 1 ? (env.DEEZER_ARL ? "DEEZER_ARL" : "DEEZER_ARL_1") : `DEEZER_ARL_${i}`;
    const value = env[name]?.trim() || (i === 1 ? env.DEEZER_ARL_1?.trim() : undefined);
    if (value) arls.push({ slot: i, name, value });
  }

  const mappings = new Map();
  for (let i = 1; i <= 50; i++) {
    const keyName = i === 1 ? (env.API_KEY ? "API_KEY" : "API_KEY_1") : `API_KEY_${i}`;
    const slotsName = i === 1 ? (env.KEY ? "KEY" : "KEY_1") : `KEY_${i}`;
    const keyVal = env[keyName]?.trim() || (i === 1 ? env.API_KEY_1?.trim() : undefined);
    if (!keyVal) continue;

    const slotsVal = env[slotsName]?.trim() || (i === 1 ? env.KEY_1?.trim() : undefined);
    let allowedSlots = null;
    if (slotsVal) {
      const parsed = slotsVal.split(",")
        .map(s => parseInt(s.trim(), 10))
        .filter(n => Number.isFinite(n) && n >= 1 && n <= 50);
      if (parsed.length > 0) allowedSlots = new Set(parsed);
    }
    mappings.set(keyVal, allowedSlots);
  }

  memoizedEnvRef = env;
  memoizedConfiguredArls = arls;
  memoizedKeyMappings = mappings;

  return { arls, mappings };
}

function authenticateRequest(request, env) {
  const { mappings } = getMemoizedConfig(env);
  const publicApi = String(env?.PUBLIC_API ?? "false").toLowerCase() === "true";
  if (publicApi) return { authorized: true, allowedSlots: null, tokenId: "public" };

  const requireKey = String(env?.REQUIRE_API_KEY ?? "true").toLowerCase() !== "false";
  if (mappings.size === 0) return { authorized: !requireKey, allowedSlots: null, tokenId: null };

  const allowQueryKey = String(env?.ALLOW_QUERY_API_KEY || "false").toLowerCase() === "true";
  const url = new URL(request.url);
  const routePath = url.pathname.replace(/\/+$/, "") || "/";
  const isPlaybackRoute = routePath === "/stream" || routePath === "/stream-track" || /^\/track\/\d+\/stream$/.test(routePath);
  let token = null;
  if (allowQueryKey || isPlaybackRoute) token = url.searchParams.get("api_key")?.trim() || url.searchParams.get("key")?.trim();

  if (!token) {
    const authHeader = request.headers.get("Authorization") || request.headers.get("X-API-Key");
    if (authHeader) {
      const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
      token = bearerMatch ? bearerMatch[1].trim() : authHeader.trim();
    }
  }

  if (!token || !mappings.has(token)) return { authorized: false, allowedSlots: null, tokenId: null };
  return { authorized: true, allowedSlots: mappings.get(token), tokenId: token };
}




function isAllowedCdnHost(hostname, env) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  const configured = String(env?.STREAM_CDN_HOSTS || "*.dzcdn.net;media.deezer.com").split(";").map(s => s.trim().toLowerCase()).filter(Boolean);
  return configured.some(pattern => {
    if (pattern.startsWith("*.")) return host.endsWith(pattern.slice(1)) && host.length > pattern.length - 1;
    return host === pattern;
  });
}




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




function cleanTextForMatching(str) {
  return String(str || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[-_./]/g, " ")
    .replace(/[^\w\s]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeSearchQuery(rawQuery, titleParam = "", artistParam = "") {
  if (titleParam && artistParam) {
    const titleHint = String(titleParam).trim();
    const artistHint = String(artistParam).trim();
    return { clean: `${cleanTextForMatching(titleHint)} ${cleanTextForMatching(artistHint)}`.trim(), titleHint, artistHint };
  }

  if (titleParam && !artistParam) {
    const titleHint = String(titleParam).trim();
    return { clean: cleanTextForMatching(titleHint), titleHint, artistHint: "" };
  }

  if (!rawQuery) return { clean: "", titleHint: "", artistHint: "" };
  const q = String(rawQuery).trim();

  const byMatch = q.match(/^(.+?)\s+by\s+(.+)$/i);
  if (byMatch) {
    const titleHint = byMatch[1].trim();
    const artistHint = byMatch[2].trim();
    return { clean: `${cleanTextForMatching(titleHint)} ${cleanTextForMatching(artistHint)}`.trim(), titleHint, artistHint };
  }

  const dashMatch = q.match(/^([^-]+)\s+-\s+([^-]+)$/);
  if (dashMatch) {
    const part1 = dashMatch[1].trim();
    const part2 = dashMatch[2].trim();
    return { clean: `${cleanTextForMatching(part1)} ${cleanTextForMatching(part2)}`.trim(), titleHint: part2, artistHint: part1 };
  }

  const clean = cleanTextForMatching(q.replace(/\bby\b/gi, " ").replace(/\b(feat\.?|ft\.?|featuring)\b/gi, " "));
  return { clean: clean || q, titleHint: "", artistHint: "" };
}

const ALT_KEYWORDS_REGEX = /\b(remix|remixed|rmx|vip\s*mix|club\s*mix|extended\s*mix|live|concert|tour|unplugged|demo|early\s*take|rehearsal|mashup|mash-up|blend|bootleg|acoustic|instrumental|karaoke|backing\s*track|sped\s*up|speed\s*up|slowed|nightcore|tribute|cover)\b/i;

function isAltVersion(track) {
  if (!track) return false;
  const version = String(track.version || track.SNG_VERSION || track.VERSION || "").trim();
  const title = String(track.title || track.SNG_TITLE || "").trim();
  if (version && ALT_KEYWORDS_REGEX.test(version)) return true;

  const suffixMatches = title.match(/(?:\(([^)]+)\)|\[([^\]]+)\]|\s+-\s+([^\-]+)$)/g);
  if (suffixMatches) {
    for (const match of suffixMatches) {
      if (ALT_KEYWORDS_REGEX.test(match)) return true;
    }
  }

  return /\b(remix|rmx|mashup|mash-up|live\s+at\b|live\s+from\b|live\s+in\b)\b/i.test(title);
}

function isAltAllowed(requestUrl, explicitQuery = "", env = null) {
  const altParam = requestUrl.searchParams.get("alt");
  if (altParam !== null) {
    const val = String(altParam).toLowerCase().trim();
    return val === "1" || val === "true" || val === "yes";
  }
  if (explicitQuery && ALT_KEYWORDS_REGEX.test(explicitQuery)) return true;
  return String(env?.DEFAULT_ALLOW_ALT || "false").toLowerCase() === "true";
}

function isExplicitPreferred(requestUrl, env = null) {
  const expParam = requestUrl.searchParams.get("explicit");
  if (expParam !== null) {
    const val = String(expParam).toLowerCase().trim();
    return !(val === "false" || val === "0" || val === "no" || val === "clean");
  }
  const cleanParam = requestUrl.searchParams.get("clean");
  if (cleanParam !== null) {
    const val = String(cleanParam).toLowerCase().trim();
    return !(val === "true" || val === "1" || val === "yes");
  }
  const envDefault = env?.DEFAULT_EXPLICIT;
  if (envDefault !== undefined && envDefault !== null) {
    return String(envDefault).toLowerCase() !== "false";
  }
  return true;
}

function isTrackExplicit(track) {
  if (!track) return false;
  if (track.explicit_lyrics === true || track.EXPLICIT_LYRICS === "1" || track.EXPLICIT_LYRICS === 1) return true;
  if (track.explicit_content_lyrics === 1 || track.explicit_content_lyrics === 4) return true;
  return false;
}

function isTrackCleanOrEdited(track) {
  if (!track) return false;
  if (track.explicit_content_lyrics === 3 || track.explicit_content_lyrics === 7) return true;
  const title = String(track.title || track.SNG_TITLE || track.title_short || "");
  const version = String(track.version || track.SNG_VERSION || "");
  return /\b(clean(\s+version)?|radio\s+edit|radio\s+version|clean\s+edit|censored)\b/i.test(`${title} ${version}`);
}

function stripVersionQualifiers(title) {
  return String(title || "")
    .replace(/\s*[\(\[](clean|explicit|radio\s*edit|radio\s*version|clean\s*version|censored|album\s*version)[\)\]]/gi, "")
    .trim();
}

function pickBestTrack(tracks, queryInfo, allowAlt = false, preferExplicit = true) {
  if (!Array.isArray(tracks) || !tracks.length) return null;

  let candidates = tracks.slice(0, 10);

  if (!allowAlt) {
    const nonAlt = candidates.filter(t => !isAltVersion(t));
    if (nonAlt.length > 0) candidates = nonAlt;
  }

  if (queryInfo.titleHint && queryInfo.artistHint) {
    const tClean = cleanTextForMatching(queryInfo.titleHint);
    const aClean = cleanTextForMatching(queryInfo.artistHint);

    const relevant = candidates.filter(t => {
      const trackTitle = cleanTextForMatching(t.title || t.title_short);
      const trackArtist = cleanTextForMatching(t.artist?.name);
      const titleMatches = trackTitle.includes(tClean) || tClean.includes(trackTitle);
      const artistMatches = trackArtist.includes(aClean) || aClean.includes(trackArtist);
      return titleMatches && artistMatches;
    });

    if (relevant.length > 0) candidates = relevant;
  }

  if (preferExplicit) {
    const expMatch = candidates.find(t => isTrackExplicit(t));
    if (expMatch) return expMatch;
    const nonEdited = candidates.find(t => !isTrackCleanOrEdited(t));
    if (nonEdited) return nonEdited;
  } else {
    const cleanMatch = candidates.find(t => isTrackCleanOrEdited(t) || !isTrackExplicit(t));
    if (cleanMatch) return cleanMatch;
  }

  return candidates[0] || tracks[0];
}




function md5(str) {
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);

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
    for (let j = 0; j < 16; j++) M[j] = view.getUint32(offset + j * 4, true);

    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | ((~b) & d); g = i; }
      else if (i < 32) { f = (d & b) | ((~d) & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | (~d)); g = (7 * i) % 16; }

      const temp = (a + f + K[i] + M[g]) >>> 0;
      a = d; d = c; c = b;
      const s = S[i];
      b = (b + (((temp << s) | (temp >>> (32 - s))) >>> 0)) >>> 0;
    }

    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }

  const out = new DataView(new ArrayBuffer(16));
  out.setUint32(0, a0, true);
  out.setUint32(4, b0, true);
  out.setUint32(8, c0, true);
  out.setUint32(12, d0, true);

  let hex = "";
  for (let i = 0; i < 16; i++) hex += out.getUint8(i).toString(16).padStart(2, "0");
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
0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZY
cYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhghfDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg
5lUl86pVq5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYMfbOXD4Wm4eTHq/WujNsJM9c
ejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshqZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5
LgtEgqSEIARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O+S6O/BQfvsqmKHxZR05rwF2
ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBIHNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCb
B1NyyYCZG3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU7UTObLrO1Lsb238UR+bMJUs
zIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XIdA/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4
PHUW3/1haxUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/8OsZzLGjE9Vc2lbJ7C7yljI
4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebb4RWXSjkm8S/uXkOHd8tqky34zYvsTQc7kxujvIMraNndMAdB+nv4r8R+0
ldvaTa6QkZjqrY5xa5PVoNCO0dCvxyXgjjxbL451lLeP9uL78hIrZIiIuBKQDfAcT61eoGiPwxzRz/GRs6jBrS8vIhi+Dhd3
6nUt/osCH6HloMwPtW906Bis89bOieKZtKhP4P0T4Ld8xDuB0q2o2RZfomaAlXcFk8xzFCEaFHfmrSBld7X6hsdUQvX7nTXP
682vDHs+iaDWQRvTrh5+SQAlDi0gcbNeImgAu1e44K8kZDab8Am5HlVjkR1Z36aqeMFDidlaU38gfVuiAuW5xYMmA3Zilc+p
EcgZaE5zSkGzRy3KexSpShtRAFKaUykV1g9XP7ybxuQrYKR2geZ0AAi6b7VXG+kf8pbsayoN2RW2Y2Uh57n5tv80BS7FhVZk
U7AtXamfj6EIukeZboUHakt6cOm1sylE23UJLsQZJiOtbqawSafffZzuYLiP7bJm7KqMcWmaF/9WZFJswrGe4Rk2AqV1CUwp
oFkTQOQYOj4/VJiaW0KdZWuP5NaZ9z/WodKcB+/oMPVNLTjm8CVdwUzdIIaEcOsmY4LpxgIezF4JaGs/PrrvyTyXGBRranCh
aH81hFKg4oa3nFMFqlAHNz4HhBx/3q5cjn1E7FcW8riwOto38FAMDfAcHwQCALP/rgz1Gjy1dLIlg3pY3AkhvdGRE/l8qS/2
lDJHcyL1RwE65eWBN8La3Mi1djSa892nqURhRg/QAw7syMc+pHUeQeI4zZk76g4vMoC7oRg+szFOVIs4T225CG9CDQP2CgS/
LLgSkCSXfHlWebByvK+Jr96adx/ZkwgQs4uuEtzPPy5VEnIfLmtxJFAa3eafhM2HelhHGHQI2he8n5q86Ut9jOx67DrbhR36
YwlDZsRkw9LvHBhHMhXZCN1DOzckwroWEqFNQyplxFFQlAACEzrk3XHf+J4QMU5Vgax31l8RGZsENVbx16PHazwRGDtZJKUJ
8o/m7Zfx+/qeur8sHhU8bobjRXDq6W+xhg5eClo+KrN3H+ccTj0G+ill3LmZ5x0PgD6J1lJmyCUuTMl4nBCzasYVDrqU4up4
pfw8Ux4KLfTy906nNh0rPRk5Jg8ZwnlgUiOnCPcTErbrrf5u6sMfZuO8RZWme8iDsX830QGM/yjDMt3vvmxapWVYIYVoq5gC
7s6lD9svlTsq732tW24vhBUhtigpB2Fw7N1HdWGfFRATzKgw62G9lgM0/h6qA2PPtXNckExwojnVnp4Ly6reFO7MhrxgYiyn
nKtcq7LzhG5kix6vGb3wyqAjabllWrtQQGhaMjwqtLMxnunVwCG495tUCxmHX6CZlfeZfmI9faj4N4ial+MtdxHtk18WaBKB
DjWIKcfmH9aW3t+heFi6mVf1hKUbInJjm4PD/xrCRpbNswrrUy4wVI/ZSORtvDEoWOvy7zTG/+r+KO1h7nw8c11KFNnoZLfj
QhBdFCA+E+BF7uK2o6qr6ttsTxX6y0/Qx0L0Qu9qu7VlTzsdQc0hBdgeeZ6GhU3H5EtHaj2BYlDPYqHyW40mRvyIg6DBx7aj
fxUkw2nLdJJHhIoLVpKyhQlbvwCtGUidFGKxdCOCDgBYQo0qDFX16h2t9D4jP3BhM3Lwko2TfkHWX+zxbCI723zeN1nL7nRg
QIXyp853Mm6mB4CEGfhQnujv2FVh2Zc1qWmnqsUMBsJaBKv8gAvK3J5Eei7DRTSE/dVnBQ4ensnbc9vTEFWIzWdf2nnjZ0NA
xcQ0ZXE+ONg9KPie8W3/IBU+IeePsD1K5uOfK9uDrffpPVpolIFA9/ZMJhyUaSk0QRUg93YC1Pe89Gsu1KIAaNQIJHEzIPRq
Q7fUt1AAYa8eOfYulyRFRhQhT3S/i4hATZX8HZa1ka9w9N3TZqAvRb+8CewDvZeFf6xt0DHLhQSW6yezVf05QdolR+arygqa
KFB4JVMEKfQKLIba6bZt+2jcFGLXSGkAaA7ApCehje5PP/6i6IetjLWM4AZ69Na2qs4efNM3X+zOeKOZQGsqQiD+njXZ84W5
7jnXqzsSTosdyfr3S20YViajZjHq45eyOm76dN1bQzJoQef3yngg+/sK9U7Y/rOXRUBWrLpIlSdVUzo6IIONh/5rqbfQlpVL
VahnvKEVmljMqSljmeHbM6YqSlY/MSX5XvR+HJApMXz9+OgCBCcvcIC7FVwFKCzjlcEVSOTGbSJIwRM/xw+G3Af5ye5BBB8P
QEd5pF2IbhcyX1Hr1ZvA0fK8wY9BETVkJXt4NGAqnGDf+OijH2NsGw4StMIC4TKer2ZP0crRgRVrI5XgMz6S4TskC2Luvrki
hbKiDua6DZnecgyMLaL3KNASeEWVt5T9ZH0IYufM9fBUSaNvh31I+sOd/SfzPo0eCkdjQZku/3Q6b26r9Pj9N6gS3GCh6934
mRvhTNtuaw3Ge1UQbWcsNydl1Dvc0OgE8SkNx8wA/6O1OQ+SaQ/tC2Z7n/vO232coJHPC9kVXqO7Ey+IUVutJHuUeb92O9br
Nzkus8wRWXmAJuKX9C4xLWhCrafGais7EnVMzHgu8RxqEkI3t5JR5wahu+ZL+2NQGmsQGBHK7fo9Jb3Y4uHDyURCFlkKEhOG
2QzsbtWr6ipkr2dO2oaoX76/6Yhk5MP+nbyAV/D3wIZgeHv4YANgTdH9g0b2OB+wd0WuBNc2/MyDQmsz8B6rcbCAQYc8AF5f
d6BXvr3oriRVRkKZv1guYU5Y9I/y3f2i9HTvOIeJvcJTZvnDyLOOdLR18lVG/Nm5eusmYYsd34SEag55kV+V4kZuWY4gtFdw
jNVVkckC3ky5C6zhu4IF0BGoYkh1dKmet38ZtuCp3AlmLQmhxDJGM+haHwIJ8L6MSpmgJR1u/hAauT0dC6Wk36GG8g8oaPFp
3Lfag1c5Bv6h4s6bT81/UlARXgGnBoP6oAK1xA3m0Cea+Iwndz+GQcNgTAZhqAa18Bd6KMD1huAAYFiqMNx9YhHmntcjOOpj
U8LdlMLCFjS7y+5WkLy23uv8faHOWR12bwXkCUt8AYg5cgo9fJJ8JIbjcl9yTZ25GsFbtNOeuPztVFV4CPyltdg9fNNNrQ/E
HlDvXrFh5viihRTZbFETPG/Vx+dW4U7ENiq/zt3GyDfXmjI0kmOCEmcO+o5AYADgOjnON9P69c+rwnc3WsUtG1ywZ55PozdC
04InQJm8m77VEY6dvw9zFdYtHH7HAMR7t4wbayGhkEWybrG+ajZutFdIqy+8lG55xqN20mVJwshTD/juRo3efdVzCh1M0E3G
KTm726m6RlCslSbovl7jBKH61fBqLVGaY++M4pqG7iLAicK4QyQu9qUeA6qc8tCkg8Bhupvpak2P5RVQumRb1igmovmnOjrh
S6mVhu9VYunHL+/T91L32j8Eb2l3+gpZgOSpFYewhgGbCeatOz7lk+mQ/VqeNNeXLPC32QIri1GW1aw6AX2mfdHPPtZ8fS0o
H58lz63yuJta1rRyWoj1TOAprHHgGaXmR7Cs/e2T+pvo08SNKDtXzPjVZil5Ey4oeF8Bke11YFX3lg5E49NejBUFbdSI9G26
A6FhJQVk8L3D654VPJBXopcnGuypOgcqGz9tmx5jIfX1nGb7JtzzGXUz2SixVf31A1Y0goq6PLsoUXcRwgrZ+KvMUWfMrZJf
TegXUTgw3I43nVhikyD5kep6kML7PnvOUSHOZHdPvjKotuN+wyk9RkjeU2lkE+aAoq4IEN1tsiRphS39CQchZrOaRgpkRcDd
WGzezxwgyK5bvvfdG1iNQMzSAX9rtOO73aJqfjpZ/0U+NQpEvLTN1XLqzqj6ZIS7jWYSrr88b0fSm+RjVC9dnq7Cdxv2TmNw
dA4NjedbE1f4chZxr1N9XUBAywhOtOLMNNJGagEVr4ThsAQolZg6HQa4n7TObqBIbz87gjUgq4IBGh1LJ3In+GEVYLHnkz/c
uzp5KzRFJb2giDnhUc55Sy8yybegH7rJ4BzIfrzH0fbPARHDoeiqxxqQh0nUT72a0Nrey9UK2jgDOcMqxpE2Z435MXzgsStP
955Zt0P1uzry1Rn/J9lFnL+XIiwV5vwqD5H8cZuUFSX65ZNhzrac68KoZFkSuqjRtsEHXuMFagwQ0lBlywOkQuDsbg4WmNs7
TJigvjJ46WSfH5Uy4NOS39OgNCuJcfIeGwp0QUujNIzFvnEgw3Yy2N81n42bmS8u5gtvRw/j8R3lTNpUHtrYkc5iec/NPn5v
FhixZv0sHQWEj9LF9vsimfUj81emMnYjk6g1MVbMzQKs8IFiWnXrtW4WNpeI0nPM3pZikoG5SdBMUJAbccZWFObGx70yehQK
ReHQBsPye5rJqlP9YqgPALslv+I1vdL2cRJpBbIEAiK2y898zXacK1MRPsAWQOPTOKu9YCVHrfC6OCCc90bOdnevocUgdWBg
hcv+Torojdh6qvmwTPmqfhlIwlwC+4qMAcNq5Nbr4fmQ1PhpplzeoD8JJS3CCOaft05hMs534ltXj9/jOsNy5g==
`;

function decodeBase64(value) {
  const normalized = String(value)
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error("Invalid Base64 character");
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

function getTrackCipher(trackId) {
  const idStr = String(trackId);
  let cipher = cipherCache.get(idStr);
  if (cipher) return cipher;

  const key = deriveTrackKey(idStr);
  cipher = new FastBlowfish(key);
  cipherCache.set(idStr, cipher);
  return cipher;
}

function decryptAlignedBuffer(cipher, buffer, startBlock, abortSignal = null) {
  const numBlocks = Math.floor(buffer.length / 2048);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  for (let i = 0; i < numBlocks; i++) {
    if (abortSignal && (i & 15) === 0 && abortSignal.aborted) {
      throw new DOMException("Client aborted the stream request", "AbortError");
    }
    const currentBlock = startBlock + i;
    if (currentBlock % 3 === 0) {
      cipher.decryptCBC(view, i * 2048);
    }
  }
}

function getSafeChunkSize(requestUrl, env) {
  const param = requestUrl.searchParams.get("chunk_size") ||
                requestUrl.searchParams.get("chunk") ||
                env?.STREAM_CHUNK_SIZE ||
                env?.CHUNK_SIZE;

  if (!param) return SAFE_DEFAULT_CHUNK;
  const clean = String(param).toLowerCase().trim();

  if (clean === "256k" || clean === "256kb") return 256 * 1024;
  if (clean === "512k" || clean === "512kb") return 512 * 1024;

  const parsed = parseInt(clean, 10);
  if (Number.isFinite(parsed) && parsed > 0) {
    const clamped = Math.max(64 * 1024, Math.min(SAFE_MAX_CHUNK, parsed));
    return Math.floor(clamped / 2048) * 2048;
  }

  return SAFE_DEFAULT_CHUNK;
}




async function getOrRenewSession(arl, env = null, forceRefresh = false) {
  const licenseTtlMinutes = Math.max(10, Math.min(55, Number(env?.LICENSE_TOKEN_TTL_MINUTES) || 45));
  if (!forceRefresh) {
    const cached = sessionCache.get(arl);
    const cachedAt = Number(cached?.createdAt || 0);
    const freshEnough = cachedAt > 0 && (Date.now() - cachedAt) < licenseTtlMinutes * 60 * 1000;


    if (cached?.sid && freshEnough) return cached;
  }

  const pingResp = await fetch(`${DEEZER_GW}?method=deezer.ping&input=3&api_version=1.0&api_token=`, {
    method: "POST",
    headers: { ...BROWSER_HEADERS, "Content-Type": "application/json", Cookie: `arl=${arl}` },
    body: "{}",
  });

  const pingResult = await readResponse(pingResp);
  const sid = pingResult.json?.results?.SESSION;
  if (!sid) throw new Error("Deezer ping failed: Could not establish gateway session.");

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
  const user = userResult.json?.results?.USER;
  const userId = toNumber(user?.USER_ID ?? user?.id);
  const apiToken = userResult.json?.results?.checkForm;
  const licenseToken = user?.OPTIONS?.license_token;
  const actualSid = userResult.json?.results?.SESSION_ID || sid;

  if (!apiToken || !licenseToken || !userId || userId === 0) {
    clearArlCache(arl);
    throw new Error("Invalid or expired DEEZER_ARL cookie (User ID is 0).");
  }

  const opts = user?.OPTIONS || {};
  const isLosslessFlagged = Boolean(opts.web_lossless || opts.lossless || opts.mobile_lossless);
  const isHqFlagged = Boolean(opts.web_hq || opts.mobile_hq);
  const isExplicitFree = (opts.web_lossless === false || opts.lossless === false) && (opts.web_hq === false);

  const canLossless = isLosslessFlagged ? true : (isExplicitFree ? false : undefined);
  const can320 = (isLosslessFlagged || isHqFlagged) ? true : (isExplicitFree ? false : undefined);

  const session = {
    arl,
    sid: actualSid,
    userId,
    apiToken,
    licenseToken,
    canLossless,
    can320,
    createdAt: Date.now(),
  };

  const ttlHours = Number(env?.SESSION_TTL_HOURS) || 2;
  sessionCache.set(arl, session, 1000 * 60 * 60 * ttlHours);
  return session;
}

async function getCandidatePools(env, allowedSlots = null) {
  const { arls } = getMemoizedConfig(env);
  if (!arls.length) {
    throw new Error("No DEEZER_ARL environment variables configured");
  }

  let configured = arls;
  if (allowedSlots && allowedSlots.size > 0) {
    configured = configured.filter(c => allowedSlots.has(c.slot));
    if (!configured.length) {
      throw new Error("No active ARL slots match the permissions of your API key.");
    }
  }

  const lossless = [];
  const lossy = [];
  const unverified = [];

  for (const c of configured) {
    const cached = sessionCache.get(c.value);
    if (cached) {
      const item = { slot: c.slot, name: c.name, arl: c.value, session: cached, trackTokens: null };
      if (cached.canLossless === true) {
        lossless.push(item);
      } else if (cached.canLossless === false && cached.can320 === false) {
        lossy.push(item);
      } else {
        lossless.push(item);
      }
    } else {
      unverified.push({ slot: c.slot, name: c.name, arl: c.value, session: null, trackTokens: null });
    }
  }

  if (!lossless.length && !lossy.length && unverified.length > 0) {
    const primary = unverified[0];
    try {
      const session = await getOrRenewSession(primary.arl, env);
      primary.session = session;
      if (session.canLossless === true) {
        lossless.push(primary);
      } else {
        lossy.push(primary);
      }
    } catch {
      clearArlCache(primary.arl);
    }
  }

  return { lossless, lossy, unverified, configured };
}

function pickAuxiliarySession(pools, env = null) {
  const spareLossless = String(env?.SPARE_LOSSLESS_ARL || "true").toLowerCase() !== "false";
  if (spareLossless && pools?.lossy?.length > 0) {
    return shuffleArray(pools.lossy)[0]?.session || null;
  }
  const allActive = [...(pools?.lossy || []), ...(pools?.lossless || [])];
  if (allActive.length > 0) {
    return shuffleArray(allActive)[0]?.session || null;
  }
  return null;
}




async function getPipeJwt(arl, forceRefresh = false, env = null) {
  if (!forceRefresh) {
    const cachedJwt = jwtCache.get(arl);
    if (cachedJwt) return cachedJwt;
  }

  const endpoints = [DEEZER_AUTH_ARL, DEEZER_AUTH_RENEW];
  for (const url of endpoints) {
    try {
      const resp = await fetchWithTimeout(url, {
        method: "POST",
        headers: {
          "User-Agent": BROWSER_HEADERS["User-Agent"],
          "Origin": "https://www.deezer.com",
          "Referer": "https://www.deezer.com/",
          Cookie: `arl=${arl}`,
        },
        body: "",
      }, env);

      const result = await readResponseLimited(resp);
      const jwt = result.json?.jwt;
      if (jwt) {
        jwtCache.set(arl, jwt, 1000 * 300);
        return jwt;
      }
    } catch (_) {}
  }

  jwtCache.delete(arl);
  return null;
}

const GQL_RECOMMENDATIONS_QUERY = `
query GetRecommendations($hotTracksLimit: Int = 50) {
  me {
    id
    recommendations {
      hotTracks(limit: $hotTracksLimit) {
        id
        title
        ISRC
        duration
        isExplicit
        popularity
        album {
          id
          displayTitle
          cover {
            id
            urls(pictureRequest: { width: 1000, height: 1000 })
          }
        }
        contributors(first: 10, roles: [MAIN, FEATURED]) {
          edges {
            roles
            node {
              ... on Artist {
                id
                name
              }
            }
          }
        }
      }
    }
  }
}
`;

function normalizeGraphqlRecommendationTrack(track) {
  if (!track) return null;

  const contributors = Array.isArray(track.contributors?.edges)
    ? track.contributors.edges.map(edge => edge?.node).filter(Boolean)
    : [];
  const mainArtist = contributors[0] || null;
  const coverUrls = track.album?.cover?.urls;
  const artworkSource = typeof coverUrls === "string"
    ? coverUrls
    : (coverUrls?.xl || coverUrls?.large || coverUrls?.medium || coverUrls?.small || null);

  return normalizeTrack({
    id: track.id,
    title: track.title,
    title_short: track.title,
    version: null,
    duration: track.duration,
    rank: track.popularity,
    explicit_lyrics: Boolean(track.isExplicit),
    isrc: track.ISRC,
    preview: null,
    bpm: null,
    gain: null,
    link: null,
    artist: mainArtist ? { id: mainArtist.id, name: mainArtist.name, link: null, picture: artworkSource } : null,
    album: track.album ? {
      id: track.album.id,
      title: track.album.displayTitle,
      link: null,
      release_date: null,
      cover: artworkSource,
      cover_xl: artworkSource,
    } : null,
  });
}

async function getPersonalizedRecommendations(env, allowedSlots = null, limit = 25, offset = 0, requestedUserId = null) {
  const pools = await getCandidatePools(env, allowedSlots);
  const session = pickAuxiliarySession(pools, env) || pools.lossless[0]?.session || pools.lossy[0]?.session;
  if (!session?.arl || !session?.userId) throw new Error("No authenticated Deezer session available for recommendations");

  const requested = requestedUserId === null || requestedUserId === undefined || String(requestedUserId).trim() === ""
    ? null
    : String(requestedUserId).trim();
  if (requested && requested.toLowerCase() !== "me" && requested !== String(session.userId)) {
    const error = new Error("Recommendations are only available for the authenticated Deezer account");
    error.status = 403;
    error.code = "RECOMMENDATIONS_USER_MISMATCH";
    throw error;
  }

  let jwt = await getPipeJwt(session.arl, false, env);
  if (!jwt) throw new Error("Could not obtain Deezer Pipe JWT for recommendations");

  const requestedCount = Math.min(50, Math.max(1, Number(limit) || 25));
  const requestedOffset = Math.max(0, Number(offset) || 0);
  const fetchCount = Math.min(50, requestedCount + requestedOffset);

  const execute = async (token) => fetchWithTimeout(DEEZER_PIPE_GQL, {
    method: "POST",
    headers: {
      ...BROWSER_HEADERS,
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
    },
    body: JSON.stringify({
      operationName: "GetRecommendations",
      variables: { hotTracksLimit: fetchCount },
      query: GQL_RECOMMENDATIONS_QUERY,
    }),
  }, env);

  let response = await execute(jwt);
  let result = await readResponseLimited(response);

  if (response.status === 401 || result.json?.errors?.some(e => /token|auth|jwt|signature/i.test(e?.message || ""))) {
    jwtCache.delete(session.arl);
    jwt = await getPipeJwt(session.arl, true, env);
    if (jwt) {
      response = await execute(jwt);
      result = await readResponseLimited(response);
    }
  }

  if (!result.ok || result.json?.errors?.length) {
    const message = result.json?.errors?.map(e => e?.message).filter(Boolean).join("; ") || `Deezer recommendations request failed (${result.status})`;
    const error = new Error(message);
    error.status = result.status >= 400 ? result.status : 502;
    error.code = "DEEZZER_RECOMMENDATIONS_UPSTREAM_ERROR";
    throw error;
  }

  const recommendations = result.json?.data?.me?.recommendations;
  const tracks = Array.isArray(recommendations?.hotTracks) ? recommendations.hotTracks : [];
  const page = tracks.slice(requestedOffset, requestedOffset + requestedCount).map(normalizeGraphqlRecommendationTrack).filter(Boolean);
  const hasMore = tracks.length > requestedOffset + page.length || tracks.length >= 50 && requestedOffset + page.length < 50;

  return {
    data: page,
    total: null,
    next: hasMore ? `?limit=${requestedCount}&offset=${requestedOffset + page.length}` : null,
    previous: requestedOffset > 0 ? `?limit=${requestedCount}&offset=${Math.max(0, requestedOffset - requestedCount)}` : null,
    user_id: String(session.userId),
    source: "deezer_pipe_graphql",
  };
}

const GQL_LYRICS_QUERY = `
query GetLyrics($trackId: String!) {
  track(trackId: $trackId) {
    id
    lyrics {
      id
      text
      ...SynchronizedWordByWordLines
      ...SynchronizedLines
      licence
      copyright
      writers
      __typename
    }
    __typename
  }
}
fragment SynchronizedWordByWordLines on Lyrics {
  id
  synchronizedWordByWordLines {
    start
    end
    words {
      start
      end
      word
      __typename
    }
    __typename
  }
  __typename
}
fragment SynchronizedLines on Lyrics {
  id
  synchronizedLines {
    lrcTimestamp
    line
    lineTranslated
    milliseconds
    duration
    __typename
  }
  __typename
}
`;

function normalizeLyricsLines(lines) {
  if (!Array.isArray(lines)) return null;
  return lines.map((line) => ({
    lrcTimestamp: line?.lrcTimestamp || null,
    line: line?.line ?? "",
    lineTranslated: line?.lineTranslated ?? null,
    milliseconds: Number.isFinite(Number(line?.milliseconds)) ? Number(line.milliseconds) : null,
    duration: Number.isFinite(Number(line?.duration)) ? Number(line.duration) : null,
  }));
}

function normalizeWordSync(lines) {
  if (!Array.isArray(lines)) return null;
  return lines.map((line) => ({
    start: Number.isFinite(Number(line?.start)) ? Number(line.start) : null,
    end: Number.isFinite(Number(line?.end)) ? Number(line.end) : null,
    words: Array.isArray(line?.words) ? line.words.map((word) => ({
      start: Number.isFinite(Number(word?.start)) ? Number(word.start) : null,
      end: Number.isFinite(Number(word?.end)) ? Number(word.end) : null,
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

async function getLyricsFromPipeGQL(arl, trackId, env = null) {
  let jwt = await getPipeJwt(arl, false, env);
  if (!jwt) return null;

  const execute = async (token) => {
    return await fetch(DEEZER_PIPE_GQL, {
      method: "POST",
      headers: {
        ...BROWSER_HEADERS,
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({
        operationName: "GetLyrics",
        variables: { trackId: String(trackId) },
        query: GQL_LYRICS_QUERY,
      }),
    });
  };

  try {
    let resp = await execute(jwt);
    let result = await readResponseLimited(resp);

    if (resp.status === 401 || result.json?.errors?.some(e => /token|auth|jwt|signature/i.test(e?.message || ""))) {
      jwtCache.delete(arl);
      jwt = await getPipeJwt(arl, true, env);
      if (jwt) {
        resp = await execute(jwt);
        result = await readResponseLimited(resp);
      }
    }

    const lyricsObj = result.json?.data?.track?.lyrics;
    if (!lyricsObj || (!lyricsObj.text && !lyricsObj.synchronizedLines?.length && !lyricsObj.synchronizedWordByWordLines?.length)) {
      return null;
    }

    const wordSync = normalizeWordSync(lyricsObj.synchronizedWordByWordLines);
    const lineSync = normalizeLyricsLines(lyricsObj.synchronizedLines);
    let lrc = null;

    if (wordSync?.length) {
      lrc = wordSyncToLrc(wordSync);
    } else if (lineSync?.length) {
      lrc = lineSync.map(l => `${l.lrcTimestamp || ""}${l.line || ""}`).join("\n");
    }

    return {
      source: "deezer_graphql",
      id: lyricsObj.id ?? null,
      syncType: wordSync?.length ? "WORD_BY_WORD" : (lineSync?.length ? "LINE_BY_LINE" : "UNSYNCED"),
      hasWordSync: Boolean(wordSync?.length),
      hasLineSync: Boolean(lineSync?.length),
      writers: lyricsObj.writers ?? null,
      copyright: lyricsObj.copyright ?? lyricsObj.licence ?? null,
      plain: lyricsObj.text ?? null,
      lrc,
      synchronizedLines: lineSync?.length ? lineSync : null,
      synchronizedWordByWordLines: wordSync?.length ? wordSync : null,
    };
  } catch {
    return null;
  }
}

async function getLyricsFromGwLight(session, trackId, env = null) {
  if (!session?.sid || !session?.apiToken) return null;
  try {
    const sngId = parseInt(trackId, 10) || trackId;
    const resp = await fetchWithTimeout(`${DEEZER_GW}?method=song.getLyrics&input=3&api_version=1.0&api_token=${session.apiToken}`, {
      method: "POST",
      headers: {
        ...BROWSER_HEADERS,
        "Content-Type": "application/json",
        Cookie: `sid=${session.sid}; arl=${session.arl}`,
      },
      body: JSON.stringify({ sng_id: sngId, SNG_ID: sngId }),
    }, env);

    const result = await readResponseLimited(resp);
    const lyricsData = result.json?.results;
    if (!lyricsData || (!lyricsData.LYRICS_TEXT && !lyricsData.LYRICS_SYNC_JSON)) return null;

    let syncJson = lyricsData.LYRICS_SYNC_JSON;
    if (typeof syncJson === "string") {
      try { syncJson = JSON.parse(syncJson); } catch {}
    }

    let lineSync = null;
    let lrc = null;
    let hasLineSync = false;

    if (Array.isArray(syncJson) && syncJson.length > 0) {
      hasLineSync = true;
      lineSync = syncJson.map(item => ({
        lrcTimestamp: item.lrc_timestamp || null,
        line: item.line ?? "",
        lineTranslated: null,
        milliseconds: toNumber(item.milliseconds),
        duration: toNumber(item.duration),
      }));
      lrc = lineSync.map(item => `${item.lrcTimestamp || ""}${item.line || ""}`).filter(Boolean).join("\n");
    }

    return {
      source: "deezer_gateway",
      id: lyricsData.LYRICS_ID ?? null,
      syncType: hasLineSync ? "LINE_BY_LINE" : "UNSYNCED",
      hasWordSync: false,
      hasLineSync,
      writers: lyricsData.LYRICS_WRITERS ?? null,
      copyright: lyricsData.LYRICS_COPYRIGHTS ?? null,
      plain: lyricsData.LYRICS_TEXT ?? null,
      lrc,
      synchronizedLines: lineSync,
      synchronizedWordByWordLines: null,
    };
  } catch {
    return null;
  }
}


async function getDeezerLyrics(sessionOrArl, trackId, env = null) {
  if (!trackId) return null;
  const songId = String(trackId);

  const mem = lyricsMemoryCache.get(songId);
  if (mem && mem.hasWordSync) return mem;

  const cacheKey = sharedCacheKey("lyrics", songId);
  const cached = await getSharedCache(env, cacheKey);
  if (cached?.hasWordSync) {
    lyricsMemoryCache.set(songId, cached, 1000 * 60 * 60);
    return cached;
  }

  let arl = typeof sessionOrArl === "string" ? sessionOrArl : sessionOrArl?.arl;
  let session = typeof sessionOrArl === "object" && sessionOrArl?.sid ? sessionOrArl : null;

  if (!arl) {
    const { arls } = getMemoizedConfig(env);
    if (arls.length) arl = arls[0].value;
  }
  if (arl && !session) {
    session = await getOrRenewSession(arl, env).catch(() => null);
  }

  let finalLyrics = null;


  if (session?.sid && session?.apiToken) {
    finalLyrics = await getLyricsFromGwLight(session, songId, env);
  }


  if ((!finalLyrics || !finalLyrics.hasWordSync) && arl) {
    const gqlLyrics = await getLyricsFromPipeGQL(arl, songId, env);
    if (gqlLyrics) {
      if (!finalLyrics) {
        finalLyrics = gqlLyrics;
      } else {
        finalLyrics = {
          ...finalLyrics,
          ...gqlLyrics,
          syncType: gqlLyrics.hasWordSync ? "WORD_BY_WORD" : (finalLyrics.hasLineSync ? "LINE_BY_LINE" : finalLyrics.syncType),
          hasWordSync: finalLyrics.hasWordSync || gqlLyrics.hasWordSync,
          hasLineSync: finalLyrics.hasLineSync || gqlLyrics.hasLineSync,
          synchronizedWordByWordLines: finalLyrics.synchronizedWordByWordLines || gqlLyrics.synchronizedWordByWordLines,
          lrc: gqlLyrics.hasWordSync ? gqlLyrics.lrc : (finalLyrics.lrc || gqlLyrics.lrc),
          plain: finalLyrics.plain || gqlLyrics.plain,
          synchronizedLines: finalLyrics.synchronizedLines || gqlLyrics.synchronizedLines,
        };
      }
    }
  }

  if (finalLyrics && (finalLyrics.plain || finalLyrics.lrc)) {
    lyricsMemoryCache.set(songId, finalLyrics, 1000 * 60 * 60 * 2);
    await putSharedCache(env, cacheKey, finalLyrics, 86400 * 30);
  }

  return finalLyrics;
}




async function getTrackTokensUncached(arl, session, trackId) {
  const sngId = parseInt(trackId, 10) || trackId;
  const listUrl = `${DEEZER_GW}?method=song.getListData&input=3&api_version=1.0&api_token=${session.apiToken}`;

  const response = await fetch(listUrl, {
    method: "POST",
    headers: { ...BROWSER_HEADERS, "Content-Type": "application/json", Cookie: `sid=${session.sid}; arl=${arl}` },
    body: JSON.stringify({ sng_ids: [sngId] }),
  });

  const result = await readResponse(response);
  let trackData = result.json?.results?.data?.[0];

  if (!trackData?.TRACK_TOKEN) {
    const singleUrl = `${DEEZER_GW}?method=song.getData&input=3&api_version=1.0&api_token=${session.apiToken}`;
    const singleResp = await fetch(singleUrl, {
      method: "POST",
      headers: { ...BROWSER_HEADERS, "Content-Type": "application/json", Cookie: `sid=${session.sid}; arl=${arl}` },
      body: JSON.stringify({ sng_id: sngId, SNG_ID: sngId }),
    });
    const singleResult = await readResponse(singleResp);
    if (singleResult.json?.results) trackData = singleResult.json.results;
  }

  if (trackData?.FALLBACK) trackData = { ...trackData, ...trackData.FALLBACK };
  return trackData;
}

async function getTrackTokens(arl, session, trackId) {
  const key = `${String(arl)}|${String(session?.sid || "")}|${String(trackId)}`;
  let pending = trackTokenInflight.get(key);
  if (pending) return pending;
  pending = getTrackTokensUncached(arl, session, trackId);
  trackTokenInflight.set(key, pending, 5000);
  pending.finally(() => trackTokenInflight.delete(key)).catch(() => {});
  return pending;
}

function getMediaTimeoutMs(env = null) {
  const value = Number(env?.MEDIA_RESOLUTION_TIMEOUT_MS);
  if (!Number.isFinite(value) || value <= 0) return 8000;
  return Math.max(2000, Math.min(20000, Math.floor(value)));
}

function getMediaRetryCount(env = null) {
  const value = Number(env?.MEDIA_REAUTH_RETRIES);
  if (!Number.isFinite(value) || value < 0) return 1;
  return Math.max(0, Math.min(3, Math.floor(value)));
}

function isMediaAuthFailure(error) {
  const status = Number(error?.status || 0);
  const code = String(error?.code || "").toUpperCase();
  const upstreamCode = String(error?.upstreamCode || "").toUpperCase();
  const message = String(error?.message || "").toLowerCase();
  if (code === "GEOLOCATION" || upstreamCode === "2002") return false;
  return (
    [400, 401, 403, 409, 422].includes(status) ||
    ["INVALID_TOKEN", "TOKEN_EXPIRED", "LICENSE", "RIGHTS", "AUTH"].includes(code) ||
    /license|token|unauthor|forbidden|rights|invalid.*session|expired/i.test(`${message} ${upstreamCode}`)
  );
}

async function resolveMediaStreamUncached(licenseToken, trackToken, targetFormat, env = null) {
  const payload = {
    license_token: licenseToken,
    media: [{ type: "FULL", formats: [{ cipher: "BF_CBC_STRIPE", format: targetFormat }] }],
    track_tokens: [trackToken],
  };

  const controller = new AbortController();
  const timeoutMs = getMediaTimeoutMs(env);
  const timer = setTimeout(() => controller.abort("media-resolution-timeout"), timeoutMs);

  try {
    let response;
    try {
      response = await fetch(DEEZER_MEDIA_API, {
        method: "POST",
        headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
        cache: "no-store",
      });
    } catch (fetchError) {
      const error = new Error(`Media resolution for ${targetFormat} network request failed`);
      error.code = fetchError?.name === "AbortError" ? "MEDIA_TIMEOUT" : "MEDIA_NETWORK";
      error.status = 504;
      error.cause = fetchError;
      throw error;
    }

    const result = await readResponse(response);
    const mediaItem = result.json?.data?.[0]?.media?.[0];
    if (mediaItem?.sources?.[0]?.url) {
      return {
        directCdnUrl: mediaItem.sources[0].url,
        format: mediaItem.format || targetFormat,
      };
    }

    const rawError = result.json?.data?.[0]?.errors?.[0] || result.json?.errors?.[0] || result.json || result.text;
    const upstreamCode = typeof rawError === "object" && rawError
      ? String(rawError.code ?? rawError.error_code ?? rawError.type ?? "")
      : "";
    const upstreamMessage = typeof rawError === "object" && rawError
      ? String(rawError.message ?? rawError.msg ?? rawError.error ?? "")
      : String(rawError || "");
    const error = new Error(`Media resolution for ${targetFormat} failed`);
    error.status = result.status;
    error.upstreamCode = upstreamCode || null;
    error.upstreamMessage = upstreamMessage || null;
    error.code = result.status === 401
      ? "INVALID_TOKEN"
      : result.status === 403
        ? "RIGHTS"
        : /2002|GEO|GEOLOCATION/i.test(`${upstreamCode} ${upstreamMessage}`)
          ? "GEOLOCATION"
          : /license|token|unauthor|forbidden|rights|expired|session/i.test(`${upstreamCode} ${upstreamMessage}`)
            ? "AUTH"
            : "MEDIA_EMPTY";
    error.details = typeof rawError === "object" ? JSON.stringify(rawError) : String(rawError || "empty media response");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveMediaStream(licenseToken, trackToken, targetFormat, env = null) {
  const key = `${String(licenseToken || "")}|${String(trackToken || "")}|${String(targetFormat || "")}`;
  let pending = mediaInflight.get(key);
  if (pending) return pending;
  pending = resolveMediaStreamUncached(licenseToken, trackToken, targetFormat, env);
  mediaInflight.set(key, pending, 5000);
  pending.finally(() => mediaInflight.delete(key)).catch(() => {});
  return pending;
}

async function refreshCandidateForMedia(candidate, trackId, env) {
  clearArlCache(candidate.arl);
  candidate.session = await getOrRenewSession(candidate.arl, env, true);
  candidate.trackTokens = await getTrackTokens(candidate.arl, candidate.session, trackId);
  if (!candidate.trackTokens?.TRACK_TOKEN) {
    throw new Error("Fresh Deezer track token was not returned after session renewal");
  }
  return candidate.trackTokens;
}

function getFormatLadder(requestedQuality, env = null) {
  const fallbackQuality = env?.DEFAULT_QUALITY?.trim() || "best";
  const q = String(requestedQuality || fallbackQuality).toLowerCase().trim();
  if (["flac", "lossless", "hifi"].includes(q)) return ["FLAC", "MP3_320", "MP3_128"];
  if (["320", "320k", "mp3_320", "hq"].includes(q)) return ["MP3_320", "MP3_128", "FLAC"];
  if (["128", "128k", "mp3_128", "standard"].includes(q)) return ["MP3_128", "MP3_320", "FLAC"];
  return ["FLAC", "MP3_320", "MP3_128"];
}

async function resolvePlaybackStreamOnly(trackId, rawQuality, env, allowedSlots = null) {
  const pools = await getCandidatePools(env, allowedSlots);
  const formatLadder = getFormatLadder(rawQuality, env);
  const isRandomStrategy = (env?.LOAD_BALANCING_STRATEGY || "random").toLowerCase().trim() !== "sequential";

  let selectedResult = null;
  let lastError = null;

  for (const targetFormat of formatLadder) {
    if (selectedResult) break;

    let targetCandidates = [];
    if (targetFormat === "FLAC" || targetFormat === "MP3_320") {
      if (!pools.lossless.length && !pools.unverified.length) continue;
      const pool = [...pools.lossless, ...pools.unverified];
      targetCandidates = isRandomStrategy ? shuffleArray(pool) : pool;
    } else {
      const lossyPart = isRandomStrategy ? shuffleArray(pools.lossy) : [...pools.lossy];
      const losslessPart = isRandomStrategy ? shuffleArray(pools.lossless) : [...pools.lossless];
      targetCandidates = [...lossyPart, ...losslessPart, ...pools.unverified];
    }

    for (const candidate of targetCandidates) {
      try {
        if (!candidate.session) {
          candidate.session = await getOrRenewSession(candidate.arl, env);
        }

        if (targetFormat === "FLAC" && candidate.session.canLossless === false) continue;
        if (targetFormat === "MP3_320" && candidate.session.can320 === false) continue;

        if (!candidate.trackTokens) {
          candidate.trackTokens = await getTrackTokens(candidate.arl, candidate.session, trackId);
          if (!candidate.trackTokens?.TRACK_TOKEN) {
            candidate.session = await getOrRenewSession(candidate.arl, env, true);
            candidate.trackTokens = await getTrackTokens(candidate.arl, candidate.session, trackId);
          }
        }

        let candidateTrackData = candidate.trackTokens;
        if (!candidateTrackData?.TRACK_TOKEN) continue;

        if (targetFormat === "FLAC" && candidateTrackData.FILESIZE_FLAC === "0") {
          continue;
        }

        let resolved;
        let mediaError = null;
        const retryCount = getMediaRetryCount(env);

        for (let mediaAttempt = 0; mediaAttempt <= retryCount; mediaAttempt++) {
          try {
            resolved = await resolveMediaStream(
              candidate.session.licenseToken,
              candidateTrackData?.TRACK_TOKEN,
              targetFormat,
              env,
            );
            mediaError = null;
            break;
          } catch (err) {
            mediaError = err;
            const canReauth = mediaAttempt < retryCount && isMediaAuthFailure(err);
            if (!canReauth) break;

            try {
              candidateTrackData = await refreshCandidateForMedia(candidate, trackId, env);
            } catch (refreshError) {
              mediaError = refreshError;
              break;
            }
          }
        }

        if (!resolved) throw mediaError || new Error(`Media resolution for ${targetFormat} failed`);

        const actualFormat = String(resolved.format || targetFormat).toUpperCase();
        const actualKey = actualFormat === "FLAC" ? "flac" : actualFormat === "MP3_320" ? "320" : "128";

        if (actualFormat === "FLAC") {
          candidate.session.canLossless = true;
          candidate.session.can320 = true;
        } else if (actualFormat === "MP3_320") {
          candidate.session.can320 = true;
        }

        selectedResult = {
          arl: candidate.arl,
          slot: candidate.slot,
          session: candidate.session,
          trackData: candidateTrackData,
          mediaResult: resolved,
          selectedProfile: QUALITY_MAP[actualKey] || QUALITY_MAP["128"],
          trackId: candidateTrackData.SNG_ID || trackId,
          pools,
        };
        break;
      } catch (err) {
        if (candidate.session) {
          if (targetFormat === "FLAC" && /rights|license|403|2002/i.test(err?.message || "")) {
            candidate.session.canLossless = false;
          } else if (targetFormat === "MP3_320" && /rights|license|403|2002/i.test(err?.message || "")) {
            candidate.session.can320 = false;
            candidate.session.canLossless = false;
          }
        }
        lastError = err;
      }
    }
  }

  if (!selectedResult) {
    throw lastError || new Error("All configured Deezer ARLs failed to resolve playback stream");
  }

  return selectedResult;
}




async function discoverTrack({ id, isrc, query, title, artist }, env = null, allowAlt = false, preferExplicit = true) {
  let cleanId = id ? String(id).trim() : "";
  let cleanIsrc = normalizeSharedIsrc(isrc);
  const cleanTitle = title ? String(title).trim() : "";
  const cleanArtist = artist ? String(artist).trim() : "";
  const cleanQuery = query ? String(query).trim() : "";

  const urlMatch = cleanId.match(/track\/(\d+)/i);
  if (urlMatch) cleanId = urlMatch[1];

  const isrcMatch = cleanId.match(/^isrc:([A-Z0-9]{12})$/i);
  if (isrcMatch) {
    cleanIsrc = isrcMatch[1].toUpperCase();
    cleanId = "";
  } else if (cleanId && !/^\d+$/.test(cleanId) && /^[A-Z0-9]{12}$/i.test(cleanId)) {
    cleanIsrc = cleanId.toUpperCase();
    cleanId = "";
  }

  const expTag = preferExplicit ? "exp" : "clean";
  const memoryKey = cleanId ? `id:${cleanId}:${expTag}` : cleanIsrc ? `isrc:${cleanIsrc}:${expTag}` : null;
  if (memoryKey) {
    const mem = trackMemoryCache.get(memoryKey);
    if (mem) return mem;
  }

  const cacheId = cleanId ? sharedCacheKey("track", `id:${cleanId}:${expTag}`) : cleanIsrc ? sharedCacheKey("track", `isrc:${cleanIsrc}:${expTag}`) : null;
  if (cacheId) {
    const cached = await getSharedCache(env, cacheId);
    if (cached?.id) {
      if (memoryKey) trackMemoryCache.set(memoryKey, cached, 1000 * 60 * 60);
      return cached;
    }
  }

  let found = null;

  if (cleanId && /^\d+$/.test(cleanId)) {
    const resp = await fetchWithTimeout(`https://api.deezer.com/track/${encodeURIComponent(cleanId)}`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    }, env);
    const result = await readResponseLimited(resp);
    if (result.json?.id) found = result.json;
  }

  if (!found && cleanIsrc) {
    const resp = await fetchWithTimeout(`https://api.deezer.com/track/isrc:${encodeURIComponent(cleanIsrc)}`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    }, env);
    const result = await readResponseLimited(resp);
    if (result.json?.id) found = result.json;
  }

  if (!found && (cleanTitle || cleanArtist || cleanQuery || (!cleanId.match(/^\d+$/) && cleanId))) {
    const queryInfo = normalizeSearchQuery(cleanQuery || cleanId, cleanTitle, cleanArtist);
    const searchKey = `${queryInfo.clean}:${expTag}:${allowAlt ? "1" : "0"}`;

    const cachedSearch = searchMemoryCache.get(searchKey);
    if (cachedSearch?.id) return cachedSearch;

    const kvSearch = await getSharedCache(env, sharedCacheKey("search", searchKey));
    if (kvSearch?.id) {
      searchMemoryCache.set(searchKey, kvSearch, 1000 * 60 * 60);
      return kvSearch;
    }

    const resp = await fetchWithTimeout(`https://api.deezer.com/search?q=${encodeURIComponent(queryInfo.clean)}&limit=10`, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
    }, env);
    const result = await readResponseLimited(resp);
    const tracks = result.json?.data || [];

    if (tracks.length > 0) {
      found = pickBestTrack(tracks, queryInfo, allowAlt, preferExplicit);
      if (found) {
        searchMemoryCache.set(searchKey, found, 1000 * 60 * 60);
        await putSharedCache(env, sharedCacheKey("search", searchKey), found, 86400);
      }
    }
  }

  if (found?.id) {
    if (memoryKey) trackMemoryCache.set(memoryKey, found, 1000 * 60 * 60);
    if (cacheId) await putSharedCache(env, cacheId, found);
    const foundIsrc = normalizeSharedIsrc(found.isrc || found.ISRC || cleanIsrc);
    if (foundIsrc) await putSharedCache(env, sharedCacheKey("track", `isrc:${foundIsrc}:${expTag}`), found);
    await putSharedCache(env, sharedCacheKey("track", `id:${found.id}:${expTag}`), found);
  }

  return found;
}




async function getCdnTotalSize(cdnUrl, signal) {
  try {
    const headResp = await fetch(cdnUrl, {
      method: "HEAD",
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] },
      signal,
    });
    if (headResp.ok && headResp.headers.has("Content-Length")) {
      const len = parseInt(headResp.headers.get("Content-Length"), 10);
      if (len > 0) return len;
    }
  } catch (_) {}

  try {
    const probeResp = await fetch(cdnUrl, {
      headers: { "User-Agent": BROWSER_HEADERS["User-Agent"], Range: "bytes=0-0" },
      signal,
    });
    const cr = probeResp.headers.get("Content-Range") || "";
    const totalMatch = cr.match(/\/(\d+)/);
    if (totalMatch) return parseInt(totalMatch[1], 10);
  } catch (_) {}

  return null;
}




function normalizeContributors(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw.filter(Boolean).map(item => typeof item === "object" ? { ...item, role: item.role || "artist" } : { role: "artist", name: String(item) });
  }
  if (typeof raw !== "object") return [];
  const result = [];
  for (const [role, names] of Object.entries(raw)) {
    if (Array.isArray(names)) {
      names.filter(Boolean).forEach(item => result.push(typeof item === "object" ? { role, ...item } : { role, name: String(item) }));
    } else if (names) {
      result.push({ role, name: String(names) });
    }
  }
  return result;
}

function buildRichMetadata(trackData, track, finalLyrics) {
  const rawContributors = firstValue(trackData?.SNG_CONTRIBUTORS, trackData?.CONTRIBUTORS, track?.contributors);
  const contributors = normalizeContributors(rawContributors);
  const contributorText = contributors.map(c => c?.name || c?.ART_NAME || c?.artist?.name).filter(Boolean).map(String);

  const writerValue = firstValue(
    trackData?.SNG_WRITERS,
    trackData?.WRITERS,
    trackData?.writers,
    track?.writers,
    finalLyrics?.writers,
    contributors.filter(c => /writer|songwriter|composer|lyricist|author/i.test(c?.role || "")).map(c => c.name)
  );

  return {
    contributors: contributors.length ? contributors : null,
    writers: Array.isArray(writerValue) ? writerValue : (writerValue ?? (contributorText.length ? contributorText : null)),
    copyright: firstValue(trackData?.COPYRIGHT, trackData?.SNG_COPYRIGHT, trackData?.COPYRIGHT_TEXT, trackData?.copyright, track?.copyright, finalLyrics?.copyright),
    label: firstValue(trackData?.LABEL_NAME, trackData?.LABEL, trackData?.label, trackData?.ALB_LABEL),
    distributor: firstValue(trackData?.DISTRIBUTOR, trackData?.DISTRIBUTOR_NAME, trackData?.distribution, track?.distributor),
    publisher: firstValue(trackData?.PUBLISHER, trackData?.PUBLISHER_NAME, trackData?.publishing, track?.publisher),
    authorsNotes: firstValue(trackData?.AUTHOR_NOTES, trackData?.AUTHORS_NOTES, trackData?.NOTES, track?.authorsNotes),
    rawCredits: rawContributors ?? null,
  };
}

function sanitizeSourceMetadata(value) {
  if (!value || typeof value !== "object") return null;
  const blocked = /(token|jwt|arl|password|secret|license|credential|cookie|authorization)/i;
  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (blocked.test(key) || typeof val === "function") continue;
    out[key] = val;
  }
  return out;
}




function clampInt(value, fallback, min, max) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

function catalogHeaders() {
  return { "User-Agent": BROWSER_HEADERS["User-Agent"], "Accept": "application/json", "Accept-Language": "en-US,en;q=0.9" };
}

async function publicApi(path, params = {}, env = null) {
  const url = new URL(`${PUBLIC_API_BASE}/${String(path).replace(/^\//, "")}`);
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
  const cacheEnabled = Boolean(env?.GENERAL_MUSIC_CACHE);
  const cacheTtl = Math.max(5, Math.min(3600, Number(env?.SEARCH_CACHE_TTL_SECONDS) || 30));
  const requestKey = url.toString();

  const memoryCached = catalogMemoryCache.get(requestKey);
  if (memoryCached !== undefined) return memoryCached;

  const cacheKey = cacheEnabled ? `catalog:${await sha256Hex(requestKey)}` : null;
  if (cacheEnabled) {
    const cached = await getSharedCache(env, cacheKey);
    if (cached?.__catalogCache === true && cached.value !== undefined) {
      catalogMemoryCache.set(requestKey, cached.value, cacheTtl * 1000);
      return cached.value;
    }
    const existing = catalogInflight.get(requestKey);
    if (existing) return existing;
  }

  const run = (async () => {
    const response = await fetchWithTimeout(requestKey, { headers: catalogHeaders() }, env);
    const result = await readResponseLimited(response);
    if (result.ok && !result.json?.error) {
      catalogMemoryCache.set(requestKey, result.json, cacheTtl * 1000);
      if (cacheEnabled) await putSharedCache(env, cacheKey, { __catalogCache: true, value: result.json }, cacheTtl);
      return result.json;
    }
    const error = new Error(result.json?.error?.message || `Deezer catalog request failed (${result.status})`);
    error.status = result.status >= 400 ? result.status : 502;
    error.code = result.json?.error?.code || "CATALOG_UPSTREAM_ERROR";
    throw error;
  })();

  if (cacheEnabled) {
    catalogInflight.set(requestKey, run, Math.max(1000, cacheTtl * 1000));
    run.finally(() => catalogInflight.delete(requestKey)).catch(() => {});
  }
  return run;
}

async function catalogResponse(data, status = 200, maxAge = 60, env = null, apiToken = null, clientIp = "unknown", userAgentHash = null) {
  const decoratedData = await decorateStreamUrls(data, apiToken, clientIp, env, userAgentHash);
  const serialized = serializeJson(decoratedData, env);
  const containsClientApiKey = serialized.includes('"api_key="') || serialized.includes("api_key=");
  return new Response(serialized, {
    status,
    headers: {
      ...getCorsHeaders(env),
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": containsClientApiKey ? "private, no-store" : `public, max-age=${Math.max(0, maxAge)}, stale-while-revalidate=300`,
      "X-Voria-API-Version": API_VERSION,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function apiErrorResponse(message, status = 400, details = null, env = null, requestId = null) {
  return catalogResponse({ error: message, status, ...(details ? { details } : {}), request_id: requestId || null, api: API_VERSION }, status, 0, env);
}
function publicError(code, status, env, requestId) {
  return jsonResponse({ error: code, status, request_id: requestId }, status, { "X-Request-ID": requestId, "Cache-Control": "no-store" }, env);
}

function normalizeLimitOffset(url, defaultLimit = 25, maxLimit = 100) {
  return {
    limit: clampInt(url.searchParams.get("limit"), defaultLimit, 1, maxLimit),
    offset: clampInt(url.searchParams.get("offset") ?? url.searchParams.get("index"), 0, 0, 1000000),
  };
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const step = 0x8000;
  for (let i = 0; i < view.length; i += step) {
    binary += String.fromCharCode(...view.subarray(i, Math.min(i + step, view.length)));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecodeBytes(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256Bytes(value) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

async function sha256Hex(value) {
  return bytesToHex(await sha256Bytes(String(value)));
}

async function getClientApiKeyHash(apiKey) {
  const key = String(apiKey || "").trim();
  if (!key || key === "public") return null;
  const cached = clientApiKeyHashCache.get(key);
  if (cached) return cached;
  const hash = await sha256Hex(key);
  clientApiKeyHashCache.set(key, hash, 15 * 60 * 1000);
  return hash;
}

async function randomTokenNonce(bytes = 32) {
  const size = Math.min(64, Math.max(16, Number.parseInt(bytes, 10) || 32));
  const randomBytes = crypto.getRandomValues(new Uint8Array(size));
  // Hash the CSPRNG output so the nonce is a fixed 256-bit SHA-256 value.
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", randomBytes)));
}

async function getStreamTokenSecret(env) {
  const configured = String(env?.STREAM_TOKEN_SECRET || "").trim();
  if (configured) return configured;
  const fallback = String(env?.ADMIN_API_KEY || env?.DEEZER_ARL || env?.DEEZER_ARL_1 || "").trim();
  if (fallback) return `fallback:${fallback}`;
  return null;
}

function getStreamTokenTtlSeconds(env) {
  const value = Number.parseInt(env?.STREAM_TOKEN_TTL_SECONDS, 10);
  if (!Number.isFinite(value)) return 600;
  return Math.min(3600, Math.max(30, value));
}

async function getStreamHmacKey(env) {
  const secret = await getStreamTokenSecret(env);
  if (!secret) return null;
  const cacheKey = `hmac:${secret}`;
  const cached = streamHmacKeyCache.get(cacheKey);
  if (cached) return cached;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  streamHmacKeyCache.set(cacheKey, key, 30 * 60 * 1000);
  return key;
}

async function signStreamToken(payload, env) {
  const key = await getStreamHmacKey(env);
  if (!key) return null;
  const encodedPayload = base64UrlEncodeBytes(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(encodedPayload));
  const nonce = String(payload?.nonce || "");
  return `${nonce}.${encodedPayload}.${base64UrlEncodeBytes(signature)}`;
}

async function verifyStreamToken(token, expected, env) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return { valid: false, reason: "malformed" };

    // The first component is deliberately opaque-looking: a fresh SHA-256
    // hash of cryptographically random bytes. Keep strict bounds on every part.
    if (!/^[a-f0-9]{64}$/.test(parts[0]) || parts[1].length > 4096 || parts[2].length > 256) {
      return { valid: false, reason: "malformed" };
    }

    const key = await getStreamHmacKey(env);
    if (!key) return { valid: false, reason: "not_configured" };

    const payloadBytes = base64UrlDecodeBytes(parts[1]);
    if (payloadBytes.byteLength > 3072) return { valid: false, reason: "malformed" };

    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    const version = Number(payload?.v);
    if (![1, 2].includes(version) || Number(payload?.exp) <= Math.floor(Date.now() / 1000)) {
      return { valid: false, reason: "expired" };
    }

    if (!payload?.nonce || !/^[a-f0-9]{64}$/.test(String(payload.nonce)) || String(payload.nonce) !== parts[0]) {
      return { valid: false, reason: "nonce_missing_or_invalid" };
    }

    if (expected?.trackId && String(payload.track) !== String(expected.trackId)) {
      return { valid: false, reason: "track_mismatch" };
    }

    if (expected?.apiKey) {
      const expectedHash = await getClientApiKeyHash(expected.apiKey);
      if (String(payload.key) !== String(expectedHash)) return { valid: false, reason: "api_key_mismatch" };
    }

    if (expected?.clientIp && String(payload.ip) !== String(expected.clientIp)) {
      return { valid: false, reason: "client_mismatch" };
    }

    if (expected?.userAgentHash && String(payload.ua || "") !== String(expected.userAgentHash)) {
      return { valid: false, reason: payload.ua ? "user_agent_mismatch" : "user_agent_missing" };
    }

    const signature = base64UrlDecodeBytes(parts[2]);
    if (signature.byteLength !== 32) return { valid: false, reason: "bad_signature" };

    const valid = await crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(parts[1]));
    return { valid, reason: valid ? null : "bad_signature", payload };
  } catch (_) {
    return { valid: false, reason: "invalid" };
  }
}

async function verifyStreamBootstrapToken(token, expected, env) {
  const check = await verifyStreamToken(token, expected, env);
  if (!check.valid) return check;
  if (Number(check.payload?.v) !== 2 || check.payload?.type !== "bootstrap") {
    return { valid: false, reason: "invalid_bootstrap_type" };
  }
  return check;
}

async function buildStreamToken(trackId, apiToken, clientIp, env, userAgentHash = null) {
  if (!apiToken || String(apiToken).trim() === "" || String(apiToken).trim() === "public") return null;
  const ttl = getStreamTokenTtlSeconds(env);
  const now = Math.floor(Date.now() / 1000);
  return signStreamToken({
    v: 2,
    type: "bootstrap",
    nonce: await randomTokenNonce(32),
    track: String(trackId),
    key: await getClientApiKeyHash(apiToken),
    ip: String(clientIp || "unknown"),
    ...(shouldBindStreamTokenToUserAgent(env) && userAgentHash ? { ua: String(userAgentHash) } : {}),
    iat: now,
    exp: now + ttl,
  }, env);
}

function getClientIp(request) {
  return String(request?.headers?.get("CF-Connecting-IP") || request?.headers?.get("X-Forwarded-For")?.split(",")[0] || "unknown").trim() || "unknown";
}

function shouldBindStreamTokenToUserAgent(env) {
  const value = String(env?.STREAM_TOKEN_BIND_USER_AGENT || "false").trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(value);
}

async function getClientUserAgent(request) {
  const ua = String(request?.headers?.get("User-Agent") || "unknown");
  const cached = clientUserAgentHashCache.get(ua);
  if (cached) return cached;
  const hash = await sha256Hex(ua);
  clientUserAgentHashCache.set(ua, hash, 15 * 60 * 1000);
  return hash;
}

const STREAM_SESSION_COOKIE = "__Host-VoriaStreamSession";

function getStreamSessionTtlSeconds(env) {
  const value = Number.parseInt(env?.STREAM_SESSION_TTL_SECONDS, 10);
  if (!Number.isFinite(value)) return 1800;
  return Math.min(7200, Math.max(60, value));
}

function getStreamSessionRefreshThresholdSeconds(env) {
  const ttl = getStreamSessionTtlSeconds(env);
  const value = Number.parseInt(env?.STREAM_SESSION_REFRESH_THRESHOLD_SECONDS, 10);
  if (!Number.isFinite(value)) return Math.min(300, Math.floor(ttl / 3));
  return Math.min(Math.max(30, Math.floor(ttl / 2)), Math.max(30, value));
}

const streamTokenReplayCache = new BoundedMap(2048);
const streamTokenConsumeInflight = new BoundedMap(2048);

async function consumeStreamBootstrapToken(token, env) {
  if (!token) return { allowed: false, reason: "missing" };
  const fingerprint = bytesToHex(await sha256Bytes(String(token)));
  const cacheKey = `stream-token-used:${fingerprint}`;
  if (streamTokenReplayCache.has(cacheKey)) return { allowed: false, reason: "replayed" };

  // Serialize concurrent attempts for the same token inside a Worker isolate.
  // This closes the check-then-mark race where two simultaneous requests could
  // both observe the token as unused before either one marked it.
  const inflightKey = `consume:${fingerprint}`;
  const existingInflight = streamTokenConsumeInflight.get(inflightKey);
  if (existingInflight) {
    await existingInflight;
    return { allowed: false, reason: "replayed" };
  }

  const consumePromise = (async () => {
    if (streamTokenReplayCache.has(cacheKey)) return { allowed: false, reason: "replayed" };

    // Optional strongly-consistent distributed replay guard. When a
    // STREAM_TOKEN_GUARD Durable Object binding is configured, token consumption
    // is serialized globally (sharded by token hash) and becomes atomic across
    // Worker isolates and locations.
    if (env?.STREAM_TOKEN_GUARD) {
      try {
        const shard = fingerprint.slice(0, 2);
        const stub = env.STREAM_TOKEN_GUARD.get(env.STREAM_TOKEN_GUARD.idFromName(`stream-token:${shard}`));
        const response = await stub.fetch("https://stream-token-guard/consume", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hash: fingerprint, ttl: Math.max(60, getStreamTokenTtlSeconds(env) + 30) }),
        });
        if (!response.ok) throw new Error(`STREAM_TOKEN_GUARD_${response.status}`);
        const result = await response.json();
        if (!result?.allowed) {
          streamTokenReplayCache.set(cacheKey, true, 60000);
          return { allowed: false, reason: "replayed" };
        }
      } catch (guardError) {
        const failClosed = String(env?.STREAM_TOKEN_GUARD_FAIL_CLOSED ?? "true").trim().toLowerCase();
        if (["1", "true", "yes", "on"].includes(failClosed)) {
          return { allowed: false, reason: "replay_guard_unavailable" };
        }
      }
    }

    // Optional distributed replay guard. KV is intentionally best-effort because
    // Cloudflare KV does not provide an atomic compare-and-set primitive.
    if (!env?.STREAM_TOKEN_GUARD && env?.GENERAL_MUSIC_CACHE) {
      try {
        const existing = await env.GENERAL_MUSIC_CACHE.get(`music:deezer:${cacheKey}`);
        if (existing) {
          streamTokenReplayCache.set(cacheKey, true, 60000);
          return { allowed: false, reason: "replayed" };
        }
        await env.GENERAL_MUSIC_CACHE.put(`music:deezer:${cacheKey}`, "1", { expirationTtl: Math.max(60, getStreamTokenTtlSeconds(env) + 30) });
      } catch (_) {
        // Keep the local guard active even when KV is unavailable.
      }
    }

    streamTokenReplayCache.set(cacheKey, true, Math.max(60000, (getStreamTokenTtlSeconds(env) + 30) * 1000));
    return { allowed: true };
  })();

  streamTokenConsumeInflight.set(inflightKey, consumePromise, 15000);
  try {
    return await consumePromise;
  } finally {
    streamTokenConsumeInflight.delete(inflightKey);
  }
}

function getCookie(request, name) {
  const header = request?.headers?.get("Cookie") || "";
  const parts = header.split(";");
  for (const part of parts) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    if (key === name) return part.slice(index + 1).trim();
  }
  return null;
}

async function buildStreamSession(trackId, apiToken, clientIp, env, userAgentHash = null) {
  if (!apiToken || String(apiToken).trim() === "" || String(apiToken).trim() === "public") return null;
  const now = Math.floor(Date.now() / 1000);
  return signStreamToken({
    v: 2,
    type: "session",
    nonce: await randomTokenNonce(32),
    track: String(trackId),
    key: await getClientApiKeyHash(apiToken),
    ip: String(clientIp || "unknown"),
    ...(shouldBindStreamTokenToUserAgent(env) && userAgentHash ? { ua: String(userAgentHash) } : {}),
    iat: now,
    exp: now + getStreamSessionTtlSeconds(env),
  }, env);
}

async function verifyStreamSession(sessionToken, expected, env) {
  try {
    const check = await verifyStreamToken(sessionToken, expected, env);
    if (!check.valid || check.payload?.v !== 2 || check.payload?.type !== "session") {
      return { valid: false, reason: check.reason || "invalid_session" };
    }
    return check;
  } catch (_) {
    return { valid: false, reason: "invalid_session" };
  }
}

function streamSessionCookie(token, env) {
  if (!token) return null;
  return `${STREAM_SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${getStreamSessionTtlSeconds(env)}; HttpOnly; Secure; SameSite=None`;
}

async function establishStreamSession(trackId, apiToken, clientIp, env, userAgentHash = null) {
  const token = await buildStreamSession(trackId, apiToken, clientIp, env, userAgentHash);
  return streamSessionCookie(token, env);
}

function authenticatedPlaybackRequiresBootstrap(env, authToken) {
  if (!authToken) return false;
  const value = String(env?.STREAM_REQUIRE_BOOTSTRAP ?? "true").trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(value);
}

async function maybeRefreshStreamSession(sessionCheck, trackId, apiToken, clientIp, env, userAgentHash = null) {
  if (!sessionCheck?.valid || !sessionCheck?.payload) return null;
  const remaining = Number(sessionCheck.payload.exp) - Math.floor(Date.now() / 1000);
  if (remaining > getStreamSessionRefreshThresholdSeconds(env)) return null;
  return establishStreamSession(trackId, apiToken, clientIp, env, userAgentHash);
}

async function appendStreamTokenToUrl(streamUrl, apiToken, clientIp, env, userAgentHash = null) {
  if (!streamUrl || !apiToken || String(apiToken).trim() === "" || String(apiToken).trim() === "public") return streamUrl;
  try {
    const url = new URL(streamUrl);
    const trackId = url.searchParams.get("id") || url.searchParams.get("track_id");
    if (!trackId) return streamUrl;

    // Bootstrap tokens are one-use credentials. Never coalesce or cache the
    // generated token: every emitted stream URL receives a fresh nonce.
    const token = await buildStreamToken(trackId, apiToken, clientIp, env, userAgentHash);
    if (token) url.searchParams.set("stream_token", token);
    return url.toString();
  } catch (_) {
    return streamUrl;
  }
}

async function decorateStreamUrls(value, apiToken, clientIp, env, userAgentHash = null) {
  if (!apiToken || String(apiToken).trim() === "" || String(apiToken).trim() === "public") return value;

  if (Array.isArray(value)) {
    return Promise.all(value.map(item => decorateStreamUrls(item, apiToken, clientIp, env, userAgentHash)));
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value);
    const out = Array.isArray(value) ? [] : {};
    await Promise.all(entries.map(async ([key, item]) => {
      if (key === "streamUrl" && typeof item === "string" && item.includes("/stream-track/")) {
        out[key] = await appendStreamTokenToUrl(item, apiToken, clientIp, env, userAgentHash);
      } else if (item && typeof item === "object") {
        out[key] = await decorateStreamUrls(item, apiToken, clientIp, env, userAgentHash);
      } else {
        out[key] = item;
      }
    }));
    return out;
  }

  return value;
}

function appendApiKeyToStreamUrl(streamUrl, apiToken = null) {
  if (!streamUrl || !apiToken || String(apiToken).trim() === "" || String(apiToken).trim() === "public") return streamUrl;
  try {
    const url = new URL(streamUrl);
    url.searchParams.set("api_key", String(apiToken).trim());
    return url.toString();
  } catch (_) {
    const separator = String(streamUrl).includes("?") ? "&" : "?";
    return `${streamUrl}${separator}api_key=${encodeURIComponent(String(apiToken).trim())}`;
  }
}

function buildTrackStreamUrl(origin, trackId, apiToken = null) {
  if (!origin || trackId === undefined || trackId === null || String(trackId).trim() === "") return null;
  const streamUrl = `${String(origin).replace(/\/$/, "")}/stream-track/?id=${encodeURIComponent(String(trackId))}`;
  return appendApiKeyToStreamUrl(streamUrl, apiToken);
}

function normalizeTrack(track, streamOrigin = null, apiToken = null) {
  if (!track) return null;
  const artwork = buildArtworkUrls(track.album?.cover_xl || track.album?.cover, "cover");
  const trackId = track.id ?? null;
  return {
    id: trackId,
    title: track.title ?? null,
    title_short: track.title_short ?? null,
    version: track.version ?? null,
    duration: toNumber(track.duration),
    rank: toNumber(track.rank),
    explicit: Boolean(track.explicit_lyrics),
    is_alt: isAltVersion(track),
    preview: track.preview ?? null,
    bpm: toNumber(track.bpm),
    gain: toNumber(track.gain),
    isrc: track.isrc ?? null,
    link: track.link ?? null,
    artist: track.artist ? { id: track.artist.id ?? null, name: track.artist.name ?? null, link: track.artist.link ?? null, artwork: buildArtworkUrls(track.artist?.picture_xl || track.artist?.picture, "artist") } : null,
    album: track.album ? { id: track.album.id ?? null, title: track.album.title ?? null, link: track.album.link ?? null, release_date: track.album.release_date ?? null, artwork } : null,
    artwork,
    streamUrl: buildTrackStreamUrl(streamOrigin, trackId, apiToken),
  };
}

function normalizeAlbum(album) {
  if (!album) return null;
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
    label: album.label ?? null,
    artwork: buildArtworkUrls(album.cover_xl || album.cover, "cover"),
    artist: album.artist ? { id: album.artist.id ?? null, name: album.artist.name ?? null, link: album.artist.link ?? null, artwork: buildArtworkUrls(album.artist.picture_xl || album.artist.picture, "artist") } : null,
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
    artwork: buildArtworkUrls(artist.picture_xl || artist.picture, "artist"),
  };
}

function normalizePlaylist(playlist) {
  if (!playlist) return null;
  return {
    id: playlist.id ?? null,
    title: playlist.title ?? null,
    description: playlist.description ?? null,
    nb_tracks: toNumber(playlist.nb_tracks),
    fans: toNumber(playlist.fans),
    duration: toNumber(playlist.duration),
    link: playlist.link ?? null,
    picture: buildArtworkUrls(playlist.picture_xl || playlist.picture, "cover"),
    creator: playlist.creator ? { id: playlist.creator.id ?? null, name: playlist.creator.name ?? null } : null,
  };
}

function normalizeCollection(result, normalizer) {
  const items = Array.isArray(result?.data) ? result.data.map(normalizer).filter(Boolean) : [];
  return { data: items, total: toNumber(result?.total), next: result?.next ?? null, previous: result?.prev ?? null };
}

function normalizeRadio(radio) {
  if (!radio) return null;
  return {
    id: radio.id ?? null,
    title: radio.title ?? null,
    description: radio.description ?? null,
    picture: buildArtworkUrls(radio.picture_xl || radio.picture || radio.cover_xl || radio.cover, "cover"),
    link: radio.link ?? null,
  };
}

function normalizeGenre(genre) {
  if (!genre) return null;
  return {
    id: genre.id ?? null,
    name: genre.name ?? null,
    picture: buildArtworkUrls(genre.picture_xl || genre.picture, "cover"),
  };
}

function envBoolean(env, name, fallback = false) {
  const raw = env?.[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  return ["1", "true", "yes", "on"].includes(String(raw).trim().toLowerCase());
}

function getInstanceName(env) {
  const value = String(env?.INSTANCE_NAME || "cfw-deezer-hifi-api").trim();
  return value.slice(0, 120) || "cfw-deezer-hifi-api";
}

function getInstanceNotes(env) {
  return String(env?.NOTES || "").trim().slice(0, 2000);
}

function buildRootStatus(env) {
  return {
    version: API_VERSION,
    github: GITHUB_REPOSITORY_URL,
    for_public_use: envBoolean(env, "PUBLIC_API", false),
    notes: getInstanceNotes(env),
    instance: getInstanceName(env),
    maintenance: envBoolean(env, "MAINTENANCE_MODE", false),
  };
}

function getRootSiteTitle(env) {
  const value = String(env?.TITLE || "cfw-deezer-hifi-api").trim();
  return value.slice(0, 200) || "cfw-deezer-hifi-api";
}

function getRootImageUrl(env) {
  const value = String(env?.IMG || "").trim().slice(0, 2048);
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.href;
  } catch {
    return null;
  }
}

function getRootTabImageUrl(env) {
  const value = String(env?.IMG_TB || "").trim().slice(0, 2048);
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.href;
  } catch {
    return null;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function rootJsonLine(key, value, trailing = true) {
  const comma = trailing ? "," : "";
  return `  <span class=\"json-key\">\"${escapeHtml(key)}\"</span>: <span class=\"json-value\">${escapeHtml(JSON.stringify(value))}</span>${comma}`;
}

function buildRootHtml(env) {
  const status = buildRootStatus(env);
  const title = getRootSiteTitle(env);
  const imageUrl = getRootImageUrl(env);
  const tabImageUrl = getRootTabImageUrl(env);
  const lines = [
    `  "version": ${JSON.stringify(status.version)},`,
    `  "github": ${JSON.stringify(status.github)},`,
    `  "for_public_use": ${JSON.stringify(status.for_public_use)},`,
    `  "notes": ${JSON.stringify(status.notes)},`,
    `  "instance": ${JSON.stringify(status.instance)},`,
    `  "maintenance": ${JSON.stringify(status.maintenance)}${imageUrl ? "," : ""}`,
  ].join("\n");
  const imageBlock = imageUrl ? `
  <details open>
    <summary>"img": {</summary>
    <span class="img-object img-value">"image": <img src="/_root-img" alt="${escapeHtml(title)}" referrerpolicy="no-referrer"></span>
    <span class="img-close">  }</span>
  </details>` : "";
  const favicon = tabImageUrl ? `<link rel="icon" href="/_root-tab-icon">` : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>${favicon}
<style>html,body{margin:0;padding:0;background:#fff;color:#111}body{font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}main{padding:8px 12px;box-sizing:border-box;width:100%}pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}details{margin:0}summary{cursor:pointer;white-space:pre-wrap;list-style-position:outside}.img-object{display:block;padding-left:24px}.img-value{white-space:normal}.img-value img{display:inline-block;vertical-align:middle;max-width:min(100%,640px);max-height:480px;width:auto;height:auto;object-fit:contain;margin:0 0 0 4px}.img-close{display:block;padding-left:24px}@media(prefers-color-scheme:dark){html,body{background:#111;color:#eee}}</style></head>
<body><main><pre>{
${lines}
${imageBlock}
}</pre></main></body></html>`;
}

async function rootAssetResponse(env, kind) {
  const source = kind === "tab" ? getRootTabImageUrl(env) : getRootImageUrl(env);
  if (!source) return new Response("Not configured", { status: 404, headers: { "Cache-Control": "no-store" } });
  try {
    const upstream = await fetch(source, { redirect: "follow", headers: { "Accept": "image/avif,image/webp,image/png,image/jpeg,image/gif,image/*;q=0.8" } });
    if (!upstream.ok) return new Response("Image unavailable", { status: 502, headers: { "Cache-Control": "no-store" } });
    const contentType = upstream.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().startsWith("image/")) return new Response("Configured URL is not an image", { status: 415, headers: { "Cache-Control": "no-store" } });
    const headers = { "Content-Type": contentType, "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400", "X-Content-Type-Options": "nosniff" };
    const length = upstream.headers.get("Content-Length");
    if (length) headers["Content-Length"] = length;
    return new Response(upstream.body, { status: 200, headers });
  } catch { return new Response("Image unavailable", { status: 502, headers: { "Cache-Control": "no-store" } }); }
}

function isMaintenanceMode(env) {
  return envBoolean(env, "MAINTENANCE_MODE", false);
}

async function handleCatalogRoute(requestUrl, env, segments, apiToken = null, clientIp = "unknown", userAgentHash = null) {
  const rootSegment = segments[0] || "";
  const subSegment = segments[1] || "";
  const actionSegment = segments[2] || "";
  const { limit, offset } = normalizeLimitOffset(requestUrl);
  const allowAlt = isAltAllowed(requestUrl, "", env, apiToken, clientIp);
  const preferExplicit = isExplicitPreferred(requestUrl, env, apiToken, clientIp);

  if (!rootSegment) {
    return catalogResponse(buildRootStatus(env), 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "info-api") {
    return catalogResponse({
      version: API_VERSION,
      provider: "deezer",
      name: "Deezer HiFi Turbo API & Streaming Gateway",
      cpuBudgetSafety: "bounded-chunk-processing",
      safeChunkSize: `${SAFE_DEFAULT_CHUNK / 1024}KB`,
      features: {
        structuredSearch: "/?s&title=BMO&artist=Ari Lennox",
        catalog: "/search, /track, /album, /artist, /playlist, /chart, /genre, /radio, /recommendations, /cover",
        loadBalancing: "50-Slot Pool with Multi-Key Role Permissions & 2.5s RPS Limiter",
        lyricsSource: "100% Native Deezer (Web Gateway song.getLyrics + Pipe GraphQL Word-by-Word)",
      },
      endpoints: [
        "/info", "/track", "/track/:id/stream", "/track/:id/lyrics",
        "/stream", "/stream-track", "/search", "/album", "/artist",
        "/playlist", "/lyrics", "/cover", "/recommendations", "/radio",
        "/chart", "/genre", "/ping"
      ],
    }, 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "info") {
    const id = subSegment || requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    const isrc = requestUrl.searchParams.get("isrc");
    if (!id && !isrc) return apiErrorResponse("Missing id or isrc parameter", 400, null, env);
    const track = await discoverTrack({ id, isrc }, env, allowAlt, preferExplicit);
    if (!track?.id) return apiErrorResponse("Track not found", 404, null, env);
    return catalogResponse({ version: API_VERSION, data: normalizeTrack(track, requestUrl.origin, apiToken) }, 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "search") {
    const isrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
    const title = requestUrl.searchParams.get("title") || requestUrl.searchParams.get("track");
    const artist = requestUrl.searchParams.get("artist");
    const q = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("s");

    let type = (subSegment || requestUrl.searchParams.get("type") || "").toLowerCase();
    if (!type) {
      if (requestUrl.searchParams.has("a")) type = "artist";
      else if (requestUrl.searchParams.has("al")) type = "album";
      else if (requestUrl.searchParams.has("p")) type = "playlist";
      else type = "track";
    }

    if (!q && !isrc && !title && !artist) return apiErrorResponse("Missing search query parameter", 400, null, env);

    const queryAllowsAlt = isAltAllowed(requestUrl, q || title, env, apiToken, clientIp);
    if (isrc) {
      const track = await discoverTrack({ isrc }, env, queryAllowsAlt, preferExplicit);
      const items = track ? [normalizeTrack(track, requestUrl.origin, apiToken)] : [];
      return catalogResponse({ version: API_VERSION, type: "track", query: isrc, data: items, total: items.length, next: null, previous: null }, 200, 30, env, apiToken, clientIp, userAgentHash);
    }

    const queryInfo = normalizeSearchQuery(q, title, artist);
    const searchPath = type === "track" ? "search" : `search/${type}`;
    const result = await publicApi(searchPath, { q: queryInfo.clean, limit, index: offset }, env, apiToken, clientIp);

    if (type === "track" && Array.isArray(result?.data) && !queryAllowsAlt) {
      const standard = result.data.filter(t => !isAltVersion(t));
      if (standard.length > 0) result.data = standard;
    }

    const normalizer = type === "track" ? (track) => normalizeTrack(track, requestUrl.origin, apiToken) : type === "album" ? normalizeAlbum : type === "artist" ? normalizeArtist : type === "playlist" ? normalizePlaylist : x => x;
    return catalogResponse({ version: API_VERSION, type, query: queryInfo.clean, alt_allowed: queryAllowsAlt, explicit_preferred: preferExplicit, ...normalizeCollection(result, normalizer) }, 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "album") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id parameter", 400, null, env);

    if (actionSegment === "tracks") {
      const tracks = await publicApi(`album/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponse({ version: API_VERSION, ...normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken)) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    const [album, tracks] = await Promise.all([
      publicApi(`album/${encodeURIComponent(id)}`, {}, env),
      publicApi(`album/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env),
    ]);

    const normalizedTracks = normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken));
    return catalogResponse({ version: API_VERSION, data: normalizeAlbum(album), tracks: normalizedTracks.data, pagination: { total: normalizedTracks.total, limit, offset } }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "artist") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id parameter", 400, null, env);

    if (actionSegment === "top") {
      const top = await publicApi(`artist/${encodeURIComponent(id)}/top`, { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponse({ version: API_VERSION, ...normalizeCollection(top, (track) => normalizeTrack(track, requestUrl.origin, apiToken)) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    if (actionSegment === "albums") {
      const albums = await publicApi(`artist/${encodeURIComponent(id)}/albums`, { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponse({ version: API_VERSION, ...normalizeCollection(albums, normalizeAlbum) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    const artist = await publicApi(`artist/${encodeURIComponent(id)}`, {}, env, apiToken, clientIp);
    return catalogResponse({ version: API_VERSION, artist: normalizeArtist(artist) }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "playlist") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id parameter", 400, null, env);

    if (actionSegment === "tracks" || actionSegment === "full") {
      const tracks = await publicApi(`playlist/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponse({ version: API_VERSION, playlist_id: id, ...normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken)) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    const [playlist, tracks] = await Promise.all([
      publicApi(`playlist/${encodeURIComponent(id)}`, {}, env),
      publicApi(`playlist/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env),
    ]);
    const normalizedTracks = normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken));
    return catalogResponse({ version: API_VERSION, data: normalizePlaylist(playlist), tracks: normalizedTracks.data, pagination: { total: normalizedTracks.total, limit, offset } }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "chart") {
    const type = subSegment || requestUrl.searchParams.get("type") || "tracks";
    const supported = new Set(["tracks", "albums", "artists", "playlists"]);
    if (!supported.has(type)) return apiErrorResponse("Unsupported chart type", 400, { supported: [...supported] }, env);
    const result = await publicApi(`chart/0/${encodeURIComponent(type)}`, { limit, index: offset }, env, apiToken, clientIp);
    const normalizer = type === "tracks" ? (track) => normalizeTrack(track, requestUrl.origin, apiToken) : type === "albums" ? normalizeAlbum : type === "artists" ? normalizeArtist : normalizePlaylist;
    return catalogResponse({ version: API_VERSION, type, ...normalizeCollection(result, normalizer) }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "genre") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) {
      const result = await publicApi("genre", { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponse({ version: API_VERSION, ...normalizeCollection(result, normalizeGenre) }, 200, 300, env, apiToken, clientIp, userAgentHash);
    }
    const [genre, radios] = await Promise.all([
      publicApi(`genre/${encodeURIComponent(id)}`, {}, env),
      publicApi(`genre/${encodeURIComponent(id)}/radios`, { limit, index: offset }, env).catch(() => null),
    ]);
    return catalogResponse({ version: API_VERSION, genre: normalizeGenre(genre), radios: radios ? normalizeCollection(radios, normalizeRadio) : null }, 200, 300, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "radio") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing radio id parameter", 400, null, env);
    const result = await publicApi(`radio/${encodeURIComponent(id)}`, {}, env, apiToken, clientIp);
    return catalogResponse({ version: API_VERSION, data: normalizeRadio(result) }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "recommendations") {
    if (envBoolean(env, "DISABLE_RECOMMENDATIONS", false)) {
      return apiErrorResponse("Recommendations are disabled on this instance", 404, { endpoint: "/recommendations" }, env);
    }
    if (subSegment || requestUrl.searchParams.has("id") || requestUrl.searchParams.has("user_id")) {
      return apiErrorResponse("Recommendations only supports the raw /recommendations route; id and user_id are not supported.", 400, {
        endpoint: "/recommendations",
        supported_parameters: ["limit", "offset", "index"],
      }, env);
    }

    const result = await getPersonalizedRecommendations(env, null, limit, offset, null);
    const streamData = Array.isArray(result.data)
      ? result.data.map(track => ({
          ...track,
          streamUrl: buildTrackStreamUrl(requestUrl.origin, track?.id, apiToken),
        }))
      : [];

    return catalogResponse({
      version: API_VERSION,
      type: "tracks",
      personalized: true,
      ...result,
      data: streamData,
    }, 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "cover") {
    const raw = subSegment || requestUrl.searchParams.get("url") || requestUrl.searchParams.get("hash") || requestUrl.searchParams.get("id");
    const type = requestUrl.searchParams.get("type") === "artist" ? "artist" : "cover";
    const artwork = buildArtworkUrls(raw, type);
    if (!artwork) return apiErrorResponse("Missing or invalid artwork hash/url", 400, null, env);
    return catalogResponse({ version: API_VERSION, type, data: artwork }, 200, 86400, env, apiToken, clientIp, userAgentHash);
  }

  return null;
}

function makeRequestId() {
  return crypto.randomUUID ? crypto.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
}
function safeRouteName(pathname) {
  return pathname.split("/").filter(Boolean).slice(0, 3).join("/") || "/";
}
function getPresentedApiToken(request, env) {
  const allowQueryKey = String(env?.ALLOW_QUERY_API_KEY || "false").toLowerCase() === "true";
  const url = new URL(request.url);
  if (allowQueryKey) {
    const q = url.searchParams.get("api_key")?.trim() || url.searchParams.get("key")?.trim();
    if (q) return q;
  }
  const h = request.headers.get("Authorization") || request.headers.get("X-API-Key") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return (m ? m[1] : h).trim();
}

const STREAM_TOKEN_SECURITY_NOTE = "Bootstrap stream tokens begin with a fresh 64-character SHA-256 hash of 256-bit cryptographically random bytes, followed by the signed payload and HMAC-SHA-256 signature. Every emitted bootstrap URL gets a new nonce; bootstrap credentials are never coalesced or cached. Authenticated playback entry points require the bootstrap token by default, and optional Durable Object coordination makes token consumption globally atomic. The random nonce is not a secret by itself and never replaces signature validation.";

const ENVIRONMENT_VARIABLES = {
  CORS_ALLOW_ORIGIN: "Allowed CORS origin; defaults to *.",
  PUBLIC_API: "Set true to disable API-key authentication for requests.",
  REQUIRE_API_KEY: "Set false to make API keys optional when API_KEY slots are configured.",
  ALLOW_QUERY_API_KEY: "Set true to accept api_key or key in the query string; Authorization/X-API-Key are always supported.",
  ADMIN_API_KEY: "Required for the /env diagnostics route.",
  DEEZER_ARL: "Primary Deezer ARL credential; equivalent to DEEZER_ARL_1.",
  DEEZER_ARL_1: "Primary Deezer ARL credential when DEEZER_ARL is not set.",
  DEEZER_ARL_2_50: "Additional Deezer ARL credentials. Each slot is independently tested and load-balanced.",
  API_KEY: "Primary client API key; equivalent to API_KEY_1.",
  API_KEY_1_50: "Client API keys mapped to ARL slots through KEY/KEY_1_50.",
  KEY: "Comma-separated ARL slot numbers allowed for API_KEY; equivalent to KEY_1.",
  KEY_1_50: "Comma-separated ARL slot numbers allowed for the matching API_KEY slot.",
  DEFAULT_QUALITY: "Default playback quality: best, flac/lossless/hifi, 320, or 128.",
  DEFAULT_ALLOW_ALT: "Set true to allow alternate/remix/live versions by default.",
  DEFAULT_EXPLICIT: "Default explicit preference; false prefers clean results.",
  LOAD_BALANCING_STRATEGY: "Set sequential to use configured ARLs in order; any other value uses randomized selection.",
  SESSION_TTL_HOURS: "In-memory Deezer session cache lifetime in hours; defaults to 2.",
  LICENSE_TOKEN_TTL_MINUTES: "Controls the freshness threshold used for Deezer license/session handling; clamped to 10-55 minutes.",
  MEDIA_RESOLUTION_TIMEOUT_MS: "Timeout for Deezer media URL resolution; clamped to 2000-20000 ms.",
  MEDIA_REAUTH_RETRIES: "Number of media-auth retry/reauth attempts; clamped to 0-3.",
  UPSTREAM_TIMEOUT_MS: "Timeout for catalog/auth/lyrics upstream requests; clamped to 1000-20000 ms.",
  STREAM_CDN_HOSTS: "Semicolon-separated HTTPS CDN host allowlist for /stream.",
  STREAM_CHUNK_SIZE: "Default decrypted audio chunk size; clamped to 64 KiB-512 KiB.",
  CHUNK_SIZE: "Fallback chunk-size setting when STREAM_CHUNK_SIZE is not set.",
  STREAM_CACHE_CONTROL: "Cache-Control header emitted by /stream; defaults to private, no-store.",
  STREAM_TOKEN_SECRET: "Secret used to sign temporary playback tokens; set independently in production.",
  STREAM_TOKEN_TTL_SECONDS: "Lifetime of the one-use bootstrap stream token; defaults to 600 seconds and is clamped to 30-3600.",
  STREAM_SESSION_TTL_SECONDS: "Idle lifetime of the signed playback session cookie; defaults to 1800 seconds and is clamped to 60-7200.",
  STREAM_SESSION_REFRESH_THRESHOLD_SECONDS: "Refresh threshold for active playback sessions; defaults to 300 seconds and is clamped to 30-3600.",
  STREAM_TOKEN_BIND_USER_AGENT: "Set true to additionally bind stream tokens and playback sessions to the caller User-Agent hash.",
  STREAM_REQUIRE_BOOTSTRAP: "Set true to require one-use bootstrap tokens for authenticated playback entry points.",
  STREAM_TOKEN_GUARD: "Optional Durable Object namespace used for globally atomic bootstrap-token replay protection.",
  STREAM_TOKEN_GUARD_FAIL_CLOSED: "Set true to reject bootstrap authorization if the configured Durable Object replay guard is unavailable.",
  GENERAL_MUSIC_CACHE: "Optional KV-style binding used for shared track/search/lyrics caching.",
  SEARCH_CACHE_TTL_SECONDS: "Shared public catalog/search cache lifetime in seconds; defaults to 30 and is clamped to 5-3600.",
  CACHE_TTL_DAYS: "Default shared-cache TTL when a cache write does not provide its own TTL; defaults to 30 days.",
  RATE_LIMITER: "Optional Cloudflare Rate Limiting binding used for distributed request limits.",
  RATE_LIMIT: "Fallback in-worker requests-per-second limit when RATE_LIMITER is not used.",
  RATE_LIMIT_FAIL_CLOSED: "Set true to reject requests if the distributed rate-limit binding fails.",
  SPARE_LOSSLESS_ARL: "Set false to avoid preferring a spare lossy session for auxiliary metadata/lyrics work.",
  PRETTY_JSON: "Set true to pretty-print JSON responses. Defaults to false for lower CPU use and smaller/faster responses.",
  INSTANCE_NAME: "Optional instance label shown at the root endpoint and in documentation. Defaults to cfw-deezer-hifi-api.",
  NOTES: "Optional instance-developer notes shown at the root endpoint and in documentation. Keep credentials and secrets out of this value.",
  TITLE: "Optional browser document title for the root status page; defaults to cfw-deezer-hifi-api.",
  IMG: "Optional HTTP(S) image URL displayed in the expanded root img dictionary. The Worker proxies it through /_root-img.",
  IMG_TB: "Optional HTTP(S) image URL used as the browser tab icon through /_root-tab-icon.",
  MAINTENANCE_MODE: "Set true to temporarily reject normal API/playback traffic with HTTP 503 while leaving the root status, /docs, and /env diagnostics available.",
  MAINTENANCE_MESSAGE: "Optional public maintenance message returned when MAINTENANCE_MODE=true. Defaults to Service temporarily unavailable for maintenance.",
  DISABLE_RECOMMENDATIONS: "Set true to disable /recommendations without disabling the rest of the catalog API.",
  DISABLE_LYRICS: "Set true to disable standalone lyrics routes and embedded lyrics resolution. This can reduce auxiliary Deezer requests and ARL usage."
};

function diagnosticEnv(env) {
  const secretPatterns = /(arl|api[_-]?key|token|secret|password|credential|cookie|license)/i;
  const names = Object.keys(env || {}).filter(k => !secretPatterns.test(k)).sort();
  return names.reduce((out, key) => {
    const v = env[key];
    if (typeof v === "string" && v.length < 200) out[key] = v;
    else if (v !== undefined && v !== null && typeof v !== "function") out[key] = `[${typeof v}]`;
    return out;
  }, {});
}
function buildDocs(requestUrl, env) {
  const origin = requestUrl.origin;
  const publicApi = String(env?.PUBLIC_API ?? "false").toLowerCase() === "true";
  const requireKey = String(env?.REQUIRE_API_KEY ?? "true").toLowerCase() !== "false";
  const allowQueryKey = String(env?.ALLOW_QUERY_API_KEY || "false").toLowerCase() === "true";
  const { arls, mappings } = getMemoizedConfig(env);

  const authentication = publicApi
    ? {
        mode: "public",
        requests_require_client_api_key: false,
        explanation: "PUBLIC_API=true makes normal API authentication bypassed. The /env diagnostics endpoint still requires ADMIN_API_KEY."
      }
    : mappings.size > 0
      ? {
          mode: "api_key",
          requests_require_client_api_key: true,
          explanation: "At least one API_KEY slot is configured, so a matching client API key is required even if REQUIRE_API_KEY=false.",
          accepted_headers: ["Authorization: Bearer <key>", "X-API-Key: <key>"],
          query_string_auth_enabled: allowQueryKey,
          query_string_parameters: allowQueryKey ? ["api_key", "key"] : [],
        }
      : {
          mode: requireKey ? "api_key_not_configured" : "open",
          requests_require_client_api_key: requireKey,
          explanation: requireKey
            ? "No API_KEY slots are configured and REQUIRE_API_KEY defaults to true, so normal requests are rejected until a client key is configured or REQUIRE_API_KEY=false."
            : "No client API keys are configured and REQUIRE_API_KEY=false, so normal API requests are open."
        };

  const envDocs = {
    CORS_ALLOW_ORIGIN: { type: "string", secret: false, default: "*", effect: "Sets Access-Control-Allow-Origin. Vary: Origin is also emitted." },
    PUBLIC_API: { type: "boolean string", secret: false, default: "false", effect: "When true, bypasses normal client API-key authentication." },
    REQUIRE_API_KEY: { type: "boolean string", secret: false, default: "true", effect: "When false and no API_KEY slots exist, normal requests are open. If API_KEY slots exist, matching keys are still required." },
    ALLOW_QUERY_API_KEY: { type: "boolean string", secret: false, default: "false", effect: "When true, also accepts api_key or key in the query string. Header authentication always remains available." },
    ADMIN_API_KEY: { type: "secret string", secret: true, required_for: ["/env"], default: "not set", effect: "Authorizes the protected /env diagnostics endpoint. It is never returned by /env." },
    DEEZER_ARL: { type: "secret string", secret: true, default: "not set", effect: "Primary Deezer ARL. This is slot 1 when present." },
    DEEZER_ARL_1: { type: "secret string", secret: true, default: "not set", effect: "Alternate name for slot 1 when DEEZER_ARL is absent." },
    DEEZER_ARL_2_50: { type: "secret string range", secret: true, default: "not set", effect: "Additional Deezer ARL slots. The Worker scans slots 2 through 50 and can load-balance among configured accounts." },
    API_KEY: { type: "secret string", secret: true, default: "not set", effect: "Primary client API key, equivalent to API_KEY_1." },
    API_KEY_1_50: { type: "secret string range", secret: true, default: "not set", effect: "Client API keys. A configured key enables API-key authentication and can be mapped to specific ARL slots." },
    KEY: { type: "string", secret: false, default: "all configured slots", effect: "Comma-separated ARL slot numbers permitted for API_KEY. Example value: 1,2,5. Equivalent to KEY_1." },
    KEY_1_50: { type: "string range", secret: false, default: "all configured slots", effect: "Comma-separated ARL slot numbers permitted for the corresponding API_KEY_N. Invalid slot numbers are ignored." },
    DEFAULT_QUALITY: { type: "string", secret: false, default: "best", allowed: ["best", "flac", "lossless", "hifi", "320", "mp3_320", "128", "mp3_128"], effect: "Default playback quality when a request does not provide quality or format. The resolver uses FLAC first for best/lossless/hifi and falls down the quality ladder when necessary." },
    DEFAULT_ALLOW_ALT: { type: "boolean string", secret: false, default: "false", effect: "Controls whether alternate, remix, live, or versioned tracks are allowed by default during discovery." },
    DEFAULT_EXPLICIT: { type: "boolean string", secret: false, default: "false", effect: "Controls the default explicit preference during track discovery." },
    LOAD_BALANCING_STRATEGY: { type: "string", secret: false, default: "random", allowed: ["random", "sequential"], effect: "sequential walks configured ARL slots in order; any other value selects randomized candidates." },
    SESSION_TTL_HOURS: { type: "number", secret: false, default: "2", effect: "How long the in-memory Deezer session cache may retain a session after creation. License freshness is separately controlled by LICENSE_TOKEN_TTL_MINUTES." },
    LICENSE_TOKEN_TTL_MINUTES: { type: "number", secret: false, default: "45", range: "10-55", effect: "Freshness threshold for reusing a Deezer session/license context before creating a fresh gateway session." },
    MEDIA_RESOLUTION_TIMEOUT_MS: { type: "number", secret: false, default: "configured fallback", range: "2000-20000", effect: "Timeout for resolving a Deezer media URL. Values are clamped to 2-20 seconds." },
    MEDIA_REAUTH_RETRIES: { type: "number", secret: false, default: "configured fallback", range: "0-3", effect: "How many media authentication retry/reauth attempts are allowed after an authorization failure." },
    UPSTREAM_TIMEOUT_MS: { type: "number", secret: false, default: "8000", range: "1000-20000", effect: "Timeout for catalog, authentication, lyrics, and other bounded upstream requests." },
    STREAM_CDN_HOSTS: { type: "semicolon-separated host patterns", secret: false, default: "*.dzcdn.net;media.deezer.com", effect: "Allowlist for HTTPS upstream hosts accepted by /stream. Wildcards only work as leading *.host patterns." },
    STREAM_CHUNK_SIZE: { type: "bytes or 256k/512k", secret: false, default: "worker safe default", range: "64 KiB-512 KiB", effect: "Default decrypted streaming chunk size. Larger chunks can improve throughput but increase per-request memory/CPU pressure." },
    CHUNK_SIZE: { type: "bytes or 256k/512k", secret: false, default: "worker safe default", range: "64 KiB-512 KiB", effect: "Fallback chunk-size setting used only when STREAM_CHUNK_SIZE is not set." },
    STREAM_TOKEN_SECRET: { type: "secret string", secret: true, default: "falls back to ADMIN_API_KEY or the primary Deezer ARL if unset", effect: "HMAC-SHA-256 signing secret for temporary client-bound playback tokens. Set this independently in production so changing client API keys or ARLs does not change the signing key." },
    STREAM_TOKEN_TTL_SECONDS: { type: "number", secret: false, default: "600", range: "30-3600", effect: "Lifetime of the initial generated stream_token. After successful authorization, the one-use bootstrap token is consumed and the Worker establishes a separate playback session cookie so chunked Range requests can continue after the URL token expires." },
    STREAM_SESSION_TTL_SECONDS: { type: "number", secret: false, default: "1800", range: "60-7200", effect: "Idle playback-session lifetime. Active playback can continue beyond this through session refreshes; inactive/stolen session cookies eventually expire." },
    STREAM_SESSION_REFRESH_THRESHOLD_SECONDS: { type: "number", secret: false, default: "300", range: "30-3600", effect: "When a valid playback session has this many seconds or less remaining, the Worker silently issues a fresh signed session cookie while serving the request." },
    STREAM_TOKEN_BIND_USER_AGENT: { type: "boolean string", secret: false, default: "false", effect: "When true, temporary stream tokens and playback sessions are additionally bound to a SHA-256 hash of the caller User-Agent. This increases copy resistance for same-IP replay but may reduce compatibility with clients that use different User-Agents for metadata and audio playback." },
    STREAM_REQUIRE_BOOTSTRAP: { type: "boolean string", secret: false, default: "true", effect: "When true, authenticated playback entry points require a valid one-use bootstrap stream_token. This prevents a copied api_key from being used to mint fresh playback sessions through /stream-track or /track/:id/stream. Public API mode remains intentionally open." },
    STREAM_TOKEN_GUARD: { type: "Durable Object namespace binding", secret: false, default: "not bound", effect: "When bound to StreamTokenGuard, bootstrap-token consumption is globally coordinated and atomically recorded using strongly consistent Durable Object storage. Tokens are sharded across 256 deterministic objects to avoid a single global bottleneck." },
    STREAM_TOKEN_GUARD_FAIL_CLOSED: { type: "boolean string", secret: false, default: "true", effect: "If the Durable Object replay guard is configured but unavailable, reject bootstrap authorization instead of falling back to a weaker replay guard." },
    STREAM_CACHE_CONTROL: { type: "string", secret: false, default: "private, no-store", effect: "Cache-Control header emitted by the decrypted /stream response." },
    TITLE: { type: "string", secret: false, default: "cfw-deezer-hifi-api", effect: "Browser document title for the root status page." },
    IMG: { type: "HTTP(S) URL", secret: false, default: "not set", effect: "Image URL displayed inside the expanded root img dictionary. The Worker proxies the configured image through a same-origin endpoint and validates its Content-Type." },
    IMG_TB: { type: "HTTP(S) URL", secret: false, default: "not set", effect: "Image URL used as the browser tab icon through a same-origin Worker proxy." },
    GENERAL_MUSIC_CACHE: { type: "KV namespace binding", secret: false, default: "not bound", effect: "Optional Cloudflare KV binding used for shared track/search/lyrics cache entries. The code checks this binding before reading or writing shared cache data." },
    SEARCH_CACHE_TTL_SECONDS: { type: "number", secret: false, default: "30", range: "5-3600", effect: "TTL for public Deezer catalog/search responses. Results are also kept in a small per-isolate memory cache for the same TTL, and identical concurrent misses are coalesced when shared caching is enabled." },
    CACHE_TTL_DAYS: { type: "number", secret: false, default: "30", effect: "Default expiration in days for shared KV cache writes that do not supply their own TTL." },
    RATE_LIMITER: { type: "Cloudflare Rate Limiting binding", secret: false, default: "not bound", effect: "Optional distributed rate limiter. When present and operational, its limit({key}) result takes precedence over the local fallback limiter." },
    RATE_LIMIT: { type: "number", secret: false, default: "disabled", effect: "Fallback local requests-per-second limit when RATE_LIMITER is unavailable or not configured. The local implementation uses a 2.5-second window." },
    RATE_LIMIT_FAIL_CLOSED: { type: "boolean string", secret: false, default: "false", effect: "When true, a RATE_LIMITER binding error rejects the request instead of falling back to the local limiter." },
    SPARE_LOSSLESS_ARL: { type: "boolean string", secret: false, default: "true", effect: "When true, auxiliary metadata/lyrics work prefers a lossy ARL as a spare so lossless-capable sessions remain available for playback." },
    PRETTY_JSON: { type: "boolean string", secret: false, default: "false", effect: "When false, JSON responses are compact to reduce CPU, bandwidth, and latency. Set true for human-readable JSON." },
    INSTANCE_NAME: { type: "string", secret: false, default: "cfw-deezer-hifi-api", effect: "Human-readable instance label shown by the root status endpoint and /docs." },
    NOTES: { type: "string", secret: false, default: "empty", effect: "Developer-supplied instance notes shown by the root status endpoint and /docs. Do not put secrets here." },
    MAINTENANCE_MODE: { type: "boolean string", secret: false, default: "false", effect: "When true, normal catalog/playback traffic returns HTTP 503. Root status, /docs, and protected /env remain available." },
    MAINTENANCE_MESSAGE: { type: "string", secret: false, default: "Service temporarily unavailable for maintenance.", effect: "Public message returned while MAINTENANCE_MODE=true." },
    DISABLE_RECOMMENDATIONS: { type: "boolean string", secret: false, default: "false", effect: "When true, /recommendations returns 404." },
    DISABLE_LYRICS: { type: "boolean string", secret: false, default: "false", effect: "When true, standalone lyrics routes are disabled and track metadata skips the auxiliary lyrics request." }
  };

  return {
    service: SERVICE_NAME,
    instance: getInstanceName(env),
    notes: getInstanceNotes(env),
    version: API_VERSION,
    github: GITHUB_REPOSITORY_URL,
    generated_for_origin: origin,
    documentation: {
      purpose: "Deezer HiFi catalog, metadata, lyrics, recommendation, and playback gateway running as a Cloudflare Worker.",
      architecture: "Clients call this Worker. Catalog/auth/lyrics work uses Deezer APIs and authenticated Deezer sessions. Playback resolves a Deezer media URL, then /stream fetches the HTTPS Deezer CDN object and performs the required Blowfish block decryption while streaming the result to the client.",
      lossless_profile: "Deezer HiFi is represented as FLAC, 16-bit, 44.1 kHz, with bitrateUncompressed=1411 kbps.",
      stream_security: "Authenticated generated stream URLs include the client api_key plus a short-lived HMAC-signed bootstrap stream_token whose first component is a fresh 256-bit SHA-256 nonce derived from cryptographically random bytes. The token has an explicit bootstrap type and is bound to the API-key identity, track id, and caller IP. Successful playback authorization consumes the short-lived bootstrap token and establishes a separate signed HttpOnly session cookie for chunked Range requests, so an expired URL token does not interrupt an already-authorized playback session. /stream does not act as an arbitrary URL proxy: upstream URLs must be HTTPS and match STREAM_CDN_HOSTS.",
      performance: "Production responses default to compact JSON. Hot-path HMAC keys, API-key hashes, User-Agent hashes, track-token requests, and media-resolution requests use short-lived in-memory caches or in-flight coalescing to reduce repeated crypto/upstream work. Bootstrap tokens are never cached or coalesced because each emitted token must remain one-use and unique.",
      caching: "Shared catalog/search/lyrics caching is optional through GENERAL_MUSIC_CACHE. Playback media URLs remain upstream-expiring data and are not treated as long-lived shared cache objects by this API."
    },
    root_status: {
      route: "/",
      behavior: "A bare GET or HEAD request with no query string returns a small credential-free instance status object before normal authentication/rate limiting.",
      fields: ["version", "github", "for_public_use", "notes"],
      notes_source: "NOTES",
      public_flag_source: "PUBLIC_API",
      cache_control: "public, max-age=30"
    },
    architecture: {
      request_pipeline: [
        "1. Handle OPTIONS/CORS and reject unsupported HTTP methods.",
        "2. Validate URL/query envelope limits and normalize the route path.",
        "3. Serve /docs and the bare root status before normal client authentication.",
        "4. Authenticate the client using PUBLIC_API, API_KEY slots, Authorization, X-API-Key, and optionally query-string api_key/key.",
        "5. Apply distributed RATE_LIMITER when configured, otherwise use the local limiter controlled by RATE_LIMIT.",
        "6. Enforce optional MAINTENANCE_MODE, feature-disable flags, and route-specific protections.",
        "7. Resolve catalog data, Deezer sessions, lyrics, recommendations, or playback according to the requested route.",
        "8. Normalize track/album/artist/playlist data and decorate authenticated streamUrl values with client identity plus a fresh bootstrap token.",
        "9. Return compact JSON by default or pretty JSON when PRETTY_JSON=true."
      ],
      playback_pipeline: [
        "Metadata produces /stream-track URLs rather than exposing the raw Deezer CDN URL to the client.",
        "Authenticated playback URLs carry api_key plus a unique one-use stream_token.",
        "The bootstrap token is bound to track id, API-key identity, caller IP, and optionally User-Agent.",
        "The token is atomically consumed when STREAM_TOKEN_GUARD is configured; otherwise the Worker uses same-isolate replay protection plus optional KV best-effort coordination.",
        "Successful bootstrap authorization creates a signed HttpOnly __Host-VoriaStreamSession cookie.",
        "Subsequent Range requests use the playback session and can silently refresh it near expiry.",
        "The Worker resolves/refreshes Deezer media authorization, validates the CDN URL against STREAM_CDN_HOSTS, fetches bounded upstream ranges, decrypts the media blocks, and returns standard HTTP audio responses."
      ],
      token_format: {
        bootstrap: "<64-char SHA-256 nonce>.<base64url payload>.<base64url HMAC-SHA-256 signature>",
        nonce: "32 cryptographically random bytes hashed with SHA-256 and rendered as 64 lowercase hexadecimal characters.",
        payload: "Contains token version/type, track id, API-key identity hash, caller IP, issue/expiry times, nonce, and optional User-Agent hash.",
        session: "A separate signed session credential stored in an HttpOnly __Host-VoriaStreamSession cookie; it is not placed in the stream URL.",
        replay: "Bootstrap tokens are intentionally never coalesced or cached because every generated bootstrap credential must remain unique and one-use."
      },
      performance_architecture: {
        crypto_caches: ["Stream HMAC CryptoKey", "client API-key SHA-256 hashes", "client User-Agent SHA-256 hashes"],
        inflight_coalescing: ["track-token/media-resolution work that is safe to share"],
        intentionally_not_coalesced: ["bootstrap stream-token generation/consumption"],
        response_optimization: "Compact JSON is the default; PRETTY_JSON is opt-in.",
        streaming: "Decrypted audio is processed in bounded chunks controlled by STREAM_CHUNK_SIZE/CHUNK_SIZE to limit memory and CPU pressure.",
        flac_note: "FLAC decryption is the expensive path. The service therefore separates media-resolution caching/coalescing from the actual per-request decryption stream."
      },
      feature_controls: {
        MAINTENANCE_MODE: "Emergency service-wide switch for normal catalog/playback traffic; root, docs, and protected env diagnostics remain available.",
        DISABLE_RECOMMENDATIONS: "Turns off personalized /recommendations without disabling the rest of the catalog API.",
        DISABLE_LYRICS: "Turns off standalone lyrics endpoints and embedded lyrics fetching to reduce auxiliary upstream work.",
        SPARE_LOSSLESS_ARL: "Lets auxiliary metadata/lyrics work prefer a spare lossy-capable ARL so lossless-capable playback accounts are preserved."
      },
      diagnostics: {
        "/ping": "Parallel ARL health/capability check with per-slot status.",
        "/routing": "Live routing, authentication, playback-security, timeout, route, and hardening configuration summary.",
        "/env": "Admin-only non-secret environment diagnostics. Secret-like names/values are filtered and never exposed.",
        "/docs": "Public machine-readable documentation generated from the current Worker origin and environment configuration.",
        "/": "Credential-free instance identity/status response."
      }
    },
    authentication,
    setup: {
      prerequisites: [
        "A Cloudflare account with Workers enabled.",
        "A current Node.js installation with npm or another package manager capable of running Wrangler.",
        "This Worker source saved as worker.js, or deployed using the existing project entry point.",
        "At least one working Deezer ARL stored as a secret. Multiple ARLs are optional and enable account pooling/load balancing.",
        "If private client authentication is desired, at least one API_KEY slot should be configured.",
        "For maximum stream-token replay resistance, optionally bind STREAM_TOKEN_GUARD to the exported StreamTokenGuard Durable Object class using a SQLite-backed Durable Object namespace."
      ],
      minimal_local_files: {
        "worker.js": "The Worker source.",
        ".dev.vars": "Local-only secrets such as DEEZER_ARL and API_KEY. Do not commit this file."
      },
      install: "npx wrangler --version",
      local_run: "npx wrangler dev",
      local_run_with_environment: "npx wrangler dev --env staging",
      deploy: "npx wrangler deploy",
      deploy_with_environment: "npx wrangler deploy --env staging",
      secret_commands: [
        "npx wrangler secret put DEEZER_ARL",
        "npx wrangler secret put API_KEY",
        "npx wrangler secret put ADMIN_API_KEY"
      ],
      important_secret_rule: "Use Cloudflare Secrets for ARLs, API keys, and admin credentials. Do not put those values in wrangler vars or commit .dev.vars/.env files.",
      durable_object_guard: {
        binding: "STREAM_TOKEN_GUARD",
        class: "StreamTokenGuard",
        purpose: "Strongly consistent one-use bootstrap-token replay prevention.",
        recommended_backend: "SQLite-backed Durable Object",
        note: "The Worker shards token hashes across 256 deterministic Durable Object IDs, so replay coordination is not forced through one global object."
      }
    },
    quick_start: {
      private_api: [
        "Save the Worker as worker.js.",
        "Set DEEZER_ARL as a Worker secret.",
        "Set API_KEY as a Worker secret.",
        "Deploy with npx wrangler deploy.",
        "Call /ping with Authorization: Bearer <the API_KEY value> to verify the configured ARL."
      ],
      public_api: [
        "Save the Worker as worker.js.",
        "Set DEEZER_ARL as a Worker secret.",
        "Set PUBLIC_API=true as a non-secret Worker variable.",
        "Deploy with npx wrangler deploy.",
        "Call /ping without a client API key to verify the configured ARL."
      ],
      open_without_public_api_flag: [
        "Leave PUBLIC_API=false or unset.",
        "Do not configure API_KEY slots.",
        "Set REQUIRE_API_KEY=false.",
        "Deploy and call the API without a client key."
      ]
    },
    examples: {
      docs: `${origin}/docs`,
      info: `${origin}/info?id=3135556`,
      search_tracks: `${origin}/search?q=Starboy%20The%20Weeknd&type=track`,
      search_by_isrc: `${origin}/search?isrc=USUG11600920`,
      album_tracks: `${origin}/album/123456/tracks`,
      artist_top: `${origin}/artist/123456/top`,
      playlist_tracks: `${origin}/playlist/123456/tracks`,
      chart_tracks: `${origin}/chart/tracks`,
      recommendations: `${origin}/recommendations?limit=25&offset=0`,
      lyrics: `${origin}/lyrics?id=3135556`,
      playable_track: `${origin}/stream-track/?id=3135556`,
      track_stream_redirect: `${origin}/track/3135556/stream?quality=flac`,
      api_key_header: "Authorization: Bearer <configured API_KEY>",
      alternate_api_key_header: "X-API-Key: <configured API_KEY>"
    },
    endpoints: {
      "/docs": "This documentation. Public and available regardless of normal client API-key mode.",
      "/": "Resolve a track from id, ISRC, or search terms and return rich metadata plus a playable Worker streamUrl. Common parameters: id, isrc/i, q/query/s, title/track/song, artist, quality/format, stream=1, json, lyrics, nolyrics, alt, explicit.",
      "/info": "Track metadata lookup by id or ISRC. Returns normalized track data with streamUrl.",
      "/search": "Search tracks, albums, artists, or playlists. Use type=track|album|artist|playlist, or the corresponding path /search/<type>. Track results include streamUrl.",
      "/track/:id": "Track metadata and playback resolution. /track/:id/stream returns a 302 to the Worker /stream URL; /track/:id/lyrics returns lyrics.",
      "/stream-track/": "Resolve a numeric Deezer track id to a decrypted Worker stream response. Accepts id and optional quality/format.",
      "/stream": "Decryption proxy for a resolved HTTPS Deezer CDN URL. Requires id, url, and format. Only hosts allowed by STREAM_CDN_HOSTS are accepted.",
      "/album/:id": "Album metadata plus normalized album tracks. Nested tracks include streamUrl.",
      "/album/:id/tracks": "Paginated album track listing. Tracks include streamUrl.",
      "/artist/:id": "Artist metadata.",
      "/artist/:id/top": "Paginated artist top-track listing. Tracks include streamUrl.",
      "/artist/:id/albums": "Paginated artist album listing.",
      "/playlist/:id": "Playlist metadata plus normalized playlist tracks. Nested tracks include streamUrl.",
      "/playlist/:id/tracks": "Paginated playlist track listing. Tracks include streamUrl.",
      "/playlist/:id/full": "Alias for playlist track listing.",
      "/chart/<tracks|albums|artists|playlists>": "Paginated Deezer chart data. Chart tracks include streamUrl.",
      "/genre": "Paginated genre listing.",
      "/genre/:id": "Genre metadata and its radio list when available.",
      "/genre/:id/radios": "Supported by the underlying Deezer catalog route through the genre handler.",
      "/radio/:id": "Radio metadata lookup.",
      "/recommendations": "Personalized Deezer recommendations using the authenticated Deezer account behind the Worker. Supports limit, offset, and index. This API intentionally does not support id or user_id routing. Recommendation tracks include streamUrl.",
      "/lyrics": "Lyrics lookup for a track id. The Worker uses native Deezer lyrics sources and can return word-level data when Deezer provides it.",
      "/cover": "Build normalized artwork URLs from a Deezer artwork hash or supported artwork URL. type=artist selects artist artwork handling.",
      "/ping": "Tests configured Deezer ARL slots and reports active/failed state and detected quality capability. Useful immediately after deployment.",
      "/routing": "Authenticated routing, authentication, stream security, timeout, and hardening diagnostics.",
      "/env": "Admin-only environment diagnostics. Values matching secret-like names are intentionally hidden. Requires ADMIN_API_KEY."
    },
    playback: {
      quality_parameter: "quality or format",
      quality_values: {
        best: "Prefer the best available configured quality, following the FLAC -> MP3_320 -> MP3_128 ladder.",
        flac: "Request lossless FLAC first, then fall back if the selected account cannot provide it.",
        lossless: "Alias for FLAC-first lossless playback.",
        hifi: "Alias for FLAC-first lossless playback.",
        "320": "Request MP3 320 kbps.",
        "128": "Request MP3 128 kbps."
      },
      response_metadata: {
        flac: "format=FLAC, sampleRate=44100, bitDepth=16, bitrateUncompressed=1411, lossless=true",
        mp3_320: "format=MP3, bitrate=320",
        mp3_128: "format=MP3, bitrate=128"
      },
      stream_flow: [
        "Resolve track metadata and Deezer media authorization.",
        "Obtain an expiring HTTPS Deezer CDN URL.",
        "Return or construct a Worker /stream URL containing the resolved CDN URL.",
        "The /stream handler validates the CDN hostname and HTTPS scheme.",
        "The Worker fetches the upstream media in bounded ranges and decrypts the required FLAC/MP3 blocks before returning audio bytes."
      ],
      performance: "FLAC decryption is substantially more CPU-intensive than the MP3 path. STREAM_CHUNK_SIZE can be tuned within the enforced 64-512 KiB range; start with the default and increase only when throughput needs it."
    },
    multi_account: {
      slots: "Up to 50 Deezer ARL slots are scanned: DEEZER_ARL/DEEZER_ARL_1 through DEEZER_ARL_50.",
      mapping: "API_KEY_N is mapped to ARL slots using KEY_N. If KEY_N is omitted, that API key can use all configured ARL slots.",
      load_balancing: "LOAD_BALANCING_STRATEGY=sequential walks slots deterministically. Any other value uses randomized candidate selection.",
      capability: "Each ARL is checked for lossless and MP3 capability. Playback prefers capable sessions and can fall down the quality ladder when a higher-quality path is unavailable."
    },
    environment_variables: envDocs,
    bindings: {
      GENERAL_MUSIC_CACHE: "Create a Cloudflare KV namespace and bind it to the Worker under exactly the name GENERAL_MUSIC_CACHE if shared catalog/search/lyrics caching is desired.",
      RATE_LIMITER: "Bind a Cloudflare Rate Limiting binding under exactly the name RATE_LIMITER if distributed rate limiting is desired. The Worker calls its limit({ key }) method.",
      secrets: ["DEEZER_ARL", "DEEZER_ARL_1..50", "API_KEY", "API_KEY_1..50", "ADMIN_API_KEY", "STREAM_TOKEN_SECRET"]
    },
    security: {
      secrets: "ARLs, client API keys, and ADMIN_API_KEY are credentials and should be stored as Cloudflare Secrets, not plaintext vars.",
      stream_proxy: "The /stream route is not an arbitrary fetch proxy. It requires HTTPS and an allowlisted Deezer CDN hostname.",
      query_keys: "Query-string API keys are disabled by default because URLs can be logged or cached. Enable ALLOW_QUERY_API_KEY only when a client cannot send headers.",
      admin: "/env is protected separately with ADMIN_API_KEY even when PUBLIC_API=true.",
      cors: "CORS is controlled by CORS_ALLOW_ORIGIN and defaults to *."
    },
    troubleshooting: {
      ping_fails: "Check DEEZER_ARL secrets first. Run /ping and inspect each configured slot's status and tier.",
      unauthorized: "If API keys are configured, send Authorization: Bearer <API_KEY> or X-API-Key. If no keys are configured, set PUBLIC_API=true or REQUIRE_API_KEY=false according to the desired deployment mode.",
      env_returns_403: "Supply ADMIN_API_KEY using Authorization: Bearer <ADMIN_API_KEY> or X-API-Key. /env never exposes secret values.",
      flac_falls_back: "The selected ARL may not have lossless capability, the Deezer media authorization may have expired, or the FLAC media URL request may have failed. /ping shows the detected account tier.",
      stream_rejected: "The /stream URL must use HTTPS and its hostname must match STREAM_CDN_HOSTS. The default allowlist is *.dzcdn.net and media.deezer.com.",
      stream_api_key: "When a request is authenticated with an API key, generated streamUrl values and stream redirects carry that same key as api_key so the returned URL can be opened directly. A short-lived stream_token is also attached and bound to that key, the track, and the caller IP. After successful token validation, the Worker consumes the bootstrap token and sets an HttpOnly signed playback session cookie so subsequent Range requests do not depend on the URL token remaining unexpired. Playback routes accept these generated query parameters even when ALLOW_QUERY_API_KEY=false. Public API requests do not append client credentials.",
      stream_token: "Generated authenticated stream URLs contain api_key for client/ARL identity plus stream_token for temporary bootstrap authorization. stream_token expires according to STREAM_TOKEN_TTL_SECONDS, is bound to the authenticated API key, track id, caller IP, and optionally the caller User-Agent when STREAM_TOKEN_BIND_USER_AGENT is enabled, and is consumed after successful authorization. The Worker then establishes an HttpOnly signed playback session cookie with an idle TTL controlled by STREAM_SESSION_TTL_SECONDS; active Range playback refreshes it near expiry. Copying only the URL to a different network/client normally causes a client-binding rejection, and replaying an already-consumed bootstrap token is rejected. The session cookie is never placed in the stream URL.",
      stream_cache_security: "Catalog responses containing client API keys are marked private, no-store so one client's stream URL cannot be publicly cached and returned to another client.",
      slow_catalog: "Increase UPSTREAM_TIMEOUT_MS only when the upstream path genuinely needs more time. Shared catalog/search/lyrics caching can be enabled with GENERAL_MUSIC_CACHE.",
      slow_flac: "FLAC decryption is CPU-heavy. Keep STREAM_CHUNK_SIZE within the enforced range and avoid unnecessarily large concurrent playback workloads on small Worker plans.",
      rate_limited: "Check RATE_LIMITER first. If no distributed binding is present, RATE_LIMIT controls the local fallback limiter. RATE_LIMIT_FAIL_CLOSED controls behavior when the distributed binding errors."
    },
    cloudflare_notes: {
      env_vars: "Cloudflare Worker vars are runtime bindings available through the env parameter. Sensitive values should be Secrets rather than plaintext vars.",
      local_secrets: "For local development, use .dev.vars or .env, not both. Do not commit either file when they contain secrets.",
      environments: "Wrangler environments are separate Worker configurations. Bindings such as vars, KV namespaces, and secrets must be configured for each environment rather than assumed to inherit.",
      config_recommendation: "Use wrangler.jsonc as the project configuration source of truth for new Worker projects. Store STREAM_TOKEN_SECRET as a Worker Secret in production; if it is omitted, the Worker falls back to ADMIN_API_KEY or the primary Deezer ARL."
    }
  };
}

function routingInfo(env) {
  return {
    service: SERVICE_NAME,
    version: API_VERSION,
    authentication: String(env?.PUBLIC_API ?? "false").toLowerCase() === "true"
      ? { mode: "public", public_api: true, api_key_required: false }
      : { mode: String(env?.REQUIRE_API_KEY ?? "true").toLowerCase() !== "false" ? "required" : "optional", public_api: false, api_key_required: String(env?.REQUIRE_API_KEY ?? "true").toLowerCase() !== "false" },
    stream_transport: "temporary client-bound Worker proxy URL with api_key client identity and one-use stream_token authorization; authenticated entry points require bootstrap authorization by default",
    media_resolution: {
      reauthentication_retries: getMediaRetryCount(env),
      timeout_ms: getMediaTimeoutMs(env),
      license_token_ttl_minutes: Math.max(10, Math.min(55, Number(env?.LICENSE_TOKEN_TTL_MINUTES) || 45)),
      fresh_session_before_media_after_ttl: true,
      fresh_track_token_on_auth_failure: true,
      quality_ladder: "FLAC -> MP3_320 -> MP3_128"
    },
    routes: {
      GET: ["/", "/info", "/search", "/track", "/album", "/artist", "/playlist", "/chart", "/genre", "/radio", "/recommendations", "/cover", "/lyrics", "/stream-track", "/stream", "/track/:id/stream", "/track/:id/lyrics", "/ping", "/routing", "/env", "/docs"],
      OPTIONS: ["/*"],
      HEAD: ["/stream", "/info", "/search", "/track", "/album", "/artist", "/playlist", "/chart", "/genre", "/radio", "/cover", "/ping", "/routing", "/env", "/docs"]
    },
    stream_security: { arbitrary_url_proxy: false, requires_signed_token: true, requires_https_cdn: true, stream_url_format: "/stream-track/?id=<trackId>&api_key=<client-key>&stream_token=<short-lived-token> (metadata/playback URLs); /stream remains an internal Worker proxy format", allowed_hosts: String(env?.STREAM_CDN_HOSTS || "*.dzcdn.net;media.deezer.com").split(";").map(x => x.trim()).filter(Boolean) },
    hardening: { allowed_methods: ["GET", "HEAD", "OPTIONS"], max_url_length: MAX_REQUEST_URL_LENGTH, max_query_value_length: MAX_QUERY_VALUE_LENGTH, upstream_timeout_ms: getUpstreamTimeoutMs(env), max_catalog_response_bytes: MAX_UPSTREAM_RESPONSE_BYTES }
  };
}




const worker = {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getCorsHeaders(env) });
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response(null, { status: 405, headers: { ...getCorsHeaders(env), Allow: "GET, HEAD, OPTIONS" } });
    }

    const requestId = request.headers.get("X-Request-ID")?.trim().slice(0, 128) || makeRequestId();
    const requestUrl = new URL(request.url);
    const envelope = validateRequestEnvelope(requestUrl);
    if (!envelope.ok) return jsonResponse({ error: envelope.error, status: 414, request_id: requestId }, 414, { "X-Request-ID": requestId }, env);

    const routePath = requestUrl.pathname.replace(/\/+$/, "") || "/";
    const segments = routePath.split("/").filter(Boolean);
    const primaryRoute = segments[0] || "";

    if (primaryRoute === "docs") {
      const response = jsonResponse(buildDocs(requestUrl, env), 200, { "Cache-Control": "public, max-age=300", "X-Request-ID": requestId }, env);
      return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }

    // The bare root is intentionally public and credential-free. It is a tiny
    // instance status page, not an authenticated catalog endpoint.
    if (primaryRoute === "_root-img" && requestUrl.search === "") return rootAssetResponse(env, "image");
    if (primaryRoute === "_root-tab-icon" && requestUrl.search === "") return rootAssetResponse(env, "tab");

    if (!primaryRoute && requestUrl.search === "") {
      const html = buildRootHtml(env);
      const headers = { ...getCorsHeaders(env), "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=30", "X-Request-ID": requestId };
      return request.method === "HEAD" ? new Response(null, { status: 200, headers }) : new Response(html, { status: 200, headers });
    }

    if (request.method === "HEAD" && !["stream", "info", "search", "track", "album", "artist", "playlist", "chart", "genre", "radio", "cover", "ping", "routing", "env", "docs"].includes((requestUrl.pathname.replace(/^\/+|\/+$/g, "").split("/")[0] || ""))) {
      return new Response(null, { status: 404, headers: { ...getCorsHeaders(env), "X-Request-ID": requestId } });
    }


    const clientIp = getClientIp(request);
    const clientUserAgentHash = await getClientUserAgent(request);
    const auth = authenticateRequest(request, env);
    if (!auth.authorized) {
      return publicError("UNAUTHORIZED", 401, env, requestId);
    }


    const rateLimit = await checkRateLimit(request, env, auth.tokenId || "anonymous");
    if (rateLimit.limited) {
      const headers = { "Retry-After": String(Math.max(1, Math.ceil((rateLimit.resetInMs || 10000) / 1000))), "X-Request-ID": requestId, "X-RateLimit-Remaining": "0" };
      if (rateLimit.limit) headers["X-RateLimit-Limit"] = String(rateLimit.limit);
      return jsonResponse({ error: "TOO_MANY_REQUESTS", status: 429, request_id: requestId }, 429, headers, env);
    }
    const authToken = auth.tokenId && auth.tokenId !== "public" ? auth.tokenId : null;
    const preferExplicit = isExplicitPreferred(requestUrl, env);

    if (isMaintenanceMode(env) && primaryRoute !== "env") {
      return jsonResponse({
        error: "MAINTENANCE_MODE",
        status: 503,
        message: String(env?.MAINTENANCE_MESSAGE || "Service temporarily unavailable for maintenance.").trim().slice(0, 500),
        request_id: requestId,
      }, 503, { "Cache-Control": "no-store", "Retry-After": "60", "X-Request-ID": requestId }, env);
    }


    if (primaryRoute === "routing") {
      const response = jsonResponse(routingInfo(env), 200, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
      return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }
    if (primaryRoute === "env") {
      const presented = getPresentedApiToken(request, env);
      if (!env?.ADMIN_API_KEY || !presented || presented !== String(env.ADMIN_API_KEY).trim()) return publicError("FORBIDDEN", 403, env, requestId);
      const response = jsonResponse({ service: SERVICE_NAME, version: API_VERSION, variables: diagnosticEnv(env), variableDocumentation: ENVIRONMENT_VARIABLES, streamTokenSecurity: STREAM_TOKEN_SECURITY_NOTE, secret_variables: ["DEEZER_ARL[_1..50]", "API_KEY[_1..50]", "ADMIN_API_KEY", "STREAM_TOKEN_SECRET"] }, 200, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
      return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }


    if (primaryRoute === "ping" || requestUrl.searchParams.has("ping")) {
      try {
        const { arls } = getMemoizedConfig(env);
        if (!arls.length) return jsonResponse({ error: "No DEEZER_ARL configured" }, 500, {}, env);

        let configured = arls;
        if (auth.allowedSlots && auth.allowedSlots.size > 0) {
          configured = configured.filter(c => auth.allowedSlots.has(c.slot));
        }

        const results = await Promise.all(configured.map(item => {
          return getOrRenewSession(item.value, env).then(session => ({
            slot: item.slot,
            variable: item.name,
            status: "active",
            tier: session.canLossless ? "lossless" : (session.can320 ? "320" : "128"),
            capabilities: ["MP3_128", ...(session.can320 ? ["MP3_320"] : []), ...(session.canLossless ? ["FLAC"] : [])],
          })).catch(() => ({ slot: item.slot, variable: item.name, status: "failed" }));
        }));

        const active = results.filter(r => r.status === "active");
        const failed = results.filter(r => r.status === "failed");
        const response = jsonResponse({
          service: SERVICE_NAME,
          version: API_VERSION,
          configured: configured.length,
          active: active.length,
          failed: failed.length,
          checked: results.length,
          results,
        }, active.length > 0 ? 200 : 503, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
        return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
      } catch (error) {
        return publicError("HEALTH_CHECK_FAILED", 503, env, requestId);
      }
    }


    if (primaryRoute === "stream") {
      const trackId = segments[1] || requestUrl.searchParams.get("id");
      const legacyCdnUrl = requestUrl.searchParams.get("url");
      const streamToken = requestUrl.searchParams.get("stream_token");

      let streamSessionValid = false;
      let streamSessionEstablishedByCookie = false;
      let streamSessionCheck = null;
      if (authToken && trackId) {
        const sessionCookie = getCookie(request, STREAM_SESSION_COOKIE);
        if (sessionCookie) {
          const sessionCheck = await verifyStreamSession(decodeURIComponent(sessionCookie), { trackId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null }, env);
          streamSessionCheck = sessionCheck;
          streamSessionValid = sessionCheck.valid;
          streamSessionEstablishedByCookie = sessionCheck.valid;
        }
      }

      let streamTokenAuthorized = false;
      if (streamToken && !streamSessionValid) {
        if (!authToken || !trackId) return publicError("INVALID_STREAM_TOKEN", 401, env, requestId);
        const tokenCheck = await verifyStreamBootstrapToken(streamToken, { trackId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null }, env);
        if (!tokenCheck.valid) return publicError("INVALID_STREAM_TOKEN", tokenCheck.reason === "expired" ? 401 : 403, env, requestId);
        const consumed = await consumeStreamBootstrapToken(streamToken, env);
        if (!consumed.allowed) return publicError("STREAM_TOKEN_REPLAYED", 403, env, requestId);
        streamTokenAuthorized = true;
        streamSessionValid = true;
      }

      if (authenticatedPlaybackRequiresBootstrap(env, authToken) && !streamSessionValid && !streamTokenAuthorized) {
        return publicError("PLAYBACK_SESSION_REQUIRED", 401, env, requestId);
      }

      if (trackId && !legacyCdnUrl) {
        const q = requestUrl.searchParams.get("quality") || env?.DEFAULT_QUALITY || "best";
        const alt = requestUrl.searchParams.get("alt") ? `&alt=${encodeURIComponent(requestUrl.searchParams.get("alt"))}` : "";
        const exp = !preferExplicit ? "&explicit=false" : "";
        let streamTrackUrl = appendApiKeyToStreamUrl(
          `${requestUrl.origin}/stream-track?id=${encodeURIComponent(trackId)}&quality=${encodeURIComponent(q)}${alt}${exp}`,
          authToken,
        );
        streamTrackUrl = await appendStreamTokenToUrl(streamTrackUrl, authToken, clientIp, env, clientUserAgentHash);
        return Response.redirect(streamTrackUrl, 302);
      }

      let cdnUrl = null;
      let format = (requestUrl.searchParams.get("format") || "FLAC").toUpperCase();
      if (legacyCdnUrl) {
        try {
          const parsed = new URL(legacyCdnUrl);
          if (parsed.protocol !== "https:" || !isAllowedCdnHost(parsed.hostname, env)) throw new Error("Untrusted CDN URL");
          cdnUrl = parsed.toString();
          format = (requestUrl.searchParams.get("format") || "FLAC").toUpperCase();
        } catch (_) {
          return jsonResponse({ error: "INVALID_STREAM_URL", status: 400 }, 400, {}, env);
        }
      }
      if (!trackId || !cdnUrl) return new Response("Missing stream URL", { status: 400, headers: getCorsHeaders(env) });
      const mimeType = format.startsWith("MP3") ? "audio/mpeg" : "audio/flac";

      if (request.method === "HEAD") {
        const headers = new Headers(getCorsHeaders(env));
        if (authToken && trackId) {
          const cookie = streamTokenAuthorized
            ? await establishStreamSession(trackId, authToken, clientIp, env, clientUserAgentHash)
            : await maybeRefreshStreamSession(streamSessionCheck, trackId, authToken, clientIp, env, clientUserAgentHash);
          if (cookie) headers.append("Set-Cookie", cookie);
        }
        headers.set("Content-Type", mimeType);
        headers.set("Accept-Ranges", "bytes");
        const total = await getCdnTotalSize(cdnUrl, request.signal);
        if (total) headers.set("Content-Length", total.toString());
        return new Response(null, { status: 200, headers });
      }

      const tStart = performance.now();
      const cipher = getTrackCipher(trackId);
      const maxChunkSize = getSafeChunkSize(requestUrl, env);

      const rangeHeader = request.headers.get("Range");
      let reqStart = 0;
      let reqEnd = null;

      if (rangeHeader) {
        const suffixMatch = rangeHeader.match(/bytes=-(\d+)/);
        const standardMatch = rangeHeader.match(/bytes=(\d+)-(\d*)/);

        if (suffixMatch) {
          const suffixLen = parseInt(suffixMatch[1], 10);
          const totalSize = await getCdnTotalSize(cdnUrl, request.signal);
          if (totalSize && totalSize > 0) {
            reqStart = Math.max(0, totalSize - suffixLen);
            reqEnd = totalSize - 1;
          }
        } else if (standardMatch) {
          reqStart = parseInt(standardMatch[1], 10);
          if (standardMatch[2]) reqEnd = parseInt(standardMatch[2], 10);
        }
      }

      if (reqEnd === null || (reqEnd - reqStart + 1) > maxChunkSize) {
        reqEnd = reqStart + maxChunkSize - 1;
      }

      const startBlock = Math.floor(reqStart / 2048);
      const alignedStart = startBlock * 2048;
      const endBlock = Math.floor(reqEnd / 2048);
      const alignedEnd = (endBlock + 1) * 2048 - 1;

      try {
        const fetchStart = performance.now();
        const cdnResp = await fetch(cdnUrl, {
          headers: { "User-Agent": BROWSER_HEADERS["User-Agent"], Range: `bytes=${alignedStart}-${alignedEnd}` },
          signal: request.signal,
        });
        const tFetch = performance.now() - fetchStart;

        if (!cdnResp.ok && cdnResp.status !== 206) return publicError("UPSTREAM_AUDIO_ERROR", 502, env, requestId);





        if (cdnResp.status === 200 && alignedStart !== 0) {
          return new Response("Upstream CDN ignored byte range", { status: 502, headers: getCorsHeaders(env) });
        }

        const contentRange = cdnResp.headers.get("content-range") || "";
        const totalMatch = contentRange.match(/\/(\d+)/);
        const contentLength = Number(cdnResp.headers.get("content-length"));
        const totalSize = totalMatch ? parseInt(totalMatch[1], 10) : (cdnResp.status === 200 && Number.isFinite(contentLength) ? contentLength : (alignedEnd + 1));

        if (reqStart >= totalSize) {
          return new Response(null, { status: 416, headers: { ...getCorsHeaders(env), "Content-Range": `bytes */${totalSize}` } });
        }

        const procStart = performance.now();
        const rawBytes = new Uint8Array(await cdnResp.arrayBuffer());
        decryptAlignedBuffer(cipher, rawBytes, startBlock, request.signal);

        const offsetInFirstBlock = reqStart - alignedStart;
        const actualEnd = Math.min(reqEnd, totalSize - 1);
        const sliceLength = Math.max(0, actualEnd - reqStart + 1);
        const clientSlice = rawBytes.subarray(offsetInFirstBlock, offsetInFirstBlock + sliceLength);
        const tProcess = performance.now() - procStart;
        const tTotal = performance.now() - tStart;

        const headers = new Headers(getCorsHeaders(env));
        if (authToken && trackId) {
          const cookie = streamTokenAuthorized
            ? await establishStreamSession(trackId, authToken, clientIp, env, clientUserAgentHash)
            : await maybeRefreshStreamSession(streamSessionCheck, trackId, authToken, clientIp, env, clientUserAgentHash);
          if (cookie) headers.append("Set-Cookie", cookie);
        }
        headers.set("Content-Type", mimeType);
        headers.set("Content-Length", clientSlice.length.toString());
        headers.set("Accept-Ranges", "bytes");
        headers.set("Cache-Control", String(env?.STREAM_CACHE_CONTROL || "private, no-store"));
        headers.set("Content-Range", `bytes ${reqStart}-${actualEnd}/${totalSize}`);
        headers.set("Server-Timing", `cdn;dur=${tFetch.toFixed(1)}, decrypt;dur=${tProcess.toFixed(1)}, total;dur=${tTotal.toFixed(1)}`);
        headers.set("X-Timing-Fetch-Ms", tFetch.toFixed(2));
        headers.set("X-Timing-Process-Ms", tProcess.toFixed(2));
        headers.set("X-Timing-Total-Ms", tTotal.toFixed(2));
        headers.set("X-CPU-Safety", `chunk-bounded (chunk=${clientSlice.length}B, dec=${tProcess.toFixed(2)}ms)`);

        return new Response(clientSlice, { status: 206, headers });
      } catch (streamErr) {
        if (streamErr.name === "AbortError" || request.signal.aborted) {
          return new Response(null, { status: 499, statusText: "Client Closed Request" });
        }
        return publicError("AUDIO_STREAM_PROCESSING_FAILED", 500, env, requestId);
      }
    }


    if (primaryRoute === "stream-track") {
      const rawId = segments[1] || requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
      const streamToken = requestUrl.searchParams.get("stream_token");
      let streamSessionCookieValue = null;
      if (authenticatedPlaybackRequiresBootstrap(env, authToken) && !streamToken) {
        return publicError("STREAM_TOKEN_REQUIRED", 401, env, requestId);
      }
      if (streamToken) {
        if (!authToken || !rawId) return publicError("INVALID_STREAM_TOKEN", 401, env, requestId);
        const tokenCheck = await verifyStreamBootstrapToken(streamToken, { trackId: rawId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null }, env);
        if (!tokenCheck.valid) return publicError("INVALID_STREAM_TOKEN", tokenCheck.reason === "expired" ? 401 : 403, env, requestId);
        const consumed = await consumeStreamBootstrapToken(streamToken, env);
        if (!consumed.allowed) return publicError("STREAM_TOKEN_REPLAYED", 403, env, requestId);
        streamSessionCookieValue = await establishStreamSession(rawId, authToken, clientIp, env, clientUserAgentHash);
      }
      const paramIsrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
      const paramTitle = requestUrl.searchParams.get("title") || requestUrl.searchParams.get("track") || requestUrl.searchParams.get("song");
      const paramArtist = requestUrl.searchParams.get("artist");
      const paramQuery = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("s");
      const allowAlt = isAltAllowed(requestUrl, paramQuery || paramTitle, env);

      if (!rawId && !paramIsrc && !paramTitle && !paramArtist && !paramQuery) {
        return apiErrorResponse("Missing track identifier (id, isrc, title/artist, or q)", 400, null, env);
      }

      const rawQuality = (requestUrl.searchParams.get("quality") || requestUrl.searchParams.get("format") || env?.DEFAULT_QUALITY || "best").toLowerCase().trim();

      try {
        let songId = rawId;
        if (!songId || !/^\d+$/.test(songId)) {
          const track = await discoverTrack({ id: rawId, isrc: paramIsrc, query: paramQuery, title: paramTitle, artist: paramArtist }, env, allowAlt, preferExplicit);
          if (!track?.id) return jsonResponse({ error: "Track not found" }, 404, {}, env);
          songId = String(track.id);
        }

        const resolved = await resolvePlaybackStreamOnly(songId, rawQuality, env, auth.allowedSlots);
        const resolvedTrackId = resolved.trackId || songId;
        let cleanStreamUrl = appendApiKeyToStreamUrl(
          `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(resolved.mediaResult.directCdnUrl)}&format=${encodeURIComponent(resolved.mediaResult.format)}`,
          authToken,
        );
        if (streamSessionCookieValue) {
          // The bootstrap token is one-use. Do not carry it into the next redirect.
          try { new URL(cleanStreamUrl).searchParams.delete("stream_token"); } catch (_) {}
          const stripped = new URL(cleanStreamUrl);
          stripped.searchParams.delete("stream_token");
          cleanStreamUrl = stripped.toString();
        } else {
          cleanStreamUrl = await appendStreamTokenToUrl(cleanStreamUrl, authToken, clientIp, env, clientUserAgentHash);
        }
        const headers = { Location: cleanStreamUrl, "Cache-Control": "no-store", "X-Request-ID": requestId };
        if (streamSessionCookieValue) headers["Set-Cookie"] = streamSessionCookieValue;
        return new Response(null, { status: 302, headers });
      } catch (err) {
        return publicError("STREAM_RESOLUTION_FAILED", 502, env, requestId);
      }
    }


    const catalogRoutes = ["info-api", "info", "search", "album", "artist", "playlist", "cover", "chart", "genre", "radio", "recommendations"];
    if (catalogRoutes.includes(primaryRoute)) {
      try {
        const catalogResult = await handleCatalogRoute(requestUrl, env, segments, authToken, clientIp, clientUserAgentHash);
        if (catalogResult) {
          if (request.method === "HEAD") return new Response(null, { status: catalogResult.status, headers: catalogResult.headers });
          return catalogResult;
        }
      } catch (error) {
        return publicError("CATALOG_REQUEST_FAILED", error?.status >= 400 ? error.status : 502, env, requestId);
      }
    }


    if (primaryRoute === "lyrics" && envBoolean(env, "DISABLE_LYRICS", false)) {
      return apiErrorResponse("Lyrics are disabled on this instance", 404, { endpoint: "/lyrics" }, env);
    }

    const paramId = (["track", "lyrics"].includes(primaryRoute) ? segments[1] : null) || requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    const paramIsrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
    const paramTitle = requestUrl.searchParams.get("title") || requestUrl.searchParams.get("track") || requestUrl.searchParams.get("song");
    const paramArtist = requestUrl.searchParams.get("artist");
    const paramQuery = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("s");
    const allowAlt = isAltAllowed(requestUrl, paramQuery || paramTitle, env);




    if (primaryRoute === "track" && segments[1] && /^\d+$/.test(segments[1]) && segments[2] === "stream") {
      const requestedTrackId = segments[1];
      const streamToken = requestUrl.searchParams.get("stream_token");
      if (authenticatedPlaybackRequiresBootstrap(env, authToken) && !streamToken) {
        return publicError("STREAM_TOKEN_REQUIRED", 401, env, requestId);
      }
      if (streamToken) {
        const tokenCheck = await verifyStreamBootstrapToken(streamToken, { trackId: requestedTrackId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null }, env);
        if (!tokenCheck.valid) return publicError("INVALID_STREAM_TOKEN", tokenCheck.reason === "expired" ? 401 : 403, env, requestId);
        const consumed = await consumeStreamBootstrapToken(streamToken, env);
        if (!consumed.allowed) return publicError("STREAM_TOKEN_REPLAYED", 403, env, requestId);
      }
      const rawQuality = (requestUrl.searchParams.get("quality") || requestUrl.searchParams.get("format") || env?.DEFAULT_QUALITY || "best").toLowerCase().trim();
      try {
        const resolved = await resolvePlaybackStreamOnly(requestedTrackId, rawQuality, env, auth.allowedSlots);
        const resolvedTrackId = resolved.trackId || requestedTrackId;
        if (String(resolvedTrackId) !== String(requestedTrackId)) {
          return publicError("STREAM_TRACK_MISMATCH", 403, env, requestId);
        }
        let streamUrl = appendApiKeyToStreamUrl(
          `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(resolved.mediaResult.directCdnUrl)}&format=${encodeURIComponent(resolved.mediaResult.format)}`,
          authToken,
        );
        let sessionCookie = null;
        if (authToken) {
          sessionCookie = await establishStreamSession(resolvedTrackId, authToken, clientIp, env, clientUserAgentHash);
        }
        if (sessionCookie) {
          const stripped = new URL(streamUrl);
          stripped.searchParams.delete("stream_token");
          streamUrl = stripped.toString();
        } else {
          streamUrl = await appendStreamTokenToUrl(streamUrl, authToken, clientIp, env, clientUserAgentHash);
        }
        const headers = { Location: streamUrl, "Cache-Control": "no-store", "X-Request-ID": requestId };
        if (sessionCookie) headers["Set-Cookie"] = sessionCookie;
        return new Response(null, { status: 302, headers });
      } catch (error) {
        return publicError("STREAM_RESOLUTION_FAILED", 502, env, requestId);
      }
    }

    if (primaryRoute === "track" && segments[1] && /^\d+$/.test(segments[1]) && segments[2] === "lyrics") {
      if (envBoolean(env, "DISABLE_LYRICS", false)) return apiErrorResponse("Lyrics are disabled on this instance", 404, { endpoint: "/track/:id/lyrics" }, env);
      try {
        const pools = await getCandidatePools(env, auth.allowedSlots);
        const session = pickAuxiliarySession(pools, env) || pools.lossless[0]?.session || pools.lossy[0]?.session;
        const lyrics = await getDeezerLyrics(session, segments[1], env);
        if (!lyrics) return apiErrorResponse("Lyrics not found", 404, null, env);
        return catalogResponse({ version: API_VERSION, track_id: segments[1], data: lyrics }, 200, 60, env, apiToken, clientIp, clientUserAgentHash);
      } catch (error) {
        return publicError("LYRICS_REQUEST_FAILED", 502, env, requestId);
      }
    }

    if (!paramId && !paramIsrc && !paramTitle && !paramArtist && !paramQuery) {
      if (primaryRoute === "track") return apiErrorResponse("Missing track identifier", 400, null, env);
      if (["lyrics", "stream-track", "stream"].includes(primaryRoute)) {
        return apiErrorResponse("Missing track identifier", 400, null, env);
      }
      return apiErrorResponse(`Unknown or incomplete route: /${primaryRoute || ""}`, 404, null, env);
    }

    const rawQuality = (requestUrl.searchParams.get("quality") || requestUrl.searchParams.get("format") || env?.DEFAULT_QUALITY || "best").toLowerCase().trim();

    try {
      let songId = paramId && /^\d+$/.test(paramId) ? paramId : null;
      let track = null;


      if (!songId) {
        track = await discoverTrack({ id: paramId, isrc: paramIsrc, query: paramQuery, title: paramTitle, artist: paramArtist }, env, allowAlt, preferExplicit);
        if (!track?.id) return jsonResponse({ error: "Track not found" }, 404, {}, env);
        songId = String(track.id);
      }


      if (requestUrl.searchParams.get("stream") === "1" && !requestUrl.searchParams.has("json")) {
        const resolved = await resolvePlaybackStreamOnly(songId, rawQuality, env, auth.allowedSlots);
        const resolvedTrackId = resolved.trackId || songId;
        let cleanStreamUrl = appendApiKeyToStreamUrl(
          `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(resolved.mediaResult.directCdnUrl)}&format=${encodeURIComponent(resolved.mediaResult.format)}`,
          authToken,
        );
        cleanStreamUrl = await appendStreamTokenToUrl(cleanStreamUrl, authToken, clientIp, env, clientUserAgentHash);
        return new Response(null, { status: 302, headers: { Location: cleanStreamUrl, "Cache-Control": "no-store", "X-Request-ID": requestId } });
      }


      const wantLyrics = !envBoolean(env, "DISABLE_LYRICS", false)
        && !requestUrl.searchParams.has("nolyrics")
        && requestUrl.searchParams.get("lyrics") !== "0"
        && requestUrl.searchParams.get("lyrics") !== "false";

      const [resolved, lyricsResult] = await Promise.all([
        resolvePlaybackStreamOnly(songId, rawQuality, env, auth.allowedSlots),
        wantLyrics ? (async () => {
          const pools = await getCandidatePools(env, auth.allowedSlots);
          const session = pickAuxiliarySession(pools, env) || pools.lossless[0]?.session;
          return getDeezerLyrics(session, songId, env);
        })() : Promise.resolve(null),
      ]);

      const selectedProfile = resolved.selectedProfile;
      const mediaResult = resolved.mediaResult;
      const trackData = resolved.trackData;
      const resolvedTrackId = resolved.trackId || songId;

      const cleanStreamUrl = appendApiKeyToStreamUrl(
        `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(mediaResult.directCdnUrl)}&format=${encodeURIComponent(mediaResult.format)}`,
        authToken,
      );
      const albumArtwork = buildArtworkUrls(trackData.ALB_PICTURE || track?.album?.cover_xl || track?.album?.cover, "cover");
      const artistArtwork = buildArtworkUrls(trackData.ART_PICTURE || track?.artist?.picture_xl || track?.artist?.picture, "artist");
      const richMetadata = buildRichMetadata(trackData, track, lyricsResult);

      const responsePayload = {
        provider: "deezer",
        id: resolvedTrackId,
        isrc: trackData.ISRC || track?.isrc || null,
        title: trackData.SNG_TITLE || track?.title,
        version: firstValue(trackData.VERSION, trackData.SNG_VERSION, trackData.TRACK_VERSION, track?.version),
        duration: Number(trackData.DURATION) || track?.duration || null,
        track_number: Number(trackData.TRACK_NUMBER) || track?.track_position || null,
        disc_number: Number(trackData.DISK_NUMBER) || track?.disk_number || null,
        bpm: toNumber(firstValue(track?.bpm, trackData.BPM, trackData.SNG_BPM, trackData.TRACK_BPM)),
        gain: trackData.GAIN ? parseFloat(trackData.GAIN) : null,
        explicit: Boolean(Number(trackData.EXPLICIT_LYRICS) || track?.explicit_lyrics || isTrackExplicit(track)),
        explicit_preferred: preferExplicit,
        is_alt: isAltVersion(trackData || track),
        alt_allowed: allowAlt,
        release_date: trackData.PHYSICAL_RELEASE_DATE || track?.release_date || null,
        artwork: albumArtwork,
        artist: { id: String(trackData.ART_ID || track?.artist?.id || ""), name: trackData.ART_NAME || track?.artist?.name || "Unknown", artwork: artistArtwork },
        album: {
          id: String(trackData.ALB_ID || track?.album?.id || ""),
          title: trackData.ALB_TITLE || track?.album?.title || null,
          release_date: track?.album?.release_date || trackData.PHYSICAL_RELEASE_DATE || null,
          track_count: toNumber(firstValue(trackData?.ALB_NB_TRACKS, trackData?.ALBUM_NB_TRACKS, track?.album?.nb_tracks)),
          artwork: albumArtwork,
        },
        audio: {
          format: selectedProfile.audioFormat,
          bitrate: selectedProfile.bitrate,
          bitrateUncompressed: selectedProfile.bitrateUncompressed ?? null,
          sampleRate: selectedProfile.sampleRate,
          bitDepth: selectedProfile.bitDepth,
          lossless: selectedProfile.lossless,
          audioQuality: selectedProfile.badge,
          qualityLabel: selectedProfile.label,
          mimeType: selectedProfile.mime,
          rawProfile: mediaResult.format,
        },
        format: selectedProfile.audioFormat,
        bitrate: selectedProfile.bitrate,
        bitrateUncompressed: selectedProfile.bitrateUncompressed ?? null,
        sampleRate: selectedProfile.sampleRate,
        bitDepth: selectedProfile.bitDepth,
        audioQuality: selectedProfile.badge,
        quality: selectedProfile.label,
        deliveredQuality: selectedProfile.audioFormat === "FLAC" ? "Lossless FLAC" : selectedProfile.label,
        contributors: richMetadata.contributors,
        writers: richMetadata.writers,
        copyright: richMetadata.copyright,
        label: richMetadata.label,
        distributor: richMetadata.distributor,
        publisher: richMetadata.publisher,
        authorsNotes: richMetadata.authorsNotes,
        credits: richMetadata.rawCredits,
        deezerAccount: {
          slot: resolved.slot,
          tier: resolved.session?.canLossless ? "lossless" : (resolved.session?.can320 ? "320" : "128"),
          canLossless: Boolean(resolved.session?.canLossless),
          can320: Boolean(resolved.session?.can320 ?? resolved.session?.canLossless),
        },
        sourceMetadata: sanitizeSourceMetadata(trackData),
        streamUrl: await appendStreamTokenToUrl(cleanStreamUrl, authToken, clientIp, env, clientUserAgentHash),
      };

      if (wantLyrics) responsePayload.lyrics = lyricsResult;

      const customHeaders = {
        "X-ARL-Slot": String(resolved.slot),
        "X-ARL-Tier": resolved.session?.canLossless ? "lossless" : (resolved.session?.can320 ? "320" : "128"),
      };

      return jsonResponse(responsePayload, 200, customHeaders, env);
    } catch (error) {
      const diagnostic = {
        code: error?.code || null,
        upstream_code: error?.upstreamCode || null,
        upstream_message: error?.upstreamMessage || null,
        upstream_status: Number(error?.status || 0) || null,
        format: error?.format || null,
      };
      return jsonResponse({
        error: "MEDIA_RESOLUTION_FAILED",
        status: 502,
        request_id: requestId,
        diagnostic,
      }, 502, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
    }
  },
};

export class StreamTokenGuard extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/consume" || request.method !== "POST") {
      return new Response("Not Found", { status: 404 });
    }

    try {
      const body = await request.json();
      const hash = String(body?.hash || "").toLowerCase();
      const ttl = Math.min(7200, Math.max(60, Number.parseInt(body?.ttl, 10) || 60));
      if (!/^[a-f0-9]{64}$/.test(hash)) {
        return Response.json({ allowed: false, reason: "invalid_hash" }, { status: 400 });
      }

      const allowed = await this.ctx.storage.transaction(async (txn) => {
        const key = `used:${hash}`;
        const existing = await txn.get(key);
        if (existing) return false;
        await txn.put(key, "1", { expirationTtl: ttl });
        return true;
      });

      return Response.json({ allowed });
    } catch (_) {
      return Response.json({ allowed: false, reason: "guard_error" }, { status: 500 });
    }
  }
}

export default worker;
