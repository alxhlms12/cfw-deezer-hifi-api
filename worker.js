// cfw-deezer-hifi-api-v1.4.29
// Public /ping authentication exception added on top of the v1.4.28 federation/racing pass.
// Playback fix: /stream Range requests bypass the generic API rate limiter so continuous audio cannot be interrupted by 429 responses.
// Playback hardening: authenticated playback entry points require signed
// bootstrap tokens by default; tokens remain reusable until their normal expiry.
// Production optimization pass: cached hot-path crypto, in-flight upstream
// coalescing, compact JSON by default, strict bootstrap/session token typing,
// and unique non-coalesced 256-bit bootstrap nonces.
// Derived from cfw-deezer-hifi-api-v11-random-nonce.
const DEEZER_GW = "https://www.deezer.com/ajax/gw-light.php";
const DEEZER_MEDIA_API = "https://media.deezer.com/v1/get_url";
const DEEZER_PIPE_GQL = "https://pipe.deezer.com/api";
const DEEZER_AUTH_ARL = "https://auth.deezer.com/login/arl?jo=p&rto=c&i=c";
const DEEZER_AUTH_RENEW = "https://auth.deezer.com/login/renew?jo=p&rto=c&i=c";
const PUBLIC_API_BASE = "https://api.deezer.com";
const API_VERSION = "1.4.31";
const GITHUB_REPOSITORY_URL = "https://github.com/alxhlms12/cfw-deezer-hifi-api/";
const SERVICE_NAME = "cfw-deezer-hifi-api";





const SAFE_DEFAULT_CHUNK = 512 * 1024;
const SAFE_MIN_CHUNK = 64 * 1024;
const SAFE_MAX_CHUNK_HARD = 1024 * 1024;

function getCorsHeaders(env) {
  const origin = env?.CORS_ALLOW_ORIGIN?.trim() || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Range, X-Chunk-Size, X-API-Key, X-Request-ID, X-Voria-Device",
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
const trackTokenCache = new BoundedMap(512);
const sessionInflight = new BoundedMap(128);
const catalogInflight = new BoundedMap(128);

// Secure instance-to-instance ARL sharing runtime state. Shared ARLs are never
// emitted by diagnostics and never placed in URLs.
const arlShareRuntime = new WeakMap();
const ARL_SHARE_CACHE_PREFIX = "arl-share:v1:";

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
  const routeName = route.split("/")[1] || "root";

  // Audio data-plane requests are intentionally exempt from the generic API
  // rate limiter. A browser/player legitimately issues repeated HTTP Range
  // requests while streaming one track, and counting every Range request as
  // an API request can terminate playback with a 429 mid-song.
  //
  // Stream-entry routes such as /stream-track remain rate limited because
  // they perform resolution/session work. Only the actual /stream data path
  // is exempt, including its repeated Range requests.
  if (routeName === "stream") {
    return { limited: false, exempt: true, distributed: false };
  }

  const key = `${authToken || "anonymous"}:${routeName}`;

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

  const sharedState = arlShareRuntime.get(env);
  if (sharedState?.arls?.length) {
    for (const shared of sharedState.arls) {
      if (!shared?.value) continue;
      if (arls.some(item => item.value === shared.value)) continue;
      arls.push(shared);
    }
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

function normalizeDedupText(value) {
  return String(value ?? "")
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[’‘]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/\s+/g, " ")
    .trim();
}

function getTrackDedupKeys(track) {
  if (!track) return [];
  const keys = [];
  const id = track.id ?? track.SNG_ID ?? track.trackId;
  const isrc = normalizeSharedIsrc(track.isrc || track.ISRC);
  const artist = normalizeDedupText(track.artist?.name || track.artist_name || track.ART_NAME);
  const titleShort = normalizeDedupText(track.title_short || track.title || track.SNG_TITLE);
  const album = normalizeDedupText(track.album?.title || track.album?.displayTitle || track.album_title || track.ALB_TITLE);
  const durationRaw = track.duration ?? track.DURATION;
  const duration = Number(durationRaw);

  if (id !== undefined && id !== null && String(id).trim()) keys.push(`id:${String(id).trim()}`);
  if (isrc) keys.push(`isrc:${isrc}`);

  // Metadata identity is deliberately strict: artist + short title + album + duration.
  // This catches duplicate Deezer catalog entries even when their IDs/ISRCs differ,
  // while avoiding broad title-only matches between genuinely different recordings.
  if (artist && titleShort && album && Number.isFinite(duration) && duration >= 0) {
    keys.push(`meta:${artist}|${titleShort}|${album}|${Math.round(duration)}`);
  }

  return keys;
}

function addTrackDedupKeys(seenKeys, track) {
  const keys = getTrackDedupKeys(track);
  if (!keys.length) return false;
  for (const key of keys) {
    if (seenKeys.has(key)) return false;
  }
  for (const key of keys) seenKeys.add(key);
  return true;
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

function getMaxChunkSize(env = null) {
  const configured = Number.parseInt(env?.STREAM_MAX_CHUNK_SIZE_BYTES || env?.STREAM_MAX_CHUNK_SIZE || "", 10);
  if (!Number.isFinite(configured) || configured <= 0) return SAFE_MAX_CHUNK_HARD;
  const clamped = Math.max(SAFE_MIN_CHUNK, Math.min(SAFE_MAX_CHUNK_HARD, configured));
  return Math.floor(clamped / 2048) * 2048;
}

function getSafeChunkSize(requestUrl, env) {
  const maxChunk = getMaxChunkSize(env);
  const param = requestUrl.searchParams.get("chunk_size") ||
                requestUrl.searchParams.get("chunk") ||
                env?.STREAM_CHUNK_SIZE ||
                env?.CHUNK_SIZE;

  if (!param) return Math.min(SAFE_DEFAULT_CHUNK, maxChunk);
  const clean = String(param).toLowerCase().trim();

  if (clean === "256k" || clean === "256kb") return Math.min(256 * 1024, maxChunk);
  if (clean === "512k" || clean === "512kb") return Math.min(512 * 1024, maxChunk);

  const parsed = parseInt(clean, 10);
  if (Number.isFinite(parsed) && parsed > 0) {
    const clamped = Math.max(SAFE_MIN_CHUNK, Math.min(maxChunk, parsed));
    return Math.floor(clamped / 2048) * 2048;
  }

  return Math.min(SAFE_DEFAULT_CHUNK, maxChunk);
}




async function getOrRenewSessionUncached(arl, env = null, forceRefresh = false) {
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


async function getOrRenewSession(arl, env = null, forceRefresh = false) {
  const cleanArl = String(arl || "").trim();
  if (!cleanArl) throw new Error("Missing Deezer ARL");
  const key = `${cleanArl}|${forceRefresh ? "force" : "normal"}`;
  const pending = sessionInflight.get(key);
  if (pending) return pending;

  const promise = getOrRenewSessionUncached(cleanArl, env, forceRefresh);
  sessionInflight.set(key, promise, 10000);
  promise.finally(() => sessionInflight.delete(key)).catch(() => {});
  return promise;
}

async function getCandidatePools(env, allowedSlots = null) {
  const { arls } = getMemoizedConfig(env);
  if (!arls.length) {
    throw new Error("No DEEZER_ARL environment variables configured");
  }

  let configured = arls;
  if (allowedSlots && allowedSlots.size > 0) {
    const allowShared = envBoolean(env, "ARL_SHARE_ACCESS", false);
    configured = configured.filter(c => c.shared ? allowShared : allowedSlots.has(c.slot));
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




function getJwtExpiryMs(jwt) {
  try {
    const parts = String(jwt || "").split(".");
    if (parts.length < 2) return 0;
    const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)));
    const exp = Number(payload?.exp || 0);
    return Number.isFinite(exp) && exp > 0 ? exp * 1000 : 0;
  } catch (_) {
    return 0;
  }
}

async function getPipeJwt(arl, forceRefresh = false, env = null) {
  const cleanArl = String(arl || "").trim();
  if (!cleanArl) return null;

  if (!forceRefresh) {
    const cachedJwt = jwtCache.get(cleanArl);
    if (cachedJwt) {
      // Pipe JWTs are short-lived. Validate the token's real exp claim instead
      // of trusting only the local cache TTL, with a 60-second safety margin.
      const cachedExpiry = getJwtExpiryMs(cachedJwt);
      if (!cachedExpiry || cachedExpiry > Date.now() + 60_000) return cachedJwt;
      jwtCache.delete(cleanArl);
    }
  }

  // Pipe authentication uses ARL -> JWT. Deezer returns text/plain
  // containing JSON, so parsing only response.json is not sufficient.
  try {
    const resp = await fetchWithTimeout(DEEZER_AUTH_ARL, {
      method: "POST",
      headers: {
        "User-Agent": BROWSER_HEADERS["User-Agent"],
        "Origin": "https://www.deezer.com",
        "Referer": "https://www.deezer.com/",
        Cookie: `arl=${cleanArl}`,
        Accept: "application/json, text/plain, */*",
      },
      body: "",
    }, env);

    const result = await readResponseLimited(resp);
    if (!result.ok) {
      jwtCache.delete(cleanArl);
      return null;
    }

    let payload = result.json;
    if (!payload && result.text) {
      try { payload = JSON.parse(String(result.text).trim()); } catch (_) {}
    }

    const jwt = String(payload?.jwt || payload?.token || payload?.access_token || "").trim();
    if (!jwt) {
      jwtCache.delete(cleanArl);
      return null;
    }

    const expiry = getJwtExpiryMs(jwt);
    const now = Date.now();
    // Deezer Pipe JWTs are currently 360 seconds. Cache only while the token
    // has at least 60 seconds of real lifetime remaining.
    if (expiry > now + 60_000) {
      const ttl = Math.max(1_000, Math.min(300_000, expiry - now - 60_000));
      jwtCache.set(cleanArl, jwt, ttl);
    } else {
      jwtCache.delete(cleanArl);
    }
    return jwt;
  } catch (_) {
    jwtCache.delete(cleanArl);
    return null;
  }
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

const GQL_SIMILAR_TRACKS_QUERY = `
query GetSimilarTracks($trackId: String!) {
  track(trackId: $trackId) {
    id
    recommendedTracks {
      id
      title
      ISRC
      duration
      isExplicit
      popularity
      album { id displayTitle cover { id urls(pictureRequest: { width: 1000, height: 1000 }) } }
      contributors(first: 10, roles: [MAIN, FEATURED]) {
        edges { roles node { ... on Artist { id name } } }
      }
    }
  }
}`;

function extractGraphqlTrackList(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value.data)) return value.data;
  if (Array.isArray(value.edges)) return value.edges.map(edge => edge?.node || edge).filter(Boolean);
  if (Array.isArray(value.nodes)) return value.nodes;
  if (Array.isArray(value.tracks)) return value.tracks;
  return [];
}

async function getPublicSimilarRecommendations(seed, env = null, apiToken = null, clientIp = "", allowAlt = false, preferExplicit = true, limit = 25, offset = 0) {
  const requestedCount = Math.min(50, Math.max(1, Number(limit) || 25));
  const requestedOffset = Math.max(0, Number(offset) || 0);
  const seedId = String(seed?.id || "");
  const seedArtistId = String(seed?.artist?.id || "");

  if (!seedId || !seedArtistId) {
    const error = new Error("The seed track does not contain enough artist metadata for public recommendation fallback");
    error.status = 502;
    error.code = "RECOMMENDATION_FALLBACK_METADATA_FAILED";
    throw error;
  }

  const artistIds = new Set([seedArtistId]);
  try {
    const related = await publicApi(`artist/${encodeURIComponent(seedArtistId)}/related`, { limit: 10, index: 0 }, env, apiToken, clientIp);
    for (const artistItem of related?.data || []) {
      const relatedId = artistItem?.id;
      if (relatedId && artistIds.size < 9) artistIds.add(String(relatedId));
    }
  } catch (_) {}

  const artistIdList = [...artistIds];
  const topResults = await Promise.all(artistIdList.map(async (artistId) => {
    try {
      const result = await publicApi(`artist/${encodeURIComponent(artistId)}/top`, { limit: 25, index: 0 }, env, apiToken, clientIp);
      return Array.isArray(result?.data) ? result.data : [];
    } catch (_) {
      return [];
    }
  }));

  const seen = new Set([seedId]);
  const tracks = [];
  for (let artistIndex = 0; artistIndex < topResults.length; artistIndex++) {
    const items = topResults[artistIndex];
    for (const track of items) {
      const trackId = String(track?.id || "");
      if (!trackId || seen.has(trackId)) continue;
      seen.add(trackId);
      if (!allowAlt && isAltVersion(track)) continue;
      if (!preferExplicit && (track?.explicit_lyrics || track?.explicit_content_lyrics || track?.explicit_content_cover)) continue;
      tracks.push(track);
    }
  }

  const page = tracks.slice(requestedOffset, requestedOffset + requestedCount)
    .map(track => normalizeTrack(track, null, apiToken))
    .filter(Boolean);

  const hasMore = tracks.length > requestedOffset + page.length;
  return {
    data: page,
    total: tracks.length,
    next: hasMore ? `?limit=${requestedCount}&offset=${requestedOffset + page.length}` : null,
    previous: requestedOffset > 0 ? `?limit=${requestedCount}&offset=${Math.max(0, requestedOffset - requestedCount)}` : null,
    seed: normalizeTrack(seed, null, apiToken),
    seed_id: seedId,
    source: "deezer_public_related_artist_fallback",
  };
}

async function getSimilarRecommendations({ id = null, isrc = null, query = null, title = null, artist = null }, env = null, apiToken = null, clientIp = "", allowAlt = false, preferExplicit = true, limit = 25, offset = 0) {
  const cleanQuery = query ? String(query).trim() : "";
  const cleanTitle = title ? String(title).trim() : "";
  const cleanArtist = artist ? String(artist).trim() : "";
  const seed = await discoverTrack({ id, isrc, query: cleanQuery, title: cleanTitle, artist: cleanArtist }, env, allowAlt, preferExplicit);
  if (!seed?.id) { const error = new Error("Could not resolve the recommendation seed track"); error.status = 404; error.code = "RECOMMENDATION_SEED_NOT_FOUND"; throw error; }

  const requestedCount = Math.min(50, Math.max(1, Number(limit) || 25));
  const requestedOffset = Math.max(0, Number(offset) || 0);
  const fetchCount = Math.min(50, requestedCount + requestedOffset);
  const pools = await getCandidatePools(env, null);
  const session = pickAuxiliarySession(pools, env) || pools.lossless[0]?.session || pools.lossy[0]?.session;
  if (!session?.arl) { const error = new Error("No authenticated Deezer session available for similar-track recommendations"); error.status = 503; error.code = "RECOMMENDATION_SESSION_UNAVAILABLE"; throw error; }

  let jwt = await getPipeJwt(session.arl, false, env);
  if (!jwt) {
    return await getPublicSimilarRecommendations(seed, env, apiToken, clientIp, allowAlt, preferExplicit, limit, offset);
  }

  const execute = async (token) => fetchWithTimeout(DEEZER_PIPE_GQL, {
    method: "POST",
    headers: { ...BROWSER_HEADERS, "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
    body: JSON.stringify({ operationName: "GetSimilarTracks", variables: { trackId: String(seed.id) }, query: GQL_SIMILAR_TRACKS_QUERY }),
  }, env);

  let response = await execute(jwt);
  let result = await readResponseLimited(response);
  if (response.status === 401 || result.json?.errors?.some(e => /token|auth|jwt|signature/i.test(e?.message || ""))) {
    jwtCache.delete(session.arl);
    jwt = await getPipeJwt(session.arl, true, env);
    if (jwt) { response = await execute(jwt); result = await readResponseLimited(response); }
  }
  if (!result.ok || result.json?.errors?.length) {
    const message = result.json?.errors?.map(e => e?.message).filter(Boolean).join("; ") || `Deezer similar-track request failed (${result.status})`;
    try {
      return await getPublicSimilarRecommendations(seed, env, apiToken, clientIp, allowAlt, preferExplicit, limit, offset);
    } catch (fallbackError) {
      const error = new Error(`${message}; fallback failed: ${fallbackError?.message || "unknown fallback error"}`);
      error.status = result.status >= 400 ? result.status : (fallbackError?.status >= 400 ? fallbackError.status : 502);
      error.code = "DEEZER_SIMILAR_TRACKS_UPSTREAM_ERROR";
      throw error;
    }
  }

  const trackNode = result.json?.data?.track;
  let tracks = extractGraphqlTrackList(trackNode?.recommendedTracks);
  if (!tracks.length) tracks = extractGraphqlTrackList(trackNode?.recommended_tracks);
  if (!tracks.length) {
    return await getPublicSimilarRecommendations(seed, env, apiToken, clientIp, allowAlt, preferExplicit, limit, offset);
  }
  tracks = tracks.filter(track => String(track?.id || "") !== String(seed.id));
  if (!allowAlt && tracks.length) { const standard = tracks.filter(track => !isAltVersion(track)); if (standard.length) tracks = standard; }

  const page = tracks.slice(requestedOffset, requestedOffset + requestedCount)
    .map(track => normalizeGraphqlRecommendationTrack(track) || normalizeTrack(track, null, apiToken)).filter(Boolean);
  const hasMore = tracks.length > requestedOffset + page.length || (tracks.length >= fetchCount && fetchCount < 50);
  return {
    data: page,
    total: null,
    next: hasMore ? `?limit=${requestedCount}&offset=${requestedOffset + page.length}` : null,
    previous: requestedOffset > 0 ? `?limit=${requestedCount}&offset=${Math.max(0, requestedOffset - requestedCount)}` : null,
    seed: normalizeTrack(seed, null, apiToken),
    seed_id: String(seed.id),
    source: "deezer_pipe_recommendedTracks",
  };
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
    error.code = "DEEZER_RECOMMENDATIONS_UPSTREAM_ERROR";
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
    lyrics {
      text
      ...SynchronizedWordByWordLines
      ...SynchronizedLines
    }
  }
}
fragment SynchronizedWordByWordLines on Lyrics {
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
fragment SynchronizedLines on Lyrics {
  synchronizedLines {
    lrcTimestamp
    line
    milliseconds
    duration
  }
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

    const graphErrors = Array.isArray(result.json?.errors) ? result.json.errors : [];
    if (graphErrors.length) {
      // A schema/auth error can be returned with HTTP 200. Treat auth/JWT
      // errors exactly like a 401 so a fresh Pipe JWT gets one clean retry.
      const authError = graphErrors.some(e => /token|auth|jwt|signature|unauthor/i.test(String(e?.message || "")));
      if (authError && jwt) {
        jwtCache.delete(String(arl));
        const freshJwt = await getPipeJwt(arl, true, env);
        if (freshJwt && freshJwt !== jwt) {
          const retryResp = await execute(freshJwt);
          const retryResult = await readResponseLimited(retryResp);
          if (!retryResult.json?.errors?.length) {
            result = retryResult;
          }
        }
      }
    }

    const lyricsObj = result.json?.data?.track?.lyrics;
    if (!lyricsObj) return null;

    const wordSync = normalizeWordSync(lyricsObj.synchronizedWordByWordLines);
    const lineSync = normalizeLyricsLines(lyricsObj.synchronizedLines);
    const hasWordSync = Array.isArray(wordSync) && wordSync.length > 0;
    const hasLineSync = Array.isArray(lineSync) && lineSync.length > 0;
    const hasPlain = typeof lyricsObj.text === "string" && lyricsObj.text.trim().length > 0;

    // Deezer can legitimately return line-synchronized lyrics with no word
    // synchronization and sometimes no plain text. That is still a valid
    // lyrics result and must not be treated as "no lyrics".
    if (!hasWordSync && !hasLineSync && !hasPlain) return null;
    let lrc = null;

    if (wordSync?.length) {
      lrc = wordSyncToLrc(wordSync);
    } else if (lineSync?.length) {
      lrc = lineSync.map(l => `${l.lrcTimestamp || ""}${l.line || ""}`).join("\n");
    }

    return {
      source: "deezer_graphql",
      id: lyricsObj.id ?? null,
      syncType: hasWordSync ? "WORD_BY_WORD" : (hasLineSync ? "LINE_BY_LINE" : "UNSYNCED"),
      hasWordSync,
      hasLineSync,
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


function hasUsableDeezerLyrics(value) {
  if (!value) return false;
  if (value.hasWordSync && Array.isArray(value.synchronizedWordByWordLines) && value.synchronizedWordByWordLines.length > 0) return true;
  if (value.hasLineSync && Array.isArray(value.synchronizedLines) && value.synchronizedLines.length > 0) return true;
  if (typeof value.plain === "string" && value.plain.trim().length > 0) return true;
  if (typeof value.lrc === "string" && value.lrc.trim().length > 0) return true;
  return false;
}

async function mergeDeezerLyricsResults(results) {
  const usable = results.filter(hasUsableDeezerLyrics);
  if (!usable.length) return null;

  // Lyrics quality is hierarchical, but every usable tier is valid:
  // WORD_BY_WORD > LINE_BY_LINE > UNSYNCED.
  // Line-only lyrics must never collapse to null just because word timing
  // is unavailable.
  const word = usable.find(x =>
    x.hasWordSync &&
    Array.isArray(x.synchronizedWordByWordLines) &&
    x.synchronizedWordByWordLines.length > 0
  );
  const line = usable.find(x =>
    x.hasLineSync &&
    Array.isArray(x.synchronizedLines) &&
    x.synchronizedLines.length > 0
  );
  const plain = usable.find(x => typeof x.plain === "string" && x.plain.trim().length > 0);
  const base = word || line || plain || usable[0];

  const hasWordSync = Boolean(word);
  const hasLineSync = Boolean(line || base?.hasLineSync);
  const synchronizedWordByWordLines =
    word?.synchronizedWordByWordLines ||
    base?.synchronizedWordByWordLines ||
    null;
  const synchronizedLines =
    line?.synchronizedLines ||
    base?.synchronizedLines ||
    null;

  let lrc = null;
  if (hasWordSync && word?.lrc) lrc = word.lrc;
  else if (line?.lrc) lrc = line.lrc;
  else lrc = base?.lrc || null;

  return {
    ...base,
    source: hasWordSync
      ? "deezer_pipe_graphql+deezer_gateway"
      : (base.source || "deezer_gateway"),
    syncType: hasWordSync
      ? "WORD_BY_WORD"
      : (hasLineSync ? "LINE_BY_LINE" : "UNSYNCED"),
    hasWordSync,
    hasLineSync,
    id: base.id || word?.id || line?.id || null,
    writers: base.writers || word?.writers || line?.writers || null,
    copyright: base.copyright || word?.copyright || line?.copyright || null,
    plain: plain?.plain || base.plain || null,
    lrc,
    synchronizedLines,
    synchronizedWordByWordLines,
  };
}

async function getDeezerLyrics(sessionOrArl, trackId, env = null) {
  if (!trackId) return null;
  const songId = String(trackId);

  // Hot caches are intentionally checked before any Deezer network request.
  const mem = lyricsMemoryCache.get(songId);
  if (hasUsableDeezerLyrics(mem)) return mem;

  const cacheKey = sharedCacheKey("lyrics-v2", songId);
  const cached = await getSharedCache(env, cacheKey);
  if (hasUsableDeezerLyrics(cached)) {
    lyricsMemoryCache.set(songId, cached, 1000 * 60 * 60);
    return cached;
  }

  // Fast path: use the already-selected authenticated session immediately.
  // Pipe is queried first because it is the richest private lyrics surface and
  // can return word-sync, line-sync, or plain lyrics in one request.
  let primaryArl = typeof sessionOrArl === "string" ? sessionOrArl : sessionOrArl?.arl;
  let primarySession = typeof sessionOrArl === "object" && sessionOrArl?.sid ? sessionOrArl : null;

  if (!primaryArl) {
    try {
      const { arls } = getMemoizedConfig(env);
      primaryArl = arls?.[0]?.value || null;
    } catch (_) {}
  }

  if (primaryArl && !primarySession) {
    primarySession = await getOrRenewSession(primaryArl, env).catch(() => null);
  }

  if (primaryArl) {
    // Race the two private Deezer lyrics surfaces instead of waiting for one
    // to fail before starting the other. Pipe can provide word-sync; the
    // gateway is often faster for line-sync/plain lyrics. First usable result
    // wins, which keeps lyrics from becoming a serial latency tax.
    const sessionPromise = primarySession
      ? Promise.resolve(primarySession)
      : getOrRenewSession(primaryArl, env).catch(() => null);
    const pipePromise = getLyricsFromPipeGQL(primaryArl, songId, env);
    const gwPromise = sessionPromise.then(session => getLyricsFromGwLight(session, songId, env));

    const racedLyrics = await Promise.any([
      pipePromise.then(value => {
        if (!hasUsableDeezerLyrics(value)) throw new Error("Pipe lyrics unavailable");
        return value;
      }),
      gwPromise.then(value => {
        if (!hasUsableDeezerLyrics(value)) throw new Error("Gateway lyrics unavailable");
        return value;
      }),
    ]).catch(() => null);

    if (hasUsableDeezerLyrics(racedLyrics)) {
      lyricsMemoryCache.set(songId, racedLyrics, 1000 * 60 * 60 * 2);
      await putSharedCache(env, cacheKey, racedLyrics, 86400 * 30);
      return racedLyrics;
    }
  }

  // Only build the full ARL failover pool after the primary authenticated
  // session has actually failed. This keeps the common path to one upstream
  // lyrics request and preserves the existing 50-ARL reliability net.
  const candidates = [];
  const seenArls = new Set(primaryArl ? [String(primaryArl)] : []);
  const addCandidate = (candidate) => {
    if (!candidate) return;
    const arl = typeof candidate === "string" ? candidate : candidate.arl;
    if (!arl || seenArls.has(String(arl))) return;
    seenArls.add(String(arl));
    candidates.push({
      arl: String(arl),
      session: typeof candidate === "object" ? candidate.session || candidate : null,
    });
  };

  try {
    const pools = await getCandidatePools(env, null);
    for (const poolName of ["lossless", "lossy", "unverified"]) {
      for (const candidate of (pools?.[poolName] || [])) addCandidate(candidate);
    }
  } catch (_) {}

  if (!candidates.length) {
    try {
      const { arls } = getMemoizedConfig(env);
      for (const item of (arls || [])) addCandidate(item?.value || item);
    } catch (_) {}
  }

  // Failover remains sequential so one broken ARL does not create a burst of
  // 50 simultaneous authenticated requests. Each fallback stops immediately
  // on any usable lyric representation, including line-only lyrics.
  for (const candidate of candidates.slice(0, 50)) {
    let session = candidate.session;
    if (!session?.sid || !session?.apiToken) {
      session = await getOrRenewSession(candidate.arl, env).catch(() => null);
    }

    const pipeLyrics = await getLyricsFromPipeGQL(candidate.arl, songId, env);
    if (hasUsableDeezerLyrics(pipeLyrics)) {
      lyricsMemoryCache.set(songId, pipeLyrics, 1000 * 60 * 60 * 2);
      await putSharedCache(env, cacheKey, pipeLyrics, 86400 * 30);
      return pipeLyrics;
    }

    const gwLyrics = await getLyricsFromGwLight(session, songId, env);
    if (hasUsableDeezerLyrics(gwLyrics)) {
      lyricsMemoryCache.set(songId, gwLyrics, 1000 * 60 * 60 * 2);
      await putSharedCache(env, cacheKey, gwLyrics, 86400 * 30);
      return gwLyrics;
    }
  }

  return null;
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

function getTrackTokenCacheTtlMs(env = null) {
  const value = Number(env?.TRACK_TOKEN_CACHE_TTL_MS);
  if (!Number.isFinite(value) || value <= 0) return 30000;
  return Math.max(5000, Math.min(120000, Math.floor(value)));
}

async function getTrackTokens(arl, session, trackId, env = null) {
  const key = `${String(arl)}|${String(session?.sid || "")}|${String(trackId)}`;
  const cached = trackTokenCache.get(key);
  if (cached?.TRACK_TOKEN) return cached;

  let pending = trackTokenInflight.get(key);
  if (pending) return pending;

  pending = getTrackTokensUncached(arl, session, trackId);
  trackTokenInflight.set(key, pending, getTrackTokenInflightTtlMs(env));
  pending.then(result => {
    if (result?.TRACK_TOKEN) trackTokenCache.set(key, result, getTrackTokenCacheTtlMs(env));
  }).catch(() => {}).finally(() => trackTokenInflight.delete(key)).catch(() => {});
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

function getMediaInflightTtlMs(env = null) {
  const value = Number(env?.MEDIA_INFLIGHT_TTL_MS);
  if (!Number.isFinite(value) || value <= 0) return 5000;
  return Math.max(1000, Math.min(30000, Math.floor(value)));
}

function getTrackTokenInflightTtlMs(env = null) {
  const value = Number(env?.TRACK_TOKEN_INFLIGHT_TTL_MS);
  if (!Number.isFinite(value) || value <= 0) return 5000;
  return Math.max(1000, Math.min(30000, Math.floor(value)));
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
  mediaInflight.set(key, pending, getMediaInflightTtlMs(env));
  pending.finally(() => mediaInflight.delete(key)).catch(() => {});
  return pending;
}

async function refreshCandidateForMedia(candidate, trackId, env) {
  clearArlCache(candidate.arl);
  candidate.session = await getOrRenewSession(candidate.arl, env, true);
  candidate.trackTokens = await getTrackTokens(candidate.arl, candidate.session, trackId, env);
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
  const configuredConcurrency = Number(env?.RESOLUTION_CONCURRENCY);
  const concurrency = Number.isFinite(configuredConcurrency) && configuredConcurrency > 0
    ? Math.max(1, Math.min(10, Math.floor(configuredConcurrency)))
    : 5;

  let lastError = null;

  async function tryCandidate(candidate, targetFormat) {
    try {
      if (!candidate.session) {
        candidate.session = await getOrRenewSession(candidate.arl, env);
      }

      if (targetFormat === "FLAC" && candidate.session.canLossless === false) return null;
      if (targetFormat === "MP3_320" && candidate.session.can320 === false) return null;

      if (!candidate.trackTokens) {
        candidate.trackTokens = await getTrackTokens(candidate.arl, candidate.session, trackId, env);
        if (!candidate.trackTokens?.TRACK_TOKEN) {
          candidate.session = await getOrRenewSession(candidate.arl, env, true);
          candidate.trackTokens = await getTrackTokens(candidate.arl, candidate.session, trackId, env);
        }
      }

      let candidateTrackData = candidate.trackTokens;
      if (!candidateTrackData?.TRACK_TOKEN) return null;
      if (targetFormat === "FLAC" && candidateTrackData.FILESIZE_FLAC === "0") return null;

      let resolved;
      let mediaError = null;
      const retryCount = getMediaRetryCount(env);

      for (let mediaAttempt = 0; mediaAttempt <= retryCount; mediaAttempt++) {
        try {
          resolved = await resolveMediaStream(
            candidate.session.licenseToken,
            candidateTrackData.TRACK_TOKEN,
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

      return {
        arl: candidate.arl,
        slot: candidate.slot,
        session: candidate.session,
        trackData: candidateTrackData,
        mediaResult: resolved,
        selectedProfile: QUALITY_MAP[actualKey] || QUALITY_MAP["128"],
        trackId: candidateTrackData.SNG_ID || trackId,
        pools,
      };
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
      return null;
    }
  }

  for (const targetFormat of formatLadder) {
    let activeCandidates = [];
    let unverifiedCandidates = [];

    if (targetFormat === "FLAC" || targetFormat === "MP3_320") {
      activeCandidates = [...(pools.lossless || [])];
      unverifiedCandidates = [...(pools.unverified || [])];
    } else {
      activeCandidates = [...(pools.lossy || []), ...(pools.lossless || [])];
      unverifiedCandidates = [...(pools.unverified || [])];
    }

    if (isRandomStrategy) {
      activeCandidates = shuffleArray(activeCandidates);
      unverifiedCandidates = shuffleArray(unverifiedCandidates);
    }

    // Race authenticated and cold ARLs together. Previously the resolver
    // exhausted the warm pool before even touching unverified ARLs, which made
    // one slow/broken session turn into a long serial fallback chain. The
    // concurrency cap still prevents an uncontrolled 50-ARL request storm.
    const candidates = [...activeCandidates, ...unverifiedCandidates];
    if (!candidates.length) continue;

    // Promise.any gives us the first successful Deezer media resolution.
    // The requested format remains authoritative, so formats themselves are
    // still processed in quality order. Within a format, however, ARLs race.
    for (let i = 0; i < candidates.length; i += concurrency) {
      const batch = candidates.slice(i, i + concurrency);
      const races = batch.map(async candidate => {
        const result = await tryCandidate(candidate, targetFormat);
        if (!result) throw new Error("candidate failed");
        return result;
      });
      try {
        return await Promise.any(races);
      } catch (_) {
        // Every candidate in this batch failed. Launch the next batch.
      }
    }
  }

  throw lastError || new Error("All configured Deezer ARLs failed to resolve playback stream");
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


async function getGatewaySession(env) {
  const pools = await getCandidatePools(env, null);
  const candidates = [
    ...(pools.lossless || []),
    ...(pools.lossy || []),
  ];
  for (const candidate of candidates) {
    const session = candidate?.session;
    if (session?.apiToken) return session;
  }
  const error = new Error("No authenticated Deezer gateway session available");
  error.status = 503;
  error.code = "GATEWAY_SESSION_UNAVAILABLE";
  throw error;
}

async function deezerGateway(method, params = {}, env = null, retryAuth = true) {
  const session = await getGatewaySession(env);
  const url = new URL(DEEZER_GW);
  url.searchParams.set("method", method);
  url.searchParams.set("input", "3");
  url.searchParams.set("api_version", "1.0");
  url.searchParams.set("api_token", session.apiToken);

  // Deezer gw-light expects method arguments in the POST JSON body. Some
  // methods may appear to accept query-string arguments, but returning HTTP
  // 200 with an error envelope is a common failure mode when their payload is
  // placed in the URL instead. Keep only the gateway metadata in the query
  // string and send the actual method payload as JSON.
  const body = JSON.stringify(params || {});
  const response = await fetchWithTimeout(url.toString(), {
    method: "POST",
    headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
    body,
  }, env);
  const result = await readResponseLimited(response);

  if (!result.ok || result.json?.error) {
    const upstream = result.json?.error || {};
    const errorText = typeof upstream === "string"
      ? upstream
      : upstream.message || upstream.MESSAGE || upstream.error || `Deezer gateway ${method} failed (${result.status})`;
    const error = new Error(errorText);
    error.status = result.status >= 400 ? result.status : 502;
    error.code = upstream.code || upstream.CODE || `GATEWAY_${method.replace(/[^A-Za-z0-9]+/g, "_").toUpperCase()}`;

    // Deezer can rotate the gateway checkForm/api token while the Worker still
    // has the old session cached. Refresh that ARL session once and retry the
    // exact same request before surfacing the failure.
    const combined = `${errorText} ${error.code}`.toLowerCase();
    const authFailure = /valid_token|invalid.*token|token.*invalid|expired.*token|login_required|authentication|unauthor/i.test(combined);
    if (retryAuth && authFailure && session?.arl) {
      try {
        clearArlCache(session.arl);
        await getOrRenewSession(session.arl, env, true);
        return await deezerGateway(method, params, env, false);
      } catch (_) {}
    }
    throw error;
  }
  return result.json;
}

function gatewayTrackList(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  return value.data || value.tracks || value.results || value.songs || [];
}

async function getGatewayTrackMix(trackId, env, limit = 50, startWithInputTrack = true) {
  const result = await deezerGateway("song.getSearchTrackMix", {
    sng_id: String(trackId),
    nb: Math.min(100, Math.max(1, Number(limit) || 50)),
    start_with_input_track: startWithInputTrack ? 1 : 0,
  }, env);
  return gatewayTrackList(result);
}

async function getGatewayArtistRadio(artistId, env, limit = 50) {
  const result = await deezerGateway("smart.getSmartRadio", {
    art_id: String(artistId),
    nb: Math.min(100, Math.max(1, Number(limit) || 50)),
  }, env);
  return gatewayTrackList(result);
}

async function getGatewayGenreChart(genreId, env, limit = 50, offset = 0) {
  const result = await deezerGateway("chart.getCharts", {
    genre_id: String(genreId),
    nb: Math.min(100, Math.max(1, Number(limit) || 50)),
    start: Math.max(0, Number(offset) || 0),
  }, env);
  return result;
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

async function catalogResponse(data, status = 200, maxAge = 60, env = null, apiToken = null, clientIp = "unknown", userAgentHash = null, deviceCredential = null) {
  const decoratedData = await decorateStreamUrls(data, apiToken, clientIp, env, userAgentHash, deviceCredential);
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

function invalidStreamBootstrapToken(reason, status, env, requestId) {
  return jsonResponse({
    error: "Invalid stream bootstrap token",
    code: "INVALID_STREAM_TOKEN",
    reason: String(reason || "invalid"),
  }, status, {
    "X-Request-ID": requestId,
    "Cache-Control": "no-store",
  }, env);
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

function deviceBoundStreamsEnabled(env) {
  return envBoolean(env, "DEVICE_BOUND_SIGNED_STREAMS", false);
}

function getDeviceBoundTokenTtlSeconds(env) {
  const value = Number.parseInt(env?.DEVICE_BOUND_TOKEN_TTL_SECONDS, 10);
  if (!Number.isFinite(value)) return 2592000;
  return Math.min(31536000, Math.max(3600, value));
}

async function getDeviceBoundSecret(env) {
  const configured = String(env?.DEVICE_BOUND_SECRET || "").trim();
  if (configured) return configured;
  const streamSecret = String(env?.STREAM_TOKEN_SECRET || "").trim();
  if (streamSecret) return `device:${streamSecret}`;
  const fallback = String(env?.ADMIN_API_KEY || env?.DEEZER_ARL || env?.DEEZER_ARL_1 || "").trim();
  if (fallback) return `device-fallback:${fallback}`;
  return null;
}

async function getDeviceHmacKey(env) {
  const secret = await getDeviceBoundSecret(env);
  if (!secret) return null;
  const cacheKey = `device-hmac:${secret}`;
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

async function signDeviceCredential(payload, env) {
  const key = await getDeviceHmacKey(env);
  if (!key) return null;
  const encodedPayload = base64UrlEncodeBytes(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(encodedPayload));
  return `d1.${encodedPayload}.${base64UrlEncodeBytes(signature)}`;
}

async function registerDeviceCredential(apiToken, env) {
  const now = Math.floor(Date.now() / 1000);
  return signDeviceCredential({
    v: 1,
    type: "device",
    id: await randomTokenNonce(32),
    key: await getClientApiKeyHash(apiToken),
    iat: now,
    exp: now + getDeviceBoundTokenTtlSeconds(env),
  }, env);
}

async function verifyDeviceCredential(token, apiToken, env) {
  try {
    if (!deviceBoundStreamsEnabled(env)) return { valid: true, disabled: true, hash: null, id: null };
    const value = String(token || "").trim();
    const parts = value.split(".");
    if (parts.length !== 3 || parts[0] !== "d1" || parts[1].length > 4096 || parts[2].length > 256) return { valid: false, reason: "malformed" };
    const key = await getDeviceHmacKey(env);
    if (!key) return { valid: false, reason: "not_configured" };
    const payloadBytes = base64UrlDecodeBytes(parts[1]);
    if (payloadBytes.byteLength > 3072) return { valid: false, reason: "malformed" };
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    if (Number(payload?.v) !== 1 || payload?.type !== "device") return { valid: false, reason: "invalid_type" };
    if (!payload?.id || !/^[a-f0-9]{64}$/.test(String(payload.id))) return { valid: false, reason: "invalid_device_id" };
    if (!Number.isFinite(Number(payload?.exp)) || Number(payload.exp) <= Math.floor(Date.now() / 1000)) return { valid: false, reason: "expired" };
    const expectedKeyHash = await getClientApiKeyHash(apiToken);
    if (String(payload.key || "") !== String(expectedKeyHash || "")) return { valid: false, reason: "api_key_mismatch" };
    const signature = base64UrlDecodeBytes(parts[2]);
    if (signature.byteLength !== 32) return { valid: false, reason: "bad_signature" };
    const valid = await crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(parts[1]));
    if (!valid) return { valid: false, reason: "bad_signature" };
    return { valid: true, hash: await sha256Hex(value), id: String(payload.id), payload };
  } catch (_) {
    return { valid: false, reason: "invalid" };
  }
}

function allowQueryDeviceSign(env) {
  return envBoolean(env, "ALLOW_QUERY_DEVICE_SIGN", false);
}

const DEVICE_CREDENTIAL_COOKIE = "__Host-VoriaDevice";

function getCookie(request, name) {
  const header = String(request?.headers?.get("Cookie") || "");
  if (!header) return "";
  const parts = header.split(/;\s*/);
  for (const part of parts) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    const key = part.slice(0, index).trim();
    if (key !== name) continue;
    const value = part.slice(index + 1).trim();
    try { return decodeURIComponent(value); } catch (_) { return value; }
  }
  return "";
}

function getPresentedDeviceCredential(request, env = null) {
  const headerCredential = String(request?.headers?.get("X-Voria-Device") || "").trim();
  if (headerCredential) return headerCredential;

  // Browser/native clients that received /device get an HttpOnly device cookie.
  // This is what lets a generated streamUrl be clickable without putting the
  // long-lived d1 credential into the URL. A copied URL therefore does not carry
  // the device credential to another browser/device.
  const cookieCredential = getCookie(request, DEVICE_CREDENTIAL_COOKIE);
  if (cookieCredential) return cookieCredential;

  if (allowQueryDeviceSign(env)) {
    try {
      const url = new URL(request.url);
      // Raw query credentials are intentionally test-only. Generated streamUrl
      // values use ?device= for the short-lived playback token instead.
      const explicitCredential = String(url.searchParams.get("device_credential") || "").trim();
      if (explicitCredential) return explicitCredential;
      const legacyDevice = String(url.searchParams.get("device") || "").trim();
      if (legacyDevice.startsWith("d1.")) return legacyDevice;
    } catch (_) {}
  }
  return "";
}

async function getRequestDeviceBinding(request, apiToken, env) {
  if (!deviceBoundStreamsEnabled(env)) return { enabled: false, present: false, valid: true, hash: null, id: null };
  const credential = getPresentedDeviceCredential(request, env);
  if (!credential) return { enabled: true, present: false, valid: false, hash: null, id: null, reason: "missing" };
  const headerCredential = String(request?.headers?.get("X-Voria-Device") || "").trim();
  const source = headerCredential
    ? "header"
    : getCookie(request, DEVICE_CREDENTIAL_COOKIE)
      ? "cookie"
      : "query";
  return { enabled: true, present: true, source, ...(await verifyDeviceCredential(credential, apiToken, env)) };
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
    if (expected?.deviceBindingHash && String(payload.device || "") !== String(expected.deviceBindingHash)) {
      return { valid: false, reason: payload.device ? "device_mismatch" : "device_missing" };
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

async function buildStreamToken(trackId, apiToken, clientIp, env, userAgentHash = null, deviceBindingHash = null) {
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
    ...(deviceBoundStreamsEnabled(env) && deviceBindingHash ? { device: String(deviceBindingHash) } : {}),
    iat: now,
    exp: now + ttl,
  }, env);
}

function getClientIp(request) {
  return String(request?.headers?.get("CF-Connecting-IP") || request?.headers?.get("X-Forwarded-For")?.split(",")[0] || "unknown").trim() || "unknown";
}

function boundedCacheSet(map, key, value, ttlMs, maxSize = 4096) {
  const now = Date.now();
  if (map.has(key)) map.delete(key);
  while (map.size >= maxSize) map.delete(map.keys().next().value);
  map.set(key, { value, expiresAt: now + ttlMs });
}

function boundedCacheGet(map, key) {
  const item = map.get(key);
  if (!item) return null;
  if (item.expiresAt <= Date.now()) {
    map.delete(key);
    return null;
  }
  map.delete(key);
  map.set(key, item);
  return item.value;
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


async function buildStreamSession(trackId, apiToken, clientIp, env, userAgentHash = null, deviceBindingHash = null) {
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
    ...(deviceBoundStreamsEnabled(env) && deviceBindingHash ? { device: String(deviceBindingHash) } : {}),
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

async function establishStreamSession(trackId, apiToken, clientIp, env, userAgentHash = null, deviceBindingHash = null) {
  const token = await buildStreamSession(trackId, apiToken, clientIp, env, userAgentHash, deviceBindingHash);
  return streamSessionCookie(token, env);
}

function authenticatedPlaybackRequiresBootstrap(env, authToken) {
  if (!authToken) return false;
  const value = String(env?.STREAM_REQUIRE_BOOTSTRAP ?? "true").trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(value);
}

async function maybeRefreshStreamSession(sessionCheck, trackId, apiToken, clientIp, env, userAgentHash = null, deviceBindingHash = null) {
  if (!sessionCheck?.valid || !sessionCheck?.payload) return null;
  const remaining = Number(sessionCheck.payload.exp) - Math.floor(Date.now() / 1000);
  if (remaining > getStreamSessionRefreshThresholdSeconds(env)) return null;
  return establishStreamSession(trackId, apiToken, clientIp, env, userAgentHash, deviceBindingHash);
}

async function appendStreamTokenToUrl(streamUrl, apiToken, clientIp, env, userAgentHash = null, deviceBindingHash = null) {
  if (!streamUrl || !apiToken || String(apiToken).trim() === "" || String(apiToken).trim() === "public") return streamUrl;
  try {
    const url = new URL(streamUrl);
    const trackId = url.searchParams.get("id") || url.searchParams.get("track_id");
    if (!trackId) return streamUrl;

    // Bootstrap tokens are temporary credentials. Never coalesce or cache the
    // generated token: every emitted stream URL receives a fresh nonce.
    const token = await buildStreamToken(trackId, apiToken, clientIp, env, userAgentHash, deviceBindingHash);
    if (token) {
      if (deviceBoundStreamsEnabled(env) && deviceBindingHash) {
        // In device-bound mode, the URL carries only a short-lived playback
        // token. The long-lived d1 device credential NEVER enters streamUrl.
        // The request still requires X-Voria-Device (or an explicitly supplied
        // raw d1 credential for testing via ALLOW_QUERY_DEVICE_SIGN).
        url.searchParams.delete("stream_token");
        url.searchParams.set("device", token);
      } else {
        url.searchParams.set("stream_token", token);
      }
    }
    return url.toString();
  } catch (_) {
    return streamUrl;
  }
}

async function decorateStreamUrls(value, apiToken, clientIp, env, userAgentHash = null, deviceCredential = null) {
  if (!apiToken || String(apiToken).trim() === "" || String(apiToken).trim() === "public") return value;

  if (Array.isArray(value)) {
    return Promise.all(value.map(item => decorateStreamUrls(item, apiToken, clientIp, env, userAgentHash, deviceCredential)));
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value);
    const out = Array.isArray(value) ? [] : {};
    await Promise.all(entries.map(async ([key, item]) => {
      if (key === "streamUrl" && typeof item === "string" && item.includes("/stream-track/")) {
        let streamUrl = appendAuthenticatedStreamCredentials(item, apiToken, deviceCredential, env);
        if (deviceBoundStreamsEnabled(env)) {
          const binding = deviceCredential ? await verifyDeviceCredential(deviceCredential, apiToken, env) : { valid: false, hash: null };
          if (binding.valid && binding.hash) streamUrl = await appendStreamTokenToUrl(streamUrl, apiToken, clientIp, env, userAgentHash, binding.hash);
        } else {
          streamUrl = await appendStreamTokenToUrl(streamUrl, apiToken, clientIp, env, userAgentHash);
        }
        out[key] = streamUrl;
      } else if (item && typeof item === "object") {
        out[key] = await decorateStreamUrls(item, apiToken, clientIp, env, userAgentHash, deviceCredential);
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

function appendAuthenticatedStreamCredentials(streamUrl, apiToken = null, deviceCredential = null, env = null) {
  // Never place the long-lived d1 device credential in generated stream URLs.
  // Device-bound playback tokens are added later by appendStreamTokenToUrl().
  return appendApiKeyToStreamUrl(streamUrl, apiToken);
}

function buildTrackStreamUrl(origin, trackId, apiToken = null, deviceCredential = null, env = null) {
  if (!origin || trackId === undefined || trackId === null || String(trackId).trim() === "") return null;
  const streamUrl = `${String(origin).replace(/\/$/, "")}/stream-track/?id=${encodeURIComponent(String(trackId))}`;
  return appendAuthenticatedStreamCredentials(streamUrl, apiToken, deviceCredential, env);
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

async function generatedSimilarityPayload(requestUrl, env, apiToken, clientIp, preferExplicit, limit, offset, seedArgs, type = "generated_playlist", deviceCredential = null) {
  const queryForAlt = seedArgs.query || seedArgs.title || seedArgs.artist || seedArgs.id || seedArgs.isrc || "";
  const queryAllowsAlt = isAltAllowed(requestUrl, queryForAlt, env, apiToken, clientIp);
  const seed = await discoverTrack(seedArgs, env, queryAllowsAlt, preferExplicit);
  if (!seed?.id) {
    const error = new Error("Could not resolve the recommendation seed track");
    error.status = 404;
    error.code = "RECOMMENDATION_SEED_NOT_FOUND";
    throw error;
  }

  // The legacy gw song.getSearchTrackMix method is currently returning HTTP 200
  // application-error envelopes. Use the working Deezer Pipe recommendedTracks
  // path for seed-aware similarity instead of letting that legacy gateway call
  // break /playlist and /radio.
  const similar = await getSimilarRecommendations(
    { id: seed.id },
    env,
    apiToken,
    clientIp,
    queryAllowsAlt,
    preferExplicit,
    limit,
    offset
  );

  const normalizedSeed = similar?.seed || normalizeTrack(seed, requestUrl.origin, apiToken);
  const page = Array.isArray(similar?.data) ? similar.data : [];
  const data = [];
  const seenKeys = new Set();

  if (normalizedSeed?.id != null && addTrackDedupKeys(seenKeys, normalizedSeed)) {
    data.push({ ...normalizedSeed, streamUrl: buildTrackStreamUrl(requestUrl.origin, normalizedSeed.id, apiToken, deviceCredential, env) });
  }
  for (const track of page) {
    if (!track?.id || !addTrackDedupKeys(seenKeys, track)) continue;
    data.push({ ...track, streamUrl: buildTrackStreamUrl(requestUrl.origin, track.id, apiToken, deviceCredential, env) });
  }

  return {
    version: API_VERSION,
    type,
    generated: true,
    title: normalizedSeed ? `${normalizedSeed.title || "Track"} ${type === "track_radio" ? "Radio" : "Playlist"}` : (type === "track_radio" ? "Track Radio" : "Generated Playlist"),
    description: normalizedSeed ? `Tracks similar to ${normalizedSeed.title || "this track"}${normalizedSeed.artist?.name ? ` by ${normalizedSeed.artist.name}` : ""}.` : "Tracks similar to the supplied seed.",
    seed: normalizedSeed,
    seed_id: normalizedSeed?.id != null ? String(normalizedSeed.id) : String(seed.id),
    source: similar?.source || "deezer_pipe_recommendedTracks",
    total: similar?.total ?? data.length,
    next: similar?.next || null,
    previous: similar?.previous || null,
    data,
  };
}
async function handleCatalogRoute(requestUrl, env, segments, apiToken = null, clientIp = "unknown", userAgentHash = null, deviceCredential = null) {
  const catalogResponseForRequest = (...args) => catalogResponse(...args, deviceCredential);
  const rootSegment = segments[0] || "";
  const subSegment = segments[1] || "";
  const actionSegment = segments[2] || "";
  const { limit, offset } = normalizeLimitOffset(requestUrl);
  const allowAlt = isAltAllowed(requestUrl, "", env, apiToken, clientIp);
  const preferExplicit = isExplicitPreferred(requestUrl, env, apiToken, clientIp);

  if (!rootSegment) {
    return catalogResponseForRequest(buildRootStatus(env), 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "info-api") {
    return catalogResponseForRequest({
      version: API_VERSION,
      provider: "deezer",
      name: "Deezer HiFi Turbo API & Streaming Gateway",
      cpuBudgetSafety: "bounded-chunk-processing",
      safeChunkSize: `${SAFE_DEFAULT_CHUNK / 1024}KB`,
      features: {
        structuredSearch: "/?s&title=BMO&artist=Ari Lennox",
        catalog: "/search, /track, /album, /artist, /playlist, /chart, /genre, /radio, /recommendations, /cover",
        recommendationModes: "personalized by default; song-similar via id, q/query/s, isrc/i, title, artist using Deezer Pipe recommendedTracks",
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
    return catalogResponseForRequest({ version: API_VERSION, data: normalizeTrack(track, requestUrl.origin, apiToken) }, 200, 30, env, apiToken, clientIp, userAgentHash);
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
      return catalogResponseForRequest({ version: API_VERSION, type: "track", query: isrc, data: items, total: items.length, next: null, previous: null }, 200, 30, env, apiToken, clientIp, userAgentHash);
    }

    const queryInfo = normalizeSearchQuery(q, title, artist);
    const searchPath = type === "track" ? "search" : `search/${type}`;
    const result = await publicApi(searchPath, { q: queryInfo.clean, limit, index: offset }, env, apiToken, clientIp);

    if (type === "track" && Array.isArray(result?.data) && !queryAllowsAlt) {
      const standard = result.data.filter(t => !isAltVersion(t));
      if (standard.length > 0) result.data = standard;
    }

    const normalizer = type === "track" ? (track) => normalizeTrack(track, requestUrl.origin, apiToken) : type === "album" ? normalizeAlbum : type === "artist" ? normalizeArtist : type === "playlist" ? normalizePlaylist : x => x;
    return catalogResponseForRequest({ version: API_VERSION, type, query: queryInfo.clean, alt_allowed: queryAllowsAlt, explicit_preferred: preferExplicit, ...normalizeCollection(result, normalizer) }, 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "album") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id parameter", 400, null, env);

    if (actionSegment === "tracks") {
      const tracks = await publicApi(`album/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponseForRequest({ version: API_VERSION, ...normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken)) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    const [album, tracks] = await Promise.all([
      publicApi(`album/${encodeURIComponent(id)}`, {}, env),
      publicApi(`album/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env),
    ]);

    const normalizedTracks = normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken));
    return catalogResponseForRequest({ version: API_VERSION, data: normalizeAlbum(album), tracks: normalizedTracks.data, pagination: { total: normalizedTracks.total, limit, offset } }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "artist") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) return apiErrorResponse("Missing id parameter", 400, null, env);

    if (actionSegment === "top") {
      const top = await publicApi(`artist/${encodeURIComponent(id)}/top`, { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponseForRequest({ version: API_VERSION, ...normalizeCollection(top, (track) => normalizeTrack(track, requestUrl.origin, apiToken)) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    if (actionSegment === "albums") {
      const albums = await publicApi(`artist/${encodeURIComponent(id)}/albums`, { limit, index: offset }, env, apiToken, clientIp);
      return catalogResponseForRequest({ version: API_VERSION, ...normalizeCollection(albums, normalizeAlbum) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    const artist = await publicApi(`artist/${encodeURIComponent(id)}`, {}, env, apiToken, clientIp);
    return catalogResponseForRequest({ version: API_VERSION, artist: normalizeArtist(artist) }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "playlist") {
    const id = subSegment || requestUrl.searchParams.get("id");
    const isrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
    const query = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("s");
    const title = requestUrl.searchParams.get("title") || requestUrl.searchParams.get("track") || requestUrl.searchParams.get("song");
    const artist = requestUrl.searchParams.get("artist");
    const generate = Boolean(isrc || query || title || artist || (id && /^\d+$/.test(String(id)) && requestUrl.searchParams.get("mode") !== "catalog") || requestUrl.searchParams.get("mode") === "generate" || requestUrl.searchParams.get("playlist") === "generated");

    if (generate) {
      if (!id && !isrc && !query && !title && !artist) return apiErrorResponse("Missing track identifier for generated playlist", 400, { supported_parameters: ["id", "isrc", "q", "query", "s", "title", "artist", "limit", "offset"] }, env);
      const payload = await generatedSimilarityPayload(requestUrl, env, apiToken, clientIp, preferExplicit, limit, offset, { id, isrc, query, title, artist }, "generated_playlist", deviceCredential);
      return catalogResponseForRequest(payload, 200, 30, env, apiToken, clientIp, userAgentHash);
    }

    if (!id) return apiErrorResponse("Missing playlist id or track seed", 400, { generated_playlist: "Use /playlist?id=<track_id>, /playlist?isrc=<isrc>, or /playlist?q=<title artist>" }, env);

    if (actionSegment === "tracks" || actionSegment === "full") {
      const tracks = await publicApi(`playlist/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env);
      return catalogResponseForRequest({ version: API_VERSION, playlist_id: id, ...normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken)) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }

    try {
      const [playlist, tracks] = await Promise.all([
        publicApi(`playlist/${encodeURIComponent(id)}`, {}, env),
        publicApi(`playlist/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env),
      ]);
      const normalizedTracks = normalizeCollection(tracks, (track) => normalizeTrack(track, requestUrl.origin, apiToken));
      return catalogResponseForRequest({ version: API_VERSION, data: normalizePlaylist(playlist), tracks: normalizedTracks.data, pagination: { total: normalizedTracks.total, limit, offset } }, 200, 120, env, apiToken, clientIp, userAgentHash);
    } catch (playlistError) {
      const track = await discoverTrack({ id }, env, allowAlt, preferExplicit).catch(() => null);
      if (!track?.id) throw playlistError;
      const payload = await generatedSimilarityPayload(requestUrl, env, apiToken, clientIp, preferExplicit, limit, offset, { id: String(track.id) }, "generated_playlist", deviceCredential);
      return catalogResponseForRequest(payload, 200, 30, env, apiToken, clientIp, userAgentHash);
    }
  }

  if (rootSegment === "chart") {
    const type = subSegment || requestUrl.searchParams.get("type") || "tracks";
    const supported = new Set(["tracks", "albums", "artists", "playlists"]);
    if (!supported.has(type)) return apiErrorResponse("Unsupported chart type", 400, { supported: [...supported] }, env);
    const result = await publicApi(`chart/0/${encodeURIComponent(type)}`, { limit, index: offset }, env, apiToken, clientIp);
    const normalizer = type === "tracks" ? (track) => normalizeTrack(track, requestUrl.origin, apiToken) : type === "albums" ? normalizeAlbum : type === "artists" ? normalizeArtist : normalizePlaylist;
    return catalogResponseForRequest({ version: API_VERSION, type, ...normalizeCollection(result, normalizer) }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "genre") {
    const id = subSegment || requestUrl.searchParams.get("id");
    if (!id) {
      let result = null;
      try { result = await publicApi("genre", { limit, index: offset }, env); } catch (_) {}
      if (result?.data?.length) {
        return catalogResponseForRequest({ version: API_VERSION, type: "genres", ...normalizeCollection(result, normalizeGenre) }, 200, 300, env, apiToken, clientIp, userAgentHash);
      }
      const fallbackGenres = [
        { id: 0, name: "All" }, { id: 132, name: "Pop" }, { id: 116, name: "Rap/Hip Hop" },
        { id: 152, name: "Rock" }, { id: 113, name: "Dance" }, { id: 106, name: "Electro" },
        { id: 165, name: "R&B" }, { id: 144, name: "Jazz" }, { id: 98, name: "Classical" },
        { id: 173, name: "Reggae" }, { id: 197, name: "Soundtracks" }, { id: 464, name: "Metal" },
        { id: 169, name: "Alternative" },
      ];
      const page = fallbackGenres.slice(offset, offset + limit).map(normalizeGenre);
      return catalogResponseForRequest({ version: API_VERSION, type: "genres", data: page, total: fallbackGenres.length, next: offset + page.length < fallbackGenres.length ? `?limit=${limit}&offset=${offset + page.length}` : null, previous: offset > 0 ? `?limit=${limit}&offset=${Math.max(0, offset - limit)}` : null, source: "deezer_gateway_genre_fallback" }, 200, 300, env, apiToken, clientIp, userAgentHash);
    }
    // Deezer's canonical genre chart is /chart/{genre_id}.
    // Resolve the genre first instead of silently inventing a "Genre {id}" object
    // when Deezer rejects an invalid/non-existent genre ID.
    let genre;
    try {
      genre = await publicApi(`genre/${encodeURIComponent(id)}`, {}, env);
    } catch (error) {
      const status = Number(error?.status) >= 400 ? Number(error.status) : 404;
      return apiErrorResponse(
        error?.message || `Genre ${id} was not found`,
        status,
        { id: String(id), code: error?.code || "GENRE_NOT_FOUND" },
        env,
      );
    }

    const chart = await publicApi(`chart/${encodeURIComponent(id)}`, { limit, index: offset }, env, apiToken, clientIp);
    const tracks = Array.isArray(chart?.tracks?.data) ? chart.tracks.data : (Array.isArray(chart?.tracks) ? chart.tracks : []);
    const artists = Array.isArray(chart?.artists?.data) ? chart.artists.data : (Array.isArray(chart?.artists) ? chart.artists : []);
    const albums = Array.isArray(chart?.albums?.data) ? chart.albums.data : (Array.isArray(chart?.albums) ? chart.albums : []);

    const normalizedTracks = tracks.map(t => normalizeTrack(t, requestUrl.origin, apiToken)).filter(Boolean);
    const normalizedArtists = normalizeCollection({ data: artists, total: Number(chart?.artists?.total) || artists.length }, normalizeArtist);
    const normalizedAlbums = normalizeCollection({ data: albums, total: Number(chart?.albums?.total) || albums.length }, normalizeAlbum);

    // Keep genre responses compact. Do not emit `radios: null` or empty
    // albums/tracks collections when Deezer has no data for them.
    const payload = {
      version: API_VERSION,
      type: "genre",
      genre: normalizeGenre(genre),
      source: "deezer_public_chart",
    };

    if (normalizedArtists.data.length || normalizedArtists.total > 0) payload.artists = normalizedArtists;
    if (normalizedAlbums.data.length || normalizedAlbums.total > 0) payload.albums = normalizedAlbums;
    if (normalizedTracks.length || Number(chart?.tracks?.total) > 0) {
      payload.tracks = {
        data: normalizedTracks,
        total: Number(chart?.tracks?.total) || normalizedTracks.length,
      };
    }

    return catalogResponseForRequest(payload, 200, 300, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "radio") {
    const id = subSegment || requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    const isrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
    const query = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("s");
    const title = requestUrl.searchParams.get("title") || requestUrl.searchParams.get("track") || requestUrl.searchParams.get("song");
    const artist = requestUrl.searchParams.get("artist");
    const trackMode = Boolean(isrc || query || title || artist || (id && /^\d+$/.test(String(id)) && requestUrl.searchParams.get("mode") !== "catalog") || requestUrl.searchParams.get("mode") === "track" || requestUrl.searchParams.get("radio") === "track");
    if (trackMode) {
      if (!id && !isrc && !query && !title && !artist) return apiErrorResponse("Missing track seed for radio", 400, null, env);
      const payload = await generatedSimilarityPayload(requestUrl, env, apiToken, clientIp, preferExplicit, limit, offset, { id, isrc, query, title, artist }, "track_radio", deviceCredential);
      return catalogResponseForRequest(payload, 200, 30, env, apiToken, clientIp, userAgentHash);
    }
    if (!id) {
      const result = await publicApi("radio", { limit, index: offset }, env);
      return catalogResponseForRequest({ version: API_VERSION, type: "radios", ...normalizeCollection(result, normalizeRadio) }, 200, 120, env, apiToken, clientIp, userAgentHash);
    }
    const radio = await publicApi(`radio/${encodeURIComponent(id)}`, {}, env);
    const tracks = await publicApi(`radio/${encodeURIComponent(id)}/tracks`, { limit, index: offset }, env).catch(() => null);
    return catalogResponseForRequest({ version: API_VERSION, type: "radio", data: normalizeRadio(radio), tracks: tracks ? normalizeCollection(tracks, t => normalizeTrack(t, requestUrl.origin, apiToken)) : null }, 200, 120, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "recommendations") {
    if (envBoolean(env, "DISABLE_RECOMMENDATIONS", false)) {
      return apiErrorResponse("Recommendations are disabled on this instance", 404, { endpoint: "/recommendations" }, env);
    }

    const recommendationId = subSegment || requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    const recommendationIsrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
    const recommendationQuery = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("s");
    const recommendationTitle = requestUrl.searchParams.get("title") || requestUrl.searchParams.get("track") || requestUrl.searchParams.get("song");
    const recommendationArtist = requestUrl.searchParams.get("artist");

    if (requestUrl.searchParams.has("user_id") && !recommendationId && !recommendationIsrc && !recommendationQuery && !recommendationTitle && !recommendationArtist) {
      const result = await getPersonalizedRecommendations(env, null, limit, offset, requestUrl.searchParams.get("user_id"));
      const streamData = Array.isArray(result.data)
        ? result.data.map(track => ({
            ...track,
            streamUrl: buildTrackStreamUrl(requestUrl.origin, track?.id, apiToken, deviceCredential, env),
          }))
        : [];
      return catalogResponseForRequest({
        version: API_VERSION,
        type: "tracks",
        personalized: true,
        ...result,
        data: streamData,
      }, 200, 30, env, apiToken, clientIp, userAgentHash);
    }

    const hasSeed = Boolean(recommendationId || recommendationIsrc || recommendationQuery || recommendationTitle || recommendationArtist);
    if (!hasSeed && !requestUrl.searchParams.has("user_id")) {
      const result = await getPersonalizedRecommendations(env, null, limit, offset, null);
      const streamData = Array.isArray(result.data)
        ? result.data.map(track => ({
            ...track,
            streamUrl: buildTrackStreamUrl(requestUrl.origin, track?.id, apiToken, deviceCredential, env),
          }))
        : [];
      return catalogResponseForRequest({
        version: API_VERSION,
        type: "tracks",
        personalized: true,
        ...result,
        data: streamData,
      }, 200, 30, env, apiToken, clientIp, userAgentHash);
    }

    if (requestUrl.searchParams.has("user_id")) {
      return apiErrorResponse("user_id cannot be combined with song-based recommendations", 400, {
        endpoint: "/recommendations",
        supported_parameters: ["id", "q", "isrc", "title", "artist", "limit", "offset", "index"],
      }, env);
    }

    const queryForAlt = recommendationQuery || recommendationTitle || recommendationArtist || recommendationId || recommendationIsrc || "";
    const queryAllowsAlt = isAltAllowed(requestUrl, queryForAlt, env, apiToken, clientIp);
    const result = await getSimilarRecommendations({
      id: recommendationId,
      isrc: recommendationIsrc,
      query: recommendationQuery,
      title: recommendationTitle,
      artist: recommendationArtist,
    }, env, apiToken, clientIp, queryAllowsAlt, preferExplicit, limit, offset);

    const streamData = Array.isArray(result.data)
      ? result.data.map(track => ({
          ...track,
          streamUrl: buildTrackStreamUrl(requestUrl.origin, track?.id, apiToken, deviceCredential, env),
        }))
      : [];

    return catalogResponseForRequest({
      version: API_VERSION,
      type: "tracks",
      personalized: false,
      similar_to: result.seed,
      seed_id: result.seed_id,
      source: result.source,
      total: result.total,
      next: result.next,
      previous: result.previous,
      data: streamData,
    }, 200, 30, env, apiToken, clientIp, userAgentHash);
  }

  if (rootSegment === "cover") {
    const rawUrl = subSegment || requestUrl.searchParams.get("url") || requestUrl.searchParams.get("hash");
    const rawId = requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
    const isrc = requestUrl.searchParams.get("isrc") || requestUrl.searchParams.get("i");
    const query = requestUrl.searchParams.get("q") || requestUrl.searchParams.get("query") || requestUrl.searchParams.get("s");
    const type = requestUrl.searchParams.get("type") === "artist" ? "artist" : "cover";
    if (rawUrl) {
      const artwork = buildArtworkUrls(rawUrl, type);
      if (!artwork) return apiErrorResponse("Invalid artwork hash/url", 400, null, env);
      return catalogResponseForRequest({ version: API_VERSION, type, data: artwork }, 200, 86400, env, apiToken, clientIp, userAgentHash);
    }
    if (type === "artist" && rawId) {
      const artistData = await publicApi(`artist/${encodeURIComponent(rawId)}`, {}, env);
      const artwork = buildArtworkUrls(artistData?.picture_xl || artistData?.picture || artistData?.picture_medium || artistData?.picture_small, "artist");
      if (!artwork) return apiErrorResponse("Artist artwork not found", 404, { id: rawId }, env);
      return catalogResponseForRequest({ version: API_VERSION, type: "artist", id: String(rawId), data: artwork }, 200, 86400, env, apiToken, clientIp, userAgentHash);
    }
    if (rawId || isrc || query) {
      const track = await discoverTrack({ id: rawId, isrc, query }, env, allowAlt, preferExplicit);
      if (!track?.id) return apiErrorResponse("Track not found", 404, null, env);
      const source = track.album?.cover_xl || track.album?.cover || track.md5_image || track.album?.md5_image;
      const artwork = buildArtworkUrls(source, "cover");
      if (!artwork) return apiErrorResponse("Track artwork not found", 404, { id: track.id }, env);
      return catalogResponseForRequest({ version: API_VERSION, type: "cover", track_id: String(track.id), data: artwork }, 200, 86400, env, apiToken, clientIp, userAgentHash);
    }
    return apiErrorResponse("Missing artwork hash/url or track identifier", 400, { supported_parameters: ["url", "hash", "id", "track_id", "isrc", "q", "type"] }, env);
  }

  return null;
}


function getTestRoutingPresentedKey(requestUrl) {
  const direct = requestUrl.searchParams.get("api_key")?.trim() || requestUrl.searchParams.get("key")?.trim();
  if (direct) return direct;
  const pathMatch = requestUrl.pathname.match(/^\/test(?:-routing|Routing|Routings)&api_key=(.+)$/i);
  return pathMatch ? decodeURIComponent(pathMatch[1]).trim() : "";
}

function isTestRoutingsPath(requestUrl) {
  const path = requestUrl.pathname.replace(/\/+$/, "") || "/";
  return /^\/test(?:-routing|Routing|Routings)(?:\/run)?$/i.test(path) || /^\/test(?:-routing|Routing|Routings)&api_key=.+$/i.test(path);
}

function authenticateTestRoutings(requestUrl, env) {
  const { mappings } = getMemoizedConfig(env);
  const publicApi = String(env?.PUBLIC_API ?? "false").toLowerCase() === "true";
  const token = getTestRoutingPresentedKey(requestUrl);
  if (publicApi && mappings.size === 0) return { authorized: true, tokenId: token || "public", allowedSlots: null };
  if (!token || !mappings.has(token)) return { authorized: false, tokenId: null, allowedSlots: null };
  return { authorized: true, tokenId: token, allowedSlots: mappings.get(token) };
}

function testRoutingErrorDetails(error, fallbackStatus = 502) {
  const status = Number(error?.status || error?.errorNumber || fallbackStatus);
  const upstreamCode = error?.upstreamCode || error?.code || null;
  const message = error?.upstreamMessage || error?.message || String(error || "Unknown error");
  return {
    errorNumber: Number.isFinite(status) && status > 0 ? status : fallbackStatus,
    errorCode: upstreamCode,
    errorText: String(message).slice(0, 1000),
  };
}

function makeTestRoutingLine(text = "") {
  return `${new Date().toISOString()}  ${String(text)}\n`;
}

function buildTestRoutingsHtml(requestUrl, env, apiKey) {
  const safeVersion = String(API_VERSION).replace(/[^0-9A-Za-z._-]/g, "");
  const origin = requestUrl.origin;
  const encodedKey = btoa(unescape(encodeURIComponent(String(apiKey || ""))));
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Worker Routing Diagnostics</title><style>
:root{color-scheme:dark;--bg:#07090d;--panel:#0b0f15;--line:#202936;--muted:#778397;--text:#e8edf5;--ok:#78e6a0;--bad:#ff7e8b;--key:#8bd5ff}*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text)}body{font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}main{width:min(100%,1050px);margin:0 auto;padding:18px}.json{border:1px solid var(--line);background:var(--panel);border-radius:12px;overflow:hidden}.bar{display:flex;justify-content:space-between;padding:12px 15px;border-bottom:1px solid var(--line)}.title{font-weight:700}.version{color:var(--muted);font-size:12px}.body{padding:16px}.key{color:var(--key)}.brace{color:#aeb8c8;font-weight:700}.field{padding-left:22px}.terminal{height:68vh;min-height:360px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;padding:13px 14px;margin:12px 0;border:1px solid #1e2733;border-radius:8px;background:#06080c}.line{min-height:1.55em}.ok{color:var(--ok)}.fail{color:var(--bad)}.dim{color:var(--muted)}@media(max-width:600px){main{padding:8px}.body{padding:11px}.terminal{height:72vh;min-height:300px}}
</style></head><body><main><section class="json"><div class="bar"><span class="title">cfw-deezer-hifi-api /test-routing</span><span class="version">v${safeVersion}</span></div><div class="body"><div class="brace">{</div><div class="field"><span class="key">"diagnostics"</span>: {</div><div class="field"><span class="key">"interactive"</span>: true,</div><div class="field"><span class="key">"description"</span>: "Routing-only end-to-end diagnostic",</div><div class="field"><span class="key">"arl_health"</span>: "separate at /arl-health"</div><div class="field">}</div><div class="brace">,</div><div id="terminal" class="terminal"></div><div id="done">"status": "starting"</div><div class="brace">}</div></div></section></main><script>
const origin=${JSON.stringify(origin)},key=decodeURIComponent(escape(atob(${JSON.stringify(encodedKey)}))),trackId=new URL(location.href).searchParams.get('track_id')||'920991742',terminal=document.getElementById('terminal'),done=document.getElementById('done');const append=(x,c='')=>{const d=document.createElement('div');d.className='line '+c;d.textContent=x;terminal.appendChild(d);terminal.scrollTop=terminal.scrollHeight};const cls=x=>x.includes('FAIL')?'fail':x.includes('PASS')?'ok':x.includes('SKIP')?'dim':'';(async()=>{append('cfw-deezer-hifi-api routing diagnostics starting...','dim');append('Track ID: '+trackId,'dim');append('Routing/catalog/playback tests only. ARL health: /arl-health','dim');const u=new URL(origin+'/test-routing/run');u.searchParams.set('phase','routes');u.searchParams.set('api_key',key);u.searchParams.set('track_id',trackId);try{const r=await fetch(u,{cache:'no-store'});if(!r.ok){append('HTTP '+r.status,'fail');done.textContent='"status": "failed"';return}const rd=r.body?.getReader();if(!rd){append('Diagnostic stream unavailable','fail');done.textContent='"status": "failed"';return}const dec=new TextDecoder();let b='';while(true){const {value,done:d}=await rd.read();if(d)break;b+=dec.decode(value,{stream:true});const a=b.split('\n');b=a.pop()||'';for(const line of a){if(!line)continue;if(line==='@@DONE@@'){done.textContent='"status": "complete"';return}append(line,cls(line))}}if(b)append(b,cls(b));done.textContent='"status": "complete"'}catch(e){append('CLIENT_ERROR: '+(e?.message||String(e)),'fail');done.textContent='"status": "failed"'}})();</script></body></html>`;
}
async function streamTestRoutingsResponse(request, env, requestUrl, phase, trackId, apiKey, allowedSlots) {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const write = (text) => controller.enqueue(encoder.encode(makeTestRoutingLine(text)));
      const writeRaw = (text) => controller.enqueue(encoder.encode(`${text}\n`));
      try {
        write(`=== cfw-deezer-hifi-api ${API_VERSION} routing diagnostics ===`);
        write(`Phase: routes`);
        if (!/^\d+$/.test(String(trackId || ""))) throw Object.assign(new Error("A numeric Deezer Track ID is required"), { status: 400, code: "INVALID_TRACK_ID" });
        write(`Track ID: ${trackId}`);
        write("Testing routing/catalog/playback paths only. ARL health is handled separately by /arl-health.");
        const base = new URL("https://diagnostic.invalid");
        const tests = [
          ["/", async()=>({status:200, value:buildRootStatus(env)})],
          ["/info-api", async()=>({status:200, value:{ok:true}})],
          ["/routing", async()=>({status:200, value:routingInfo(env)})],
          ["/docs", async()=>({status:200, value:buildDocs(base, env)})],
          ["/recommendations?q="+encodeURIComponent(searchText), async()=>handleCatalogRoute(new URL(`/recommendations?q=${encodeURIComponent(searchText)}`, base), env, ["recommendations"], apiKey, "diagnostic", null)],
          ["/recommendations?isrc="+(seed?.isrc || seed?.ISRC || "n/a"), async()=>{
            const seedIsrc=String(seed?.isrc || seed?.ISRC || "").trim();
            if (!seedIsrc) return {status:204, value:{skipped:"seed has no ISRC"}};
            return handleCatalogRoute(new URL(`/recommendations?isrc=${encodeURIComponent(seedIsrc)}`, base), env, ["recommendations"], apiKey, "diagnostic", null);
          }],
          ["/info?id="+trackId, async()=>handleCatalogRoute(new URL(`/info?id=${trackId}`, base), env, ["info"], apiKey, "diagnostic", null)],
          ["/search?q="+encodeURIComponent(searchText), async()=>handleCatalogRoute(new URL(`/search?q=${encodeURIComponent(searchText)}`, base), env, ["search"], apiKey, "diagnostic", null)],
          ["/track?id="+trackId, async()=>{const t=await discoverTrack({id:String(trackId)},env,true,true);if(!t?.id)throw Object.assign(new Error("Track metadata could not be resolved"),{status:404,code:"TRACK_NOT_FOUND"});const r=await resolvePlaybackStreamOnly(String(trackId),"best",env,allowedSlots);return {status:200,value:{id:t.id,format:r.mediaResult?.format}};}],
          ["/playlist?id="+trackId, async()=>handleCatalogRoute(new URL(`/playlist?id=${trackId}`, base), env, ["playlist"], apiKey, "diagnostic", null)],
          ["/radio?id="+trackId, async()=>handleCatalogRoute(new URL(`/radio?id=${trackId}`, base), env, ["radio"], apiKey, "diagnostic", null)],
          ["/recommendations?id="+trackId, async()=>handleCatalogRoute(new URL(`/recommendations?id=${trackId}`, base), env, ["recommendations"], apiKey, "diagnostic", null)],
          ["/cover?id="+trackId, async()=>handleCatalogRoute(new URL(`/cover?id=${trackId}`, base), env, ["cover"], apiKey, "diagnostic", null)],
          ["/lyrics?id="+trackId, async()=>{const pools=await getCandidatePools(env, allowedSlots);const session=pickAuxiliarySession(pools,env)||pools.lossless[0]?.session||pools.lossy[0]?.session;if(!session) throw Object.assign(new Error("No session for lyrics"),{status:503,code:"LYRICS_SESSION_UNAVAILABLE"});const lyrics=await getDeezerLyrics(session,String(trackId),env);if(!lyrics) return {status:204,value:{skipped:"lyrics not available for diagnostic track",code:"LYRICS_NOT_FOUND"}};return {status:200,value:{hasWordSync:Boolean(lyrics.hasWordSync)}};}],
          ["/chart?type=tracks", async()=>handleCatalogRoute(new URL("/chart?type=tracks", base), env, ["chart"], apiKey, "diagnostic", null)],
          ["/genre?id=132", async()=>handleCatalogRoute(new URL("/genre?id=132", base), env, ["genre"], apiKey, "diagnostic", null)],
          ["/genre", async()=>handleCatalogRoute(new URL("/genre", base), env, ["genre"], apiKey, "diagnostic", null)],
        ];
        if (deviceBoundStreamsEnabled(env)) {
          tests.push(["/device", async()=>{
            const credential=await registerDeviceCredential(apiKey, env);
            if (!credential) throw Object.assign(new Error("Device signing is enabled but no credential could be registered"),{status:503,code:"DEVICE_SIGNING_NOT_CONFIGURED"});
            const verified=await verifyDeviceCredential(credential, apiKey, env);
            if (!verified?.valid || !verified?.id) throw Object.assign(new Error("Generated device credential failed verification"),{status:500,code:"DEVICE_CREDENTIAL_SELF_TEST_FAILED"});
            return {status:200,value:{enabled:true,valid:true,device_id:verified.id,expires_at:verified.payload?.exp||null}};
          }]);
        } else {
          write("SKIP  /device  DEVICE_BOUND_SIGNED_STREAMS=false");
        }

        if (albumId) {
          tests.push([`/album?id=${albumId}`, async()=>handleCatalogRoute(new URL(`/album?id=${albumId}`, base), env, ["album"], apiKey, "diagnostic", null)]);
          tests.push([`/album/${albumId}/tracks`, async()=>handleCatalogRoute(new URL(`/album/${albumId}/tracks`, base), env, ["album",String(albumId),"tracks"], apiKey, "diagnostic", null)]);
        } else {
          write("/album: SKIP (seed did not expose an album id)");
        }
        if (artistId) {
          tests.push([`/artist?id=${artistId}`, async()=>handleCatalogRoute(new URL(`/artist?id=${artistId}`, base), env, ["artist"], apiKey, "diagnostic", null)]);
          tests.push([`/artist/${artistId}/top`, async()=>handleCatalogRoute(new URL(`/artist/${artistId}/top`, base), env, ["artist",String(artistId),"top"], apiKey, "diagnostic", null)]);
          tests.push([`/artist/${artistId}/albums`, async()=>handleCatalogRoute(new URL(`/artist/${artistId}/albums`, base), env, ["artist",String(artistId),"albums"], apiKey, "diagnostic", null)]);
        } else {
          write("/artist: SKIP (seed did not expose an artist id)");
        }

        let playback = null;
        for (const [label, fn] of tests) {
          const started = Date.now();
          try {
            const result = await fn();
            const status = result?.status || 200;
            if (status >= 400) {
              let body = null;
              if (result instanceof Response) {
                try { body = await result.clone().json(); } catch (_) {}
              }
              const d = { errorNumber: status, errorCode: body?.code || body?.error || null, errorText: body?.message || body?.errorText || body?.details?.message || `HTTP ${status}` };
              write(`FAIL  ${label}  [${d.errorNumber}] ${d.errorText}${d.errorCode ? ` (${d.errorCode})` : ""}  ${Date.now()-started}ms`);
            } else if (status === 204 || result?.value?.skipped) {
              write(`SKIP  ${label}  ${result?.value?.skipped || "diagnostic skipped"}  ${Date.now()-started}ms`);
            } else {
              write(`PASS  ${label}  ${Date.now()-started}ms`);
            }
          } catch (err) {
            const d = testRoutingErrorDetails(err, 502);
            write(`FAIL  ${label}  [${d.errorNumber}] ${d.errorText}${d.errorCode ? ` (${d.errorCode})` : ""}  ${Date.now()-started}ms`);
          }
        }

        const playbackStarted = Date.now();
        try {
          playback = await resolvePlaybackStreamOnly(String(trackId), "best", env, allowedSlots);
          write(`PASS  /stream-track?id=${trackId}  resolved ${playback.selectedProfile?.label || playback.mediaResult?.format || "media"} via ARL slot ${playback.slot}  ${Date.now()-playbackStarted}ms`);
          write(`PASS  /track/${trackId}/stream  playback resolver verified  ${Date.now()-playbackStarted}ms`);
          write(`PASS  /stream  CDN media source verified; full decrypt is intentionally not consumed by diagnostics to avoid downloading audio.`);
        } catch (err) {
          const d = testRoutingErrorDetails(err, 502);
          write(`FAIL  /stream-track?id=${trackId}  [${d.errorNumber}] ${d.errorText}${d.errorCode ? ` (${d.errorCode})` : ""}`);
          write(`FAIL  /track/${trackId}/stream  [${d.errorNumber}] ${d.errorText}${d.errorCode ? ` (${d.errorCode})` : ""}`);
          write(`FAIL  /stream  [${d.errorNumber}] ${d.errorText}${d.errorCode ? ` (${d.errorCode})` : ""}`);
        }

        const adminKey = String(env?.ADMIN_API_KEY || "").trim();
        if (adminKey && apiKey === adminKey) {
          write("PASS  /env  admin key supplied by test API key");
        } else {
          write("SKIP  /env  requires ADMIN_API_KEY; the diagnostic only has the client API key");
        }
        write(`Diagnostic contract: /test-routing is canonical; /testRouting and /testRoutings remain compatibility aliases.`);
        write(`=== ROUTING TEST COMPLETE ===`);
        writeRaw("@@DONE@@");
      } catch (error) {
        const d = testRoutingErrorDetails(error, 502);
        write(`FATAL FAIL  [${d.errorNumber}] ${d.errorText}${d.errorCode ? ` (${d.errorCode})` : ""}`);
        writeRaw("@@DONE@@");
      } finally {
        controller.close();
      }
    }
  });
  return new Response(stream, { status: 200, headers: { ...getCorsHeaders(env), "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Accel-Buffering": "no" } });
}

async function runTestRoutingsJson(request, env, requestUrl, trackId, apiKey, allowedSlots) {
  const phases = [];
  const run = async (phase) => {
    const phaseResponse = await streamTestRoutingsResponse(request, env, requestUrl, phase, trackId, apiKey, allowedSlots);
    const raw = await phaseResponse.text();
    const lines = raw.split(/\r?\n/).filter(Boolean);
    const output = [];
    let status = "complete";
    let sawFatal = false;
    let sawArlFailure = false;
    for (const line of lines) {
      const match = line.match(/^\d{4}-\d{2}-\d{2}T[^ ]+\s{2}(.*)$/);
      const text = match ? match[1] : line;
      if (text === "@@CONTINUE@@" || text === "@@DONE@@") continue;
      if (/FATAL FAIL/.test(text)) sawFatal = true;
      if (/^\s*RESULT:\s+FAILED\b/.test(text)) sawArlFailure = true;
      if (phase !== "arls" && /\bFAIL\b/.test(text)) sawFatal = true;
      output.push(text);
    }
    if (sawFatal || sawArlFailure) status = "failed";
    phases.push({ phase, status, output });
    return status === "complete";
  };

  const startedAt = new Date().toISOString();
  let overallStatus = "complete";
  try {
    if (!/^\d+$/.test(String(trackId || ""))) {
      return {
        diagnostics: "test-routing",
        version: API_VERSION,
        status: "failed",
        track_id: String(trackId || ""),
        started_at: startedAt,
        errorNumber: 400,
        errorCode: "INVALID_TRACK_ID",
        errorText: "A numeric Deezer Track ID is required",
        phases: []
      };
    }
    const routesOk = await run("routes");
    if (!routesOk) overallStatus = "failed";
  } catch (error) {
    const d = testRoutingErrorDetails(error, 502);
    overallStatus = "failed";
    phases.push({ phase: "fatal", status: "failed", output: [`FATAL FAIL [${d.errorNumber}] ${d.errorText}${d.errorCode ? ` (${d.errorCode})` : ""}`], error: d });
  }

  const routePhase = phases.find(x => x.phase === "routes");
  const routeOutput = routePhase?.output || [];
  const passCount = routeOutput.filter(x => /^PASS\s/.test(x)).length;
  const failCount = routeOutput.filter(x => /\bFAIL\b/.test(x)).length;
  const skipCount = routeOutput.filter(x => /^SKIP\s/.test(x)).length;

  return {
    diagnostics: "test-routing",
    version: API_VERSION,
    status: overallStatus,
    track_id: String(trackId),
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    phases,
    summary: {
      arls_tested: 0,
      routes_passed: passCount,
      routes_failed: failCount,
      routes_skipped: skipCount,
      routes_tested: passCount + failCount + skipCount
    }
  };
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

const STREAM_TOKEN_SECURITY_NOTE = "Bootstrap stream tokens use a fresh 256-bit cryptographically random nonce plus an HMAC-SHA-256 signed payload. Every emitted bootstrap URL gets a new nonce and token generation is never coalesced. Authenticated playback entry points can require a valid signed bootstrap token by default. DEVICE_BOUND_SIGNED_STREAMS adds a long-lived signed device credential and binds playback sessions/tokens to its hash, so copied stream URLs are not independently playable.";

// -----------------------------------------------------------------------------
// Secure instance-to-instance ARL sharing
// -----------------------------------------------------------------------------
function getArlShareSecret(env) {
  return String(env?.ARL_SHARE_SECRET || "").trim();
}

function normalizeInstanceUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    const local = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) return null;
    return url.origin;
  } catch (_) {
    return null;
  }
}

function parseArlShareSlots(env) {
  return String(env?.GET_ARL || "")
    .split(",")
    .map(v => Number.parseInt(v.trim(), 10))
    .filter(v => Number.isInteger(v) && v >= 1 && v <= 50)
    .filter((v, i, a) => a.indexOf(v) === i);
}

function getArlShareSenderUrl(env) { return normalizeInstanceUrl(env?.GET_ARL_SENDER_URL); }
function getArlShareReceiverUrl(env) { return normalizeInstanceUrl(env?.GET_ARL_RECEIVER_URL); }
function arlShareConfigured(env) { return Boolean(getArlShareSecret(env) && (getArlShareSenderUrl(env) || getArlShareReceiverUrl(env))); }

async function arlShareStableCacheKey(env, receiverUrlOverride = null) {
  const sender = getArlShareSenderUrl(env) || "none";
  const receiver = normalizeInstanceUrl(receiverUrlOverride) || getArlShareReceiverUrl(env) || "none";
  const raw = `${sender}|${receiver}`;
  const state = getArlShareCryptoRuntime(env);
  if (state.cacheKey.has(raw)) return state.cacheKey.get(raw);
  const key = `${ARL_SHARE_CACHE_PREFIX}${await sha256Hex(raw)}`;
  state.cacheKey.set(raw, key);
  return key;
}

const arlShareCryptoRuntime = new WeakMap();

function getArlShareCryptoRuntime(env) {
  let state = arlShareCryptoRuntime.get(env);
  if (!state) {
    state = { secret: null, hmacSignKey: null, hmacVerifyKey: null, aesEncryptKey: null, aesDecryptKey: null, fingerprint: new Map(), cacheKey: new Map() };
    arlShareCryptoRuntime.set(env, state);
  }
  return state;
}

async function getArlShareCryptoKey(env, usage) {
  const secret = getArlShareSecret(env);
  if (!secret) return null;
  const state = getArlShareCryptoRuntime(env);
  if (state.secret !== secret) {
    state.secret = secret;
    state.hmacSignKey = null; state.hmacVerifyKey = null;
    state.aesEncryptKey = null; state.aesDecryptKey = null;
  }
  const cacheName = usage.includes("encrypt") ? "aesEncryptKey" : "aesDecryptKey";
  if (!state[cacheName]) {
    const digest = await sha256Bytes(`cfw-deezer-hifi-api|arl-share|aes-gcm|v1|${secret}`);
    state[cacheName] = await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, usage);
  }
  return state[cacheName];
}

async function getArlShareHmacKey(env, verify = false) {
  const secret = getArlShareSecret(env);
  if (!secret) return null;
  const state = getArlShareCryptoRuntime(env);
  if (state.secret !== secret) {
    state.secret = secret;
    state.hmacSignKey = null; state.hmacVerifyKey = null;
    state.aesEncryptKey = null; state.aesDecryptKey = null;
  }
  const cacheName = verify ? "hmacVerifyKey" : "hmacSignKey";
  if (!state[cacheName]) {
    const digest = await sha256Bytes(`cfw-deezer-hifi-api|arl-share|hmac|v1|${secret}`);
    state[cacheName] = await crypto.subtle.importKey("raw", digest, { name: "HMAC", hash: "SHA-256" }, false, verify ? ["verify"] : ["sign"]);
  }
  return state[cacheName];
}

async function arlShareSign(value, env) {
  const key = await getArlShareHmacKey(env, false);
  if (!key) return null;
  return base64UrlEncodeBytes(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

async function arlShareVerify(value, signature, env) {
  const key = await getArlShareHmacKey(env, true);
  if (!key || !signature) return false;
  try { return await crypto.subtle.verify("HMAC", key, base64UrlDecodeBytes(signature), new TextEncoder().encode(value)); }
  catch (_) { return false; }
}

async function encryptArlShare(payload, env) {
  const key = await getArlShareCryptoKey(env, ["encrypt"]);
  if (!key) throw new Error("ARL_SHARE_SECRET is not configured");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`cfw-deezer-hifi-api|arl-share|${payload.nonce}|${payload.receiver_url}`);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, new TextEncoder().encode(JSON.stringify(payload)));
  return { v: 1, iv: base64UrlEncodeBytes(iv), data: base64UrlEncodeBytes(new Uint8Array(ciphertext)) };
}

async function decryptArlShare(envelope, expectedNonce, expectedReceiverUrl, env) {
  const key = await getArlShareCryptoKey(env, ["decrypt"]);
  if (!key) throw new Error("ARL_SHARE_SECRET is not configured");
  if (!envelope || Number(envelope.v) !== 1) throw new Error("Invalid ARL share envelope");
  const iv = base64UrlDecodeBytes(envelope.iv);
  const data = base64UrlDecodeBytes(envelope.data);
  if (iv.byteLength !== 12 || data.byteLength < 17 || data.byteLength > 256 * 1024) throw new Error("Invalid ARL share envelope size");
  const aad = new TextEncoder().encode(`cfw-deezer-hifi-api|arl-share|${expectedNonce}|${expectedReceiverUrl}`);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, data);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function getArlShareState(env) {
  let state = arlShareRuntime.get(env);
  if (!state) {
    state = { arls: [], loadedKeys: new Set(), syncing: null, lastSyncAt: 0, lastError: null, lastStatus: "not_configured", sourceUrl: null };
    arlShareRuntime.set(env, state);
  }
  return state;
}

function setSharedArls(env, records, meta = {}) {
  const state = getArlShareState(env);
  const seen = new Set();
  const normalized = [];
  for (const record of Array.isArray(records) ? records : []) {
    const value = String(record?.value || record?.arl || "").trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    normalized.push({ slot: 1000 + normalized.length + 1, name: `SHARED_ARL_${normalized.length + 1}`, value, shared: true, source: "instance", sourceUrl: String(meta.sourceUrl || ""), originSlot: Number(record?.slot) || null, importedAt: Date.now() });
  }
  state.arls = normalized;
  state.lastSyncAt = Date.now();
  state.lastError = null;
  state.lastStatus = normalized.length ? "healthy" : "empty";
  state.sourceUrl = String(meta.sourceUrl || state.sourceUrl || "") || null;
  memoizedEnvRef = null; memoizedConfiguredArls = null; memoizedKeyMappings = null;
  return normalized;
}

function clearSharedArls(env, reason = "revoked") {
  const state = getArlShareState(env);
  for (const item of state.arls) clearArlCache(item.value);
  state.arls = [];
  state.lastSyncAt = Date.now();
  state.lastError = reason;
  state.lastStatus = reason;
  memoizedEnvRef = null; memoizedConfiguredArls = null; memoizedKeyMappings = null;
}

function getArlShareSyncTtlMs(env) {
  const value = Number(env?.ARL_SHARE_SYNC_TTL_SECONDS);
  if (!Number.isFinite(value) || value <= 0) return 30000;
  return Math.max(5000, Math.min(3600000, Math.floor(value * 1000)));
}

async function persistSharedArls(env, records, sourceUrl, receiverUrl) {
  if (!env?.GENERAL_MUSIC_CACHE) return;
  try {
    const key = await arlShareStableCacheKey(env, receiverUrl);
    await env.GENERAL_MUSIC_CACHE.put(key, JSON.stringify({ v: 1, source_url: sourceUrl, records, stored_at: Date.now() }), { expirationTtl: Math.max(60, Math.ceil(getArlShareSyncTtlMs(env) / 1000) * 4) });
  } catch (_) {}
}

async function loadPersistedSharedArls(env, receiverUrl) {
  const state = getArlShareState(env);
  const key = await arlShareStableCacheKey(env, receiverUrl);
  if (state.loadedKeys.has(key)) return state;
  state.loadedKeys.add(key);
  if (!env?.GENERAL_MUSIC_CACHE || !getArlShareSenderUrl(env) || !getArlShareSecret(env)) return state;
  try {
    const cached = await env.GENERAL_MUSIC_CACHE.get(key, { type: "json" });
    if (cached?.records?.length) setSharedArls(env, cached.records, { sourceUrl: cached.source_url || getArlShareSenderUrl(env) });
  } catch (_) {}
  return state;
}

function makeArlShareRequestMessage(timestamp, nonce, receiverUrl, senderUrl, fingerprint) {
  return `v1|${timestamp}|${nonce}|${receiverUrl}|${senderUrl}|${fingerprint}`;
}

async function getArlShareFingerprint(env, receiverUrl) {
  const state = getArlShareCryptoRuntime(env);
  if (state.fingerprint.has(receiverUrl)) return state.fingerprint.get(receiverUrl);
  const value = await sha256Hex(receiverUrl);
  state.fingerprint.set(receiverUrl, value);
  return value;
}

async function syncSharedArlsFromSender(env, receiverUrlOverride) {
  const state = getArlShareState(env);
  if (state.syncing) return state.syncing;
  const senderUrl = getArlShareSenderUrl(env);
  const receiverUrl = normalizeInstanceUrl(receiverUrlOverride);
  const secret = getArlShareSecret(env);
  if (!senderUrl || !receiverUrl || !secret) { state.lastStatus = "not_configured"; return state; }
  state.syncing = (async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = await randomTokenNonce(32);
    const fingerprint = await getArlShareFingerprint(env, receiverUrl);
    const message = makeArlShareRequestMessage(timestamp, nonce, receiverUrl, senderUrl, fingerprint);
    const signature = await arlShareSign(message, env);
    try {
      const url = new URL(senderUrl);
      url.pathname = "/arl-share/request";
      url.search = "";
      url.searchParams.set("ts", String(timestamp));
      url.searchParams.set("nonce", nonce);
      url.searchParams.set("receiver", receiverUrl);
      url.searchParams.set("sender", senderUrl);
      url.searchParams.set("fingerprint", fingerprint);
      const response = await fetch(url.toString(), { headers: { "Accept": "application/json", "X-ARL-Share-Signature": signature || "", "Cache-Control": "no-store" }, cf: { cacheTtl: 0, cacheEverything: false } });
      const body = await readResponse(response);
      if (!response.ok) {
        if (response.status === 403) clearSharedArls(env, body?.json?.code === "ARL_SHARE_REVOKED" ? "revoked" : "authorization_failed");
        state.lastError = body?.json?.message || `sender_http_${response.status}`;
        state.lastStatus = response.status === 403 ? "revoked" : "error";
        return state;
      }
      const payload = await decryptArlShare(body.json, nonce, receiverUrl, env);
      if (Number(payload?.v) !== 1 || payload?.nonce !== nonce || payload?.receiver_url !== receiverUrl || payload?.sender_url !== senderUrl) throw new Error("Sender response identity check failed");
      const records = Array.isArray(payload?.arls) ? payload.arls : [];
      setSharedArls(env, records, { sourceUrl: senderUrl });
      await persistSharedArls(env, records, senderUrl, receiverUrl);
      return state;
    } catch (error) {
      state.lastError = String(error?.message || error);
      if (state.lastStatus !== "revoked") state.lastStatus = "error";
      return state;
    } finally { state.syncing = null; }
  })();
  return state.syncing;
}

async function maybeSyncSharedArls(env, ctx, force, receiverUrl) {
  const state = getArlShareState(env);
  if (!getArlShareSenderUrl(env) || !getArlShareSecret(env) || !receiverUrl) {
    await loadPersistedSharedArls(env, receiverUrl);
    return state;
  }
  const loadPromise = loadPersistedSharedArls(env, receiverUrl);
  const stale = !state.lastSyncAt || Date.now() - state.lastSyncAt >= getArlShareSyncTtlMs(env);
  if (!force && !stale) { await loadPromise; return state; }
  if (!force && state.arls.length && ctx?.waitUntil) {
    await loadPromise;
    ctx.waitUntil(syncSharedArlsFromSender(env, receiverUrl));
    return state;
  }
  // Cold-start path: KV restore and sender handshake run concurrently.
  const syncPromise = syncSharedArlsFromSender(env, receiverUrl);
  const [, synced] = await Promise.all([loadPromise, syncPromise]);
  return synced || state;
}

async function handleArlShareRoute(request, env, requestUrl, requestId) {
  const route = requestUrl.pathname.replace(/\/+$/, "") || "/";
  const secret = getArlShareSecret(env);
  const senderReceiverUrl = getArlShareReceiverUrl(env);
  const receiverSenderUrl = getArlShareSenderUrl(env);
  if (!secret) return publicError("ARL_SHARE_NOT_CONFIGURED", 404, env, requestId);

  if (route === "/arl-share/sync") {
    if (!receiverSenderUrl) return jsonResponse({ error: "ARL_SHARE_SENDER_NOT_CONFIGURED", message: "Set GET_ARL_SENDER_URL on this Worker first." }, 503, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
    const state = await syncSharedArlsFromSender(env, requestUrl.origin);
    return jsonResponse({ version: API_VERSION, status: state.lastStatus, shared: state.arls.length > 0, count: state.arls.length, source: receiverSenderUrl, last_sync_at: state.lastSyncAt || null, error: state.lastError || null }, state.lastStatus === "revoked" ? 403 : state.lastStatus === "error" ? 502 : 200, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
  }

  if (route !== "/arl-share/request") return publicError("NOT_FOUND", 404, env, requestId);
  if (!parseArlShareSlots(env).length) return publicError("ARL_SHARE_SENDER_NOT_CONFIGURED", 503, env, requestId);
  if (!senderReceiverUrl) return publicError("ARL_SHARE_REVOKED", 403, env, requestId);
  const ts = Number(requestUrl.searchParams.get("ts"));
  const nonce = String(requestUrl.searchParams.get("nonce") || "");
  const requestedReceiver = normalizeInstanceUrl(requestUrl.searchParams.get("receiver"));
  const requestedSender = normalizeInstanceUrl(requestUrl.searchParams.get("sender"));
  const fingerprint = String(requestUrl.searchParams.get("fingerprint") || "");
  const thisOrigin = requestUrl.origin;
  if (!Number.isFinite(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > 120) return publicError("ARL_SHARE_REQUEST_EXPIRED", 401, env, requestId);
  if (!/^[a-f0-9]{64}$/.test(nonce) || !requestedReceiver || requestedReceiver !== senderReceiverUrl || requestedSender !== thisOrigin || fingerprint !== await sha256Hex(requestedReceiver)) return publicError("ARL_SHARE_IDENTITY_MISMATCH", 403, env, requestId);
  const signature = request.headers.get("X-ARL-Share-Signature") || "";
  const message = makeArlShareRequestMessage(ts, nonce, requestedReceiver, requestedSender, fingerprint);
  if (!await arlShareVerify(message, signature, env)) return publicError("ARL_SHARE_AUTH_FAILED", 403, env, requestId);
  const { arls } = getMemoizedConfig(env);
  const slots = new Set(parseArlShareSlots(env));
  const selected = arls.filter(item => slots.has(item.slot) && !item.shared).map(item => ({ slot: item.slot, value: item.value }));
  if (!selected.length) return publicError("ARL_SHARE_NO_SELECTED_ARLS", 404, env, requestId);
  const envelope = await encryptArlShare({ v: 1, nonce, receiver_url: requestedReceiver, sender_url: requestedSender, issued_at: Date.now(), arls: selected }, env);
  return jsonResponse(envelope, 200, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
}

function arlShareStatus(env) {
  const state = getArlShareState(env);
  return { enabled: arlShareConfigured(env), sender: Boolean(getArlShareReceiverUrl(env) && parseArlShareSlots(env).length), receiver: Boolean(getArlShareSenderUrl(env)), configured_slots: parseArlShareSlots(env), imported_count: state.arls.length, shared: state.arls.length > 0, revokable: Boolean(getArlShareReceiverUrl(env)), sync_status: state.lastStatus, last_sync_at: state.lastSyncAt || null, last_error: state.lastError || null, source: state.sourceUrl };
}

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
  MEDIA_INFLIGHT_TTL_MS: "How long identical concurrent media-resolution requests are coalesced; defaults to 5000 ms and is clamped to 1000-30000 ms.",
  TRACK_TOKEN_INFLIGHT_TTL_MS: "How long identical concurrent track-token requests are coalesced; defaults to 5000 ms and is clamped to 1000-30000 ms.",
  UPSTREAM_TIMEOUT_MS: "Timeout for catalog/auth/lyrics upstream requests; clamped to 1000-20000 ms.",
  STREAM_CDN_HOSTS: "Semicolon-separated HTTPS CDN host allowlist for /stream.",
  STREAM_CHUNK_SIZE: "Default decrypted audio chunk size; clamped to the configured maximum.",
  STREAM_MAX_CHUNK_SIZE_BYTES: "Hard per-request decrypted chunk ceiling; defaults to 512 KiB and is clamped to 64 KiB-1 MiB. Larger values can improve throughput but increase CPU/memory pressure.",
  CHUNK_SIZE: "Fallback chunk-size setting when STREAM_CHUNK_SIZE is not set; still capped by STREAM_MAX_CHUNK_SIZE_BYTES.",
  STREAM_CACHE_CONTROL: "Cache-Control header emitted by /stream; defaults to private, no-store.",
  STREAM_TOKEN_SECRET: "Secret used to sign temporary playback tokens; set independently in production.",
  STREAM_TOKEN_TTL_SECONDS: "Lifetime of the temporary bootstrap stream token; defaults to 600 seconds and is clamped to 30-3600.",
  STREAM_SESSION_TTL_SECONDS: "Idle lifetime of the signed playback session cookie; defaults to 1800 seconds and is clamped to 60-7200.",
  STREAM_SESSION_REFRESH_THRESHOLD_SECONDS: "Refresh threshold for active playback sessions; defaults to 300 seconds and is clamped to 30-3600.",
  STREAM_TOKEN_BIND_USER_AGENT: "Set true to additionally bind stream tokens and playback sessions to the caller User-Agent hash.",
  STREAM_REQUIRE_BOOTSTRAP: "Set true to require temporary bootstrap tokens for authenticated playback entry points.",
  DEVICE_BOUND_SIGNED_STREAMS: "Set true to bind authenticated playback to a cryptographically signed device credential. Native clients supply it with X-Voria-Device; browsers can use the HttpOnly __Host-VoriaDevice cookie from /device. Generated authenticated streamUrl values carry api_key plus a short-lived device-bound playback token as ?device=; the long-lived d1 credential is never emitted into the URL.",
  DEVICE_BOUND_SECRET: "Optional independent secret used to sign device credentials. If omitted, the Worker derives a separate device-signing secret from STREAM_TOKEN_SECRET or an existing secret. Set this explicitly in production for independent rotation.",
  DEVICE_BOUND_TOKEN_TTL_SECONDS: "Lifetime of a registered device credential; defaults to 2592000 seconds (30 days) and is clamped to 3600-31536000.",
  ALLOW_QUERY_DEVICE_SIGN: "Set true only for testing/clients that cannot send X-Voria-Device. Accepts a raw d1 device credential as ?device_credential= (and legacy d1 values in ?device=). Generated streamUrl values do NOT contain the long-lived device credential; they use ?device= for a short-lived device-bound playback token. Defaults to false.",
  GENERAL_MUSIC_CACHE: "Optional KV-style binding used for shared track/search/lyrics caching.",
  SEARCH_CACHE_TTL_SECONDS: "Shared public catalog/search cache lifetime in seconds; defaults to 30 and is clamped to 5-3600.",
  CACHE_TTL_DAYS: "Default shared-cache TTL when a cache write does not provide its own TTL; defaults to 30 days.",
  RATE_LIMITER: "Optional Cloudflare Rate Limiting binding used for distributed request limits.",
  RATE_LIMIT: "Fallback in-worker requests-per-second limit when RATE_LIMITER is not used. The actual /stream audio data path is exempt because continuous playback legitimately generates repeated HTTP Range requests; stream-entry/API routes remain rate limited.",
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
  DISABLE_LYRICS: "Set true to disable standalone lyrics routes and embedded lyrics resolution. This can reduce auxiliary Deezer requests and ARL usage.",
  GET_ARL: "Sender-side comma-separated local ARL slot numbers explicitly approved for instance sharing, e.g. 1,2,6. Empty/unset disables sending.",
  GET_ARL_RECEIVER_URL: "Sender-side exact HTTPS origin of the one Worker allowed to receive GET_ARL. Removing or changing it revokes future synchronization.",
  GET_ARL_SENDER_URL: "Receiver-side exact HTTPS origin of the one Worker authorized to send shared ARLs to this Worker.",
  ARL_SHARE_SECRET: "Required shared secret for instance authentication and AES-GCM encryption. Set the same strong random secret on both Workers and store it as a Cloudflare Secret.",
  ARL_SHARE_SYNC_TTL_SECONDS: "Receiver refresh interval for authorization/revocation checks. Defaults to 30 seconds; clamped to 5 seconds-1 hour.",
  ARL_SHARE_ACCESS: "Set true to allow imported shared ARLs into normal candidate pools even when the caller API key is restricted to local slots. Defaults to false."
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

  const authenticationExceptions = {
    public_without_client_key: ["/ping", "/arl-health", "/routing", "/docs"],
    note: "/ping may contact Deezer using configured ARLs for health/capability checks, but it never returns streamUrl, media URL, track token, lyrics, or protected catalog payloads to the caller."
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
    MEDIA_INFLIGHT_TTL_MS: { type: "number", secret: false, default: "5000", range: "1000-30000", effect: "TTL for coalescing identical concurrent media URL resolution requests." },
    TRACK_TOKEN_INFLIGHT_TTL_MS: { type: "number", secret: false, default: "5000", range: "1000-30000", effect: "TTL for coalescing identical concurrent Deezer track-token requests." },
    UPSTREAM_TIMEOUT_MS: { type: "number", secret: false, default: "8000", range: "1000-20000", effect: "Timeout for catalog, authentication, lyrics, and other bounded upstream requests." },
    STREAM_CDN_HOSTS: { type: "semicolon-separated host patterns", secret: false, default: "*.dzcdn.net;media.deezer.com", effect: "Allowlist for HTTPS upstream hosts accepted by /stream. Wildcards only work as leading *.host patterns." },
    STREAM_CHUNK_SIZE: { type: "bytes or 256k/512k", secret: false, default: "worker safe default", range: "64 KiB-configured maximum", effect: "Default decrypted streaming chunk size." },
    STREAM_MAX_CHUNK_SIZE_BYTES: { type: "number", secret: false, default: "524288", range: "65536-1048576", effect: "Hard ceiling for a single decrypted audio request. Raising it may improve throughput on fast clients while increasing per-request CPU and memory pressure." },
    CHUNK_SIZE: { type: "bytes or 256k/512k", secret: false, default: "worker safe default", range: "64 KiB-configured maximum", effect: "Fallback chunk-size setting used only when STREAM_CHUNK_SIZE is not set." },
    STREAM_TOKEN_SECRET: { type: "secret string", secret: true, default: "falls back to ADMIN_API_KEY or the primary Deezer ARL if unset", effect: "HMAC-SHA-256 signing secret for temporary client-bound playback tokens. Set this independently in production so changing client API keys or ARLs does not change the signing key." },
    STREAM_TOKEN_TTL_SECONDS: { type: "number", secret: false, default: "600", range: "30-3600", effect: "Lifetime of the generated stream_token. The token remains valid until expiration and is used to authorize the playback session." },
    STREAM_SESSION_TTL_SECONDS: { type: "number", secret: false, default: "1800", range: "60-7200", effect: "Idle playback-session lifetime. Active playback can continue beyond this through session refreshes; inactive/stolen session cookies eventually expire." },
    STREAM_SESSION_REFRESH_THRESHOLD_SECONDS: { type: "number", secret: false, default: "300", range: "30-3600", effect: "When a valid playback session has this many seconds or less remaining, the Worker silently issues a fresh signed session cookie while serving the request." },
    STREAM_TOKEN_BIND_USER_AGENT: { type: "boolean string", secret: false, default: "false", effect: "When true, temporary stream tokens and playback sessions are additionally bound to a SHA-256 hash of the caller User-Agent. This increases copy resistance for same-IP replay but may reduce compatibility with clients that use different User-Agents for metadata and audio playback." },
    STREAM_REQUIRE_BOOTSTRAP: { type: "boolean string", secret: false, default: "true", effect: "When true, authenticated playback entry points require a valid temporary bootstrap stream_token. This prevents a copied api_key from being used to mint fresh playback sessions through /stream-track or /track/:id/stream. Public API mode remains intentionally open." },
    STREAM_CACHE_CONTROL: { type: "string", secret: false, default: "private, no-store", effect: "Cache-Control header emitted by the decrypted /stream response." },
    DEVICE_BOUND_SIGNED_STREAMS: { type: "boolean string", secret: false, default: "false", effect: "When true, authenticated playback is bound to a signed device credential. Native clients use X-Voria-Device; browsers use the HttpOnly __Host-VoriaDevice cookie set by /device. Generated stream URLs use a short-lived ?device= playback token, never the long-lived d1 credential." },
    DEVICE_BOUND_SECRET: { type: "secret string", secret: true, default: "derived signing secret", effect: "Independent HMAC secret for device credentials. Set explicitly in production for independent rotation." },
    DEVICE_BOUND_TOKEN_TTL_SECONDS: { type: "number", secret: false, default: "2592000", range: "3600-31536000", effect: "Lifetime of the signed device credential. Default is 30 days." },
    DEVICE_CREDENTIAL_COOKIE: { type: "fixed cookie name", secret: false, default: "__Host-VoriaDevice", effect: "Browser cookie name used by /device. HttpOnly, Secure, SameSite=Lax, Path=/, host-only." },
    TITLE: { type: "string", secret: false, default: "cfw-deezer-hifi-api", effect: "Browser document title for the root status page." },
    IMG: { type: "HTTP(S) URL", secret: false, default: "not set", effect: "Image URL displayed inside the expanded root img dictionary. The Worker proxies the configured image through a same-origin endpoint and validates its Content-Type." },
    IMG_TB: { type: "HTTP(S) URL", secret: false, default: "not set", effect: "Image URL used as the browser tab icon through a same-origin Worker proxy." },
    GENERAL_MUSIC_CACHE: { type: "KV namespace binding", secret: false, default: "not bound", effect: "Optional Cloudflare KV binding used for shared track/search/lyrics cache entries. The code checks this binding before reading or writing shared cache data." },
    SEARCH_CACHE_TTL_SECONDS: { type: "number", secret: false, default: "30", range: "5-3600", effect: "TTL for public Deezer catalog/search responses. Results are also kept in a small per-isolate memory cache for the same TTL, and identical concurrent misses are coalesced when shared caching is enabled." },
    CACHE_TTL_DAYS: { type: "number", secret: false, default: "30", effect: "Default expiration in days for shared KV cache writes that do not supply their own TTL." },
    RATE_LIMITER: { type: "Cloudflare Rate Limiting binding", secret: false, default: "not bound", effect: "Optional distributed rate limiter. When present and operational, its limit({key}) result takes precedence over the local fallback limiter." },
    RATE_LIMIT: { type: "number", secret: false, default: "disabled", effect: "Fallback local requests-per-second limit when RATE_LIMITER is unavailable or not configured. The local implementation uses a 2.5-second window. The actual /stream audio data path is exempt so repeated Range requests cannot terminate playback with 429." },
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
    diagnostics_disclaimer: "This diagnostic sweep checks configured Deezer ARLs and representative catalog/playback routes, including /routing and /docs. It may create upstream requests and media authorization work, but it intentionally does not download the full audio stream.",
    diagnostics_default_track_id: "920991742",
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
      stream_security: "Authenticated generated stream URLs include the client api_key plus a short-lived HMAC-signed bootstrap stream_token whose first component is a fresh 256-bit SHA-256 nonce derived from cryptographically random bytes. The token has an explicit bootstrap type and is bound to the API-key identity, track id, and caller IP. A valid token may be used again until expiration; there is no replay blacklist or one-use state. Successful playback authorization can establish a separate signed HttpOnly session cookie for chunked Range requests. /stream does not act as an arbitrary URL proxy: upstream URLs must be HTTPS and match STREAM_CDN_HOSTS.",
      performance: "Production responses default to compact JSON. Hot-path HMAC keys, API-key hashes, User-Agent hashes, track-token requests, and media-resolution requests use short-lived in-memory caches or in-flight coalescing to reduce repeated crypto/upstream work. Bootstrap token generation remains uncached so each emitted URL gets a fresh nonce.",
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
        "5. Apply distributed RATE_LIMITER when configured, otherwise use the local limiter controlled by RATE_LIMIT. The /stream audio data path is exempt because continuous HTTP Range requests are part of normal playback.",
        "6. Enforce optional MAINTENANCE_MODE, feature-disable flags, and route-specific protections.",
        "7. Resolve catalog data, Deezer sessions, lyrics, recommendations, or playback according to the requested route.",
        "8. Normalize track/album/artist/playlist data and decorate authenticated streamUrl values with client identity plus a fresh bootstrap token.",
        "9. Return compact JSON by default or pretty JSON when PRETTY_JSON=true."
      ],
      playback_pipeline: [
        "Metadata produces /stream-track URLs rather than exposing the raw Deezer CDN URL to the client.",
        "Authenticated playback URLs carry api_key plus a unique temporary stream_token.",
        "The bootstrap token is bound to track id, API-key identity, caller IP, and optionally User-Agent.",
        "The bootstrap token is signature-checked and client-bound, but is not stored as one-use state. The same valid token may be used again until it expires.",
        "Successful bootstrap authorization creates a signed HttpOnly __Host-VoriaStreamSession cookie.",
        "Subsequent Range requests use the playback session and can silently refresh it near expiry.",
        "The Worker resolves/refreshes Deezer media authorization, validates the CDN URL against STREAM_CDN_HOSTS, fetches bounded upstream ranges, decrypts the media blocks, and returns standard HTTP audio responses."
      ],
      token_format: {
        bootstrap: "<64-char SHA-256 nonce>.<base64url payload>.<base64url HMAC-SHA-256 signature>",
        nonce: "32 cryptographically random bytes hashed with SHA-256 and rendered as 64 lowercase hexadecimal characters.",
        payload: "Contains token version/type, track id, API-key identity hash, caller IP, issue/expiry times, nonce, and optional User-Agent hash.",
        session: "A separate signed session credential stored in an HttpOnly __Host-VoriaStreamSession cookie; it is not placed in the stream URL.",
        reuse: "Bootstrap tokens are not stored as one-use state. A valid signed token remains usable until its expiration time."
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
        "/ping": "Cheap public instance liveness check. It does not contact Deezer or validate ARLs. Use /arl-health for live ARL validation and per-slot capability checks.",
      "/arl-health": "Public detailed Worker and ARL health report. Includes ARL status/capabilities, federation state, bindings, configuration flags, and in-memory runtime counters. No ARL values or protected Deezer payloads are returned.",
        "/routing": "Public live routing, authentication, playback-security, timeout, route, and hardening configuration summary; no API key required.",
        "/env": "Admin-only non-secret environment diagnostics. Secret-like names/values are filtered and never exposed.",
        "/docs": "Public machine-readable documentation generated from the current Worker origin and environment configuration.",
        "/arl-share/sync": "Receiver-side manual synchronization test. It authenticates to the configured sender, imports the encrypted ARL bundle, and reports the result without returning raw credentials.",
        "/arl-share/request": "Sender-side internal handshake endpoint. It only responds to the exact receiver configured in GET_ARL_RECEIVER_URL and requires a valid ARL_SHARE_SECRET signature.",
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
        "No replay-protection KV namespace is required. Keep the API private and use API keys for access control."
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
    },
    arl_sharing: {
      overview: "Two Workers can share explicitly selected ARLs without exposing them in public diagnostics or query strings. The sender selects slots with GET_ARL and names exactly one receiver. The receiver names exactly one sender. Both use the same ARL_SHARE_SECRET.",
      sender: [
        "Set GET_ARL=1,2,6 (only the local slots you intentionally want to share).",
        "Set GET_ARL_RECEIVER_URL=https://receiver.example.workers.dev.",
        "Create one strong random ARL_SHARE_SECRET and store it as a Cloudflare Secret. Use the identical secret on the receiver.",
        "Deploy the sender."
      ],
      receiver: [
        "Set GET_ARL_SENDER_URL=https://sender.example.workers.dev.",
        "Set the identical ARL_SHARE_SECRET as the sender.",
        "Bind GENERAL_MUSIC_CACHE if you want imported shared ARLs to survive Worker isolate restarts. Without it, the hot copy lasts only while the isolate remains warm.",
        "Call /arl-share/sync once to test the relationship. After that, normal traffic refreshes authorization in the background every ARL_SHARE_SYNC_TTL_SECONDS."
      ],
      access: "When API keys are restricted to local slots, set ARL_SHARE_ACCESS=true on the receiver if those clients should also be allowed to use imported shared slots. Leave it false if shared ARLs should only be used by internal/default selection paths.",
      revocation: "Remove or change GET_ARL_RECEIVER_URL on the sender. The receiver detects the 403 on its next synchronization and deletes its imported shared ARLs and their cached sessions. Lower ARL_SHARE_SYNC_TTL_SECONDS for faster revocation detection.",
      security: "The receiver request is HMAC-authenticated with ARL_SHARE_SECRET and binds the exact sender/receiver origins plus a fresh nonce and timestamp. The selected ARLs are returned only inside an AES-GCM authenticated encrypted envelope. No raw ARL is returned by /routing, /docs, /ping, /env, or /arl-share/sync.",
      diagnostics: "Use /arl-share/sync for a manual receiver test. Use /routing for configuration state and /ping for ARL health. Error states include not_configured, authorization_failed, revoked, request_expired, identity_mismatch, no_selected_arls, and synchronization errors."
    },
    quick_start: {
      private_api: [
        "Save the Worker as worker.js.",
        "Set DEEZER_ARL as a Worker secret.",
        "Set API_KEY as a Worker secret.",
        "Deploy with npx wrangler deploy.",
        "Call /ping without a client API key for a cheap instance liveness check; use /arl-health for live ARL validation."
      ],
      public_api: [
        "Save the Worker as worker.js.",
        "Set DEEZER_ARL as a Worker secret.",
        "Set PUBLIC_API=true as a non-secret Worker variable.",
        "Deploy with npx wrangler deploy.",
        "Call /ping without a client API key for a cheap instance liveness check."
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
      similar_recommendations: `${origin}/recommendations?id=3135556&limit=25`,
      similar_recommendations_q: `${origin}/recommendations?q=Starboy%20The%20Weeknd&limit=25`,
      similar_recommendations_isrc: `${origin}/recommendations?isrc=USUG11600920&limit=25`,
      device: `${origin}/device`,
      routing: `${origin}/routing`,
      arl_share_sync: `${origin}/arl-share/sync`,
      test_routing: `${origin}/test-routing?api_key=<configured-api-key>&track_id=920991742`,
      test_routing_alias: `${origin}/test-routing?api_key=<configured-api-key>&track_id=920991742`,
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
      "/stream-track/": "Resolve a numeric Deezer track id to the Worker playback path. Accepts id and optional quality/format. Authenticated generated URLs use api_key plus stream_token, or api_key plus a short-lived ?device= token when DEVICE_BOUND_SIGNED_STREAMS=true; the long-lived d1 device credential is never embedded.",
      "/stream": "Decryption proxy for a resolved HTTPS Deezer CDN URL. Requires id, url, and format. Only hosts allowed by STREAM_CDN_HOSTS are accepted.",
      "/album/:id": "Album metadata plus normalized album tracks. Nested tracks include streamUrl.",
      "/album/:id/tracks": "Paginated album track listing. Tracks include streamUrl.",
      "/artist/:id": "Artist metadata.",
      "/artist/:id/top": "Paginated artist top-track listing. Tracks include streamUrl.",
      "/artist/:id/albums": "Paginated artist album listing.",
      "/playlist/:id": "Playlist metadata plus normalized playlist tracks; /playlist can also generate a similar-track playlist from id/isrc/q/title/artist and includes the seed.",
      "/playlist/:id/tracks": "Paginated playlist track listing. Tracks include streamUrl.",
      "/playlist/:id/full": "Alias for playlist track listing.",
      "/chart/<tracks|albums|artists|playlists>": "Paginated Deezer chart data. Chart tracks include streamUrl.",
      "/genre": "Paginated genre listing. /genre/:id resolves the real Deezer genre first and then loads its canonical genre chart; invalid genre IDs return a proper error instead of fabricated metadata.",
      "/genre/:id": "Genre metadata plus non-empty chart collections (artists, albums, tracks) when Deezer returns them. Empty/null collections are omitted.",
      "/radio": "Radio listing or generated track radio; use id/isrc/q/title/artist for track-based radio.",
      "/radio/:id": "Radio metadata plus tracks; track-radio mode uses the same similarity engine as /recommendations.",
      "/recommendations": "Personalized Deezer recommendations by default. For song-based recommendations, provide id, q/query/s, isrc/i, title, and/or artist to resolve a seed and return similar tracks. Examples: /recommendations?id=3135556, /recommendations?q=Starboy%20The%20Weeknd, /recommendations?isrc=USUG11600920. user_id is retained only for personalized mode and cannot be combined with song-based recommendations. Recommendation tracks include streamUrl.",
      "/lyrics": "Lyrics lookup for a track id. The Worker uses native Deezer lyrics sources and can return word-level data when Deezer provides it.",
      "/cover": "Build normalized artwork URLs from an artwork hash/URL, or resolve artwork from a track id, ISRC, query, or artist id.",
      "/ping": "Tests configured Deezer ARL slots and reports active/failed state and detected quality capability. Shared imported slots are included in instance health when available.",
      "/arl-share/sync": "Receiver-only manual synchronization endpoint. It performs the authenticated encrypted sender handshake and reports shared count/status without returning ARL values.",
      "/arl-share/request": "Sender-side handshake endpoint. It accepts only the exact GET_ARL_RECEIVER_URL and a valid ARL_SHARE_SECRET signature, then returns an encrypted ARL bundle.",
      "/device": "Registers a cryptographically signed device credential when DEVICE_BOUND_SIGNED_STREAMS=true. Native clients should store device_token securely and send X-Voria-Device. Browsers can use the HttpOnly __Host-VoriaDevice cookie automatically set by /device. Refresh /device if the signing secret/credential is rotated or the browser no longer has a valid device cookie. If ALLOW_QUERY_DEVICE_SIGN=true, raw d1 credentials may be supplied as ?device_credential= for testing. Generated streamUrl values never contain the long-lived d1 credential.",
      "/routing": "Public, rate-limited routing/security diagnostics. No API key is required because it reports configuration shape and limits, not credential values. It reports device-bound signing state, playback URL authorization, diagnostic aliases, and supported HTTP methods.",
      "/env": "Admin-only environment diagnostics. Values matching secret-like names are intentionally hidden. Requires ADMIN_API_KEY directly; normal API_KEY is not required.",
      "/test-routing": "Protected routing-only end-to-end diagnostic. Exercises catalog, recommendation, artwork, lyrics, genre, routing, docs, and playback resolution paths. ARL health is handled separately by /arl-health. /testRouting and /testRoutings remain compatibility aliases."
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
      secrets: ["DEEZER_ARL", "DEEZER_ARL_1..50", "API_KEY", "API_KEY_1..50", "ADMIN_API_KEY", "STREAM_TOKEN_SECRET", "ARL_SHARE_SECRET"]
    },
    security: {
      secrets: "ARLs, client API keys, and ADMIN_API_KEY are credentials and should be stored as Cloudflare Secrets, not plaintext vars.",
      stream_proxy: "The /stream route is not an arbitrary fetch proxy. It requires HTTPS and an allowlisted Deezer CDN hostname.",
      query_keys: "Query-string API keys are disabled by default because URLs can be logged or cached. Enable ALLOW_QUERY_API_KEY only when a client cannot send headers. Generated playback URLs may still carry api_key for the authenticated stream flow; those responses are marked private/no-store and protected by short-lived playback authorization.",
      admin: "/env is protected separately with ADMIN_API_KEY even when PUBLIC_API=true.",
      cors: "CORS is controlled by CORS_ALLOW_ORIGIN and defaults to *."
    },
    troubleshooting: {
      ping_fails: "Check DEEZER_ARL secrets first. Run /ping and inspect each configured slot's status and tier.",
      unauthorized: "Protected Deezer data routes require Authorization: Bearer <API_KEY> or X-API-Key when client keys are configured. Public informational routes such as /ping and /routing do not require a client API key.",
      env_returns_403: "Supply ADMIN_API_KEY using Authorization: Bearer <ADMIN_API_KEY> or X-API-Key. /env never exposes secret values.",
      flac_falls_back: "The selected ARL may not have lossless capability, the Deezer media authorization may have expired, or the FLAC media URL request may have failed. /ping shows the detected account tier.",
      stream_rejected: "The /stream URL must use HTTPS and its hostname must match STREAM_CDN_HOSTS. The default allowlist is *.dzcdn.net and media.deezer.com.",
      stream_api_key: "When a request is authenticated with an API key, generated streamUrl values and stream redirects carry that same key as api_key so the returned URL can be opened directly. A short-lived stream_token is also attached and bound to that key, the track, and the caller IP. After successful token validation, the Worker can set an HttpOnly signed playback session cookie so subsequent Range requests do not depend on the URL token remaining unexpired. Playback routes accept these generated query parameters even when ALLOW_QUERY_API_KEY=false. Public API requests do not append client credentials.",
      stream_token: "Generated authenticated stream URLs contain api_key for client/ARL identity plus stream_token for temporary bootstrap authorization. stream_token expires according to STREAM_TOKEN_TTL_SECONDS and is bound to the authenticated API key, track id, caller IP, and optionally the caller User-Agent when STREAM_TOKEN_BIND_USER_AGENT is enabled. The token is reusable until expiration because no replay blacklist is maintained. The Worker can establish an HttpOnly signed playback session cookie with an idle TTL controlled by STREAM_SESSION_TTL_SECONDS; active Range playback refreshes it near expiry. The session cookie is never placed in the stream URL.",
      device_bound_streams: "When DEVICE_BOUND_SIGNED_STREAMS=true, call /device on the same host used for playback. Native clients should persist device_token securely and send X-Voria-Device; browsers can use the HttpOnly __Host-VoriaDevice cookie automatically set by /device. If the signing secret/credential is rotated or the browser no longer has the cookie, refresh /device. If ALLOW_QUERY_DEVICE_SIGN=true, raw credentials may be supplied as ?device_credential= for test clients. Generated streamUrl values include api_key and a short-lived device-bound playback token in ?device=, but never the long-lived d1 credential. A copied streamUrl therefore still fails without the original device credential. /stream-track, /track/:id/stream, and /stream validate both the device credential and the device-bound playback token.",
      stream_cache_security: "Catalog responses containing client API keys are marked private, no-store so one client's stream URL cannot be publicly cached and returned to another client.",
      slow_catalog: "Increase UPSTREAM_TIMEOUT_MS only when the upstream path genuinely needs more time. Shared catalog/search/lyrics caching can be enabled with GENERAL_MUSIC_CACHE.",
      slow_flac: "FLAC decryption is CPU-heavy. Keep STREAM_CHUNK_SIZE within the enforced range and avoid unnecessarily large concurrent playback workloads on small Worker plans.",
      rate_limited: "Check RATE_LIMITER first. If no distributed binding is present, RATE_LIMIT controls the local fallback limiter. RATE_LIMIT_FAIL_CLOSED controls behavior when the distributed binding errors."
    },
    cloudflare_notes: {
      env_vars: "Cloudflare Worker vars are runtime bindings available through the env parameter. Sensitive values should be Secrets rather than plaintext vars.",
      local_secrets: "For local development, use .dev.vars or .env, not both. Do not commit either file when they contain secrets.",
      environments: "Wrangler environments are separate Worker configurations. Bindings such as vars, KV namespaces, and secrets must be configured for each environment rather than assumed to inherit.",
      config_recommendation: "Use wrangler.jsonc as the project configuration source of truth for new Worker projects. Store STREAM_TOKEN_SECRET and DEVICE_BOUND_SECRET as Worker Secrets in production. Prefer a Custom Domain when this Worker is the origin for all paths; use a Workers Route when the Worker sits in front of an existing origin."
    }
  };
}

function routingInfo(env) {
  return {
    service: SERVICE_NAME,
    version: API_VERSION,
    authentication: {
      mode: String(env?.PUBLIC_API ?? "false").toLowerCase() === "true" ? "public" : (String(env?.REQUIRE_API_KEY ?? "true").toLowerCase() !== "false" ? "required" : "optional"),
      public_api: String(env?.PUBLIC_API ?? "false").toLowerCase() === "true",
      api_key_required: String(env?.PUBLIC_API ?? "false").toLowerCase() === "true" ? false : String(env?.REQUIRE_API_KEY ?? "true").toLowerCase() !== "false",
      routing_public: true,
      routing_api_key_required: false
    },
    public_diagnostics: {
      docs: true,
      routing: true,
      testRouting_aliases: ["/test-routing", "/testRouting", "/testRoutings"],
      env: false,
      testRouting_authentication: "client API key unless PUBLIC_API=true with no configured API_KEY mappings"
    },
    recommendation_inputs: {
      supported_seed_parameters: ["id", "q", "query", "s", "isrc", "i", "title", "track", "song", "artist"],
      route: "/recommendations",
      track_radio_route: "/radio?mode=track with the same seed parameters"
    },
    stream_transport: deviceBoundStreamsEnabled(env)
      ? "temporary client-bound Worker proxy URL with api_key client identity and short-lived device-bound playback token in ?device=; the long-lived d1 device credential stays in X-Voria-Device or the __Host-VoriaDevice cookie"
      : "temporary client-bound Worker proxy URL with api_key client identity and temporary stream_token authorization; authenticated entry points require bootstrap authorization by default",
    device_bound_streams: {
      enabled: deviceBoundStreamsEnabled(env),
      credential_header: "X-Voria-Device",
      browser_cookie: DEVICE_CREDENTIAL_COOKIE,
      query_credential_enabled: allowQueryDeviceSign(env),
      query_credential_parameter: "device_credential",
      generated_url_parameter: "device",
      generated_url_token: "short-lived HMAC playback token bound to the device credential hash, track, API key, caller IP, and optional User-Agent",
      long_lived_credential_in_url: false,
      refresh_note: "Browsers must obtain/refresh /device on the same host so the __Host- cookie is present. Native clients should persist device_token and send X-Voria-Device."
    },
    arl_sharing: arlShareStatus(env),
    media_resolution: {
      reauthentication_retries: getMediaRetryCount(env),
      timeout_ms: getMediaTimeoutMs(env),
      license_token_ttl_minutes: Math.max(10, Math.min(55, Number(env?.LICENSE_TOKEN_TTL_MINUTES) || 45)),
      fresh_session_before_media_after_ttl: true,
      fresh_track_token_on_auth_failure: true,
      quality_ladder: "FLAC -> MP3_320 -> MP3_128"
    },
    routes: {
      GET: ["/", "/info", "/search", "/track", "/album", "/artist", "/playlist", "/chart", "/genre", "/radio", "/recommendations", "/cover", "/lyrics", "/stream-track", "/stream", "/track/:id/stream", "/track/:id/lyrics", "/ping", "/arl-health", "/device", "/routing", "/env", "/docs", "/arl-share/sync", "/arl-share/request", "/test-routing", "/testRoutings", "/testRouting"],
      OPTIONS: ["/*"],
      HEAD: ["/stream", "/info", "/search", "/track", "/album", "/artist", "/playlist", "/chart", "/genre", "/radio", "/cover", "/ping", "/arl-health", "/device", "/routing", "/env", "/docs", "/test-routing", "/testRoutings", "/testRouting"]
    },
    stream_security: {
      arbitrary_url_proxy: false,
      requires_signed_token: true,
      requires_https_cdn: true,
      device_bound: deviceBoundStreamsEnabled(env),
      stream_url_format: deviceBoundStreamsEnabled(env)
        ? "/stream-track/?id=<trackId>&api_key=<client-key>&device=<short-lived-device-bound-token> (generated authenticated URLs; long-lived d1 credential is never embedded)"
        : "/stream-track/?id=<trackId>&api_key=<client-key>&stream_token=<short-lived-token> (generated authenticated URLs)",
      internal_proxy_route: "/stream",
      allowed_hosts: String(env?.STREAM_CDN_HOSTS || "*.dzcdn.net;media.deezer.com").split(";").map(x => x.trim()).filter(Boolean) },
    hardening: { allowed_methods: ["GET", "HEAD", "OPTIONS"], max_url_length: MAX_REQUEST_URL_LENGTH, max_query_value_length: MAX_QUERY_VALUE_LENGTH, upstream_timeout_ms: getUpstreamTimeoutMs(env), max_catalog_response_bytes: MAX_UPSTREAM_RESPONSE_BYTES }
  };
}




const worker = {
  async fetch(request, env, ctx) {
    try {
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

    const isArlShareRoute = primaryRoute === "arl-share";
    if (isArlShareRoute) {
      const response = await handleArlShareRoute(request, env, requestUrl, requestId);
      return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }

    // Load persisted shared ARLs before pool/auth selection. Once a hot copy
    // exists, refresh authorization in the background so playback stays fast.
    await maybeSyncSharedArls(env, ctx, false, requestUrl.origin);

    if (isTestRoutingsPath(requestUrl)) {
      const testAuth = authenticateTestRoutings(requestUrl, env);
      if (!testAuth.authorized) return publicError("FORBIDDEN", 403, env, requestId);
      const testKey = getTestRoutingPresentedKey(requestUrl);
      const diagnosticTrackId = requestUrl.searchParams.get("track_id")?.trim() || "920991742";
      if (request.method === "HEAD") {
        return new Response(null, { status: 200, headers: { ...getCorsHeaders(env), "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Request-ID": requestId } });
      }
      // /test-routing is intentionally a machine-readable routing-only diagnostic endpoint.
      const diagnostics = await runTestRoutingsJson(request, env, requestUrl, diagnosticTrackId, testKey, testAuth.allowedSlots);
      return jsonResponse(diagnostics, diagnostics.status === "complete" ? 200 : 502, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
    }

    if (primaryRoute === "arl-health") {
      const { arls, mappings } = getMemoizedConfig(env);
      const share = arlShareStatus(env);
      const sharedRuntime = arlShareRuntime.get(env);
      const started = Date.now();
      const results = await Promise.all(arls.map(async item => {
        const t = Date.now();
        try {
          const session = await getOrRenewSession(item.value, env);
          return { slot:item.slot, variable:item.name, status:"active", tier:session.canLossless?"lossless":(session.can320?"320":"128"), capabilities:["MP3_128",...(session.can320?["MP3_320"]:[]),...(session.canLossless?["FLAC"]:[])], shared:item.shared===true, source:item.shared?(item.sourceUrl||null):"local", origin_slot:item.shared?(item.originSlot||null):null, latency_ms:Date.now()-t };
        } catch(error) { const d=testRoutingErrorDetails(error,502); return {slot:item.slot,variable:item.name,status:"failed",shared:item.shared===true,source:item.shared?(item.sourceUrl||null):"local",origin_slot:item.shared?(item.originSlot||null):null,latency_ms:Date.now()-t,error:d}; }
      }));
      const active=results.filter(x=>x.status==="active").length, failed=results.length-active;
      return jsonResponse({service:SERVICE_NAME,version:API_VERSION,status:failed===0&&results.length?"healthy":(active?"degraded":"unhealthy"),checked_at:new Date().toISOString(),health:{arls:{configured:results.length,active,failed,checked_in_parallel:true,results},sharing:share,shared_runtime:{loaded:sharedRuntime?.arls?.length||0,last_sync_at:sharedRuntime?.lastSyncAt||null,last_sync_status:sharedRuntime?.lastSyncStatus||null,last_sync_error:sharedRuntime?.lastSyncError||null},bindings:{GENERAL_MUSIC_CACHE:Boolean(env?.GENERAL_MUSIC_CACHE),RATE_LIMITER:Boolean(env?.RATE_LIMITER)},configuration:{api_key_mappings:mappings.size,public_api:envBoolean(env,"PUBLIC_API",false),maintenance_mode:isMaintenanceMode(env),device_bound_signed_streams:deviceBoundStreamsEnabled(env)},runtime:{session_cache_entries:sessionCache.size,jwt_cache_entries:jwtCache.size,media_inflight:mediaInflight.size,track_token_inflight:trackTokenInflight.size,track_token_cache_entries:trackTokenCache.size,session_inflight:sessionInflight.size,catalog_inflight:catalogInflight.size,check_duration_ms:Date.now()-started}}},200,{"Cache-Control":"no-store","X-Request-ID":requestId},env);
    }

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

    if (request.method === "HEAD" && !["stream", "info", "search", "track", "album", "artist", "playlist", "chart", "genre", "radio", "cover", "ping", "arl-health", "device", "routing", "env", "docs", "arl-share", "test-routing", "testRoutings", "testRouting"].includes((requestUrl.pathname.replace(/^\/+|\/+$/g, "").split("/")[0] || ""))) {
      return new Response(null, { status: 404, headers: { ...getCorsHeaders(env), "X-Request-ID": requestId } });
    }


    const clientIp = getClientIp(request);
    const clientUserAgentHash = await getClientUserAgent(request);

    // /routing is intentionally public. It reports route/authentication metadata
    // only and does not expose credentials, ARLs, tokens, or other secret values.
    // Keep rate limiting in place so making this endpoint credential-free does not
    // make it an unlimited request target.
    const isPublicRouting = primaryRoute === "routing";
    const isPublicPing = primaryRoute === "ping" || requestUrl.searchParams.has("ping");
    const isPublicArlHealth = primaryRoute === "arl-health";
    const isAdminEnv = primaryRoute === "env";
    // /ping is intentionally credential-free. It performs an ARL health/capability
    // check but never returns a Deezer streamUrl, media URL, track token, lyrics,
    // catalog payload, or other protected Deezer data to the caller.
    const auth = (isPublicRouting || isPublicPing || isPublicArlHealth || isAdminEnv)
      ? {
          authorized: true,
          allowedSlots: null,
          tokenId: isPublicRouting ? "public-routing" : (isPublicPing ? "public-ping" : (isPublicArlHealth ? "public-arl-health" : "admin-env"))
        }
      : authenticateRequest(request, env);
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
    const deviceBinding = await getRequestDeviceBinding(request, authToken, env);
    const deviceBindingHash = deviceBoundStreamsEnabled(env) ? deviceBinding.hash : null;
    const deviceCredential = deviceBinding.valid ? getPresentedDeviceCredential(request, env) : null;
    const catalogResponseForRequest = (...args) => catalogResponse(...args, deviceCredential);

    if (primaryRoute === "device") {
      if (!deviceBoundStreamsEnabled(env)) return jsonResponse({ version: API_VERSION, enabled: false, message: "DEVICE_BOUND_SIGNED_STREAMS is disabled" }, 200, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
      if (request.method !== "GET") return publicError("METHOD_NOT_ALLOWED", 405, env, requestId);
      const credential = await registerDeviceCredential(authToken, env);
      if (!credential) return publicError("DEVICE_SIGNING_NOT_CONFIGURED", 503, env, requestId);
      const deviceCheck = await verifyDeviceCredential(credential, authToken, env);
      const ttl = Math.max(1, Number(deviceCheck.payload?.exp || 0) - Math.floor(Date.now() / 1000));
      const deviceCookie = `${DEVICE_CREDENTIAL_COOKIE}=${encodeURIComponent(credential)}; Path=/; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Lax`;
      return jsonResponse({ version: API_VERSION, enabled: true, device_token: credential, device_id: deviceCheck.id, expires_at: deviceCheck.payload?.exp || null, header: "X-Voria-Device", cookie: DEVICE_CREDENTIAL_COOKIE, usage: "Store the device_token securely for native clients, or rely on the HttpOnly device cookie set by this response. Generated streamUrl values never contain the long-lived d1 device credential." }, 200, { "Cache-Control": "no-store", "X-Request-ID": requestId, "Set-Cookie": deviceCookie }, env);
    }

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
      const configuredAdmin = String(env?.ADMIN_API_KEY || "").trim();
      if (!configuredAdmin || !presented || presented !== configuredAdmin) return publicError("FORBIDDEN", 403, env, requestId);
      const response = jsonResponse({ service: SERVICE_NAME, version: API_VERSION, variables: diagnosticEnv(env), variableDocumentation: ENVIRONMENT_VARIABLES, streamTokenSecurity: STREAM_TOKEN_SECURITY_NOTE, secret_variables: ["DEEZER_ARL[_1..50]", "API_KEY[_1..50]", "ADMIN_API_KEY", "STREAM_TOKEN_SECRET"] }, 200, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
      return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }


    if (primaryRoute === "ping" || requestUrl.searchParams.has("ping")) {
      // Cheap liveness only. Live Deezer ARL validation belongs to /arl-health.
      const { arls } = getMemoizedConfig(env);
      const shared = arls.filter(item => item.shared === true).length;
      const local = arls.length - shared;
      const configuredQuality = String(env?.DEFAULT_QUALITY || "best").trim().toLowerCase() || "best";
      const response = jsonResponse({
        service: SERVICE_NAME,
        version: API_VERSION,
        status: arls.length > 0 ? "healthy" : "degraded",
        configured: arls.length,
        local,
        shared,
        configured_quality: configuredQuality,
        maintenance: isMaintenanceMode(env),
        timestamp: new Date().toISOString(),
      }, arls.length > 0 ? 200 : 503, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
      return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }

    if (primaryRoute === "stream") {
      const trackId = segments[1] || requestUrl.searchParams.get("id");
      const legacyCdnUrl = requestUrl.searchParams.get("url");
      const streamToken = requestUrl.searchParams.get("stream_token") || (String(requestUrl.searchParams.get("device") || "").startsWith("d1.") ? null : requestUrl.searchParams.get("device"));

      if (deviceBoundStreamsEnabled(env) && !deviceBinding.valid) return publicError(deviceBinding.present ? "DEVICE_CREDENTIAL_INVALID" : "DEVICE_CREDENTIAL_REQUIRED", 401, env, requestId);
      let streamSessionValid = false;
      let streamSessionEstablishedByCookie = false;
      let streamSessionCheck = null;
      if (authToken && trackId) {
        const sessionCookie = getCookie(request, STREAM_SESSION_COOKIE);
        if (sessionCookie) {
          let decodedSessionCookie = sessionCookie;
          try { decodedSessionCookie = decodeURIComponent(sessionCookie); } catch (_) { decodedSessionCookie = sessionCookie; }
          const sessionCheck = await verifyStreamSession(decodedSessionCookie, { trackId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null, deviceBindingHash }, env);
          streamSessionCheck = sessionCheck;
          streamSessionValid = sessionCheck.valid;
          streamSessionEstablishedByCookie = sessionCheck.valid;
        }
      }

      let streamTokenAuthorized = false;
      if (streamToken && !streamSessionValid) {
        if (!authToken || !trackId) return publicError("INVALID_STREAM_TOKEN", 401, env, requestId);
        const tokenCheck = await verifyStreamBootstrapToken(streamToken, { trackId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null, deviceBindingHash }, env);
        if (!tokenCheck.valid) return invalidStreamBootstrapToken(tokenCheck.reason, tokenCheck.reason === "expired" ? 401 : 403, env, requestId);
        streamTokenAuthorized = true;
        streamSessionValid = true;
      }

      // A valid device-bound credential is itself sufficient playback authorization.
      // This allows device-bound stream URLs to be replayable by the registered device
      // without requiring a separate bootstrap/session token on every generated URL.
      if (authenticatedPlaybackRequiresBootstrap(env, authToken) && !deviceBinding.valid && !streamSessionValid && !streamTokenAuthorized) {
        return publicError("PLAYBACK_SESSION_REQUIRED", 401, env, requestId);
      }

      if (trackId && !legacyCdnUrl) {
        const q = requestUrl.searchParams.get("quality") || env?.DEFAULT_QUALITY || "best";
        const alt = requestUrl.searchParams.get("alt") ? `&alt=${encodeURIComponent(requestUrl.searchParams.get("alt"))}` : "";
        const exp = !preferExplicit ? "&explicit=false" : "";
        let streamTrackUrl = appendAuthenticatedStreamCredentials(
          `${requestUrl.origin}/stream-track?id=${encodeURIComponent(trackId)}&quality=${encodeURIComponent(q)}${alt}${exp}`,
          authToken,
          deviceCredential,
          env,
        );
        streamTrackUrl = await appendStreamTokenToUrl(streamTrackUrl, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash);
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
            ? await establishStreamSession(trackId, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash)
            : await maybeRefreshStreamSession(streamSessionCheck, trackId, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash);
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
            ? await establishStreamSession(trackId, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash)
            : await maybeRefreshStreamSession(streamSessionCheck, trackId, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash);
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
      if (deviceBoundStreamsEnabled(env) && !deviceBinding.valid) return publicError(deviceBinding.present ? "DEVICE_CREDENTIAL_INVALID" : "DEVICE_CREDENTIAL_REQUIRED", 401, env, requestId);
      const rawId = segments[1] || requestUrl.searchParams.get("id") || requestUrl.searchParams.get("track_id");
      const streamToken = requestUrl.searchParams.get("stream_token") || (String(requestUrl.searchParams.get("device") || "").startsWith("d1.") ? null : requestUrl.searchParams.get("device"));
      let streamSessionCookieValue = null;
      // Device-bound credentials can authorize playback directly.
      // Bootstrap tokens remain required for authenticated clients that do not
      // present a valid device credential.
      if (authenticatedPlaybackRequiresBootstrap(env, authToken) && !deviceBinding.valid && !streamToken) {
        return publicError("STREAM_TOKEN_REQUIRED", 401, env, requestId);
      }
      if (streamToken) {
        if (!authToken || !rawId) return publicError("INVALID_STREAM_TOKEN", 401, env, requestId);
        const tokenCheck = await verifyStreamBootstrapToken(streamToken, { trackId: rawId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null, deviceBindingHash }, env);
        if (!tokenCheck.valid) return invalidStreamBootstrapToken(tokenCheck.reason, tokenCheck.reason === "expired" ? 401 : 403, env, requestId);
        streamSessionCookieValue = await establishStreamSession(rawId, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash);
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
        let cleanStreamUrl = appendAuthenticatedStreamCredentials(
          `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(resolved.mediaResult.directCdnUrl)}&format=${encodeURIComponent(resolved.mediaResult.format)}`,
          authToken,
          deviceCredential,
          env,
        );
        if (streamSessionCookieValue) {
          // The bootstrap token is temporary. Do not carry it into the next redirect.
          try { new URL(cleanStreamUrl).searchParams.delete("stream_token"); } catch (_) {}
          const stripped = new URL(cleanStreamUrl);
          stripped.searchParams.delete("stream_token");
          cleanStreamUrl = stripped.toString();
        } else {
          cleanStreamUrl = await appendStreamTokenToUrl(cleanStreamUrl, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash);
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
        const catalogResult = await handleCatalogRoute(requestUrl, env, segments, authToken, clientIp, clientUserAgentHash, deviceCredential);
        if (catalogResult) {
          if (request.method === "HEAD") return new Response(null, { status: catalogResult.status, headers: catalogResult.headers });
          return catalogResult;
        }
      } catch (error) {
        if (primaryRoute === "recommendations" || requestUrl.pathname.startsWith("/recommendations")) {
          return jsonResponse({
            error: "CATALOG_REQUEST_FAILED",
            status: error?.status >= 400 ? error.status : 502,
            code: error?.code || "CATALOG_UPSTREAM_ERROR",
            message: error?.message || "Catalog request failed",
            request_id: requestId,
          }, error?.status >= 400 ? error.status : 502, { "X-Request-ID": requestId, "Cache-Control": "no-store" }, env);
        }
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
      if (deviceBoundStreamsEnabled(env) && !deviceBinding.valid) return publicError(deviceBinding.present ? "DEVICE_CREDENTIAL_INVALID" : "DEVICE_CREDENTIAL_REQUIRED", 401, env, requestId);
      const requestedTrackId = segments[1];
      const streamToken = requestUrl.searchParams.get("stream_token") || (String(requestUrl.searchParams.get("device") || "").startsWith("d1.") ? null : requestUrl.searchParams.get("device"));
      if (authenticatedPlaybackRequiresBootstrap(env, authToken) && !streamToken) {
        return publicError("STREAM_TOKEN_REQUIRED", 401, env, requestId);
      }
      if (streamToken) {
        const tokenCheck = await verifyStreamBootstrapToken(streamToken, { trackId: requestedTrackId, apiKey: authToken, clientIp, userAgentHash: shouldBindStreamTokenToUserAgent(env) ? clientUserAgentHash : null, deviceBindingHash }, env);
        if (!tokenCheck.valid) return invalidStreamBootstrapToken(tokenCheck.reason, tokenCheck.reason === "expired" ? 401 : 403, env, requestId);
      }
      const rawQuality = (requestUrl.searchParams.get("quality") || requestUrl.searchParams.get("format") || env?.DEFAULT_QUALITY || "best").toLowerCase().trim();
      try {
        const resolved = await resolvePlaybackStreamOnly(requestedTrackId, rawQuality, env, auth.allowedSlots);
        const resolvedTrackId = resolved.trackId || requestedTrackId;
        if (String(resolvedTrackId) !== String(requestedTrackId)) {
          return publicError("STREAM_TRACK_MISMATCH", 403, env, requestId);
        }
        let streamUrl = appendAuthenticatedStreamCredentials(
          `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(resolved.mediaResult.directCdnUrl)}&format=${encodeURIComponent(resolved.mediaResult.format)}`,
          authToken,
          deviceCredential,
          env,
        );
        let sessionCookie = null;
        if (authToken) {
          sessionCookie = await establishStreamSession(resolvedTrackId, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash);
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
        return catalogResponseForRequest({ version: API_VERSION, track_id: segments[1], data: lyrics }, 200, 0, env, apiToken, clientIp, clientUserAgentHash);
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
        let cleanStreamUrl = appendAuthenticatedStreamCredentials(
          `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(resolved.mediaResult.directCdnUrl)}&format=${encodeURIComponent(resolved.mediaResult.format)}`,
          authToken,
          deviceCredential,
          env,
        );
        cleanStreamUrl = await appendStreamTokenToUrl(cleanStreamUrl, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash);
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

      const cleanStreamUrl = appendAuthenticatedStreamCredentials(
        `${requestUrl.origin}/stream?id=${resolvedTrackId}&url=${encodeURIComponent(mediaResult.directCdnUrl)}&format=${encodeURIComponent(mediaResult.format)}`,
        authToken,
        deviceCredential,
        env,
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
        streamUrl: await appendStreamTokenToUrl(cleanStreamUrl, authToken, clientIp, env, clientUserAgentHash, deviceBindingHash),
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
    } catch (error) {
      const requestId = request.headers.get("X-Request-ID")?.trim().slice(0, 128) || makeRequestId();
      return jsonResponse({
        error: "STREAM_REQUEST_FAILED",
        status: 500,
        request_id: requestId,
        diagnostic: {
          code: error?.code || null,
          message: String(error?.message || error || "Unknown Worker error").slice(0, 500),
        },
      }, 500, { "Cache-Control": "no-store", "X-Request-ID": requestId }, env);
    }
  },
};

export default worker;
