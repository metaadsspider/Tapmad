'use strict';
/*
 * Shared relay core for Vercel serverless functions.
 *
 * Stateless by design (serverless instances share no memory):
 *   - Tokens are HMAC-signed (sid|exp|ip) with a fixed TTL — no session store.
 *   - Playlist URIs pointing outside the stream dir are AES-256-GCM sealed into
 *     the path (/live/<token>/e/<sealed>/<name>) — opaque without SECRET.
 *   - Same-origin requests (page + API on one Vercel deployment) are allowed
 *     automatically; extra origins go in ALLOWED_ORIGINS.
 */

const crypto = require('crypto');
const path = require('path');

function flag(name, dflt) {
  const v = process.env[name];
  return v === undefined ? dflt : (v !== 'false' && v !== '0');
}

const CFG = {
  UPSTREAM_MASTER: (process.env.UPSTREAM_MASTER || '').trim(),
  SECRET: process.env.SECRET || '',
  SESSION_HOURS: Number(process.env.SESSION_HOURS || 2),
  BIND_IP: flag('BIND_IP', true),
  REQUIRE_HEADER: flag('REQUIRE_HEADER', true),
  PLAYER_HDR: 'hls-secure',
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim().replace(/\/+$/, '').toLowerCase()).filter(Boolean),
  RATE_LIVE_PER_MIN: Number(process.env.RATE_LIVE_PER_MIN || 600),
  RATE_SESSION_PER_MIN: Number(process.env.RATE_SESSION_PER_MIN || 12),
  UPSTREAM_TIMEOUT_MS: 20000,
  UPSTREAM_HEADERS: { 'User-Agent': process.env.UPSTREAM_UA || 'Mozilla/5.0 (HLS relay)' }
};

let BASE_DIR = null;
try {
  if (CFG.UPSTREAM_MASTER) {
    const u = new URL(CFG.UPSTREAM_MASTER);
    if (/^https?:$/.test(u.protocol)) BASE_DIR = new URL('.', u);
  }
} catch (_) { /* left null → handlers answer 503 "not configured" */ }

const TTL_MS = () => Math.max(1, CFG.SESSION_HOURS) * 3600000;

/* ── tokens (stateless) ─────────────────────────────────────────────── */

const sign = p => crypto.createHmac('sha256', CFG.SECRET).update(p).digest('base64url');
function sigEqual(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function issueToken(ip) {
  const sid = crypto.randomBytes(16).toString('hex');
  const exp = Date.now() + TTL_MS();
  return sid + '.' + exp + '.' + sign(sid + '|' + exp + '|' + ip);
}

function checkToken(token, ip) {
  if (!CFG.SECRET) return false;
  const p = String(token || '').split('.');
  if (p.length !== 3) return false;
  const [sid, exp, sig] = p;
  if (!sigEqual(sig, sign(sid + '|' + exp + '|' + ip))) return false;
  if (Number(exp) < Date.now()) return false;
  return true;
}

/* ── AES-sealed foreign URLs (replaces the old in-memory urlMap) ────── */

function urlKey() { return crypto.createHash('sha256').update('sealed-url:' + CFG.SECRET).digest(); }

function sealUrl(abs) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', urlKey(), iv);
  const ct = Buffer.concat([c.update(abs, 'utf8'), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]).toString('base64url');
}

function openUrl(sealed) {
  try {
    const buf = Buffer.from(String(sealed), 'base64url');
    if (buf.length < 12 + 16) return null;
    const d = crypto.createDecipheriv('aes-256-gcm', urlKey(), buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(buf.length - 16));
    const out = Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString('utf8');
    const u = new URL(out);
    return /^https?:$/.test(u.protocol) ? u : null;
  } catch (_) { return null; }
}

/* ── per-instance rate limiting (still useful, not global on serverless) */

const buckets = new Map();
function allow(ip, key, max, winMs) {
  const now = Date.now(), k = ip + '|' + key;
  let b = buckets.get(k);
  if (!b || now - b.t0 >= winMs) { b = { t0: now, n: 0 }; buckets.set(k, b); }
  b.n++;
  if (buckets.size > 20000) buckets.clear();
  return b.n <= max;
}

/* ── request helpers ────────────────────────────────────────────────── */

function clientIP(req) {
  const xff = req.headers['x-forwarded-for'] || req.headers['x-vercel-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function requestOrigin(req) {
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').toLowerCase();
  if (!host) return '';
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim().toLowerCase();
  return proto + '://' + host;
}

function originAllowed(req) {
  const o = req.headers.origin || req.headers.referer || '';
  let org = '';
  try { org = new URL(String(o)).origin; } catch (_) {}
  if (!org) return false;
  if (org === requestOrigin(req)) return true; // same deployment → always fine
  return CFG.ALLOWED_ORIGINS.includes(org);
}

function corsFor(req, res) {
  const o = req.headers.origin;
  if (o && (originAllowed(req) || CFG.ALLOWED_ORIGINS.includes(String(o).toLowerCase()))) {
    res.setHeader('Access-Control-Allow-Origin', String(o));
    res.setHeader('Vary', 'Origin');
  }
}

function deny(res, code) { res.statusCode = code; res.end(); }

function json(res, obj) {
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

const MIME = {
  '.m3u8': 'application/vnd.apple.mpegurl', '.m3u': 'application/vnd.apple.mpegurl',
  '.ts': 'video/mp2t', '.m4s': 'video/iso.segment', '.mp4': 'video/mp4',
  '.aac': 'audio/aac', '.key': 'application/octet-stream', '.vtt': 'text/vtt'
};

/* ── playlist rewriting ─────────────────────────────────────────────── */

function toProxyURL(token, base, uri) {
  let abs;
  try { abs = new URL(uri, base); } catch (_) { return uri; }
  if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return uri;
  if (BASE_DIR && abs.href.startsWith(BASE_DIR.href))
    return '/live/' + token + '/' + abs.href.slice(BASE_DIR.href.length);
  /* foreign host → AES-sealed opaque id (no server-side state needed) */
  const name = abs.pathname.split('/').pop() || 'file';
  return '/live/' + token + '/e/' + sealUrl(abs.href) + '/' + name;
}

function rewritePlaylist(text, token, base) {
  return text.split(/\r?\n/).map(line => {
    const t = line.trim();
    if (!t) return line;
    if (t[0] === '#')
      return line.replace(/URI="([^"]+)"/g, (_, u) => 'URI="' + toProxyURL(token, base, u) + '"');
    return toProxyURL(token, base, t);
  }).join('\n');
}

function parseLivePath(req) {
  let p = String(req.url || '');
  const qi = p.indexOf('?');
  const search = qi >= 0 ? p.slice(qi) : '';
  if (qi >= 0) p = p.slice(0, qi);
  p = p.replace(/^\/api\/live\//i, '').replace(/^\/live\//i, '').replace(/^\/+/, '');
  if (!p) return null;
  const segs = p.split('/').map(s => { try { return decodeURIComponent(s); } catch (_) { return s; } });
  return { token: segs[0], rest: segs.slice(1), search };
}

function resolveUpstream(rest, search) {
  if (rest.length === 0 || (rest.length === 1 && rest[0] === 'index.m3u8'))
    return new URL(CFG.UPSTREAM_MASTER);
  if (rest[0] === 'e' && rest.length >= 2) return openUrl(rest[1]);
  return new URL(rest.join('/') + (search || ''), BASE_DIR);
}

/* ── endpoints ──────────────────────────────────────────────────────── */

async function handleSession(req, res) {
  if (req.method === 'OPTIONS') {
    corsFor(req, res);
    res.writeHead(204, {
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Player',
      'Access-Control-Max-Age': '600'
    });
    return res.end();
  }
  if (req.method !== 'POST') return deny(res, 405);
  if (!CFG.SECRET || !BASE_DIR) {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({
      ok: false,
      error: 'relay not configured — set UPSTREAM_MASTER and SECRET (Vercel env vars or .env)'
    }));
  }
  if (!originAllowed(req)) return deny(res, 403);
  const ip = clientIP(req);
  if (!allow(ip, 'sess', CFG.RATE_SESSION_PER_MIN, 60000)) return deny(res, 429);
  corsFor(req, res);
  const token = issueToken(ip);
  return json(res, { ok: true, url: '/live/' + token + '/index.m3u8', ttl: TTL_MS() });
}

async function handleLive(req, res) {
  corsFor(req, res);
  if (!CFG.SECRET || !BASE_DIR) return deny(res, 503);
  if (CFG.REQUIRE_HEADER) {
    const dest = String(req.headers['sec-fetch-dest'] || '');
    const ok = req.headers['x-player'] === CFG.PLAYER_HDR || ['video', 'audio', 'media'].includes(dest);
    if (!ok) return deny(res, 403);
  }
  const parsed = parseLivePath(req);
  if (!parsed) return deny(res, 400);
  const ip = clientIP(req);
  if (!checkToken(parsed.token, CFG.BIND_IP ? ip : '*')) return deny(res, 403);
  if (!allow(ip, 'live', CFG.RATE_LIVE_PER_MIN, 60000)) return deny(res, 429);

  const joined = parsed.rest.join('/');
  if (joined.includes('..') || joined.includes('\\') ||
      /^[a-z][a-z0-9+.-]*:/i.test(joined)) return deny(res, 400);

  let upstream;
  try { upstream = resolveUpstream(parsed.rest, parsed.search); } catch (_) { return deny(res, 400); }
  if (!upstream) return deny(res, 404);

  const headers = Object.assign({}, CFG.UPSTREAM_HEADERS);
  if (req.headers.range) headers.Range = String(req.headers.range);

  let up;
  try {
    up = await fetch(upstream, {
      headers, redirect: 'follow',
      signal: AbortSignal.timeout(CFG.UPSTREAM_TIMEOUT_MS)
    });
  } catch (_) { return deny(res, 502); }

  const looksPlaylist = /\.(m3u8|m3u)(\?|$)/i.test(joined) ||
                        /mpegurl/i.test(up.headers.get('content-type') || '');

  if (looksPlaylist && up.ok) {
    const text = await up.text();
    const base = new URL('.', up.url || upstream.href); // per HLS spec, resolve against final URL
    const out = rewritePlaylist(text, parsed.token, base);
    res.writeHead(200, {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-store'
    });
    return res.end(out);
  }

  const ct = up.headers.get('content-type') ||
             MIME[path.extname(upstream.pathname).toLowerCase()] ||
             'application/octet-stream';
  const out = { 'Content-Type': ct, 'Cache-Control': 'private, max-age=30' };
  for (const h of ['Content-Range', 'Accept-Ranges']) {
    const v = up.headers.get(h); if (v) out[h] = v;
  }
  const cl = up.headers.get('content-length');
  if (cl && !up.headers.get('content-encoding')) out['Content-Length'] = cl;
  res.writeHead(up.status, out);
  if (!up.body) return res.end();
  const { Readable } = require('stream');
  Readable.fromWeb(up.body).pipe(res);
}

module.exports = { CFG, handleSession, handleLive, issueToken, sealUrl, openUrl };
