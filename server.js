#!/usr/bin/env node
/*
 * Secure HLS relay — the browser never sees the real stream host.
 *
 * How it protects the m3u8:
 *   1. The real URL exists only here / in .env — never in the page source.
 *   2. The player POSTs /api/session (Origin-checked, rate-limited) and gets a
 *      short-lived HMAC-signed token bound to its IP: 30 s to start streaming,
 *      sliding to 10 min while the stream is actually being watched.
 *   3. Every playlist is rewritten on the fly: variant playlists, segments,
 *      AES keys, I-frame playlists and renditions become opaque
 *      /live/<token>/... paths. The upstream host never appears in any
 *      response body, so extensions/scrapers only see expiring proxy URLs.
 *
 * Run:    node server.js          (Node 18+, zero npm dependencies)
 * Config: environment variables, or a .env file next to this script
 *         (see .env.example)
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');

/* optional .env loader (no dependencies) */
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    if (line.trim().startsWith('#')) continue;
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && m[2] !== '' && process.env[m[1]] === undefined)
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch (_) { /* no .env file — fine */ }

function flag(name, dflt) {
  const v = process.env[name];
  return v === undefined ? dflt : (v !== 'false' && v !== '0');
}

/* ── Configuration ──────────────────────────────────────────────────── */

const CFG = {
  PORT: Number(process.env.PORT || 3000),
  // The real stream URL — the ONLY place it exists. Never sent to the browser.
  UPSTREAM_MASTER: process.env.UPSTREAM_MASTER || 'https://example.com/live/stream/index.m3u8',
  // HMAC secret. Set a long random value (openssl rand -hex 32), otherwise
  // sessions do not survive restarts.
  SECRET: process.env.SECRET || crypto.randomBytes(32).toString('hex'),
  TOKEN_TTL_MS: 30 * 1000,           // issued token must be used within 30 s
  SESSION_TTL_MS: 10 * 60 * 1000,    // sliding: every proxied request extends 10 min
  BIND_IP: flag('BIND_IP', true),    // token only usable from the requesting IP
  REQUIRE_HEADER: flag('REQUIRE_HEADER', true), // /live/* must carry X-Player
                                                // (set false to support old iPhone native HLS)
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
    .split(',').map(s => s.trim().replace(/\/+$/, '').toLowerCase()).filter(Boolean),
  MAX_SESSIONS_PER_IP: 8,
  RATE_LIVE_PER_MIN: 600,
  RATE_SESSION_PER_MIN: 12,
  UPSTREAM_TIMEOUT_MS: 20 * 1000,
  UPSTREAM_HEADERS: { 'User-Agent': process.env.UPSTREAM_UA || 'Mozilla/5.0 (HLS relay)' },
  SERVE_PLAYER: flag('SERVE_PLAYER', true), // serve ./index.html at /
  TRUST_PROXY: flag('TRUST_PROXY', false)   // use X-Forwarded-For behind nginx/Cloudflare
};

const PLAYER_HDR = 'hls-secure'; // must match SEC_HEADERS in index.html

let BASE_DIR;
try {
  BASE_DIR = new URL('.', CFG.UPSTREAM_MASTER);
  if (!/^https?:$/.test(BASE_DIR.protocol)) throw new Error('scheme');
} catch (_) {
  console.error('UPSTREAM_MASTER must be an absolute http(s) URL to the master .m3u8');
  process.exit(1);
}

const MIME = {
  '.m3u8': 'application/vnd.apple.mpegurl', '.m3u': 'application/vnd.apple.mpegurl',
  '.ts': 'video/mp2t', '.m4s': 'video/iso.segment', '.mp4': 'video/mp4',
  '.aac': 'audio/aac', '.key': 'application/octet-stream', '.vtt': 'text/vtt'
};

/* ── sessions & tokens ──────────────────────────────────────────────── */

const sessions = new Map(); // sid -> { ip, exp, urlMap:Map(abs->id), urlRev:Map(id->abs) }

const sign = p => crypto.createHmac('sha256', CFG.SECRET).update(p).digest('base64url');
function sigEqual(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function issueToken(ip) {
  const now = Date.now();
  for (const [k, s] of sessions) if (s.exp < now) sessions.delete(k);
  let n = 0; for (const [, s] of sessions) if (s.ip === ip) n++;
  if (n >= CFG.MAX_SESSIONS_PER_IP) return null;
  const sid = crypto.randomBytes(16).toString('hex');
  const exp = now + CFG.TOKEN_TTL_MS;
  const token = sid + '.' + exp + '.' + sign(sid + '|' + exp + '|' + ip);
  sessions.set(sid, { ip, exp: now + CFG.SESSION_TTL_MS, urlMap: new Map(), urlRev: new Map() });
  return token;
}

function checkToken(token, ip) {
  const p = String(token || '').split('.');
  if (p.length !== 3) return null;
  const [sid, exp, sig] = p;
  if (!sigEqual(sig, sign(sid + '|' + exp + '|' + ip))) return null;
  if (Number(exp) < Date.now()) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (CFG.BIND_IP && s.ip !== ip) return null;
  s.exp = Date.now() + CFG.SESSION_TTL_MS; // sliding renewal while watching
  return s;
}

/* simple in-memory rate limiter */
const buckets = new Map();
function allow(ip, key, max, winMs) {
  const now = Date.now(), k = ip + '|' + key;
  let b = buckets.get(k);
  if (!b || now - b.t0 >= winMs) { b = { t0: now, n: 0 }; buckets.set(k, b); }
  b.n++;
  if (buckets.size > 20000) buckets.clear();
  return b.n <= max;
}

/* ── playlist rewriting ─────────────────────────────────────────────── */

function toProxyURL(sess, token, base, uri) {
  let abs;
  try { abs = new URL(uri, base); } catch (_) { return uri; }
  if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return uri;
  if (abs.href.startsWith(BASE_DIR.href))
    return '/live/' + token + '/' + abs.href.slice(BASE_DIR.href.length);
  /* different host or outside the stream dir → opaque mapped id */
  let id = sess.urlMap.get(abs.href);
  if (!id) {
    id = crypto.randomBytes(8).toString('hex');
    sess.urlMap.set(abs.href, id);
    sess.urlRev.set(id, abs.href);
  }
  const name = abs.pathname.split('/').pop() || 'file';
  return '/live/' + token + '/u/' + id + '/' + name;
}

function rewritePlaylist(text, sess, token, base) {
  return text.split(/\r?\n/).map(line => {
    const t = line.trim();
    if (!t) return line;
    if (t[0] === '#')
      return line.replace(/URI="([^"]+)"/g, (_, u) => 'URI="' + toProxyURL(sess, token, base, u) + '"');
    return toProxyURL(sess, token, base, t);
  }).join('\n');
}

function resolveUpstream(sess, rest, search) {
  if (!rest || rest === 'index.m3u8') return new URL(CFG.UPSTREAM_MASTER);
  if (rest.startsWith('u/')) {
    const target = sess.urlRev.get(rest.split('/')[1]);
    return target ? new URL(target) : null;
  }
  return new URL(rest + (search || ''), BASE_DIR);
}

/* ── http plumbing ──────────────────────────────────────────────────── */

function deny(res, code) { res.statusCode = code; res.end(); }

function json(res, obj) {
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

function corsFor(req, res) {
  const o = req.headers.origin;
  if (o && CFG.ALLOWED_ORIGINS.includes(String(o))) {
    res.setHeader('Access-Control-Allow-Origin', String(o));
    res.setHeader('Vary', 'Origin');
  }
}

function clientIP(req) {
  if (CFG.TRUST_PROXY) {
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function servePlayer(res) {
  fs.readFile(path.join(__dirname, 'index.html'), (err, buf) => {
    if (err) { res.statusCode = 404; return res.end('index.html not found next to server.js'); }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " +
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " +
        "img-src 'self' https://cdn.jsdelivr.net data:; media-src 'self' blob:; " +
        "connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; " +
        "base-uri 'none'; form-action 'none'"
    });
    res.end(buf);
  });
}

async function handleSession(req, res, ip) {
  if (req.method !== 'POST') return deny(res, 405);
  const origin = req.headers.origin || req.headers.referer || '';
  let org = '';
  try { org = new URL(origin).origin; } catch (_) {}
  if (!CFG.ALLOWED_ORIGINS.includes(org)) return deny(res, 403);
  if (!allow(ip, 'sess', CFG.RATE_SESSION_PER_MIN, 60000)) return deny(res, 429);
  corsFor(req, res);
  const token = issueToken(ip);
  if (!token) return deny(res, 429);
  json(res, { ok: true, url: '/live/' + token + '/index.m3u8', ttl: CFG.SESSION_TTL_MS });
}

async function handleLive(req, res, token, rest, search, ip) {
  corsFor(req, res);
  if (CFG.REQUIRE_HEADER) {
    const dest = String(req.headers['sec-fetch-dest'] || '');
    const ok = req.headers['x-player'] === PLAYER_HDR || ['video', 'audio', 'media'].includes(dest);
    if (!ok) return deny(res, 403);
  }
  const sess = checkToken(token, ip);
  if (!sess) return deny(res, 403);
  if (!allow(ip, 'live', CFG.RATE_LIVE_PER_MIN, 60000)) return deny(res, 429);

  /* guards: no traversal, no absolute URLs, no re-encoding tricks */
  let restDec;
  try { restDec = decodeURIComponent(rest); } catch (_) { return deny(res, 400); }
  if (/%2f/i.test(rest) || restDec.includes('..') || restDec.includes('\\') ||
      /^[a-z][a-z0-9+.-]*:/i.test(restDec)) return deny(res, 400);

  const upstream = resolveUpstream(sess, restDec, search);
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

  const looksPlaylist = /\.(m3u8|m3u)(\?|$)/i.test(restDec) ||
                        /mpegurl/i.test(up.headers.get('content-type') || '');

  if (looksPlaylist && up.ok) {
    const text = await up.text();
    const base = new URL('.', up.url || upstream.href); // per HLS spec, resolve against final URL
    const out = rewritePlaylist(text, sess, token, base);
    res.writeHead(200, {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-store'
    });
    return res.end(out);
  }

  /* segment / key / other binary — stream through unchanged */
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
  Readable.fromWeb(up.body).pipe(res);
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');

  let u;
  try { u = new URL(req.url, 'http://internal'); } catch (_) { return deny(res, 400); }
  const ip = clientIP(req);

  try {
    /* CORS preflight for cross-origin player hosting */
    if (req.method === 'OPTIONS' && (u.pathname === '/api/session' || u.pathname.startsWith('/live/'))) {
      corsFor(req, res);
      res.writeHead(204, {
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,X-Player',
        'Access-Control-Max-Age': '600'
      });
      return res.end();
    }

    if (CFG.SERVE_PLAYER && (u.pathname === '/' || u.pathname === '/index.html')) return servePlayer(res);
    if (u.pathname === '/api/session') return await handleSession(req, res, ip);

    const m = u.pathname.match(/^\/live\/([A-Za-z0-9._-]+)(?:\/(.*))?$/);
    if (m) return await handleLive(req, res, m[1], m[2] || '', u.search, ip);

    return deny(res, 404);
  } catch (_) {
    if (!res.headersSent) { res.statusCode = 500; res.end('error'); }
    else try { res.destroy(); } catch (_) {}
  }
});

server.listen(CFG.PORT, () => {
  console.log('Secure HLS relay on :' + CFG.PORT + '  (player: http://localhost:' + CFG.PORT + '/)');
  if (!process.env.SECRET)
    console.log('NOTE: SECRET not set — using a random value; sessions will not survive restarts.');
  if (!process.env.UPSTREAM_MASTER)
    console.log('NOTE: UPSTREAM_MASTER not set — using placeholder example.com URL.');
});
