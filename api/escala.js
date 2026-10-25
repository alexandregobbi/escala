/* Função da Vercel: guarda a escala no Upstash Redis.
   GET  /api/escala            -> qualquer pessoa lê
   POST /api/escala            -> {action:'login'} confere a senha de administrador
   PUT  /api/escala            -> {v, data} grava (exige a senha no cabeçalho x-admin-password) */
const crypto = require('crypto');

const KEY = 'escala:dados';
const MAX_BYTES = 400 * 1024;

function dbConfig() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url: url.replace(/\/$/, ''), token } : null;
}

async function redis(cmd) {
  const c = dbConfig();
  const r = await fetch(c.url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error(j.error || 'redis ' + r.status);
  return j.result;
}

function sameSecret(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body) {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  return {};
}

async function read() {
  const raw = await redis(['GET', KEY]);
  if (!raw) return { v: 0, data: null };
  try {
    const o = JSON.parse(raw);
    return { v: Number(o.v) || 0, data: o.data || null };
  } catch (e) {
    return { v: 0, data: null };
  }
}

module.exports = async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      if (!dbConfig()) return send(res, 503, { error: 'not_configured' });
      const cur = await read();
      return send(res, 200, cur);
    }

    if (req.method === 'POST' || req.method === 'PUT') {
      const admin = process.env.ADMIN_PASSWORD;
      if (!admin) return send(res, 503, { error: 'no_password' });
      const given = req.headers['x-admin-password'] || '';
      if (!sameSecret(given, admin)) {
        await new Promise((r) => setTimeout(r, 500));
        return send(res, 401, { error: 'unauthorized' });
      }
      const body = readBody(req);

      if (req.method === 'POST') {
        return send(res, 200, { ok: true });
      }

      if (!dbConfig()) return send(res, 503, { error: 'not_configured' });
      const d = body.data;
      if (!d || typeof d !== 'object' || !Array.isArray(d.cultos) || !Array.isArray(d.pessoas)) {
        return send(res, 400, { error: 'bad_data' });
      }
      const expected = Number(body.v) || 0;
      const cur = await read();
      if (cur.v !== expected) return send(res, 409, { error: 'conflict', v: cur.v });
      const next = cur.v + 1;
      const value = JSON.stringify({ v: next, data: d });
      if (Buffer.byteLength(value) > MAX_BYTES) return send(res, 413, { error: 'too_large' });
      await redis(['SET', KEY, value]);
      return send(res, 200, { ok: true, v: next });
    }

    res.setHeader('Allow', 'GET, POST, PUT');
    return send(res, 405, { error: 'method' });
  } catch (e) {
    return send(res, 500, { error: 'server' });
  }
};
