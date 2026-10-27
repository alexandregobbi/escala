/* Função da Vercel: guarda a escala no Upstash Redis.
   GET  /api/escala  -> qualquer pessoa lê
   POST /api/escala  -> {action:'login'} confere usuário e senha
                        {action:'users-list'|'users-save'|'users-del'} gerencia usuários (só administrador)
   PUT  /api/escala  -> {v, data} grava
   Credenciais nos cabeçalhos: x-login (vazio = administrador) e x-admin-password.
   O administrador usa a senha ADMIN_PASSWORD. Os demais usuários só gravam as áreas liberadas para eles. */
const crypto = require('crypto');

const KEY = 'escala:dados';
const UKEY = 'escala:usuarios';
const MAX_BYTES = 400 * 1024;

/* permissão -> partes dos dados que ela libera */
const PERMS = {
  pregacao: ['escala', 'regras'],
  oanse: ['oanse'],
  liturgia: ['lit'],
  cadastros: ['cultos', 'pessoas', 'familias'],
};
/* partes que qualquer usuário com acesso pode alterar (período mostrado no calendário) */
const META = ['periodo', 'periodos', 'example', 'stale'];

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

function hashSenha(senha, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(senha), salt, 32, (e, k) => (e ? reject(e) : resolve(k.toString('hex'))));
  });
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

async function readUsers() {
  const raw = await redis(['GET', UKEY]);
  if (!raw) return [];
  try {
    const o = JSON.parse(raw);
    return Array.isArray(o.users) ? o.users : [];
  } catch (e) {
    return [];
  }
}

function cleanPerms(p) {
  return Object.keys(PERMS).filter((k) => Array.isArray(p) && p.indexOf(k) >= 0);
}

function publicUser(u) {
  return { id: u.id, nome: u.nome, login: u.login, perms: cleanPerms(u.perms) };
}

/* quem está chamando: {admin:true} ou {admin:false,user} ou null */
async function authenticate(req) {
  const admin = process.env.ADMIN_PASSWORD;
  const login = String(req.headers['x-login'] || '').trim().toLowerCase();
  const given = String(req.headers['x-admin-password'] || '');
  if (!login) {
    if (!admin) return { error: 503 };
    return sameSecret(given, admin) ? { admin: true } : null;
  }
  if (!dbConfig()) return { error: 503 };
  const users = await readUsers();
  const u = users.find((x) => x.login === login);
  if (!u) {
    await hashSenha(given, 'x'.repeat(16)).catch(() => {});
    return null;
  }
  const h = await hashSenha(given, u.salt);
  if (!sameSecret(h, u.hash)) return null;
  return { admin: false, user: u };
}

/* aplica sobre os dados gravados só o que o usuário pode alterar */
function nomeKey(n) {
  return String(n).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
}

/* quem administra só OANSE e/ou Liturgia pode: incluir ou tirar pessoas do próprio módulo,
   acrescentar cultos a quem entra no módulo e cadastrar pessoas novas (só nos próprios módulos). */
function mergePessoas(storedList, sentList, storedCultos, perms) {
  const mods = [];
  if (perms.indexOf('oanse') >= 0) mods.push('oanse');
  if (perms.indexOf('liturgia') >= 0) mods.push('lit');
  const cultoIds = new Set((Array.isArray(storedCultos) ? storedCultos : []).map((c) => c && c.id));
  const out = (Array.isArray(storedList) ? storedList : []).map((p) => Object.assign({}, p));
  if (!mods.length || !Array.isArray(sentList)) return out;
  const byId = new Map(out.map((p) => [p.id, p]));
  const names = new Set(out.map((p) => nomeKey(p.nome)));
  sentList.forEach((sp) => {
    if (!sp || typeof sp !== 'object' || typeof sp.id !== 'string') return;
    const cs = (Array.isArray(sp.cultos) ? sp.cultos : []).filter((id) => cultoIds.has(id));
    const cur = byId.get(sp.id);
    if (cur) {
      mods.forEach((m) => {
        if (typeof sp[m] === 'boolean') cur[m] = sp[m];
      });
      if (mods.some((m) => cur[m])) {
        cur.cultos = Array.isArray(cur.cultos) ? cur.cultos : [];
        cs.forEach((id) => { if (cur.cultos.indexOf(id) < 0) cur.cultos.push(id); });
      }
      return;
    }
    const nome = String(sp.nome || '').replace(/\s+/g, ' ').trim().slice(0, 80);
    if (!nome || names.has(nomeKey(nome)) || !/^[A-Za-z0-9]{3,24}$/.test(sp.id) || out.length >= 500) return;
    const novo = {
      id: sp.id, nome, funcao: '', igreja: '', cultos: cs, papeis: [],
      oanse: mods.indexOf('oanse') >= 0 && sp.oanse === true,
      lit: mods.indexOf('lit') >= 0 && sp.lit === true,
    };
    if (!novo.oanse && !novo.lit) return;
    names.add(nomeKey(nome));
    byId.set(novo.id, novo);
    out.push(novo);
  });
  return out;
}

function mergeForUser(stored, sent, perms) {
  const out = Object.assign({}, stored);
  if (perms.indexOf('cadastros') < 0 && (perms.indexOf('oanse') >= 0 || perms.indexOf('liturgia') >= 0)) {
    out.pessoas = mergePessoas(stored.pessoas, sent.pessoas, stored.cultos, perms);
  }
  const keys = new Set(META);
  perms.forEach((p) => (PERMS[p] || []).forEach((k) => keys.add(k)));
  keys.forEach((k) => {
    if (Object.prototype.hasOwnProperty.call(sent, k)) out[k] = sent[k];
  });
  return out;
}

module.exports = async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      if (!dbConfig()) return send(res, 503, { error: 'not_configured' });
      const cur = await read();
      return send(res, 200, cur);
    }

    if (req.method === 'POST' || req.method === 'PUT') {
      const who = await authenticate(req);
      if (who && who.error) return send(res, 503, { error: 'no_password' });
      if (!who) {
        await new Promise((r) => setTimeout(r, 500));
        return send(res, 401, { error: 'unauthorized' });
      }
      const body = readBody(req);

      if (req.method === 'POST') {
        const action = body.action;
        if (action === 'login') {
          return send(res, 200, who.admin
            ? { ok: true, admin: true, nome: 'Administrador', perms: Object.keys(PERMS) }
            : { ok: true, admin: false, nome: who.user.nome, perms: cleanPerms(who.user.perms) });
        }
        if (action === 'change-password') {
          if (who.admin) return send(res, 400, { error: 'admin_env' });
          const atual = String(body.atual || '');
          const nova = String(body.nova || '');
          if (nova.length < 6 || nova.length > 100) return send(res, 400, { error: 'senha' });
          if (!sameSecret(atual, String(req.headers['x-admin-password'] || ''))) {
            await new Promise((r) => setTimeout(r, 500));
            return send(res, 401, { error: 'atual' });
          }
          const all = await readUsers();
          const me = all.find((x) => x.id === who.user.id);
          if (!me) return send(res, 404, { error: 'not_found' });
          me.salt = crypto.randomBytes(16).toString('hex');
          me.hash = await hashSenha(nova, me.salt);
          await redis(['SET', UKEY, JSON.stringify({ users: all })]);
          return send(res, 200, { ok: true });
        }
        if (!who.admin) return send(res, 403, { error: 'forbidden' });
        if (!dbConfig()) return send(res, 503, { error: 'not_configured' });
        const users = await readUsers();
        if (action === 'users-list') {
          return send(res, 200, { users: users.map(publicUser) });
        }
        if (action === 'users-del') {
          const rest = users.filter((u) => u.id !== body.id);
          await redis(['SET', UKEY, JSON.stringify({ users: rest })]);
          return send(res, 200, { users: rest.map(publicUser) });
        }
        if (action === 'users-save') {
          const nome = String(body.nome || '').trim().slice(0, 60);
          const login = String(body.login || '').trim().toLowerCase();
          const senha = String(body.senha || '');
          if (!nome) return send(res, 400, { error: 'nome' });
          if (!/^[a-z0-9._-]{3,30}$/.test(login)) return send(res, 400, { error: 'login' });
          if (users.some((u) => u.login === login && u.id !== body.id)) return send(res, 409, { error: 'login_em_uso' });
          let u = body.id ? users.find((x) => x.id === body.id) : null;
          if (body.id && !u) return send(res, 404, { error: 'not_found' });
          if (!u) {
            if (senha.length < 6) return send(res, 400, { error: 'senha' });
            if (users.length >= 50) return send(res, 400, { error: 'limite' });
            u = { id: 'u' + crypto.randomBytes(5).toString('hex') };
            users.push(u);
          } else if (senha && senha.length < 6) {
            return send(res, 400, { error: 'senha' });
          }
          u.nome = nome;
          u.login = login;
          u.perms = cleanPerms(body.perms);
          if (senha) {
            u.salt = crypto.randomBytes(16).toString('hex');
            u.hash = await hashSenha(senha, u.salt);
          }
          await redis(['SET', UKEY, JSON.stringify({ users })]);
          return send(res, 200, { users: users.map(publicUser) });
        }
        return send(res, 400, { error: 'action' });
      }

      if (!dbConfig()) return send(res, 503, { error: 'not_configured' });
      const d = body.data;
      if (!d || typeof d !== 'object' || !Array.isArray(d.cultos) || !Array.isArray(d.pessoas)) {
        return send(res, 400, { error: 'bad_data' });
      }
      const cur = await read();

      if (who.admin) {
        const expected = Number(body.v) || 0;
        if (cur.v !== expected) return send(res, 409, { error: 'conflict', v: cur.v });
        const next = cur.v + 1;
        const value = JSON.stringify({ v: next, data: d });
        if (Buffer.byteLength(value) > MAX_BYTES) return send(res, 413, { error: 'too_large' });
        await redis(['SET', KEY, value]);
        return send(res, 200, { ok: true, v: next });
      }

      const perms = cleanPerms(who.user.perms);
      if (!perms.length) return send(res, 403, { error: 'forbidden' });
      if (!cur.data) return send(res, 409, { error: 'sem_dados' });
      const merged = mergeForUser(cur.data, d, perms);
      const next = cur.v + 1;
      const value = JSON.stringify({ v: next, data: merged });
      if (Buffer.byteLength(value) > MAX_BYTES) return send(res, 413, { error: 'too_large' });
      await redis(['SET', KEY, value]);
      return send(res, 200, { ok: true, v: next, data: merged });
    }

    res.setHeader('Allow', 'GET, POST, PUT');
    return send(res, 405, { error: 'method' });
  } catch (e) {
    return send(res, 500, { error: 'server' });
  }
};
