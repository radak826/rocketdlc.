// ETHER VISUAL — Vercel serverless API (один эндпоинт: /api?op=register|login|logout|me|users)
// База: Upstash Redis (через Vercel Storage → Marketplace). Переменные подставляются автоматически.
const crypto = require('crypto');
const ADMIN = 'radak53'; // только этот аккаунт видит базу пользователей
const DB_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const DB_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

const db = async (...cmd) => {
  const r = await fetch(DB_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + DB_TOKEN },
    body: JSON.stringify(cmd),
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error);
  return d.result;
};
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64);

module.exports = async (req, res) => {
  const send = (code, obj, cookie) => {
    if (cookie) res.setHeader('Set-Cookie', cookie);
    res.setHeader('Cache-Control', 'no-store');
    res.status(code).json(obj);
  };
  if (!DB_URL || !DB_TOKEN)
    return send(500, { error: 'База данных не подключена к проекту (нет KV_REST_API_URL / KV_REST_API_TOKEN).' });

  try {
    const op = new URL(req.url, 'http://x').searchParams.get('op');
    const ip = String(req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0]).trim();
    let body = req.body || {};
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
    const sid = ((req.headers.cookie || '').match(/(?:^|;\s*)sid=([a-f0-9]+)/) || [])[1];

    const sessionKey = async () => (sid ? await db('GET', 'session:' + sid) : null);
    const getUser = async k => { const v = await db('GET', 'user:' + k); return v ? JSON.parse(v) : null; };
    const putUser = (k, u) => db('SET', 'user:' + k, JSON.stringify(u));
    const noteIp = u => {
      u.lastIp = ip;
      u.ips = u.ips || [];
      if (!u.ips.includes(ip)) u.ips.push(ip);
      u.ips = u.ips.slice(-20);
    };
    const newSession = async key => {
      const s = crypto.randomBytes(32).toString('hex');
      await db('SET', 'session:' + s, key, 'EX', 2592000);
      return `sid=${s}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
    };

    if (op === 'register' && req.method === 'POST') {
      const name = String(body.login || '').trim(), key = name.toLowerCase(), pw = String(body.password || '');
      if (name.length < 3 || name.length > 32 || !/^[a-zA-Z0-9_А-Яа-яЁё-]+$/.test(name))
        return send(400, { error: 'Некорректный логин.' });
      if (pw.length < 6) return send(400, { error: 'Пароль должен быть не короче 6 символов.' });
      const salt = crypto.randomBytes(16).toString('hex'), now = new Date().toISOString();
      const user = { login: name, salt, hash: hash(pw, salt).toString('hex'),
        created: now, regIp: ip, lastIp: ip, lastLogin: now, ips: [ip] };
      const ok = await db('SET', 'user:' + key, JSON.stringify(user), 'NX');
      if (!ok) return send(409, { error: 'Такой логин уже занят. Выбери другой.' });
      await db('SADD', 'users', key);
      return send(200, { login: name, admin: key === ADMIN }, await newSession(key));
    }

    if (op === 'login' && req.method === 'POST') {
      const fk = 'fail:' + ip;
      if (Number(await db('GET', fk)) >= 10)
        return send(429, { error: 'Слишком много попыток. Попробуй через 10 минут.' });
      const key = String(body.login || '').trim().toLowerCase();
      const user = key ? await getUser(key) : null;
      const ok = user && crypto.timingSafeEqual(hash(String(body.password || ''), user.salt), Buffer.from(user.hash, 'hex'));
      if (!ok) {
        if ((await db('INCR', fk)) === 1) await db('EXPIRE', fk, 600);
        return send(401, { error: 'Неверный логин или пароль.' });
      }
      user.lastLogin = new Date().toISOString();
      noteIp(user);
      await putUser(key, user);
      return send(200, { login: user.login, admin: key === ADMIN }, await newSession(key));
    }

    if (op === 'logout' && req.method === 'POST') {
      if (sid) await db('DEL', 'session:' + sid);
      return send(200, {}, 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
    }

    if (op === 'me') {
      const key = await sessionKey();
      const user = key && (await getUser(key));
      if (!user) return send(200, {});
      if (user.lastIp !== ip) { noteIp(user); await putUser(key, user); }
      return send(200, { login: user.login, admin: key === ADMIN });
    }

    if (op === 'users') {
      if ((await sessionKey()) !== ADMIN) return send(403, { error: 'Нет доступа.' });
      const keys = await db('SMEMBERS', 'users');
      const vals = keys.length ? await db('MGET', ...keys.map(k => 'user:' + k)) : [];
      const users = vals.filter(Boolean).map(v => {
        const { login, created, regIp, lastLogin, lastIp, ips } = JSON.parse(v);
        return { login, created, regIp, lastLogin, lastIp, ips };
      }).sort((a, b) => b.created.localeCompare(a.created));
      return send(200, { users });
    }

    send(404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    send(500, { error: 'Ошибка сервера.' });
  }
};
