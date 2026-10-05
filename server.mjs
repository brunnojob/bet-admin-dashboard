import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const derive = promisify(scrypt);
const root = fileURLToPath(new URL('.', import.meta.url));
const fields = {
  sites: ['name', 'url', 'status'],
  domains: ['name', 'site_id', 'status'],
  transactions: ['kind', 'customer', 'amount', 'status', 'site_id'],
  users: ['username', 'password', 'active']
};
const token = () => randomBytes(32).toString('base64url');
const equal = (a, b) => {
  const left = Buffer.from(a || ''), right = Buffer.from(b || '');
  return left.length === right.length && timingSafeEqual(left, right);
};
async function hash(password) {
  const salt = randomBytes(16);
  return salt.toString('hex') + ':' + (await derive(password, salt, 64)).toString('hex');
}
async function matches(password, stored) {
  const [salt, digest] = stored.split(':');
  return equal((await derive(password, Buffer.from(salt, 'hex'), 64)).toString('hex'), digest);
}
function bad(message, status = 400) { return Object.assign(new Error(message), { status }); }
async function validate(resource, data, existing) {
  const value = { ...existing };
  for (const key of fields[resource]) if (Object.hasOwn(data, key)) value[key] = data[key];
  for (const key of ['name', 'username', 'customer', 'url']) {
    if (!fields[resource].includes(key)) continue;
    if (typeof value[key] !== 'string' || !value[key].trim() || value[key].length > 240) throw bad('Preencha os campos obrigatórios (máximo 240 caracteres).');
    value[key] = value[key].trim();
  }
  if (resource === 'sites') {
    try { if (!['http:', 'https:'].includes(new URL(value.url).protocol)) throw Error(); }
    catch { throw bad('Informe uma URL com http:// ou https://.'); }
  }
  if (resource === 'domains') {
    value.name = value.name.toLowerCase();
    if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(value.name)) throw bad('Informe apenas o domínio, como exemplo.com.');
  }
  if (['sites', 'domains'].includes(resource) && !['ativo', 'inativo'].includes(value.status)) throw bad('Status inválido.');
  if (fields[resource].includes('site_id')) {
    value.site_id = value.site_id === '' || value.site_id == null ? null : Number(value.site_id);
    if (value.site_id !== null && (!Number.isSafeInteger(value.site_id) || value.site_id < 1)) throw bad('Site inválido.');
  }
  if (resource === 'users') {
    if (data.active !== undefined && ![true, false, 0, 1].includes(data.active)) throw bad('Status do administrador inválido.');
    value.active = Number(Boolean(value.active ?? 1));
    if (data.password) {
      if (typeof data.password !== 'string' || data.password.length < 5 || data.password.length > 128) throw bad('A senha precisa ter entre 5 e 128 caracteres.');
      value.password = await hash(data.password);
    } else if (!existing) throw bad('Informe uma senha.');
    else value.password = existing.password;
  }
  if (resource === 'transactions') {
    if (!['deposito', 'saque'].includes(value.kind) || !['pendente', 'concluido', 'cancelado'].includes(value.status)) throw bad('Tipo ou status inválido.');
    if (Object.hasOwn(data, 'amount')) {
      const amount = String(data.amount).replace(',', '.');
      if (!/^\d+(?:\.\d{1,2})?$/.test(amount)) throw bad('Valor inválido; use até duas casas decimais.');
      const [whole, fraction = ''] = amount.split('.');
      value.amount = Number(whole) * 100 + Number(fraction.padEnd(2, '0'));
      if (!Number.isSafeInteger(value.amount) || value.amount <= 0 || value.amount > 10000000000) throw bad('Informe um valor positivo de até R$ 100.000.000.');
    }
    if (!value.amount) throw bad('Informe um valor positivo.');
  }
  return Object.fromEntries(fields[resource].map(key => [key, value[key]]));
}

export async function createApp({ databasePath = process.env.BET_ADMIN_DB || resolve(root, 'admin.sqlite3') } = {}) {
  const db = new DatabaseSync(databasePath);
  db.exec(`PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, status TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS domains(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, site_id INTEGER REFERENCES sites(id) ON DELETE RESTRICT, status TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, customer TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0), status TEXT NOT NULL, site_id INTEGER REFERENCES sites(id) ON DELETE RESTRICT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);
  if (!db.prepare('SELECT 1 FROM users').get()) db.prepare('INSERT INTO users(username,password) VALUES (?,?)').run('admingb', await hash('admin'));
  const sessions = new Map(), attempts = new Map();
  const server = createServer(async (req, res) => {
    const send = (status, value, cookie, html = false) => {
      res.writeHead(status, { 'Content-Type': html ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', ...(cookie ? { 'Set-Cookie': cookie } : {}) });
      res.end(html ? value : JSON.stringify(value));
    };
    try {
      const port = server.address().port;
      const hosts = [`localhost:${port}`, `127.0.0.1:${port}`];
      if (!hosts.includes(req.headers.host)) throw bad('Host local inválido.', 403);
      const path = new URL(req.url, 'http://' + req.headers.host).pathname;
      if (req.method === 'GET' && path === '/') return send(200, await readFile(resolve(root, 'index.html'), 'utf8'), null, true);
      let data = {};
      if (req.method !== 'GET') {
        if (req.headers.origin && req.headers.origin !== 'http://' + req.headers.host) throw bad('Origem inválida.', 403);
        if (req.headers['content-type']?.split(';')[0] !== 'application/json') throw bad('Envie JSON.', 415);
        let size = 0; const chunks = [];
        for await (const chunk of req) { size += chunk.length; if (size > 16384) throw bad('Requisição muito grande.', 413); chunks.push(chunk); }
        try { data = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { throw bad('JSON inválido.'); }
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw bad('JSON inválido.');
      }
      const cookieToken = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.cookie || '')?.[1];
      const session = sessions.get(cookieToken);
      if (path === '/api/login' && req.method === 'POST') {
        const now = Date.now(), key = req.socket.remoteAddress;
        const history = (attempts.get(key) || []).filter(t => now - t < 60000);
        attempts.set(key, history);
        if (history.length >= 10) throw bad('Aguarde um minuto antes de tentar novamente.', 429);
        history.push(now);
        const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(String(data.username || ''));
        if (typeof data.password !== 'string' || data.password.length > 128 || !user || !await matches(data.password, user.password)) throw bad('Login ou senha inválidos.', 401);
        const id = token(), csrf = token();
        sessions.set(id, { id: user.id, csrf, expires: now + 28800000 });
        return send(200, { username: user.username, csrf }, `session=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
      }
      const user = session && session.expires > Date.now() ? db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(session.id) : null;
      if (!user) throw bad('Entre para acessar o painel.', 401);
      if (req.method !== 'GET' && !equal(req.headers['x-csrf-token'], session.csrf)) throw bad('Sessão inválida. Entre novamente.', 403);
      if (path === '/api/logout' && req.method === 'POST') { sessions.delete(cookieToken); return send(200, { ok: true }, 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); }
      if (path === '/api/state' && req.method === 'GET') {
        const state = { username: user.username, csrf: session.csrf, gateway: { connected: false } };
        for (const resource of Object.keys(fields)) state[resource] = db.prepare(`SELECT ${resource === 'users' ? 'id,username,active' : '*'} FROM ${resource} ORDER BY id DESC`).all();
        state.audit = db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 100').all();
        return send(200, state);
      }
      const parts = path.split('/').filter(Boolean), resource = parts[1];
      if (![2, 3].includes(parts.length) || parts[0] !== 'api' || !Object.hasOwn(fields, resource)) throw bad('Não encontrado.', 404);
      let recordId = parts[2] ? Number(parts[2]) : null;
      if (parts[2] && (!Number.isSafeInteger(recordId) || recordId < 1)) throw bad('ID inválido.');
      const existing = recordId ? db.prepare(`SELECT * FROM ${resource} WHERE id=?`).get(recordId) : null;
      if (recordId && !existing) throw bad('Registro não encontrado.', 404);
      let values;
      if (req.method === 'POST' && !recordId || req.method === 'PUT' && existing) values = await validate(resource, data, existing);
      db.exec('BEGIN IMMEDIATE');
      try {
        const activeCount = () => db.prepare('SELECT count(*) AS count FROM users WHERE active=1').get().count;
        if (req.method === 'POST' && !recordId) recordId = Number(db.prepare(`INSERT INTO ${resource} (${Object.keys(values).join(',')}) VALUES (${Object.keys(values).map(() => '?').join(',')})`).run(...Object.values(values)).lastInsertRowid);
        else if (req.method === 'PUT' && existing) {
          if (resource === 'users' && existing.active && !values.active && activeCount() === 1) throw bad('Mantenha ao menos um administrador ativo.');
          db.prepare(`UPDATE ${resource} SET ${Object.keys(values).map(k => k + '=?').join(',')} WHERE id=?`).run(...Object.values(values), recordId);
        } else if (req.method === 'DELETE' && existing) {
          if (resource === 'users' && (recordId === user.id || existing.active && activeCount() === 1)) throw bad('Não é possível excluir seu login nem o último administrador ativo.');
          db.prepare(`DELETE FROM ${resource} WHERE id=?`).run(recordId);
        } else throw bad('Método não permitido.', 405);
        db.prepare('INSERT INTO audit(actor,action) VALUES (?,?)').run(user.username, `${req.method} ${resource} #${recordId}`);
        db.exec('COMMIT');
      } catch (error) { db.exec('ROLLBACK'); throw error; }
      if (resource === 'users') for (const [key, item] of sessions) if (item.id === recordId) sessions.delete(key);
      send(200, { ok: true, id: recordId });
    } catch (error) {
      const constraint = error.code === 'ERR_SQLITE_ERROR' && /constraint/i.test(error.message);
      const status = error.status || (constraint ? 409 : 500);
      if (status === 500) console.error(error);
      send(status, { error: constraint ? 'Registro duplicado ou vinculado. Remova os vínculos antes de excluir.' : status === 500 ? 'Erro interno.' : error.message });
    }
  });
  server.on('close', () => db.close());
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const port = Number(process.env.PORT || 8000);
  const server = await createApp();
  server.listen(port, '127.0.0.1', () => console.log(`NOVA BET disponível em http://localhost:${server.address().port}`));
  server.on('error', error => { console.error(error.code === 'EADDRINUSE' ? 'Porta ocupada. Feche o servidor anterior ou defina PORT.' : error.message); process.exitCode = 1; });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)));
}
