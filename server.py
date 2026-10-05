import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from decimal import Decimal, InvalidOperation
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('BET_ADMIN_DB', ROOT / 'admin.sqlite3'))
SESSIONS = {}
ATTEMPTS = {}
FIELDS = {
    'sites': ('name', 'url', 'status'),
    'domains': ('name', 'site_id', 'status'),
    'transactions': ('kind', 'customer', 'amount', 'status', 'site_id'),
    'users': ('username', 'password', 'active'),
}


def connection():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest


def password_matches(password, stored):
    salt, digest = stored.split(':')
    calculated = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return hmac.compare_digest(calculated, digest)


def initialize():
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS domains(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, site_id INTEGER REFERENCES sites(id) ON DELETE RESTRICT, status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, customer TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0), status TEXT NOT NULL, site_id INTEGER REFERENCES sites(id) ON DELETE RESTRICT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        ''')
        if not db.execute('SELECT 1 FROM users').fetchone():
            db.execute('INSERT INTO users(username,password) VALUES (?,?)', ('admingb', password_hash('admin')))


def validate(resource, data, existing=None):
    result = dict(existing or {})
    for key in FIELDS[resource]:
        if key in data:
            result[key] = data[key]
    for key in ('name', 'username', 'customer', 'url'):
        if key in FIELDS[resource]:
            value = str(result.get(key, '')).strip()
            if not value or len(value) > 240:
                raise ValueError('Preencha os campos obrigatórios (máximo 240 caracteres).')
            result[key] = value
    if resource == 'sites' and not result['url'].startswith(('https://', 'http://')):
        raise ValueError('Informe uma URL com http:// ou https://.')
    if resource == 'domains':
        name = result['name'].lower()
        if '.' not in name or any(c in name for c in '/ :'):
            raise ValueError('Informe apenas o domínio, como exemplo.com.')
        result['name'] = name
    if resource in ('sites', 'domains') and result.get('status') not in ('ativo', 'inativo'):
        raise ValueError('Status inválido.')
    if 'site_id' in FIELDS[resource]:
        result['site_id'] = int(result['site_id']) if result.get('site_id') else None
    if resource == 'users':
        result['active'] = int(bool(result.get('active', True)))
        if data.get('password'):
            if len(data['password']) < 5 or len(data['password']) > 128:
                raise ValueError('A senha precisa ter entre 5 e 128 caracteres.')
            result['password'] = password_hash(data['password'])
        elif not existing:
            raise ValueError('Informe uma senha.')
    if resource == 'transactions':
        if result.get('kind') not in ('deposito', 'saque') or result.get('status') not in ('pendente', 'concluido', 'cancelado'):
            raise ValueError('Tipo ou status inválido.')
        if 'amount' in data:
            try:
                amount = Decimal(str(data['amount']).replace(',', '.'))
                if not amount.is_finite() or amount <= 0 or amount > 100000000 or amount * 100 != (amount * 100).to_integral_value():
                    raise ValueError('Valor inválido; use até duas casas decimais.')
                result['amount'] = int(amount * 100)
            except InvalidOperation:
                raise ValueError('Valor inválido.')
        if not result.get('amount'):
            raise ValueError('Informe um valor positivo.')
    return {key: result[key] for key in FIELDS[resource]}


class Handler(BaseHTTPRequestHandler):
    def send(self, status, data, cookie=None, html=False):
        raw = data.encode() if html else json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(raw)

    def dispatch(self):
        try:
            host = self.headers.get('Host', '')
            if host not in ('localhost:8000', '127.0.0.1:8000'):
                return self.send(403, {'error': 'Host local inválido.'})
            if self.command == 'GET' and self.path == '/':
                return self.send(200, (ROOT / 'index.html').read_text(), html=True)
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            token = cookies.get('session')
            session = SESSIONS.get(token.value if token else '')
            data = {}
            if self.command != 'GET':
                if self.headers.get('Origin') not in (None, 'http://' + host):
                    return self.send(403, {'error': 'Origem inválida.'})
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self.send(415, {'error': 'Envie JSON.'})
                length = int(self.headers.get('Content-Length', 0))
                if length > 16384:
                    return self.send(413, {'error': 'Requisição muito grande.'})
                data = json.loads(self.rfile.read(length) or '{}')
                if not isinstance(data, dict):
                    raise ValueError('JSON inválido.')
            with connection() as db:
                if self.path == '/api/login' and self.command == 'POST':
                    now = time.time()
                    key = self.client_address[0]
                    history = [t for t in ATTEMPTS.get(key, []) if now-t < 60]
                    ATTEMPTS[key] = history
                    if len(history) >= 10:
                        return self.send(429, {'error': 'Aguarde um minuto antes de tentar novamente.'})
                    user = db.execute('SELECT * FROM users WHERE username=? AND active=1', (str(data.get('username', '')),)).fetchone()
                    password = str(data.get('password', ''))
                    if len(password) > 128 or not user or not password_matches(password, user['password']):
                        history.append(now)
                        return self.send(401, {'error': 'Login ou senha inválidos.'})
                    token_value = secrets.token_urlsafe(32)
                    csrf = secrets.token_urlsafe(32)
                    SESSIONS[token_value] = {'id': user['id'], 'csrf': csrf, 'expires': now + 28800}
                    return self.send(200, {'username': user['username'], 'csrf': csrf}, 'session='+token_value+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800')
                user = db.execute('SELECT * FROM users WHERE id=? AND active=1', (session['id'],)).fetchone() if session and session['expires'] > time.time() else None
                if not user:
                    return self.send(401, {'error': 'Entre para acessar o painel.'})
                if self.command != 'GET' and not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                    return self.send(403, {'error': 'Sessão inválida. Entre novamente.'})
                if self.path == '/api/logout' and self.command == 'POST':
                    SESSIONS.pop(token.value, None)
                    return self.send(200, {'ok': True}, 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
                if self.path == '/api/state' and self.command == 'GET':
                    state = {'username': user['username'], 'csrf': session['csrf']}
                    for resource in FIELDS:
                        columns = 'id,username,active' if resource == 'users' else '*'
                        state[resource] = [dict(row) for row in db.execute(f'SELECT {columns} FROM {resource} ORDER BY id DESC')]
                    state['audit'] = [dict(row) for row in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]
                    return self.send(200, state)
                parts = self.path.strip('/').split('/')
                if len(parts) not in (2, 3) or parts[0] != 'api' or parts[1] not in FIELDS:
                    return self.send(404, {'error': 'Não encontrado.'})
                resource = parts[1]
                record_id = int(parts[2]) if len(parts) == 3 else None
                existing = db.execute(f'SELECT * FROM {resource} WHERE id=?', (record_id,)).fetchone() if record_id else None
                if record_id and not existing:
                    return self.send(404, {'error': 'Registro não encontrado.'})
                if self.command == 'POST' and not record_id:
                    values = validate(resource, data)
                    record_id = db.execute(f"INSERT INTO {resource} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values())).lastrowid
                elif self.command == 'PUT' and existing:
                    values = validate(resource, data, dict(existing))
                    if resource == 'users' and existing['active'] and not values['active'] and db.execute('SELECT count(*) FROM users WHERE active=1').fetchone()[0] == 1:
                        raise ValueError('Mantenha ao menos um administrador ativo.')
                    db.execute(f"UPDATE {resource} SET {','.join(k+'=?' for k in values)} WHERE id=?", (*values.values(), record_id))
                elif self.command == 'DELETE' and existing:
                    if resource == 'users' and (record_id == user['id'] or (existing['active'] and db.execute('SELECT count(*) FROM users WHERE active=1').fetchone()[0] == 1)):
                        raise ValueError('Não é possível excluir seu login nem o último administrador ativo.')
                    db.execute(f'DELETE FROM {resource} WHERE id=?', (record_id,))
                else:
                    return self.send(405, {'error': 'Método não permitido.'})
                db.execute('INSERT INTO audit(actor,action) VALUES (?,?)', (user['username'], f'{self.command} {resource} #{record_id}'))
                if resource == 'users' and record_id:
                    for key, item in list(SESSIONS.items()):
                        if item['id'] == record_id:
                            SESSIONS.pop(key, None)
                return self.send(200, {'ok': True, 'id': record_id})
        except sqlite3.IntegrityError:
            self.send(409, {'error': 'Registro duplicado ou vinculado. Remova os vínculos antes de excluir.'})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            self.send(400, {'error': str(error)})

    do_GET = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


if __name__ == '__main__':
    initialize()
    print('Bet Admin disponível em http://localhost:8000')
    ThreadingHTTPServer(('127.0.0.1', 8000), Handler).serve_forever()
