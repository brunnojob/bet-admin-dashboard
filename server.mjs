import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import handler from './api/index.mjs';

const html = await readFile(new URL('./index.html', import.meta.url));
const port = Number(process.env.PORT || 8000);

const server = createServer(async (req, res) => {
  if ((req.url || '').startsWith('/api/')) return handler(req, res);
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.statusCode = 405; return res.end('Method Not Allowed');
  }
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'HEAD') return res.end();
  res.end(html);
});

server.listen(port, '127.0.0.1', () => console.log(`NOVA BET em http://localhost:${port}`));
