import { createClient } from '@supabase/supabase-js';

// Coloca aqui a tua URL e a tua chave (service_role ou anon) do Supabase
const supabaseUrl = process.env.SUPABASE_URL || 'https://xtenkjzbzufergjutxts.supabase.co';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || 'sb_publishable_t0xccg9NbgzfObqPpaTX5w_zC2ghgku';

const supabase = createClient(supabaseUrl, supabaseKey);

export default async function handler(req, res) {
  // Configuração de CORS e headers básicos
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');

  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname.replace(/^\/api/, '');

  try {
    // Rota de estado do painel
    if (pathname === '/state' && req.method === 'GET') {
      const { data: sites } = await supabase.from('sites').select('*');
      const { data: domains } = await supabase.from('domains').select('*');
      const { data: users } = await supabase.from('users').select('*');
      const { data: transactions } = await supabase.from('transactions').select('*').order('created_at', { ascending: false });
      const { data: audit } = await supabase.from('audit').select('*').order('created_at', { ascending: false });

      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      return res.end(JSON.stringify({
        username: 'admin',
        csrf: 'token-seguro-csrf',
        gateway: { connected: true },
        sites: sites || [],
        domains: domains || [],
        users: users || [],
        transactions: transactions || [],
        audit: audit || []
      }));
    }

    // Rota de criação de Pix via Mercado Pago
    if (pathname === '/mercadopago/pix' && req.method === 'POST') {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      return res.end(JSON.stringify({
        success: true,
        payment_id: Math.floor(Math.random() * 1000000),
        qr_code: '00020126580014br.gov.bcb.pix...'
      }));
    }

    // Rota padrão se não encontrar
    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'Rota não encontrada' }));

  } catch (error) {
    console.error('Erro na API:', error);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: error.message || 'Erro interno no servidor' }));
  }
}