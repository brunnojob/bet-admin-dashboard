# NOVA BET

Painel administrativo em produção com backend na Vercel, PostgreSQL no Supabase e integração de pagamentos Pix pelo Mercado Pago.

## Infraestrutura

- GitHub: `brunnojob/bet-admin-dashboard`
- Supabase: `https://xtenkjzbzufergjutxts.supabase.co`
- Vercel: projeto `bet-admin-dashboard`
- Node.js 24
- Sessão HttpOnly persistida no Supabase, proteção CSRF e senhas scrypt.
- Tabelas com RLS habilitado; `anon` e `authenticated` não possuem acesso direto.

## Variáveis da Vercel

Configure somente em Environment Variables, nunca no Git:

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY` (preferido) ou `SUPABASE_SERVICE_ROLE_KEY`
- `INITIAL_ADMIN_USERNAME`
- `INITIAL_ADMIN_PASSWORD` (mínimo 12 caracteres; usado apenas se ainda não existir administrador)
- `MERCADOPAGO_ACCESS_TOKEN`
- `MERCADOPAGO_WEBHOOK_SECRET`

Depois que o primeiro administrador for criado, remova `INITIAL_ADMIN_PASSWORD` da Vercel.

## Mercado Pago via MCP no VS Code

O repositório inclui `.vscode/mcp.json`:

```json
{
  "servers": {
    "mercadopago-mcp-server": {
      "type": "http",
      "url": "https://mcp.mercadopago.com/mcp"
    }
  }
}
```

No VS Code, recarregue a janela e use **Connect** para autenticar o MCP. O MCP auxilia o agente no desenvolvimento e configuração da integração; as credenciais de produção continuam armazenadas apenas no backend da Vercel.

## Pagamentos

`POST /api/mercadopago/pix` cria um pagamento Pix real em `https://api.mercadopago.com/v1/payments`, com `X-Idempotency-Key`. O endpoint de webhook valida `x-signature` por HMAC-SHA256 e consulta o pagamento no Mercado Pago antes de atualizar o status no Supabase.

Não existe retorno de sucesso simulado: se as credenciais reais não estiverem configuradas, a API responde erro 503.

Saques não são marcados como concluídos manualmente. Um fluxo de payout deve ser implementado somente com o produto/API de desembolso efetivamente habilitado na conta Mercado Pago.

## Desenvolvimento local

```sh
npm install
npm run dev
```

Use as mesmas variáveis de ambiente da produção. Abra `http://localhost:8000`.
