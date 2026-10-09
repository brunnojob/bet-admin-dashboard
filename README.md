# NOVA Administration

Painel administrativo com sessões, CRUD de sites e domínios, registros financeiros, integração Mercado Pago e relatórios por dia e estado.

## Executar

Requisitos: Node.js 24, Vercel Functions e Supabase.

```sh
npm test
npm start
```

## Funcionamento

Backend Supabase exige `SUPABASE_URL` e uma chave de serviço exclusivamente no servidor. O primeiro administrador exige `INITIAL_ADMIN_USERNAME` e `INITIAL_ADMIN_PASSWORD`. Mercado Pago depende de `MERCADOPAGO_ACCESS_TOKEN` e `MERCADOPAGO_WEBHOOK_SECRET`. `/api/reports?month=2026-10` retorna totais em centavos e informa quando o limite de consulta foi atingido. Testes de API usam respostas controladas; não realizam pagamentos.

## Persistência de resultados

O arquivo de operações está em [vercel-home-telemetry-api.vercel.app](https://vercel-home-telemetry-api.vercel.app/laboratory.html?project=bet-admin-dashboard). As migrações Supabase estão no [repositório da API](https://github.com/brunnojob/vercel-home-telemetry-api/tree/main/supabase/migrations).

```sh
python cloud/sync.py enqueue resultado.json --project bet-admin-dashboard
python cloud/sync.py sync
```

Defina `BRUNNODEV_ACCESS_TOKEN` com sua sessão. A fila SQLite conserva os relatórios até confirmação do servidor; o mesmo conteúdo não gera registros duplicados. Tokens não são gravados no código.
