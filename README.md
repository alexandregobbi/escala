# Escala de Pregação

Site com a escala de pregação e avisos dos cultos.

- **Visitantes** abrem o link e veem a escala atual, sem login.
- **Administrador** clica em "Entrar como administrador", digita a senha e passa a poder cadastrar cultos, pessoas, regras, gerar a escala e trocar pessoas no calendário. Cada alteração é salva no servidor e todos passam a ver a versão nova.

## Como funciona

- `index.html`: a página (visitante e administrador).
- `api/escala.js`: função da Vercel que lê e grava a escala no Upstash Redis e confere a senha.

## Configuração na Vercel (uma vez)

1. No projeto da Vercel, abra **Storage** e crie um banco **Upstash Redis** (plano gratuito) pelo Marketplace, conectando-o a este projeto. A Vercel cria sozinha as variáveis `KV_REST_API_URL` e `KV_REST_API_TOKEN`.
2. Em **Settings → Environment Variables**, crie `ADMIN_PASSWORD` com a senha do administrador.
3. Faça um novo deploy (**Deployments → Redeploy**) para as variáveis valerem.

Enquanto o banco não estiver configurado, a página mostra a escala que vem embutida no `index.html`, só para consulta.
