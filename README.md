# Keyflow

**Cofre de senhas colaborativo para pequenas equipes.**

Sabe quando alguém manda a senha do Instagram da empresa pelo WhatsApp, três pessoas copiam pro celular pessoal, e quando o estagiário sai ninguém sabe revogar o acesso? O Keyflow resolve isso.

É uma plataforma web onde sua equipe cadastra, compartilha e controla credenciais de forma segura — com log de tudo que acontece, pronto pra qualquer auditoria da LGPD.

> Projeto do 4º Período de Ciência da Computação — CESAR School — 2026

---

## O que ele faz

**Cofre de senhas** — Cadastre credenciais (serviço, login, senha, notas) com criptografia. Organize por categorias (Rede Social, Financeiro, Cloud, etc.) e encontre rápido com busca e filtros visuais.

**Compartilhamento controlado** — Defina quem pode ver cada senha. Tem o modo "mascarado": a pessoa usa a credencial mas não consegue ver a senha real. Ações em lote na tela de permissões pra gerenciar tudo de uma vez. Perfeito pra estagiários.

**Gerenciamento de equipe** — Convite por código ou por e-mail. Quando alguém sai, remove com um clique e pronto — acesso revogado na hora.

**Dashboard com gráficos** — Painel com visão geral: acessos por dia, ações por tipo, credenciais mais usadas (com contagem de acessos), health score das senhas e detecção de vazamentos via HaveIBeenPwned.

**Painel de Segurança (admin)** — Dashboard dedicado com score de segurança da organização (0-100), detecção de senhas fracas, reutilizadas, expiradas e vazadas. Alertas proativos de vazamento checados automaticamente no login do admin. Políticas de senha configuráveis por categoria (financeiro, email, cloud, etc.) com padrões inteligentes e rotação. Gráfico de evolução do score ao longo do tempo.

**Log de auditoria completo** — Tudo registrado automaticamente: quem, o quê e quando. Exporta em CSV ou gera um relatório PDF profissional pra LGPD.

**Autenticação forte** — Login com bcrypt, MFA com Google Authenticator (QR Code), rate limiting contra brute force e auto-logout por inatividade.

**Gerador de senhas** — Gera senhas de 8 a 32 caracteres com indicador de força em tempo real.

**Extras** — Dark mode, favoritar credenciais, atalhos de teclado (Ctrl+K pra buscar), tour guiado pra quem acabou de entrar, páginas de erro estilizadas e sistema de ícones SVG.

**Landing page completa** — Página institucional com seções de problema, solução, features, comparativo com concorrentes, segurança, dados de mercado, público-alvo, FAQ interativo e planos de preços.

---

## Tecnologias

- **Backend:** Python 3.13, Flask 3.1, SQLAlchemy, bcrypt, Fernet (AES-128-CBC)
- **Frontend:** HTML, CSS, JavaScript puro (sem framework)
- **Banco:** SQLite (dev) / PostgreSQL (produção via psycopg2)
- **Extras:** Chart.js, ReportLab (PDF), Flask-Mail, pyotp (MFA), qrcode, Pillow
- **Deploy:** Render / Railway com Gunicorn e HTTPS

---

## Como rodar

```bash
git clone https://github.com/joaovictorgcu/projeto_5
cd PROJETO_5
python -m venv venv
source venv/Scripts/activate   # Windows
pip install -r requirements.txt
cp .env.example .env           # edite com SECRET_KEY e configs de e-mail
python app.py
```

Acesse `http://127.0.0.1:5000`

---

## Estrutura

O código é separado em blueprints por domínio — cada área tem seu próprio arquivo:

```
routes/
├── auth.py    → login, registro, logout, MFA
├── vault.py   → cofre, credenciais, permissões, favoritos
├── org.py     → dashboard, membros, logs, perfil, exports
└── api.py     → endpoints JSON (health score, stats, vazamentos, security score)

templates/
├── landing.html              → página institucional com pricing e FAQ
├── vault.html                → cofre de credenciais
├── dashboard.html            → painel com gráficos
├── security_dashboard.html   → painel de segurança (admin)
├── permissions.html          → permissões com ação em lote
├── members.html              → gerenciamento de membros
├── logs.html                 → log de auditoria
├── mfa_setup.html            → configuração MFA (QR Code)
├── mfa_verify.html           → verificação de código TOTP
├── errors/                   → 404 e 500 estilizados
└── ...
```

Outros arquivos importantes:
- `models.py` — 9 tabelas (users, organizations, credentials, permissions, logs, favorites, password_policies, breach_results, security_scores)
- `security.py` — lógica de score de segurança, políticas de senha e checagem de vazamentos
- `config.py` — configuração centralizada (DB, e-mail, CSRF)
- `rate_limit.py` — proteção brute force no login
- `crypto_utils.py` — criptografia Fernet para o cofre
- `seed.py` — dados de demonstração para desenvolvimento
- `static/style.css` — design system completo com dark mode
- `static/main.js` — dark mode, reveal, gerador, gráficos, atalhos

---

## Segurança

Segurança é a proposta central do Keyflow. Não é opcional:

- Senhas de login: **bcrypt com salt** (nunca texto puro)
- Senhas do cofre: **Fernet (AES-128-CBC)** com PBKDF2 e 480.000 iterações
- Autenticação em dois fatores: **TOTP** (Google Authenticator)
- Proteção contra brute force: **rate limiting** (5 tentativas por IP)
- Auto-logout: **sessão expira** após 30 min de inatividade
- CSRF: **token** em toda requisição POST
- Isolamento: **verificação de org_id** em toda query
- Vazamentos: **API k-Anonymity** (senha nunca sai do servidor)
- Políticas de senha: **regras por categoria** com rotação configurável
- Score de segurança: **monitoramento contínuo** com detecção de senhas fracas, reutilizadas e expiradas
- Variáveis sensíveis: **arquivo .env** (nunca no código)

---

## Deploy

O projeto já vem configurado pra Render:

```
Procfile       → gunicorn app:app
render.yaml    → web service + PostgreSQL free
runtime.txt    → Python 3.13.2
```

Basta conectar o repositório no Render, configurar `SECRET_KEY`, `DATABASE_URL` e as variáveis de e-mail (`MAIL_SERVER`, `MAIL_USERNAME`, `MAIL_PASSWORD`), e pronto.

---

## Variáveis de ambiente

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `SECRET_KEY` | Chave secreta do Flask | `dev-key-troque-em-producao` |
| `DATABASE_URL` | URI do banco de dados | `sqlite:///keyflow.db` |
| `MAIL_SERVER` | Servidor SMTP | `sandbox.smtp.mailtrap.io` |
| `MAIL_PORT` | Porta SMTP | `587` |
| `MAIL_USE_TLS` | Usar TLS | `True` |
| `MAIL_USERNAME` | Usuário SMTP | — |
| `MAIL_PASSWORD` | Senha SMTP | — |
| `MAIL_DEFAULT_SENDER` | Remetente padrão | `noreply@keyflow.com` |

---

## Equipe

12 integrantes em 6 duplas:

| Dupla | Foco |
|-------|------|
| 1 — Produto & Pesquisa | Entrevistas, personas, validação |
| 2 — Design & Protótipo | Wireframes, UI, identidade visual |
| 3 — Backend: Auth | Login, sessões, hash, MFA |
| 4 — Backend: Cofre | CRUD credenciais, permissões, criptografia |
| 5 — Backend: Logs & Org | Logs, membros, PDF, e-mail |
| 6 — Pitch & Documento | Documento estratégico, slides |

---

Projeto acadêmico — 4º Período — Ciência da Computação — CESAR School — 2026
