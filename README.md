# Keyflow

**Cofre de senhas colaborativo para pequenas equipes.**

Sabe quando alguém manda a senha do Instagram da empresa pelo WhatsApp, três pessoas copiam pro celular pessoal, e quando o estagiário sai ninguém sabe revogar o acesso? O Keyflow resolve isso.

É uma plataforma web onde sua equipe cadastra, compartilha e controla credenciais de forma segura — com log de tudo que acontece, pronto pra qualquer auditoria da LGPD.

> Projeto do 4º Período de Ciência da Computação — CESAR School — 2026

---

## O que ele faz

**Cofre de senhas** — Cadastre credenciais (serviço, login, senha, notas) com criptografia. Organize por categorias (Rede Social, Financeiro, Cloud, etc.) e encontre rápido com busca e filtros visuais.

**Compartilhamento controlado** — Defina quem pode ver cada senha. Tem o modo "mascarado": a pessoa usa a credencial mas não consegue ver a senha real. Perfeito pra estagiários.

**Gerenciamento de equipe** — Convite por código ou por e-mail. Quando alguém sai, remove com um clique e pronto — acesso revogado na hora.

**Dashboard com gráficos** — Painel com visão geral: acessos por dia, ações por tipo, credenciais mais usadas, health score das senhas e detecção de vazamentos via HaveIBeenPwned.

**Log de auditoria completo** — Tudo registrado automaticamente: quem, o quê e quando. Exporta em CSV ou gera um relatório PDF profissional pra LGPD.

**Autenticação forte** — Login com bcrypt, MFA com Google Authenticator (QR Code), rate limiting contra brute force e auto-logout por inatividade.

**Gerador de senhas** — Gera senhas de 8 a 32 caracteres com indicador de força em tempo real.

**Extras** — Dark mode, favoritar credenciais, atalhos de teclado (Ctrl+K pra buscar), tour guiado pra quem acabou de entrar, páginas de erro estilizadas e sistema de ícones SVG.

---

## Tecnologias

- **Backend:** Python 3.13, Flask, SQLAlchemy, bcrypt, Fernet (AES-128-CBC)
- **Frontend:** HTML, CSS, JavaScript puro (sem framework)
- **Banco:** SQLite (dev) / PostgreSQL (produção)
- **Extras:** Chart.js, ReportLab (PDF), Flask-Mail, pyotp (MFA), qrcode
- **Deploy:** Render / Railway com Gunicorn e HTTPS

---

## Como rodar

```bash
git clone https://github.com/joaovictorgcu/projeto_5
cd PROJETO_5
python -m venv venv
source venv/Scripts/activate   # Windows
pip install -r requirements.txt
cp .env.example .env           # edite com sua SECRET_KEY
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
└── api.py     → endpoints JSON (health score, stats, vazamentos)
```

Outros arquivos importantes:
- `models.py` — 6 tabelas (users, organizations, credentials, permissions, logs, favorites)
- `rate_limit.py` — proteção brute force no login
- `crypto_utils.py` — criptografia Fernet para o cofre
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
- Variáveis sensíveis: **arquivo .env** (nunca no código)

---

## Deploy

O projeto já vem configurado pra Render:

```
Procfile       → gunicorn app:app
render.yaml    → web service + PostgreSQL free
runtime.txt    → Python 3.13.2
```

Basta conectar o repositório no Render, configurar SECRET_KEY e DATABASE_URL, e pronto.

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
