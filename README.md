# Keyflow

**Cofre de Senhas Colaborativo para Pequenas Equipes**

O Keyflow é uma plataforma web de compartilhamento seguro de senhas para agências digitais, startups e PMEs com 3 a 50 pessoas. O produto resolve um problema cotidiano e crítico: equipes compartilham credenciais de redes sociais, ferramentas SaaS e contas bancárias por WhatsApp e planilhas, expondo a empresa a vazamentos, invasões e multas da LGPD.

> Projeto Acadêmico — 4º Período de Ciência da Computação — CESAR School — 2026

---

## Funcionalidades

### Autenticação
- Cadastro com nome, e-mail e senha
- Login/logout com sessão segura (Flask-Login)
- Hash de senhas com bcrypt + salt
- Isolamento por organização (cada usuário só vê dados da sua org)
- **MFA com TOTP** (Google Authenticator) — QR Code, ativação/desativação no perfil

### Cofre de Senhas
- Cadastrar credencial: nome do serviço, login, senha criptografada, observações
- Listar, editar e deletar credenciais
- Campo de senha oculto por padrão com botão revelar/ocultar
- Copiar login ou senha com um clique
- Busca por nome ou login
- Auto-ocultar senha após 30 segundos
- **Categorias com ícones** — Rede Social, E-mail, Financeiro, Cloud/Dev, Comunicação, Marketing
- **Filtro por categoria** — chips visuais para filtrar credenciais no cofre

### Gerador de Senhas
- Tamanho configurável de 8 a 32 caracteres
- Opções: maiúsculas, minúsculas, números, símbolos
- Gerado com `crypto.getRandomValues()` (criptograficamente seguro)
- Indicador de força em tempo real (Muito fraca → Forte)

### Compartilhamento
- Convite de membros por código único da organização
- Permissão por credencial: "pode ver a senha" ou "só pode usar sem ver" (mascarado)
- Revogar acesso de um membro com um clique
- **Notificação por e-mail** — convite de equipe, alerta de acesso, confirmação de remoção

### Log de Auditoria (LGPD)
- Registro automático: quem acessou qual credencial, qual ação e quando
- Tela de auditoria com lista cronológica
- Exportação em CSV (Data, Usuário, E-mail, Credencial, Ação)
- **Relatório LGPD em PDF** — documento profissional com cabeçalho, tabela de logs e resumo estatístico

### Dashboard
- Número de credenciais e membros ativos
- Código de convite da organização
- Health Score de senhas (analisa fracas, curtas, pouco complexas, duplicadas)
- Últimos 10 acessos com usuário, credencial e ação
- **Gráficos interativos** (Chart.js) — acessos por dia, ações por tipo, top credenciais
- **Detecção de senhas vazadas** — integração com HaveIBeenPwned (API k-Anonymity)

### Outros
- Dark mode com persistência (localStorage)
- Página de perfil (alterar nome e senha)
- Páginas de erro 404 e 500 estilizadas
- Sistema de ícones SVG inline (25+ ícones Lucide)
- Skip-link e ARIA labels para acessibilidade
- Responsivo (mobile-first)

---

## Stack Tecnológica

| Camada | Tecnologia | Por quê |
|--------|-----------|---------|
| Frontend | HTML + CSS + JavaScript puro | Equipe já domina; sem necessidade de framework |
| Backend | Python 3.13 + Flask 3.1 | Familiar para a equipe; direto para criar APIs REST |
| ORM | Flask-SQLAlchemy | Abstrai SQL; facilita migração SQLite → PostgreSQL |
| Banco de dados | SQLite (dev) / PostgreSQL (prod) | SQL já é domínio da equipe |
| Autenticação | Flask-Login + bcrypt + pyotp (MFA) | Sessões seguras; padrão da indústria para hash |
| Criptografia (cofre) | Fernet (AES-128-CBC via PBKDF2) | Criptografia simétrica; fácil de usar |
| Proteção CSRF | Flask-WTF | Nativo do Flask; protege todos os formulários |
| Gráficos | Chart.js 4.x (CDN) | Leve, interativo, suporta dark mode |
| PDF | ReportLab | Geração de PDF profissional no backend |
| E-mail | Flask-Mail + Mailtrap (demo) | Envio assíncrono; simulado para apresentação |
| Ícones | SVG inline (Lucide) | Escalável, tematizável, sem emojis |
| Deploy | Render / Railway + Gunicorn | Deploy via GitHub sem custo; HTTPS gratuito |

---

## Como Rodar Localmente

```bash
# 1. Clone o repositório
git clone https://github.com/joaovictorgcu/projeto_5
cd PROJETO_5

# 2. Crie o ambiente virtual
python -m venv venv

# 3. Ative (Windows)
source venv/Scripts/activate
# Linux/Mac: source venv/bin/activate

# 4. Instale as dependências
pip install -r requirements.txt

# 5. Configure variáveis de ambiente
cp .env.example .env
# Edite o .env com sua SECRET_KEY

# 6. Rode a aplicação
python app.py
```

Acesse `http://127.0.0.1:5000`

---

## Estrutura do Projeto

```
PROJETO_5/
├── app.py                    # Factory Flask + error handlers
├── config.py                 # Configuração via .env
├── models.py                 # Modelos SQLAlchemy
├── routes.py                 # Endpoints (auth + main + APIs)
├── crypto_utils.py           # Criptografia Fernet para cofre
├── schema.sql                # Schema SQL de referência
├── requirements.txt          # Dependências Python
├── Procfile                  # Deploy (Gunicorn)
├── render.yaml               # Blueprint Render + PostgreSQL
├── runtime.txt               # Versão Python
├── .env.example              # Exemplo de variáveis de ambiente
├── .gitignore
│
├── static/
│   ├── style.css             # Design system completo
│   ├── main.js               # Dark mode, reveal, gerador, toast, gráficos
│   └── favicon.svg           # Favicon SVG (cadeado laranja)
│
├── templates/
│   ├── base.html             # Layout: navbar, ícones, skip-link, ARIA, footer
│   ├── icons.html            # 30+ ícones SVG Lucide inline
│   ├── landing.html          # Landing page completa (12 seções)
│   ├── login.html            # Tela de login com ícones
│   ├── register.html         # Cadastro + convite
│   ├── dashboard.html        # Dashboard + Health Score + gráficos
│   ├── vault.html            # Cofre com busca e filtro por categoria
│   ├── credential_form.html  # Form + gerador de senhas + categoria
│   ├── permissions.html      # Permissões por credencial
│   ├── members.html          # Gerenciamento de membros + convite e-mail
│   ├── logs.html             # Logs + export CSV + PDF
│   ├── profile.html          # Perfil + ativação MFA
│   ├── mfa_setup.html        # QR Code para Google Authenticator
│   ├── mfa_verify.html       # Campo de código MFA no login
│   └── errors/
│       ├── 404.html
│       └── 500.html
│
└── docs/
    └── superpowers/specs/    # Documentos de design e especificação
```

---

## Modelo de Dados

```
organizations ──── users ──── access_logs
      │                │
      └── credentials ─┴── credential_permissions
```

| Tabela | Campos Principais | Relação |
|--------|-------------------|---------|
| `organizations` | id, name, invite_code, created_at | Tem muitos users e credentials |
| `users` | id, name, email, password_hash, org_id, role, mfa_enabled, totp_secret | Pertence a uma organization |
| `credentials` | id, org_id, name, login, encrypted_password, notes, category, created_by | Pertence a uma organization |
| `credential_permissions` | id, credential_id, user_id, can_view_password | Referência credential e user |
| `access_logs` | id, user_id, credential_id, action, accessed_at | Referência user e credential |

---

## Segurança

Estas práticas não são opcionais — segurança é a proposta central do Keyflow:

| Prática | Implementação |
|---------|---------------|
| Senha de login | bcrypt com salt (nunca texto puro) |
| Senhas do cofre | Fernet (AES-128-CBC) via PBKDF2 com 480.000 iterações |
| MFA | TOTP (RFC 6238) com Google Authenticator |
| CSRF | Flask-WTF com token em toda requisição POST |
| Isolamento | Verificação de org_id em toda query |
| Vazamentos | API k-Anonymity do HaveIBeenPwned (senha nunca sai do servidor) |
| Variáveis sensíveis | .env (nunca no código-fonte) |
| HTTPS | Obrigatório em produção (Render/Railway) |
| Sessões | Flask-Login com cookie seguro |
| Validação | Backend valida todos os dados (nunca confia só no frontend) |

---

## Deploy em Produção

O projeto inclui configuração pronta:

- `Procfile` — `gunicorn app:app --bind 0.0.0.0:$PORT`
- `render.yaml` — Web service + PostgreSQL free tier
- `runtime.txt` — Python 3.13.2

Para usar PostgreSQL, configure no `.env`:
```
DATABASE_URL=postgresql://usuario:senha@host:5432/keyflow
```

---

## API Endpoints

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/` | Landing page |
| GET/POST | `/register` | Cadastro |
| GET/POST | `/login` | Login |
| GET/POST | `/login/mfa` | Verificação MFA |
| GET | `/logout` | Logout |
| GET | `/dashboard` | Dashboard |
| GET | `/vault` | Cofre de senhas |
| GET | `/vault/search?q=` | Busca no cofre |
| GET/POST | `/vault/new` | Nova credencial |
| GET/POST | `/vault/<id>/edit` | Editar credencial |
| POST | `/vault/<id>/delete` | Deletar credencial |
| POST | `/vault/<id>/reveal` | Revelar senha (JSON) |
| GET/POST | `/vault/<id>/permissions` | Permissões |
| GET | `/members` | Lista de membros |
| POST | `/members/<id>/remove` | Remover membro |
| POST | `/members/<id>/reactivate` | Reativar membro |
| POST | `/members/invite-email` | Convite por e-mail |
| GET | `/logs` | Logs de auditoria |
| GET | `/logs/export` | Exportar CSV |
| GET | `/logs/export-pdf` | Relatório PDF LGPD |
| GET/POST | `/profile` | Perfil do usuário |
| GET/POST | `/profile/mfa/setup` | Configurar MFA |
| POST | `/profile/mfa/disable` | Desativar MFA |
| GET | `/api/health-score` | Health Score (JSON) |
| GET | `/api/dashboard-stats` | Estatísticas para gráficos (JSON) |
| GET | `/api/check-breaches` | Verificar senhas vazadas (JSON) |

---

## Análise de Mercado

- Mercado global de gerenciamento de senhas: **~$3.5B** (2025), crescendo **~19% ao ano**
- 70% da receita concentrada no enterprise — PMEs são o nicho menos atendido
- Brasil representa **45% do mercado** da América Latina em cibersegurança
- Nenhum player atual combina: interface simples + compartilhamento mascarado + LGPD + preço acessível

---

## Equipe

12 integrantes organizados em 6 duplas:

| Dupla | Área | Foco Técnico |
|-------|------|-------------|
| 1 — Produto & Pesquisa | Entrevistas, personas, validação | Pesquisa qualitativa, Figma |
| 2 — Design & Protótipo | Wireframes, UI, identidade visual | Figma, CSS, HTML |
| 3 — Backend: Auth | Cadastro, login, sessões, hash, MFA | Python, Flask, bcrypt, pyotp |
| 4 — Backend: Cofre | CRUD credenciais, permissões, cripto | Python, Flask, SQL |
| 5 — Backend: Logs & Org | Logs, membros, remoção, PDF, e-mail | Python, Flask, ReportLab |
| 6 — Pitch & Documento | Documento estratégico, slides, métricas | Storytelling, dados |

---

## Licença

Projeto acadêmico dos alunos do 4º Período da CESAR School — Ciência da Computação — 2026.
