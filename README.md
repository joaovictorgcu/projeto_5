# Keyflow

**Cofre de Senhas Colaborativo para Pequenas Equipes**

O Keyflow e uma plataforma web de compartilhamento seguro de senhas para agencias digitais, startups e PMEs com 3 a 50 pessoas. O produto resolve um problema cotidiano e critico: equipes compartilham credenciais de redes sociais, ferramentas SaaS e contas bancarias por WhatsApp e planilhas, expondo a empresa a vazamentos, invasoes e multas da LGPD.

> Projeto Academico — Ciencia da Computacao — 4o Periodo — CESAR School — 2026

---

## Funcionalidades do MVP

### Autenticacao
- Cadastro com nome, e-mail e senha
- Login/logout com sessao segura (Flask-Login)
- Hash de senhas com bcrypt + salt
- Isolamento por organizacao (cada usuario so ve dados da sua org)

### Cofre de Senhas
- Cadastrar credencial: nome do servico, login, senha criptografada, observacoes
- Listar, editar e deletar credenciais
- Campo de senha oculto por padrao com botao revelar/ocultar
- Copiar login ou senha com um clique
- Busca por nome ou login
- Auto-ocultar senha apos 30 segundos

### Gerador de Senhas
- Tamanho configuravel de 8 a 32 caracteres
- Opcoes: maiusculas, minusculas, numeros, simbolos
- Gerado com `crypto.getRandomValues()` (criptograficamente seguro)
- Indicador de forca em tempo real (Muito fraca → Forte)

### Compartilhamento
- Convite de membros por codigo unico da organizacao
- Permissao por credencial: "pode ver a senha" ou "so pode usar sem ver" (mascarado)
- Revogar acesso de um membro com um clique

### Log de Auditoria (LGPD)
- Registro automatico: quem acessou qual credencial, qual acao e quando
- Tela de auditoria com lista cronologica
- Exportacao em CSV (Data, Usuario, E-mail, Credencial, Acao)

### Dashboard
- Numero de credenciais e membros ativos
- Codigo de convite da organizacao
- Health Score de senhas (analisa fracas, curtas, pouco complexas, duplicadas)
- Ultimos 10 acessos com usuario, credencial e acao

### Outros
- Dark mode com persistencia (localStorage)
- Pagina de perfil (alterar nome e senha)
- Paginas de erro 404 e 500 estilizadas
- Sistema de icones SVG inline (25+ icones Lucide)
- Skip-link e ARIA labels para acessibilidade
- Responsivo (mobile-first)

---

## Stack Tecnologica

| Camada | Tecnologia | Por que |
|--------|-----------|---------|
| Frontend | HTML + CSS + JavaScript puro | Equipe ja domina; sem necessidade de framework |
| Backend | Python 3.13 + Flask 3.1 | Familiar para a equipe; direto para criar APIs REST |
| ORM | Flask-SQLAlchemy | Abstrai SQL; facilita migracao SQLite → PostgreSQL |
| Banco de dados | SQLite (dev) / PostgreSQL (prod) | SQL ja e dominio da equipe |
| Autenticacao | Flask-Login + bcrypt | Sessoes seguras; padrao da industria para hash |
| Criptografia (cofre) | Fernet (AES-128-CBC via PBKDF2) | Criptografia simetrica; facil de usar |
| Protecao CSRF | Flask-WTF | Nativo do Flask; protege todos os formularios |
| Icons | SVG inline (Lucide) | Escalavel, tematizavel, sem emojis |
| Deploy | Render / Railway + Gunicorn | Deploy via GitHub sem custo; HTTPS gratuito |

---

## Como Rodar Localmente

```bash
# 1. Clone o repositorio
git clone https://github.com/joaovictorgcu/projeto_5
cd PROJETO_5

# 2. Crie o ambiente virtual
python -m venv venv

# 3. Ative (Windows)
source venv/Scripts/activate
# Linux/Mac: source venv/bin/activate

# 4. Instale as dependencias
pip install -r requirements.txt

# 5. Configure variaveis de ambiente
cp .env.example .env
# Edite o .env com sua SECRET_KEY

# 6. Rode a aplicacao
python app.py
```

Acesse `http://127.0.0.1:5000`

---

## Estrutura do Projeto

```
PROJETO_5/
├── app.py                    # Factory Flask + error handlers
├── config.py                 # Configuracao via .env
├── models.py                 # 5 modelos SQLAlchemy
├── routes.py                 # 15+ endpoints (auth + main)
├── crypto_utils.py           # Criptografia Fernet para cofre
├── schema.sql                # Schema SQL de referencia
├── requirements.txt          # Dependencias Python
├── Procfile                  # Deploy (Gunicorn)
├── render.yaml               # Blueprint Render + PostgreSQL
├── runtime.txt               # Versao Python
├── .env.example              # Exemplo de variaveis de ambiente
├── .gitignore
│
├── static/
│   ├── style.css             # Design system (~1400 linhas)
│   ├── main.js               # Dark mode, reveal, gerador, toast
│   └── favicon.svg           # Favicon SVG (cadeado roxo)
│
└── templates/
    ├── base.html             # Layout: navbar, icons, skip-link, ARIA
    ├── icons.html            # 25+ icones SVG Lucide inline
    ├── landing.html          # Landing page completa (12 secoes)
    ├── login.html            # Tela de login
    ├── register.html         # Cadastro + convite
    ├── dashboard.html        # Dashboard + Health Score
    ├── vault.html            # Cofre com busca
    ├── credential_form.html  # Form + gerador de senhas
    ├── permissions.html      # Permissoes por credencial
    ├── members.html          # Gerenciamento de membros
    ├── logs.html             # Logs + export CSV
    ├── profile.html          # Perfil do usuario
    └── errors/
        ├── 404.html
        └── 500.html
```

---

## Modelo de Dados

```
organizations ──── users ──── access_logs
      │                │
      └── credentials ─┴── credential_permissions
```

| Tabela | Campos Principais | Relacao |
|--------|-------------------|---------|
| `organizations` | id, name, invite_code, created_at | Tem muitos users e credentials |
| `users` | id, name, email, password_hash, org_id, role | Pertence a uma organization |
| `credentials` | id, org_id, name, login, encrypted_password, notes, created_by | Pertence a uma organization |
| `credential_permissions` | id, credential_id, user_id, can_view_password | Referencia credential e user |
| `access_logs` | id, user_id, credential_id, action, accessed_at | Referencia user e credential |

---

## Seguranca

Estas praticas nao sao opcionais — seguranca e a proposta central do Keyflow:

| Pratica | Implementacao |
|---------|---------------|
| Senha de login | bcrypt com salt (nunca texto puro) |
| Senhas do cofre | Fernet (AES-128-CBC) via PBKDF2 com 480.000 iteracoes |
| CSRF | Flask-WTF com token em toda requisicao POST |
| Isolamento | Verificacao de org_id em toda query |
| Variaveis sensiveis | .env (nunca no codigo-fonte) |
| HTTPS | Obrigatorio em producao (Render/Railway) |
| Sessoes | Flask-Login com cookie seguro |
| Validacao | Backend valida todos os dados (nunca confia so no frontend) |

---

## Deploy em Producao

O projeto inclui configuracao pronta:

- `Procfile` — `gunicorn app:app --bind 0.0.0.0:$PORT`
- `render.yaml` — Web service + PostgreSQL free tier
- `runtime.txt` — Python 3.13.2

Para usar PostgreSQL, configure no `.env`:
```
DATABASE_URL=postgresql://usuario:senha@host:5432/keyflow
```

---

## API Endpoints

| Metodo | Rota | Descricao |
|--------|------|-----------|
| GET | `/` | Landing page |
| GET/POST | `/register` | Cadastro |
| GET/POST | `/login` | Login |
| GET | `/logout` | Logout |
| GET | `/dashboard` | Dashboard |
| GET | `/vault` | Cofre de senhas |
| GET | `/vault/search?q=` | Busca no cofre |
| GET/POST | `/vault/new` | Nova credencial |
| GET/POST | `/vault/<id>/edit` | Editar credencial |
| POST | `/vault/<id>/delete` | Deletar credencial |
| POST | `/vault/<id>/reveal` | Revelar senha (JSON) |
| GET/POST | `/vault/<id>/permissions` | Permissoes |
| GET | `/members` | Lista de membros |
| POST | `/members/<id>/remove` | Remover membro |
| POST | `/members/<id>/reactivate` | Reativar membro |
| GET | `/logs` | Logs de auditoria |
| GET | `/logs/export` | Exportar CSV |
| GET/POST | `/profile` | Perfil do usuario |
| GET | `/api/health-score` | Health Score (JSON) |

---

## Analise de Mercado

- Mercado global de gerenciamento de senhas: **~$3.5B** (2025), crescendo **~19% ao ano**
- 70% da receita concentrada no enterprise — PMEs sao o nicho menos atendido
- Brasil representa **45% do mercado** da America Latina em ciberseguranca
- Nenhum player atual combina: interface simples + compartilhamento mascarado + LGPD + preco acessivel

---

## Equipe

12 integrantes organizados em 6 duplas:

| Dupla | Area | Foco Tecnico |
|-------|------|-------------|
| 1 — Produto & Pesquisa | Entrevistas, personas, validacao | Pesquisa qualitativa, Figma |
| 2 — Design & Prototipo | Wireframes, UI, identidade visual | Figma, CSS, HTML |
| 3 — Backend: Auth | Cadastro, login, sessoes, hash | Python, Flask, bcrypt |
| 4 — Backend: Cofre | CRUD credenciais, permissoes, cripto | Python, Flask, SQL |
| 5 — Backend: Logs & Org | Logs, membros, remocao de acesso | Python, Flask, SQL |
| 6 — Pitch & Documento | Documento estrategico, slides, metricas | Storytelling, dados |

---

## Licenca

Projeto academico dos alunos do 4o Periodo da CESAR School — Ciencia da Computacao — 2026.
