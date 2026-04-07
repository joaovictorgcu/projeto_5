# Keyflow

Cofre de senhas colaborativo para pequenas equipes. Compartilhe credenciais com seguranca, controle de acesso por membro e log completo de auditoria.

## Funcionalidades

- **Cofre de credenciais** — armazene logins e senhas com criptografia AES (Fernet/PBKDF2) em repouso
- **Organizacoes e convites** — crie uma organizacao ou entre em uma existente via codigo de convite
- **Controle de acesso** — defina quem pode visualizar cada senha (dono, acesso mascarado ou acesso total)
- **Papeis** — administradores gerenciam membros; membros acessam credenciais conforme permissoes
- **Log de auditoria** — todas as acoes (criar, editar, deletar, visualizar senha) sao registradas com usuario, credencial e timestamp
- **Exportacao CSV** — exporte o historico de logs em formato CSV
- **Health Score** — painel com pontuacao de saude das senhas (tamanho, complexidade, duplicatas)
- **Busca no cofre** — filtre credenciais por nome ou login
- **Perfil** — altere nome e senha da conta
- **Tema claro/escuro** — alternancia de tema na interface
- **Protecao CSRF** — todas as rotas protegidas contra Cross-Site Request Forgery
- **Landing page** — pagina inicial publica com apresentacao do produto

## Tecnologias

| Camada       | Tecnologia                          |
|--------------|-------------------------------------|
| Backend      | Python 3.13, Flask 3.1              |
| Banco de dados | SQLite (dev) / PostgreSQL (prod) |
| ORM          | Flask-SQLAlchemy                    |
| Autenticacao | Flask-Login, bcrypt                 |
| Criptografia | cryptography (Fernet + PBKDF2)     |
| Frontend     | HTML, CSS, JavaScript (vanilla)     |
| Deploy       | Render (Gunicorn)                   |

## Estrutura do projeto

```
├── app.py                 # Factory da aplicacao Flask
├── config.py              # Configuracoes (env vars)
├── models.py              # Modelos SQLAlchemy (Organization, User, Credential, etc.)
├── routes.py              # Blueprints de rotas (auth + main)
├── crypto_utils.py        # Criptografia Fernet para senhas armazenadas
├── schema.sql             # Schema SQL de referencia
├── requirements.txt       # Dependencias Python
├── Procfile               # Comando de start (Gunicorn)
├── render.yaml            # Configuracao de deploy no Render
├── runtime.txt            # Versao do Python
├── static/                # CSS, JS, favicon
└── templates/             # Templates Jinja2
    ├── base.html
    ├── landing.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── vault.html
    ├── credential_form.html
    ├── permissions.html
    ├── members.html
    ├── logs.html
    ├── profile.html
    └── errors/
```

## Como rodar localmente

```bash
# 1. Clone o repositorio
git clone <https://github.com/joaovictorgcu/projeto_5>
cd PROJETO_5

# 2. Crie e ative o ambiente virtual
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Instale as dependencias
pip install -r requirements.txt

# 4. Configure as variaveis de ambiente (opcional)
# Crie um arquivo .env na raiz:
#   SECRET_KEY=sua-chave-secreta
#   DATABASE_URL=sqlite:///keyflow.db

# 5. Rode a aplicacao
python app.py
```

A aplicacao estara disponivel em `http://localhost:5000`.

## Deploy

O projeto esta configurado para deploy no **Render** com PostgreSQL. O arquivo `render.yaml` define o servico web e o banco de dados. As variaveis `SECRET_KEY` e `DATABASE_URL` sao configuradas automaticamente.

## Modelo de dados

- **Organization** — grupo/equipe com codigo de convite unico
- **User** — membro com papel (admin/member) vinculado a uma organizacao
- **Credential** — login + senha criptografada pertencente a uma organizacao
- **CredentialPermission** — controle granular de quem pode ver cada senha
- **AccessLog** — registro de auditoria de todas as acoes sobre credenciais

## Licenca

Projeto academico dos alunos do 5º Período da CESAR School.
