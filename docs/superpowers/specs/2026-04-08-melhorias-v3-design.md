# Keyflow — Melhorias v3.0

**Data:** 2026-04-08
**Autor:** João Victor
**Status:** Aprovado
**Objetivo:** Refatorar código, melhorar segurança e adicionar UX features que impressionam tanto na demo quanto na revisão de código pela banca.

---

## Contexto

O Keyflow MVP está completo com 6 features avançadas (MFA, gráficos, PDF, vazamentos, categorias, e-mail). O `routes.py` cresceu para ~890 linhas e precisa ser separado. Faltam proteções de segurança básicas (rate limiting, auto-logout) e toques de UX profissional (onboarding, favoritos, atalhos).

---

## Melhoria 1: Separar routes.py em blueprints

### Estrutura

```
routes/
├── __init__.py    # Importa e expõe os 4 blueprints
├── auth.py        # Login, register, logout, MFA
├── vault.py       # Cofre, credenciais, permissões
├── org.py         # Dashboard, membros, logs, perfil, exports
└── api.py         # Endpoints JSON (health, stats, breaches)
```

### Regra de separação
- `auth.py`: tudo que envolve autenticação (login, register, logout, login_mfa)
- `vault.py`: tudo de `/vault/*` (CRUD, reveal, permissions, search)
- `org.py`: dashboard, members, logs, profile, MFA setup, invite email, export CSV/PDF
- `api.py`: endpoints que retornam JSON (/api/health-score, /api/dashboard-stats, /api/check-breaches)

### app.py atualizado
```python
from routes import auth, main_routes, vault, api
app.register_blueprint(auth)
app.register_blueprint(main_routes)
app.register_blueprint(vault)
app.register_blueprint(api)
```

### Helper
- Função `_log_access()` vai para `routes/__init__.py` (compartilhada por vault e org)

---

## Melhoria 2: Rate limiting no login

### Implementação
- Dicionário em memória: `login_attempts = {}` com chave IP
- Cada IP armazena: `{'count': int, 'blocked_until': datetime}`
- Máximo 5 tentativas erradas em 15 minutos
- Na 6ª tentativa: flash "Muitas tentativas. Aguarde 15 minutos." + retorna 429
- Login bem-sucedido: reseta o contador do IP
- Limpeza automática: entradas com mais de 15 minutos são removidas a cada request

### Localização
- Novo arquivo `rate_limit.py` com classe `LoginRateLimiter`
- Usado em `routes/auth.py` na rota de login

---

## Melhoria 3: Auto-logout por inatividade

### Backend
- `config.py`: `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)`
- `app.py`: `session.permanent = True` em before_request

### Frontend
- Timer em JS que detecta inatividade (sem mouse/teclado)
- Aos 25 minutos: mostra banner "Sua sessão expira em 5 minutos" com botão "Continuar"
- Aos 30 minutos: redireciona para `/logout` automaticamente
- Qualquer interação reseta o timer

---

## Melhoria 4: Tour guiado (onboarding)

### Quando aparece
- Dashboard, quando a organização tem 0 credenciais E o usuário nunca dispensou o tour
- Verificação: `localStorage.getItem('keyflow_tour_dismissed')`

### Conteúdo
Card visual com 3 passos:
1. "Adicione sua primeira credencial" → link para `/vault/new`
2. "Convide sua equipe" → link para `/members`
3. "Defina permissões" → texto explicativo

### Comportamento
- Botão "Dispensar" seta `localStorage` e remove o card
- Desaparece automaticamente quando há credenciais na org

---

## Melhoria 5: Favoritar credenciais

### Modelo de dados
- Novo campo `is_favorite` (Boolean, default False) na tabela `credential_permissions`
- Para o criador da credencial: novo campo na própria tabela `credentials` NÃO — melhor criar uma tabela simples `user_favorites` (user_id, credential_id) para manter separação limpa

### Tabela nova
```sql
CREATE TABLE user_favorites (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    credential_id INTEGER NOT NULL REFERENCES credentials(id),
    UNIQUE(user_id, credential_id)
);
```

### Endpoint
- `POST /vault/<id>/favorite` — toggle favorito (JSON response)

### Frontend
- Ícone de estrela no card da credencial
- Click faz toggle via fetch (sem reload)
- Credenciais favoritas aparecem primeiro na listagem

---

## Melhoria 6: Resumo de categorias no cofre

### Implementação
- Contagem por categoria via Jinja2 no template vault.html
- Linha acima dos filtros: "12 credenciais — 3 Rede Social, 2 Financeiro, 4 Cloud..."
- Sem endpoint novo — dados já disponíveis no template

---

## Melhoria 7: Gráfico de membros no dashboard

### Endpoint
- Extender `/api/dashboard-stats` com campo `members_timeline`
- Agrupa users por mês de criação, com contagem acumulativa de ativos vs removidos

### Frontend
- Novo gráfico de área (Chart.js) no dashboard
- Duas séries: "Ativos" (verde) e "Removidos" (vermelho)

---

## Melhoria 8: Distribuição de categorias no dashboard

### Implementação
- Card no dashboard com mini barras horizontais coloridas
- Dados: contagem de credenciais por categoria
- Reutiliza as cores já definidas no CSS (rede_social=#e1306c, financeiro=#22c55e, etc.)
- Sem endpoint novo — dados calculados no template ou via JS

---

## Melhoria 9: Atalhos de teclado

### Atalhos
| Tecla | Ação | Página |
|-------|------|--------|
| `Ctrl+K` | Foca no campo de busca | Cofre |
| `N` | Abre nova credencial | Cofre |
| `?` | Mostra/oculta painel de atalhos | Todas |

### Implementação
- Listener `keydown` no `main.js`
- Ignora quando foco está em input/textarea
- Tooltip flutuante no canto inferior direito com os atalhos
- `?` toggle a visibilidade do tooltip

---

## Ordem de implementação

| Ordem | Melhoria | Risco |
|-------|----------|-------|
| 1 | Separar routes.py em blueprints | Baixo (refactor puro) |
| 2 | Rate limiting | Baixo (novo arquivo isolado) |
| 3 | Auto-logout | Baixo (config + JS) |
| 4 | Favoritar credenciais | Baixo (nova tabela + toggle) |
| 5 | Resumo de categorias no cofre | Nenhum (só template) |
| 6 | Distribuição de categorias no dashboard | Baixo (template + JS) |
| 7 | Gráfico de membros | Baixo (extender API existente) |
| 8 | Tour guiado | Nenhum (só HTML/CSS/JS) |
| 9 | Atalhos de teclado | Nenhum (só JS) |

## Dependências novas
Nenhuma. Tudo usa o que já está instalado.
