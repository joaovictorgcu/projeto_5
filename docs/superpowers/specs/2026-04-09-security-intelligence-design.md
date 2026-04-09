# Security Intelligence — Design Spec

**Data:** 2026-04-09
**Status:** Aprovado
**Escopo:** Dashboard de segurança unificado para admins, com score de risco, alertas de vazamento e políticas de senha por categoria.

---

## Contexto

O Keyflow já possui checagem pontual de vazamentos (`/api/breach-check`) e análise de força de senha (`/api/health-score`), mas essas funcionalidades são reativas e isoladas. O admin não tem uma visão consolidada da postura de segurança da organização.

Este design cria um sistema integrado de inteligência de segurança que responde à pergunta: **"como está a segurança da minha org?"** em uma única página.

---

## Decisões de design

| Decisão | Escolha | Motivo |
|---------|---------|--------|
| Público-alvo | Apenas admin | Admin é o guardião da segurança da org |
| Arquitetura de página | Página única `/dashboard/security` | Visão consolidada sem fragmentar informação |
| Checagem de vazamento | No login do admin (background thread) | Simples, sem infra extra (Celery/APScheduler) |
| Políticas de senha | Híbrido (pré-definidas + customizáveis) | Funciona out-of-the-box, mas flexível |
| Violação de política | Alerta sem bloquear | Não impede fluxo de trabalho, apenas informa |

---

## 1. Modelos de dados

### PasswordPolicy

Regras de senha por categoria, vinculadas à organização.

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `id` | Integer, PK | Identificador |
| `org_id` | Integer, FK(Organization) | Organização dona da política |
| `category` | String(50) | Nome da categoria (ex: "Bancário") |
| `min_length` | Integer | Comprimento mínimo da senha |
| `require_uppercase` | Boolean | Exige letra maiúscula |
| `require_numbers` | Boolean | Exige número |
| `require_special` | Boolean | Exige caractere especial |
| `max_age_days` | Integer | Dias até a senha ser considerada expirada |
| `is_default` | Boolean | True = criada pelo sistema |

### BreachResult

Cache dos resultados de checagem contra o HaveIBeenPwned.

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `id` | Integer, PK | Identificador |
| `org_id` | Integer, FK(Organization) | Organização |
| `credential_id` | Integer, FK(Credential) | Credencial verificada |
| `is_breached` | Boolean | Se apareceu em vazamento |
| `breach_count` | Integer | Quantidade de vazamentos encontrados |
| `checked_at` | DateTime | Quando foi verificada |

### SecurityScore

Snapshot do score da organização para evolução temporal.

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `id` | Integer, PK | Identificador |
| `org_id` | Integer, FK(Organization) | Organização |
| `score` | Integer | Score de 0-100 |
| `weak_count` | Integer | Qtd de senhas fracas |
| `reused_count` | Integer | Qtd de senhas reutilizadas |
| `old_count` | Integer | Qtd de senhas expiradas |
| `breached_count` | Integer | Qtd de senhas vazadas |
| `recorded_at` | DateTime | Quando foi registrado |

---

## 2. Políticas de senha

### Defaults pré-definidos

Criados automaticamente no registro da organização.

| Categoria | Min. chars | Maiúsculas | Números | Especiais | Rotação |
|-----------|-----------|------------|---------|-----------|---------|
| Bancário / Financeiro | 16 | sim | sim | sim | 60 dias |
| Email | 12 | sim | sim | sim | 90 dias |
| Redes Sociais | 10 | sim | sim | não | 180 dias |
| Desenvolvimento | 14 | sim | sim | sim | 90 dias |
| Outros | 8 | sim | sim | não | 365 dias |

### Validação

- Executada na criação e edição de credenciais.
- Não bloqueia a operação — marca a credencial com flags de violação (`too_short`, `missing_special`, `missing_uppercase`, `missing_numbers`, `expired`).
- As violações alimentam o dashboard de segurança.

### Customização

- Seção dentro de `/dashboard/security` (bloco inferior).
- Admin pode editar valores de qualquer política ou criar novas categorias.
- Botão "Restaurar padrões" reseta para os defaults do sistema.

---

## 3. Checagem de vazamento no login

### Fluxo

1. Admin faz login com sucesso (após MFA se habilitado).
2. Sistema dispara checagem em **background thread** (mesmo padrão do Flask-Mail existente).
3. Para cada credencial da org, verifica se existe `BreachResult` com menos de 24h.
4. Credenciais sem resultado recente são checadas via API HaveIBeenPwned (k-anonymity SHA prefix, lógica já existente em `/api/breach-check`).
5. Resultados salvos/atualizados na tabela `BreachResult`.

### Rate limiting da API HIBP

- API pública: ~1 request a cada 1.5s.
- Thread usa `time.sleep(1.6)` entre checagens.
- Org com 50 credenciais: ~80 segundos em background, sem impactar UX.

### Experiência

- Checagem em andamento: dashboard mostra resultados existentes + indicador "Verificação em andamento...".
- Sem resultados (primeira vez): "Nenhuma verificação realizada — resultados aparecerão após seu próximo login".

---

## 4. Dashboard de Segurança

### Rota

- `GET /dashboard/security` — apenas admin (redirect com flash para membros).
- Registrada no blueprint `org`.

### Layout — 3 blocos verticais

#### Bloco 1 — Score geral (topo)

- Número grande de 0-100 com cor semântica:
  - Verde: > 80
  - Amarelo: 50-80
  - Vermelho: < 50
- **Fórmula do score:** começa em 100, desconta por problema:
  - Senha fraca: **-3** por credencial
  - Senha reutilizada: **-5** por grupo de duplicatas
  - Senha expirada: **-2** por credencial
  - Senha vazada: **-10** por credencial
  - Mínimo: 0
- 4 mini-cards ao lado: contagens de fracas, reutilizadas, expiradas, vazadas.
- Gráfico de linha (Chart.js): evolução do score nos últimos 30 dias via snapshots `SecurityScore`.

#### Bloco 2 — Lista de problemas (meio)

- Tabela com credenciais que têm pelo menos uma violação.
- Colunas: nome do serviço, categoria, problemas (badges coloridos), data de criação.
- Ordenação por severidade: vazadas > fracas > reutilizadas > expiradas.
- Filtros por tipo de problema.

#### Bloco 3 — Políticas (rodapé)

- Tabela com políticas por categoria.
- Botão "Editar" abre modal com campos da política.
- Botão "Nova categoria" para criar regras adicionais.
- Botão "Restaurar padrões".

### Snapshot do score

- Calculado e salvo como `SecurityScore` ao acessar a página, se o último snapshot tem mais de 1h.

---

## 5. Navegação e API

### Navegação

- Novo link "Segurança" no menu, ao lado de "Dashboard", visível apenas para admins.
- Ícone de escudo (SVG já existente no projeto).

### Novo endpoint

- `GET /api/security-score` — retorna score atual + dados de evolução em JSON para o Chart.js.

---

## Fora do escopo

- Notificações por email sobre vazamentos.
- Bloqueio de credenciais que violam políticas.
- Checagem de vazamento para membros não-admin.
- Rotação automática de senhas.
- Browser extension ou API pública.
