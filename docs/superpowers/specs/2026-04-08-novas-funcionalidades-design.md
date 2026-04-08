# Keyflow — Novas Funcionalidades v2.0

**Data:** 2026-04-08
**Autor:** João Victor
**Status:** Aprovado
**Objetivo:** Adicionar 6 funcionalidades ao MVP para a apresentação final, cobrindo segurança, dados, compliance, UX e integração externa.

---

## Contexto

O MVP do Keyflow está funcional com: autenticação, cofre de senhas criptografado, compartilhamento com permissões, log de auditoria, dashboard com health score, gerador de senhas, dark mode e busca. O objetivo agora é adicionar features com alto impacto visual na demo para a banca avaliadora.

**Restrição:** Apenas 1 desenvolvedor (João) implementa. Stack atual (Flask + JS puro + SQL) deve ser mantida. Nenhuma tecnologia nova complexa.

---

## Feature 1: MFA com TOTP (Google Authenticator)

### Descrição
Autenticação de dois fatores usando códigos temporários (TOTP) compatíveis com Google Authenticator e Authy.

### Modelo de dados
- Novo campo `totp_secret` (String, nullable) na tabela `users`
- Novo campo `mfa_enabled` (Boolean, default False) na tabela `users`

### Fluxo de ativação
1. Usuário vai em Perfil → "Ativar autenticação de dois fatores"
2. Backend gera `totp_secret` via `pyotp.random_base32()`
3. Gera QR Code com `qrcode` e exibe na tela como imagem base64
4. Usuário escaneia com Google Authenticator
5. Digita o código de 6 dígitos para confirmar
6. Backend valida com `pyotp.TOTP(secret).verify(code)`
7. Se válido, salva `totp_secret` criptografado e `mfa_enabled=True`

### Fluxo de login
1. Usuário digita email + senha (fluxo atual)
2. Se `mfa_enabled=True`, redireciona para tela intermediária `/login/mfa`
3. Usuário digita código de 6 dígitos
4. Backend valida. Se correto, completa o login. Se errado, mensagem de erro.

### Fluxo de desativação
1. Perfil → "Desativar MFA"
2. Pede o código atual para confirmar
3. Remove `totp_secret`, seta `mfa_enabled=False`

### Endpoints
- `GET /profile/mfa/setup` — exibe QR Code
- `POST /profile/mfa/setup` — valida código e ativa
- `POST /profile/mfa/disable` — desativa MFA
- `GET /login/mfa` — tela de código MFA
- `POST /login/mfa` — valida código MFA

### Templates
- `mfa_setup.html` — QR Code + campo de confirmação
- `mfa_verify.html` — campo de 6 dígitos no login

### Dependências
- `pyotp` — geração e validação TOTP
- `qrcode[pil]` — geração de QR Code
- `Pillow` — renderização da imagem

### Segurança
- `totp_secret` armazenado criptografado com Fernet (mesmo esquema das senhas do cofre)
- Código TOTP válido por 30 segundos (padrão RFC 6238)
- Máximo de 5 tentativas erradas antes de bloquear por 5 minutos

---

## Feature 2: Dashboard com Gráficos (Chart.js)

### Descrição
3 gráficos interativos no dashboard usando Chart.js via CDN.

### Gráficos
1. **Acessos por dia (7 dias)** — gráfico de linha
2. **Ações por tipo** — gráfico de rosca (donut): visualizou, criou, editou, deletou
3. **Top 5 credenciais mais acessadas** — barras horizontais

### Endpoint
- `GET /api/dashboard-stats` — retorna JSON:
```json
{
  "daily_access": [
    {"date": "07/04", "count": 12},
    {"date": "08/04", "count": 8}
  ],
  "actions_breakdown": {
    "visualizou senha": 45,
    "criou": 12,
    "editou": 8,
    "deletou": 3
  },
  "top_credentials": [
    {"name": "Instagram", "count": 23},
    {"name": "AWS Console", "count": 15}
  ]
}
```

### Frontend
- Chart.js carregado via CDN: `https://cdn.jsdelivr.net/npm/chart.js`
- 3 elementos `<canvas>` no dashboard.html
- Cores adaptáveis: detecta `data-theme="dark"` e ajusta paleta
- Paleta laranja: tons de `#f97316`, `#ea580c`, `#fb923c` para as séries

### Dependências
- Nenhuma no backend
- Chart.js 4.x via CDN no frontend

---

## Feature 3: Relatório LGPD em PDF

### Descrição
Gera PDF profissional com log de acessos para fins de auditoria LGPD.

### Conteúdo do PDF
1. **Cabeçalho:** "Keyflow — Relatório de Auditoria", nome da organização, data de geração
2. **Resumo:** total de acessos no período, usuário mais ativo, credencial mais acessada, total de membros
3. **Tabela de logs:** data/hora, usuário, e-mail, credencial, ação
4. **Rodapé:** "Documento gerado automaticamente pelo Keyflow para fins de auditoria — LGPD Lei 13.709/2018"

### Endpoint
- `GET /logs/export-pdf` — retorna o arquivo PDF para download
- Parâmetro opcional `?days=30` para filtrar período (default: 30 dias)

### Implementação
- Biblioteca `reportlab` para geração do PDF
- Layout: A4, margens de 2cm, fonte Helvetica
- Tabela com cores alternadas nas linhas (zebra striping)
- Cabeçalho laranja (#ea580c) com texto branco

### Template de logs atualizado
- Novo botão ao lado de "Exportar CSV": "Gerar PDF"

### Dependências
- `reportlab`

---

## Feature 4: Detecção de Senhas Vazadas (HaveIBeenPwned)

### Descrição
Verifica se senhas do cofre aparecem em vazamentos públicos usando a API k-Anonymity do HaveIBeenPwned.

### Como funciona a API k-Anonymity
1. Calcula SHA-1 da senha em texto puro
2. Envia apenas os 5 primeiros caracteres do hash para a API
3. API retorna todos os hashes que começam com esses 5 chars
4. Backend compara localmente se o hash completo está na lista
5. A senha real nunca sai do servidor

### Endpoint
- `GET /api/check-breaches` — analisa todas as credenciais da org
- Retorna JSON:
```json
{
  "total_checked": 12,
  "breached": 2,
  "results": [
    {"credential_name": "Instagram", "breach_count": 10234567},
    {"credential_name": "Slack", "breach_count": 452}
  ]
}
```

### Integração visual
- No Health Score do dashboard: seção "Senhas vazadas" com contagem
- No card da credencial no cofre: badge vermelho "Vazada" se detectada
- Botão "Verificar vazamentos" no dashboard que dispara a verificação

### Rate limiting
- Máximo 1 verificação completa por hora (cache resultado)
- API do HaveIBeenPwned: sem rate limit para k-Anonymity, mas respeitar 1 req/1.5s

### Dependências
- Nenhuma nova (`hashlib` é nativo, `urllib` é nativo)

---

## Feature 5: Categorias com Ícones no Cofre

### Descrição
Credenciais ganham categoria visual com ícone SVG e cor. Cofre pode ser filtrado por categoria.

### Modelo de dados
- Novo campo `category` (String, default "outros") na tabela `credentials`

### Categorias pré-definidas

| Categoria | Ícone | Cor |
|-----------|-------|-----|
| Rede Social | icon-users | #e1306c |
| E-mail | icon-mail | #ea4335 |
| Financeiro | icon-dollar | #22c55e |
| Cloud/Dev | icon-cloud | #3b82f6 |
| Comunicação | icon-message | #7c3aed |
| Marketing | icon-megaphone | #f97316 |
| Outros | icon-folder | #78716c |

### Ícones SVG novos em icons.html
- `icon-mail`, `icon-dollar`, `icon-cloud`, `icon-message`, `icon-megaphone`, `icon-folder`

### Formulário de credencial
- Novo campo `<select>` de categoria antes do campo de notas
- Ícone da categoria selecionada aparece ao lado do select

### Cofre
- Barra de filtros (chips) acima dos cards: "Todos | Rede Social | E-mail | Financeiro | ..."
- Chip ativo muda de cor. Filtro via JavaScript (mostra/esconde cards, sem request)
- Header do card mostra ícone + cor da categoria

### Migração
- Credenciais existentes recebem category="outros" por default

### Dependências
- Nenhuma

---

## Feature 6: Notificação por E-mail

### Descrição
E-mails automáticos em momentos-chave do sistema.

### E-mails

| Evento | Destinatário | Assunto |
|--------|-------------|---------|
| Convite de equipe | E-mail digitado | "Você foi convidado para [org] no Keyflow" |
| Acesso a credencial | Criador da credencial | "[nome] acessou [credencial]" |
| Membro removido | Admin | "[nome] foi removido de [org]" |

### Implementação
- `Flask-Mail` configurado via `.env`
- Templates HTML inline para os e-mails (estilo Keyflow: laranja + branco)
- Envio em thread separada (`threading.Thread`) para não bloquear a resposta
- Formulário de convite por e-mail na página de membros

### Configuração (.env)
```
MAIL_SERVER=smtp.mailtrap.io
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=seu_username
MAIL_PASSWORD=seu_password
MAIL_DEFAULT_SENDER=noreply@keyflow.com
```

### Para a demo
- Usar Mailtrap (gratuito) — captura e-mails sem enviar de verdade
- Mostra caixa de entrada simulada na apresentação

### Endpoints novos
- `POST /members/invite-email` — envia convite por e-mail

### Dependências
- `Flask-Mail`

---

## Ordem de implementação sugerida

| Ordem | Feature | Justificativa |
|-------|---------|---------------|
| 1 | Categorias com ícones | Sem dependência externa, melhora visual imediata |
| 2 | Dashboard com gráficos | Só frontend, alto impacto visual |
| 3 | Detecção de vazamentos | API simples, efeito wow |
| 4 | Relatório PDF | Backend puro, entregável tangível |
| 5 | MFA com TOTP | Mais complexo, mas muito impactante |
| 6 | Notificação por e-mail | Depende de config externa (SMTP) |

## Dependências totais a instalar

```
pyotp
qrcode[pil]
Pillow
reportlab
Flask-Mail
```
