# Security Intelligence — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a unified security dashboard for admins with org-level risk score, proactive breach alerts, and configurable password policies per category.

**Architecture:** Single page `/dashboard/security` in the `org` blueprint. Three new models (`PasswordPolicy`, `BreachResult`, `SecurityScore`) + one field added to `Credential`. A background thread checks breaches on admin login. A new API endpoint feeds Chart.js for score evolution.

**Tech Stack:** Flask, SQLAlchemy, Chart.js, HaveIBeenPwned k-anonymity API, Jinja2, existing CSS design system.

**Spec:** `docs/superpowers/specs/2026-04-09-security-intelligence-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `models.py` | Add `password_changed_at` to Credential, add 3 new models |
| Modify | `routes/vault.py` | Set `password_changed_at` on create/edit |
| Modify | `routes/auth.py` | Trigger breach check thread on admin login |
| Create | `security.py` | Score calculation, policy validation, breach check logic |
| Modify | `routes/org.py` | Add `/dashboard/security` route + policy CRUD routes |
| Modify | `routes/api.py` | Add `/api/security-score` endpoint |
| Create | `templates/security_dashboard.html` | Dashboard template (3 blocks) |
| Modify | `templates/base.html` | Add "Seguranca" nav link for admins |
| Modify | `templates/icons.html` | Add `#icon-loader` SVG symbol |
| Modify | `static/style.css` | Styles for security dashboard components (score, modals, badges, spinner) |
| Modify | `static/main.js` | Policy modal + filter interactions |

---

### Task 1: Add `password_changed_at` to Credential model

**Files:**
- Modify: `models.py:35-50`

- [ ] **Step 1: Add the field to Credential**

In `models.py`, add after line 46 (`created_at`):

```python
password_changed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
```

- [ ] **Step 2: Verify the app starts**

Run: `python -c "from app import app; print('OK')"`
Expected: `OK`

Since SQLite with `db.create_all()` won't add columns to existing tables, we need a manual migration for existing data.

- [ ] **Step 3: Add migration helper in app.py**

In `app.py`, inside the `with app.app_context():` block (line 53), add after `db.create_all()`:

```python
# migrate: add password_changed_at if missing
with db.engine.connect() as conn:
    from sqlalchemy import inspect, text
    cols = [c['name'] for c in inspect(db.engine).get_columns('credentials')]
    if 'password_changed_at' not in cols:
        conn.execute(text('ALTER TABLE credentials ADD COLUMN password_changed_at DATETIME'))
        conn.execute(text('UPDATE credentials SET password_changed_at = created_at WHERE password_changed_at IS NULL'))
        conn.commit()
```

- [ ] **Step 4: Commit**

```bash
git add models.py app.py
git commit -m "adiciona campo password_changed_at ao modelo Credential"
```

---

### Task 2: Update vault routes to set `password_changed_at`

**Files:**
- Modify: `routes/vault.py:28-53` (credential_new)
- Modify: `routes/vault.py:61-84` (credential_edit)

- [ ] **Step 1: Import datetime in vault.py**

At the top of `routes/vault.py`, add:

```python
from datetime import datetime, timezone
```

- [ ] **Step 2: Set `password_changed_at` on new credential**

In `credential_new()`, after line 49 (`created_by=current_user.id`), the `Credential()` constructor already sets it via default. No change needed here — the model default handles it.

- [ ] **Step 3: Update `password_changed_at` on password edit**

In `credential_edit()`, after line 77 (`cred.encrypted_password = encrypt_password(new_password)`), add:

```python
            cred.password_changed_at = datetime.now(timezone.utc)
```

- [ ] **Step 4: Verify the app starts**

Run: `python -c "from app import app; print('OK')"`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add routes/vault.py
git commit -m "atualiza password_changed_at ao editar senha de credencial"
```

---

### Task 3: Add PasswordPolicy, BreachResult, SecurityScore models

**Files:**
- Modify: `models.py`

- [ ] **Step 1: Add PasswordPolicy model**

Append to `models.py`:

```python
class PasswordPolicy(db.Model):
    __tablename__ = 'password_policies'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    min_length = db.Column(db.Integer, default=8)
    require_uppercase = db.Column(db.Boolean, default=True)
    require_numbers = db.Column(db.Boolean, default=True)
    require_special = db.Column(db.Boolean, default=False)
    max_age_days = db.Column(db.Integer, default=365)
    is_default = db.Column(db.Boolean, default=True)

    organization = db.relationship('Organization', backref='password_policies')
```

- [ ] **Step 2: Add BreachResult model**

Append to `models.py`:

```python
class BreachResult(db.Model):
    __tablename__ = 'breach_results'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    credential_id = db.Column(db.Integer, db.ForeignKey('credentials.id'), nullable=False, unique=True)
    is_breached = db.Column(db.Boolean, default=False)
    breach_count = db.Column(db.Integer, default=0)
    checked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    organization = db.relationship('Organization', backref='breach_results')
    credential = db.relationship('Credential', backref=db.backref('breach_result', uselist=False, cascade='all, delete-orphan'))
```

- [ ] **Step 3: Add SecurityScore model**

Append to `models.py`:

```python
class SecurityScore(db.Model):
    __tablename__ = 'security_scores'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    weak_count = db.Column(db.Integer, default=0)
    reused_count = db.Column(db.Integer, default=0)
    old_count = db.Column(db.Integer, default=0)
    breached_count = db.Column(db.Integer, default=0)
    recorded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    organization = db.relationship('Organization', backref='security_scores')
```

- [ ] **Step 4: Verify the app starts and tables are created**

Run: `python -c "from app import app; print('OK')"`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add models.py
git commit -m "adiciona modelos PasswordPolicy, BreachResult e SecurityScore"
```

---

### Task 4: Create `security.py` — default policies and policy validation

**Files:**
- Create: `security.py`

- [ ] **Step 1: Create file with default policy definitions and creation function**

Create `security.py` with **all imports at the top** (Tasks 5 and 6 will append functions only, no new imports):

```python
import hashlib
import time
import threading
import urllib.request
from datetime import datetime, timezone, timedelta

from models import db, Credential, PasswordPolicy, BreachResult, SecurityScore
from crypto_utils import decrypt_password

DEFAULT_POLICIES = [
    {'category': 'financeiro', 'min_length': 16, 'require_uppercase': True, 'require_numbers': True, 'require_special': True, 'max_age_days': 60},
    {'category': 'email', 'min_length': 12, 'require_uppercase': True, 'require_numbers': True, 'require_special': True, 'max_age_days': 90},
    {'category': 'rede_social', 'min_length': 10, 'require_uppercase': True, 'require_numbers': True, 'require_special': False, 'max_age_days': 180},
    {'category': 'cloud', 'min_length': 14, 'require_uppercase': True, 'require_numbers': True, 'require_special': True, 'max_age_days': 90},
    {'category': 'comunicacao', 'min_length': 10, 'require_uppercase': True, 'require_numbers': True, 'require_special': False, 'max_age_days': 180},
    {'category': 'marketing', 'min_length': 10, 'require_uppercase': True, 'require_numbers': True, 'require_special': False, 'max_age_days': 180},
    {'category': 'outros', 'min_length': 8, 'require_uppercase': True, 'require_numbers': True, 'require_special': False, 'max_age_days': 365},
]


def ensure_default_policies(org_id):
    """Cria politicas padrao para a org se nao existirem (lazy creation)."""
    existing = PasswordPolicy.query.filter_by(org_id=org_id).count()
    if existing > 0:
        return
    for p in DEFAULT_POLICIES:
        policy = PasswordPolicy(org_id=org_id, is_default=True, **p)
        db.session.add(policy)
    db.session.commit()


def validate_credential_against_policy(password, category, org_id):
    """Retorna lista de violacoes da senha contra a politica da categoria."""
    policy = PasswordPolicy.query.filter_by(org_id=org_id, category=category).first()
    if not policy:
        policy = PasswordPolicy.query.filter_by(org_id=org_id, category='outros').first()
    if not policy:
        return []

    violations = []
    if len(password) < policy.min_length:
        violations.append('too_short')
    if policy.require_uppercase and not any(c.isupper() for c in password):
        violations.append('missing_uppercase')
    if policy.require_numbers and not any(c.isdigit() for c in password):
        violations.append('missing_numbers')
    if policy.require_special and not any(not c.isalnum() for c in password):
        violations.append('missing_special')

    return violations


def check_password_expired(password_changed_at, category, org_id):
    """Verifica se a senha esta expirada de acordo com a politica."""
    policy = PasswordPolicy.query.filter_by(org_id=org_id, category=category).first()
    if not policy:
        policy = PasswordPolicy.query.filter_by(org_id=org_id, category='outros').first()
    if not policy:
        return False

    if password_changed_at is None:
        return False

    age = datetime.now(timezone.utc) - password_changed_at
    return age > timedelta(days=policy.max_age_days)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from security import DEFAULT_POLICIES; print(len(DEFAULT_POLICIES))"`
Expected: `7`

- [ ] **Step 3: Commit**

```bash
git add security.py
git commit -m "cria security.py com politicas padrao e validacao de senha"
```

---

### Task 5: Add score calculation to `security.py`

**Files:**
- Modify: `security.py`

- [ ] **Step 1: Add score calculation function**

Append to `security.py` (imports already at top from Task 4):

```python
def calculate_security_score(org_id):
    """Calcula o score de seguranca da org (0-100) e retorna detalhes."""
    credentials = Credential.query.filter_by(org_id=org_id).all()
    if not credentials:
        return {'score': 100, 'weak_count': 0, 'reused_count': 0, 'old_count': 0, 'breached_count': 0, 'problems': []}

    ensure_default_policies(org_id)

    score = 100
    weak_count = 0
    reused_count = 0
    old_count = 0
    breached_count = 0
    problems = []
    passwords = {}  # cred_id -> plaintext

    # Descriptografar senhas para analise
    for cred in credentials:
        try:
            passwords[cred.id] = decrypt_password(cred.encrypted_password)
        except Exception:
            continue

    # Verificar fraqueza e violacoes de politica
    for cred in credentials:
        pw = passwords.get(cred.id)
        if not pw:
            continue

        violations = validate_credential_against_policy(pw, cred.category, org_id)
        if violations:
            weak_count += 1
            score -= 3
            problems.append({
                'credential_id': cred.id,
                'name': cred.name,
                'category': cred.category,
                'created_at': cred.created_at.strftime('%d/%m/%Y') if cred.created_at else '',
                'issues': violations,
                'severity': 2
            })

        # Verificar expiracao
        changed_at = cred.password_changed_at or cred.created_at
        if check_password_expired(changed_at, cred.category, org_id):
            old_count += 1
            score -= 2
            # Adicionar 'expired' ao problema existente ou criar novo
            existing = next((p for p in problems if p['credential_id'] == cred.id), None)
            if existing:
                existing['issues'].append('expired')
            else:
                problems.append({
                    'credential_id': cred.id,
                    'name': cred.name,
                    'category': cred.category,
                    'created_at': cred.created_at.strftime('%d/%m/%Y') if cred.created_at else '',
                    'issues': ['expired'],
                    'severity': 1
                })

    # Verificar senhas reutilizadas
    pw_to_creds = {}
    for cred_id, pw in passwords.items():
        pw_to_creds.setdefault(pw, []).append(cred_id)

    for pw, cred_ids in pw_to_creds.items():
        if len(cred_ids) > 1:
            reused_count += 1
            score -= 5
            for cid in cred_ids:
                cred = next(c for c in credentials if c.id == cid)
                existing = next((p for p in problems if p['credential_id'] == cid), None)
                if existing:
                    existing['issues'].append('reused')
                    existing['severity'] = max(existing['severity'], 3)
                else:
                    problems.append({
                        'credential_id': cid,
                        'name': cred.name,
                        'category': cred.category,
                        'created_at': cred.created_at.strftime('%d/%m/%Y') if cred.created_at else '',
                        'issues': ['reused'],
                        'severity': 3
                    })

    # Verificar vazamentos (usa cache da tabela BreachResult)
    for cred in credentials:
        breach = BreachResult.query.filter_by(credential_id=cred.id, is_breached=True).first()
        if breach:
            breached_count += 1
            score -= 10
            existing = next((p for p in problems if p['credential_id'] == cred.id), None)
            if existing:
                existing['issues'].append('breached')
                existing['severity'] = 4
            else:
                problems.append({
                    'credential_id': cred.id,
                    'name': cred.name,
                    'category': cred.category,
                    'created_at': cred.created_at.strftime('%d/%m/%Y') if cred.created_at else '',
                    'issues': ['breached'],
                    'severity': 4
                })

    score = max(0, score)

    # Ordenar por severidade (vazadas primeiro)
    problems.sort(key=lambda p: p['severity'], reverse=True)

    return {
        'score': score,
        'weak_count': weak_count,
        'reused_count': reused_count,
        'old_count': old_count,
        'breached_count': breached_count,
        'problems': problems
    }


def maybe_save_snapshot(org_id):
    """Salva um SecurityScore snapshot se o ultimo tem mais de 1h."""
    last = (SecurityScore.query
            .filter_by(org_id=org_id)
            .order_by(SecurityScore.recorded_at.desc())
            .first())

    if last and (datetime.now(timezone.utc) - last.recorded_at) < timedelta(hours=1):
        return last

    data = calculate_security_score(org_id)
    snapshot = SecurityScore(
        org_id=org_id,
        score=data['score'],
        weak_count=data['weak_count'],
        reused_count=data['reused_count'],
        old_count=data['old_count'],
        breached_count=data['breached_count']
    )
    db.session.add(snapshot)
    db.session.commit()
    return snapshot
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from security import calculate_security_score; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add security.py
git commit -m "adiciona calculo de score de seguranca e snapshot temporal"
```

---

### Task 6: Add breach check background thread to `security.py`

**Files:**
- Modify: `security.py`

- [ ] **Step 1: Add breach check function**

Append to `security.py` (imports already at top from Task 4):

```python
def _check_breach_for_password(password):
    """Checa uma senha contra HaveIBeenPwned (k-anonymity). Retorna (is_breached, count)."""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Keyflow-MVP'})
        resp = urllib.request.urlopen(req, timeout=5)
        body = resp.read().decode('utf-8')

        for line in body.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return True, int(count)
    except Exception:
        pass

    return False, 0


def run_breach_check_background(app, org_id):
    """Roda checagem de vazamento em background thread para todas as credenciais da org."""
    def _run():
        with app.app_context():
            credentials = Credential.query.filter_by(org_id=org_id).all()
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=24)

            for cred in credentials:
                # Pular se ja checou nas ultimas 24h
                existing = BreachResult.query.filter_by(credential_id=cred.id).first()
                if existing and existing.checked_at > cutoff:
                    continue

                try:
                    pw = decrypt_password(cred.encrypted_password)
                except Exception:
                    continue

                is_breached, count = _check_breach_for_password(pw)

                if existing:
                    existing.is_breached = is_breached
                    existing.breach_count = count
                    existing.checked_at = datetime.now(timezone.utc)
                else:
                    result = BreachResult(
                        org_id=org_id,
                        credential_id=cred.id,
                        is_breached=is_breached,
                        breach_count=count
                    )
                    db.session.add(result)

                db.session.commit()
                time.sleep(1.6)  # Rate limit HIBP API

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from security import run_breach_check_background; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add security.py
git commit -m "adiciona checagem de vazamento em background thread"
```

---

### Task 7: Trigger breach check on admin login

**Files:**
- Modify: `routes/auth.py:66-102`

- [ ] **Step 1: Add breach check trigger after admin login**

In `routes/auth.py`, add `current_app` to the existing flask import on line 5 (change `from flask import Blueprint, render_template, request, redirect, url_for, flash, session` to also include `current_app`).

In the `login()` function, after line 92 (`login_user(user)`), add:

```python
            if user.role == 'admin' and user.org_id:
                from security import run_breach_check_background
                run_breach_check_background(current_app._get_current_object(), user.org_id)
```

Also in `login_mfa()`, after line 127 (`login_user(user)`), add the same:

```python
                if user.role == 'admin' and user.org_id:
                    from security import run_breach_check_background
                    run_breach_check_background(current_app._get_current_object(), user.org_id)
```

- [ ] **Step 2: Verify the app starts**

Run: `python -c "from app import app; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add routes/auth.py
git commit -m "dispara checagem de vazamento no login do admin"
```

---

### Task 8: Add `/dashboard/security` route and policy CRUD

**Files:**
- Modify: `routes/org.py`

- [ ] **Step 1: Add security dashboard route**

In `routes/org.py`, add after the `dashboard()` function (after line 51):

```python
# --- Seguranca ----------------------------------------------------------
@org.route('/dashboard/security')
@login_required
def security_dashboard():
    if current_user.role != 'admin':
        flash('Apenas administradores podem acessar o painel de seguranca.', 'error')
        return redirect(url_for('vault.index'))

    organization = current_user.organization
    if not organization:
        flash('Voce nao pertence a nenhuma organizacao.', 'error')
        return redirect(url_for('org.landing'))

    from security import ensure_default_policies, calculate_security_score, maybe_save_snapshot
    from models import PasswordPolicy, SecurityScore, BreachResult

    ensure_default_policies(organization.id)
    score_data = calculate_security_score(organization.id)
    maybe_save_snapshot(organization.id)

    policies = PasswordPolicy.query.filter_by(org_id=organization.id).order_by(PasswordPolicy.category).all()

    # Dados para grafico de evolucao (ultimos 30 dias)
    from datetime import timedelta
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    snapshots = (SecurityScore.query
                 .filter_by(org_id=organization.id)
                 .filter(SecurityScore.recorded_at >= thirty_days_ago)
                 .order_by(SecurityScore.recorded_at)
                 .all())

    # Verificar se ha checagem de breach em andamento
    from models import Credential
    total_creds = Credential.query.filter_by(org_id=organization.id).count()
    total_checked = BreachResult.query.filter_by(org_id=organization.id).count()
    breach_in_progress = total_checked < total_creds and total_creds > 0

    return render_template('security_dashboard.html',
                           org=organization,
                           score=score_data['score'],
                           weak_count=score_data['weak_count'],
                           reused_count=score_data['reused_count'],
                           old_count=score_data['old_count'],
                           breached_count=score_data['breached_count'],
                           problems=score_data['problems'],
                           policies=policies,
                           snapshots=snapshots,
                           breach_in_progress=breach_in_progress)
```

- [ ] **Step 2: Add policy edit route**

```python
@org.route('/dashboard/security/policy/<int:policy_id>/edit', methods=['POST'])
@login_required
def policy_edit(policy_id):
    if current_user.role != 'admin':
        flash('Acesso negado.', 'error')
        return redirect(url_for('org.security_dashboard'))

    from models import PasswordPolicy
    policy = PasswordPolicy.query.get_or_404(policy_id)
    if policy.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('org.security_dashboard'))

    policy.min_length = int(request.form.get('min_length', 8))
    policy.require_uppercase = request.form.get('require_uppercase') == 'on'
    policy.require_numbers = request.form.get('require_numbers') == 'on'
    policy.require_special = request.form.get('require_special') == 'on'
    policy.max_age_days = int(request.form.get('max_age_days', 365))
    policy.is_default = False

    db.session.commit()
    flash('Politica atualizada.', 'success')
    return redirect(url_for('org.security_dashboard'))
```

- [ ] **Step 3: Add new policy route**

```python
@org.route('/dashboard/security/policy/new', methods=['POST'])
@login_required
def policy_new():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'error')
        return redirect(url_for('org.security_dashboard'))

    from models import PasswordPolicy
    category = request.form.get('category', '').strip().lower()
    if not category:
        flash('Informe o nome da categoria.', 'error')
        return redirect(url_for('org.security_dashboard'))

    existing = PasswordPolicy.query.filter_by(org_id=current_user.org_id, category=category).first()
    if existing:
        flash('Ja existe uma politica para essa categoria.', 'error')
        return redirect(url_for('org.security_dashboard'))

    policy = PasswordPolicy(
        org_id=current_user.org_id,
        category=category,
        min_length=int(request.form.get('min_length', 8)),
        require_uppercase=request.form.get('require_uppercase') == 'on',
        require_numbers=request.form.get('require_numbers') == 'on',
        require_special=request.form.get('require_special') == 'on',
        max_age_days=int(request.form.get('max_age_days', 365)),
        is_default=False
    )
    db.session.add(policy)
    db.session.commit()
    flash('Nova politica criada.', 'success')
    return redirect(url_for('org.security_dashboard'))
```

- [ ] **Step 4: Add restore defaults route**

```python
@org.route('/dashboard/security/policy/restore', methods=['POST'])
@login_required
def policy_restore_defaults():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'error')
        return redirect(url_for('org.security_dashboard'))

    from models import PasswordPolicy
    PasswordPolicy.query.filter_by(org_id=current_user.org_id).delete()
    db.session.commit()

    from security import ensure_default_policies
    ensure_default_policies(current_user.org_id)
    flash('Politicas restauradas para os padroes.', 'success')
    return redirect(url_for('org.security_dashboard'))
```

- [ ] **Step 5: Verify the app starts**

Run: `python -c "from app import app; print('OK')"`
Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add routes/org.py
git commit -m "adiciona rota do dashboard de seguranca e CRUD de politicas"
```

---

### Task 9: Add `/api/security-score` endpoint

**Files:**
- Modify: `routes/api.py`

- [ ] **Step 1: Add security-score endpoint**

In `routes/api.py`, add at the end:

```python
@api.route('/api/security-score')
@login_required
def security_score():
    if current_user.role != 'admin':
        return jsonify({'error': 'Acesso negado'}), 403

    org = current_user.organization
    if not org:
        return jsonify({'score': 0})

    from security import calculate_security_score
    from models import SecurityScore

    data = calculate_security_score(org.id)

    # Dados de evolucao (ultimos 30 dias)
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    snapshots = (SecurityScore.query
                 .filter_by(org_id=org.id)
                 .filter(SecurityScore.recorded_at >= thirty_days_ago)
                 .order_by(SecurityScore.recorded_at)
                 .all())

    return jsonify({
        'score': data['score'],
        'weak_count': data['weak_count'],
        'reused_count': data['reused_count'],
        'old_count': data['old_count'],
        'breached_count': data['breached_count'],
        'evolution': [
            {'date': s.recorded_at.strftime('%d/%m'), 'score': s.score}
            for s in snapshots
        ]
    })
```

- [ ] **Step 2: Commit**

```bash
git add routes/api.py
git commit -m "adiciona endpoint /api/security-score com dados de evolucao"
```

---

### Task 10: Create security dashboard template

**Files:**
- Create: `templates/security_dashboard.html`

- [ ] **Step 1: Create the template**

Create `templates/security_dashboard.html`:

```html
{% extends 'base.html' %}
{% block title %}Seguranca — Keyflow{% endblock %}

{% block content %}
<div class="page-header">
    <h1><svg class="icon" style="margin-right:0.5rem"><use href="#icon-shield-check"/></svg> Painel de Seguranca</h1>
    <p class="text-muted">Visao consolidada da postura de seguranca da organizacao {{ org.name }}.</p>
</div>

{# ── Bloco 1: Score Geral ────────────────────────────────── #}
<section class="security-score-section">
    <div class="score-main">
        <div class="score-circle score-{{ 'green' if score > 80 else ('yellow' if score >= 50 else 'red') }}">
            <span class="score-value">{{ score }}</span>
            <span class="score-label">/ 100</span>
        </div>
    </div>
    <div class="score-cards">
        <div class="mini-card mini-card-weak">
            <span class="mini-card-count">{{ weak_count }}</span>
            <span class="mini-card-label">Fracas</span>
        </div>
        <div class="mini-card mini-card-reused">
            <span class="mini-card-count">{{ reused_count }}</span>
            <span class="mini-card-label">Reutilizadas</span>
        </div>
        <div class="mini-card mini-card-old">
            <span class="mini-card-count">{{ old_count }}</span>
            <span class="mini-card-label">Expiradas</span>
        </div>
        <div class="mini-card mini-card-breached">
            <span class="mini-card-count">{{ breached_count }}</span>
            <span class="mini-card-label">Vazadas</span>
        </div>
    </div>
</section>

{# Grafico de evolucao #}
<section class="card" style="margin-top:1.5rem;">
    <h2>Evolucao do Score (30 dias)</h2>
    {% if snapshots|length > 1 %}
    <canvas id="scoreChart" height="80"></canvas>
    {% else %}
    <p class="text-muted">Dados insuficientes para exibir o grafico. Continue acessando esta pagina para acumular historico.</p>
    {% endif %}
</section>

{# ── Bloco 2: Lista de Problemas ─────────────────────────── #}
<section class="card" style="margin-top:1.5rem;">
    <div class="card-header-flex">
        <h2>Credenciais com Problemas</h2>
        {% if breach_in_progress %}
        <span class="badge badge-warning">
            <svg class="icon icon-sm spin"><use href="#icon-loader"/></svg>
            Verificacao de vazamentos em andamento...
        </span>
        {% endif %}
    </div>

    {% if problems %}
    <div class="problems-filters" style="margin-bottom:1rem;">
        <button class="btn btn-sm btn-outline filter-btn active" data-filter="all">Todos</button>
        <button class="btn btn-sm btn-outline filter-btn" data-filter="breached">Vazadas</button>
        <button class="btn btn-sm btn-outline filter-btn" data-filter="reused">Reutilizadas</button>
        <button class="btn btn-sm btn-outline filter-btn" data-filter="too_short">Fracas</button>
        <button class="btn btn-sm btn-outline filter-btn" data-filter="expired">Expiradas</button>
    </div>
    <div class="table-responsive">
        <table class="table">
            <thead>
                <tr>
                    <th>Servico</th>
                    <th>Categoria</th>
                    <th>Problemas</th>
                    <th>Criada em</th>
                </tr>
            </thead>
            <tbody>
                {% for p in problems %}
                <tr class="problem-row" data-issues="{{ p.issues|join(',') }}">
                    <td><strong>{{ p.name }}</strong></td>
                    <td>{{ p.category }}</td>
                    <td>
                        {% for issue in p.issues %}
                        <span class="badge badge-{{ 'danger' if issue == 'breached' else ('warning' if issue in ['reused', 'too_short'] else 'info') }}">
                            {% if issue == 'breached' %}vazada
                            {% elif issue == 'reused' %}reutilizada
                            {% elif issue == 'too_short' %}curta
                            {% elif issue == 'expired' %}expirada
                            {% elif issue == 'missing_uppercase' %}sem maiuscula
                            {% elif issue == 'missing_numbers' %}sem numero
                            {% elif issue == 'missing_special' %}sem especial
                            {% else %}{{ issue }}
                            {% endif %}
                        </span>
                        {% endfor %}
                    </td>
                    <td>{{ p.created_at }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% else %}
    <p class="text-muted">Nenhum problema encontrado. Todas as credenciais estao em conformidade!</p>
    {% endif %}
</section>

{# ── Bloco 3: Politicas ──────────────────────────────────── #}
<section class="card" style="margin-top:1.5rem;">
    <div class="card-header-flex">
        <h2>Politicas de Senha</h2>
        <div>
            <button class="btn btn-sm btn-primary" onclick="document.getElementById('modal-new-policy').classList.add('active')">Nova Categoria</button>
            <form method="POST" action="{{ url_for('org.policy_restore_defaults') }}" style="display:inline;">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button type="submit" class="btn btn-sm btn-outline" onclick="return confirm('Restaurar todas as politicas para os padroes?')">Restaurar Padroes</button>
            </form>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table">
            <thead>
                <tr>
                    <th>Categoria</th>
                    <th>Min. Chars</th>
                    <th>Maiusculas</th>
                    <th>Numeros</th>
                    <th>Especiais</th>
                    <th>Rotacao (dias)</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                {% for policy in policies %}
                <tr>
                    <td><strong>{{ policy.category }}</strong></td>
                    <td>{{ policy.min_length }}</td>
                    <td>{{ 'Sim' if policy.require_uppercase else 'Nao' }}</td>
                    <td>{{ 'Sim' if policy.require_numbers else 'Nao' }}</td>
                    <td>{{ 'Sim' if policy.require_special else 'Nao' }}</td>
                    <td>{{ policy.max_age_days }}</td>
                    <td>
                        <button class="btn btn-sm btn-outline" onclick="openEditPolicy({{ policy.id }}, '{{ policy.category }}', {{ policy.min_length }}, {{ policy.require_uppercase|lower }}, {{ policy.require_numbers|lower }}, {{ policy.require_special|lower }}, {{ policy.max_age_days }})">Editar</button>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</section>

{# ── Modal: Editar Politica ──────────────────────────────── #}
<div class="modal-overlay" id="modal-edit-policy">
    <div class="modal">
        <div class="modal-header">
            <h3>Editar Politica: <span id="edit-policy-cat"></span></h3>
            <button class="modal-close" onclick="document.getElementById('modal-edit-policy').classList.remove('active')">&times;</button>
        </div>
        <form method="POST" id="edit-policy-form">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
                <label>Comprimento minimo</label>
                <input type="number" name="min_length" id="edit-min-length" min="1" max="128" class="form-control">
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="require_uppercase" id="edit-uppercase"> Exigir maiusculas</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="require_numbers" id="edit-numbers"> Exigir numeros</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="require_special" id="edit-special"> Exigir caracteres especiais</label>
            </div>
            <div class="form-group">
                <label>Rotacao (dias)</label>
                <input type="number" name="max_age_days" id="edit-max-age" min="1" max="9999" class="form-control">
            </div>
            <button type="submit" class="btn btn-primary">Salvar</button>
        </form>
    </div>
</div>

{# ── Modal: Nova Politica ────────────────────────────────── #}
<div class="modal-overlay" id="modal-new-policy">
    <div class="modal">
        <div class="modal-header">
            <h3>Nova Politica</h3>
            <button class="modal-close" onclick="document.getElementById('modal-new-policy').classList.remove('active')">&times;</button>
        </div>
        <form method="POST" action="{{ url_for('org.policy_new') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
                <label>Nome da categoria (slug)</label>
                <input type="text" name="category" class="form-control" required placeholder="ex: vpn">
            </div>
            <div class="form-group">
                <label>Comprimento minimo</label>
                <input type="number" name="min_length" value="8" min="1" max="128" class="form-control">
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="require_uppercase" checked> Exigir maiusculas</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="require_numbers" checked> Exigir numeros</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="require_special"> Exigir caracteres especiais</label>
            </div>
            <div class="form-group">
                <label>Rotacao (dias)</label>
                <input type="number" name="max_age_days" value="365" min="1" max="9999" class="form-control">
            </div>
            <button type="submit" class="btn btn-primary">Criar</button>
        </form>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script>
// ── Grafico de evolucao ──
{% if snapshots|length > 1 %}
const ctx = document.getElementById('scoreChart').getContext('2d');
new Chart(ctx, {
    type: 'line',
    data: {
        labels: [{% for s in snapshots %}'{{ s.recorded_at.strftime("%d/%m") }}'{% if not loop.last %},{% endif %}{% endfor %}],
        datasets: [{
            label: 'Score',
            data: [{% for s in snapshots %}{{ s.score }}{% if not loop.last %},{% endif %}{% endfor %}],
            borderColor: '#ea580c',
            backgroundColor: 'rgba(234,88,12,0.1)',
            fill: true,
            tension: 0.3
        }]
    },
    options: {
        responsive: true,
        scales: { y: { min: 0, max: 100 } },
        plugins: { legend: { display: false } }
    }
});
{% endif %}

// ── Filtros de problemas ──
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const filter = btn.dataset.filter;
        document.querySelectorAll('.problem-row').forEach(row => {
            if (filter === 'all') {
                row.style.display = '';
            } else {
                row.style.display = row.dataset.issues.includes(filter) ? '' : 'none';
            }
        });
    });
});

// ── Modal editar politica ──
function openEditPolicy(id, category, minLen, upper, numbers, special, maxAge) {
    document.getElementById('edit-policy-cat').textContent = category;
    document.getElementById('edit-policy-form').action = `/dashboard/security/policy/${id}/edit`;
    document.getElementById('edit-min-length').value = minLen;
    document.getElementById('edit-uppercase').checked = upper;
    document.getElementById('edit-numbers').checked = numbers;
    document.getElementById('edit-special').checked = special;
    document.getElementById('edit-max-age').value = maxAge;
    document.getElementById('modal-edit-policy').classList.add('active');
}
</script>
{% endblock %}
```

- [ ] **Step 2: Verify the template renders without syntax errors**

Run: `python -c "from app import app; client = app.test_client(); print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add templates/security_dashboard.html
git commit -m "cria template do dashboard de seguranca com score, problemas e politicas"
```

---

### Task 11: Add `#icon-loader` SVG symbol to icons.html

**Files:**
- Modify: `templates/icons.html`

- [ ] **Step 1: Add loader icon symbol**

Add inside the `<svg>` defs block in `templates/icons.html`, alongside the other symbols:

```html
    <symbol id="icon-loader" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="12" y1="2" x2="12" y2="6"/>
        <line x1="12" y1="18" x2="12" y2="22"/>
        <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/>
        <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/>
        <line x1="2" y1="12" x2="6" y2="12"/>
        <line x1="18" y1="12" x2="22" y2="12"/>
        <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/>
        <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>
    </symbol>
```

- [ ] **Step 2: Commit**

```bash
git add templates/icons.html
git commit -m "adiciona icone loader em icons.html"
```

---

### Task 12: Add navigation link for admins

**Files:**
- Modify: `templates/base.html:28-41`

- [ ] **Step 1: Add "Seguranca" link in navbar**

In `templates/base.html`, after the Logs nav link (line 39), add:

```html
                {% if current_user.role == 'admin' %}
                <a href="{{ url_for('org.security_dashboard') }}" class="nav-link {% if request.endpoint == 'org.security_dashboard' %}active{% endif %}" role="menuitem">
                    <svg class="icon icon-nav"><use href="#icon-shield-check"/></svg> Seguranca
                </a>
                {% endif %}
```

- [ ] **Step 2: Commit**

```bash
git add templates/base.html
git commit -m "adiciona link Seguranca na navbar para admins"
```

---

### Task 13: Add CSS styles for security dashboard

**Files:**
- Modify: `static/style.css`

- [ ] **Step 1: Add security dashboard styles**

Append to `static/style.css`. Note: uses `var(--radius)` (10px, existing) instead of `--radius-md` (doesn't exist), and `var(--orange-500)` instead of `--primary` (doesn't exist).

```css
/* ─── Security Dashboard ────────────────────────────────── */
.security-score-section {
    display: flex;
    align-items: center;
    gap: 2rem;
    padding: 2rem;
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
}

.score-main {
    flex-shrink: 0;
}

.score-circle {
    width: 140px;
    height: 140px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border: 6px solid;
}

.score-circle.score-green { border-color: var(--green-500); background: rgba(34,197,94,0.08); }
.score-circle.score-yellow { border-color: var(--yellow-500); background: rgba(234,179,8,0.08); }
.score-circle.score-red { border-color: var(--red-500); background: rgba(239,68,68,0.08); }

.score-value {
    font-size: 2.5rem;
    font-weight: 800;
    line-height: 1;
}

.score-green .score-value { color: var(--green-500); }
.score-yellow .score-value { color: var(--yellow-500); }
.score-red .score-value { color: var(--red-500); }

.score-label {
    font-size: 0.85rem;
    color: var(--text-muted);
    font-weight: 500;
}

.score-cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    flex: 1;
}

.mini-card {
    padding: 1rem;
    border-radius: var(--radius);
    text-align: center;
    background: var(--bg-card);
    border: 1px solid var(--border);
}

.mini-card-count {
    display: block;
    font-size: 1.75rem;
    font-weight: 800;
    line-height: 1.2;
}

.mini-card-label {
    display: block;
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-top: 0.25rem;
}

.mini-card-weak .mini-card-count { color: var(--yellow-500); }
.mini-card-reused .mini-card-count { color: var(--orange-500); }
.mini-card-old .mini-card-count { color: var(--text-muted); }
.mini-card-breached .mini-card-count { color: var(--red-500); }

.card-header-flex {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 1rem;
}

.card-header-flex h2 { margin: 0; }

/* Badge variants for security issues */
.badge-danger {
    background: rgba(239,68,68,0.15);
    color: var(--red-500);
}

.badge-warning {
    background: rgba(234,179,8,0.15);
    color: #ca8a04;
}

.badge-info {
    background: rgba(59,130,246,0.15);
    color: #2563eb;
}

/* Problems filter buttons */
.problems-filters {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
}

.filter-btn.active {
    background: var(--orange-500);
    color: white;
    border-color: var(--orange-500);
}

/* Table responsive wrapper */
.table-responsive {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
}

/* Modal overlay and content */
.modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.5);
    z-index: 1000;
    align-items: center;
    justify-content: center;
}

.modal-overlay.active {
    display: flex;
}

.modal {
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    padding: 2rem;
    width: 90%;
    max-width: 480px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
}

.modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.5rem;
}

.modal-header h3 { margin: 0; }

.modal-close {
    background: none;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
    color: var(--text-muted);
    padding: 0.25rem 0.5rem;
}

.modal-close:hover { color: var(--text-primary); }

/* Spinner animation for loader icon */
@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

.spin {
    animation: spin 1.2s linear infinite;
}

@media (max-width: 768px) {
    .security-score-section {
        flex-direction: column;
        text-align: center;
    }
    .score-cards {
        grid-template-columns: repeat(2, 1fr);
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add static/style.css
git commit -m "adiciona estilos do dashboard de seguranca"
```

---

### Task 14: Manual smoke test

- [ ] **Step 1: Start the app**

Run: `python app.py`

- [ ] **Step 2: Register as admin or login with existing admin account**

- [ ] **Step 3: Navigate to `/dashboard/security`**

Verify:
- Score circle displays with correct color
- Mini-cards show counts
- Problems table lists credentials with violations (if any)
- Policies table shows 7 default categories
- "Editar" opens modal and saves changes
- "Nova Categoria" creates a new policy
- "Restaurar Padroes" resets all policies
- Filter buttons toggle visibility of problem rows
- Nav link "Seguranca" appears only for admin users

- [ ] **Step 4: Verify breach check triggered on login**

Log out and log back in. Check the `breach_results` table has entries being populated.

- [ ] **Step 5: Final commit if any fixes needed**

```bash
git add -A
git commit -m "ajustes finais no dashboard de seguranca"
```
