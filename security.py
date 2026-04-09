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
    passwords = {}

    for cred in credentials:
        try:
            passwords[cred.id] = decrypt_password(cred.encrypted_password)
        except Exception:
            continue

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

        changed_at = cred.password_changed_at or cred.created_at
        if check_password_expired(changed_at, cred.category, org_id):
            old_count += 1
            score -= 2
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
                time.sleep(1.6)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
