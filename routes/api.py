import time
from datetime import datetime, timezone, timedelta

from flask import Blueprint, jsonify
from flask_login import login_required, current_user

from sqlalchemy.orm import joinedload
from models import db, User, Credential, AccessLog
from crypto_utils import decrypt_password
from security import _check_breach_for_password

api = Blueprint('api', __name__)


@api.route('/api/health-score')
@login_required
def health_score():
    org = current_user.organization
    if not org:
        return jsonify({'score': 0, 'issues': []})

    credentials = Credential.query.filter_by(org_id=org.id).all()
    if not credentials:
        return jsonify({'score': 100, 'issues': [], 'total': 0})

    issues = []
    total_score = 100
    passwords = []

    for cred in credentials:
        try:
            pw = decrypt_password(cred.encrypted_password)
        except Exception:
            continue
        passwords.append((cred.name, pw))

        if len(pw) < 8:
            issues.append({'type': 'weak', 'message': f'{cred.name}: senha com menos de 8 caracteres'})
            total_score -= 10
        elif len(pw) < 12:
            total_score -= 3

        has_upper = any(c.isupper() for c in pw)
        has_lower = any(c.islower() for c in pw)
        has_digit = any(c.isdigit() for c in pw)
        has_symbol = any(not c.isalnum() for c in pw)
        complexity = sum([has_upper, has_lower, has_digit, has_symbol])
        if complexity < 3:
            issues.append({'type': 'simple', 'message': f'{cred.name}: senha pouco complexa'})
            total_score -= 5

    pw_values = [pw for _, pw in passwords]
    seen = set()
    duplicates = set()
    for pw in pw_values:
        if pw in seen:
            duplicates.add(pw)
        seen.add(pw)

    if duplicates:
        dup_names = [name for name, pw in passwords if pw in duplicates]
        issues.append({'type': 'duplicate', 'message': f'Senhas repetidas em: {", ".join(dup_names)}'})
        total_score -= 15 * len(duplicates)

    total_score = max(0, min(100, total_score))

    return jsonify({
        'score': total_score,
        'issues': issues[:10],
        'total': len(credentials)
    })


@api.route('/api/dashboard-stats')
@login_required
def dashboard_stats():
    org = current_user.organization
    if not org:
        return jsonify({})

    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    logs_7d = (AccessLog.query
               .join(Credential)
               .filter(Credential.org_id == org.id,
                       AccessLog.accessed_at >= seven_days_ago)
               .all())

    daily = {}
    for i in range(7):
        day = (now - timedelta(days=6 - i)).strftime('%d/%m')
        daily[day] = 0
    for log in logs_7d:
        day_key = log.accessed_at.strftime('%d/%m')
        if day_key in daily:
            daily[day_key] += 1

    all_logs = (AccessLog.query
                .join(Credential)
                .options(joinedload(AccessLog.credential))
                .filter(Credential.org_id == org.id)
                .all())
    actions = {}
    for log in all_logs:
        actions[log.action] = actions.get(log.action, 0) + 1

    cred_counts = {}
    cred_names = {}
    for log in all_logs:
        cred_counts[log.credential_id] = cred_counts.get(log.credential_id, 0) + 1
        if log.credential_id not in cred_names:
            cred_names[log.credential_id] = log.credential.name if log.credential else '?'
    top_ids = sorted(cred_counts, key=cred_counts.get, reverse=True)[:5]
    top_creds = [{'name': cred_names.get(cid, '?'), 'count': cred_counts[cid]} for cid in top_ids]

    return jsonify({
        'daily_access': [{'date': d, 'count': c} for d, c in daily.items()],
        'actions_breakdown': actions,
        'top_credentials': top_creds
    })


@api.route('/api/check-breaches')
@login_required
def check_breaches():
    org = current_user.organization
    if not org:
        return jsonify({'total_checked': 0, 'breached': 0, 'results': []})

    credentials = Credential.query.filter_by(org_id=org.id).all()
    results = []

    for cred in credentials:
        try:
            pw = decrypt_password(cred.encrypted_password)
        except Exception:
            continue

        is_breached, count = _check_breach_for_password(pw)
        if is_breached:
            results.append({
                'credential_name': cred.name,
                'breach_count': count
            })
        time.sleep(0.2)

    return jsonify({
        'total_checked': len(credentials),
        'breached': len(results),
        'results': results
    })


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
