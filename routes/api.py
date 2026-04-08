import hashlib
import time
import urllib.request
from datetime import datetime, timezone, timedelta

from flask import Blueprint, jsonify
from flask_login import login_required, current_user

from models import db, User, Credential, AccessLog
from crypto_utils import decrypt_password

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
                .filter(Credential.org_id == org.id)
                .all())
    actions = {}
    for log in all_logs:
        actions[log.action] = actions.get(log.action, 0) + 1

    cred_counts = {}
    for log in all_logs:
        cred_counts[log.credential_id] = cred_counts.get(log.credential_id, 0) + 1
    top_ids = sorted(cred_counts, key=cred_counts.get, reverse=True)[:5]
    top_creds = []
    for cid in top_ids:
        cred = Credential.query.get(cid)
        if cred:
            top_creds.append({'name': cred.name, 'count': cred_counts[cid]})

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

        sha1 = hashlib.sha1(pw.encode('utf-8')).hexdigest().upper()
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
                    results.append({
                        'credential_name': cred.name,
                        'breach_count': int(count)
                    })
                    break

            time.sleep(0.2)
        except Exception:
            continue

    return jsonify({
        'total_checked': len(credentials),
        'breached': len(results),
        'results': results
    })
