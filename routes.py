import base64
import csv
import hashlib
import io
import time
import uuid
import urllib.request
from datetime import datetime, timezone

import bcrypt
import pyotp
import qrcode
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, session
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User, Organization, Credential, CredentialPermission, AccessLog
from crypto_utils import encrypt_password, decrypt_password

main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)


# ─── Landing ────────────────────────────────────────────────────
@main.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('landing.html')


# ─── Auth ───────────────────────────────────────────────────────
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        org_name = request.form.get('org_name', '').strip()
        invite_code = request.form.get('invite_code', '').strip()

        if not name or not email or not password:
            flash('Preencha todos os campos obrigatórios.', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('A senha deve ter pelo menos 6 caracteres.', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Este e-mail já está cadastrado.', 'error')
            return render_template('register.html')

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        if invite_code:
            org = Organization.query.filter_by(invite_code=invite_code).first()
            if not org:
                flash('Código de convite inválido.', 'error')
                return render_template('register.html')
            user = User(name=name, email=email, password_hash=pw_hash,
                        org_id=org.id, role='member')
        else:
            if not org_name:
                flash('Informe o nome da organização ou um código de convite.', 'error')
                return render_template('register.html')
            org = Organization(name=org_name, invite_code=str(uuid.uuid4())[:8])
            db.session.add(org)
            db.session.flush()
            user = User(name=name, email=email, password_hash=pw_hash,
                        org_id=org.id, role='admin')

        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Conta criada com sucesso!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('register.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            if not user.is_active_member:
                flash('Sua conta foi desativada. Contate o administrador.', 'error')
                return render_template('login.html')

            # Se MFA ativado, redirecionar para verificação
            if user.mfa_enabled and user.totp_secret:
                session['mfa_user_id'] = user.id
                return redirect(url_for('auth.login_mfa'))

            login_user(user)
            return redirect(url_for('main.dashboard'))

        flash('E-mail ou senha incorretos.', 'error')

    return render_template('login.html')


@auth.route('/login/mfa', methods=['GET', 'POST'])
def login_mfa():
    user_id = session.get('mfa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        user = User.query.get(user_id)

        if user and user.totp_secret:
            try:
                secret = decrypt_password(user.totp_secret)
            except Exception:
                flash('Erro interno. Tente novamente.', 'error')
                return render_template('mfa_verify.html')

            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):
                session.pop('mfa_user_id', None)
                login_user(user)
                return redirect(url_for('main.dashboard'))

        flash('Código inválido. Tente novamente.', 'error')
        return render_template('mfa_verify.html')

    return render_template('mfa_verify.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('mfa_user_id', None)
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('main.landing'))


# ─── Dashboard ──────────────────────────────────────────────────
@main.route('/dashboard')
@login_required
def dashboard():
    org = current_user.organization
    if not org:
        flash('Você não pertence a nenhuma organização.', 'error')
        return redirect(url_for('main.landing'))

    total_credentials = Credential.query.filter_by(org_id=org.id).count()
    total_members = User.query.filter_by(org_id=org.id, is_active_member=True).count()
    recent_logs = (AccessLog.query
                   .join(User).join(Credential)
                   .filter(Credential.org_id == org.id)
                   .order_by(AccessLog.accessed_at.desc())
                   .limit(10)
                   .all())
    members = User.query.filter_by(org_id=org.id).order_by(User.created_at).all()

    return render_template('dashboard.html',
                           org=org,
                           total_credentials=total_credentials,
                           total_members=total_members,
                           recent_logs=recent_logs,
                           members=members)


# ─── Cofre (Vault) ─────────────────────────────────────────────
@main.route('/vault')
@login_required
def vault():
    org = current_user.organization
    if not org:
        return redirect(url_for('main.dashboard'))
    credentials = Credential.query.filter_by(org_id=org.id).order_by(Credential.created_at.desc()).all()
    return render_template('vault.html', credentials=credentials)


@main.route('/vault/new', methods=['GET', 'POST'])
@login_required
def credential_new():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        login_val = request.form.get('login', '').strip()
        password = request.form.get('password', '')
        notes = request.form.get('notes', '').strip()
        category = request.form.get('category', 'outros')

        if not name or not login_val or not password:
            flash('Preencha nome, login e senha.', 'error')
            return render_template('credential_form.html', editing=False)

        cred = Credential(
            org_id=current_user.org_id,
            name=name,
            login=login_val,
            encrypted_password=encrypt_password(password),
            notes=notes,
            category=category,
            created_by=current_user.id
        )
        db.session.add(cred)
        db.session.commit()

        _log_access(current_user.id, cred.id, 'criou')

        flash('Credencial salva com sucesso!', 'success')
        return redirect(url_for('main.vault'))

    return render_template('credential_form.html', editing=False)


@main.route('/vault/<int:cred_id>/edit', methods=['GET', 'POST'])
@login_required
def credential_edit(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('main.vault'))

    if request.method == 'POST':
        cred.name = request.form.get('name', '').strip()
        cred.login = request.form.get('login', '').strip()
        new_password = request.form.get('password', '')
        cred.notes = request.form.get('notes', '').strip()
        cred.category = request.form.get('category', 'outros')

        if new_password:
            cred.encrypted_password = encrypt_password(new_password)

        db.session.commit()
        _log_access(current_user.id, cred.id, 'editou')
        flash('Credencial atualizada.', 'success')
        return redirect(url_for('main.vault'))

    return render_template('credential_form.html', editing=True, cred=cred)


@main.route('/vault/<int:cred_id>/delete', methods=['POST'])
@login_required
def credential_delete(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('main.vault'))

    _log_access(current_user.id, cred.id, 'deletou')
    db.session.delete(cred)
    db.session.commit()
    flash('Credencial removida.', 'success')
    return redirect(url_for('main.vault'))


@main.route('/vault/<int:cred_id>/reveal', methods=['POST'])
@login_required
def credential_reveal(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        return jsonify({'error': 'Acesso negado'}), 403

    # Verificar permissão mascarada
    if cred.created_by != current_user.id:
        perm = CredentialPermission.query.filter_by(
            credential_id=cred.id, user_id=current_user.id
        ).first()
        if perm and not perm.can_view_password:
            return jsonify({'error': 'Você não tem permissão para ver esta senha'}), 403

    _log_access(current_user.id, cred.id, 'visualizou senha')

    try:
        plain = decrypt_password(cred.encrypted_password)
    except Exception:
        return jsonify({'error': 'Erro ao descriptografar'}), 500

    return jsonify({'password': plain})


# ─── Membros ────────────────────────────────────────────────────
@main.route('/members')
@login_required
def members():
    org = current_user.organization
    if not org:
        return redirect(url_for('main.dashboard'))
    all_members = User.query.filter_by(org_id=org.id).order_by(User.created_at).all()
    return render_template('members.html', members=all_members, org=org)


@main.route('/members/<int:user_id>/remove', methods=['POST'])
@login_required
def member_remove(user_id):
    if current_user.role != 'admin':
        flash('Apenas administradores podem remover membros.', 'error')
        return redirect(url_for('main.members'))

    member = User.query.get_or_404(user_id)
    if member.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('main.members'))

    if member.id == current_user.id:
        flash('Você não pode remover a si mesmo.', 'error')
        return redirect(url_for('main.members'))

    member.is_active_member = False
    db.session.commit()
    flash(f'{member.name} foi removido da organização.', 'success')
    return redirect(url_for('main.members'))


@main.route('/members/<int:user_id>/reactivate', methods=['POST'])
@login_required
def member_reactivate(user_id):
    if current_user.role != 'admin':
        flash('Apenas administradores podem reativar membros.', 'error')
        return redirect(url_for('main.members'))

    member = User.query.get_or_404(user_id)
    if member.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('main.members'))

    member.is_active_member = True
    db.session.commit()
    flash(f'{member.name} foi reativado.', 'success')
    return redirect(url_for('main.members'))


# ─── Permissões por credencial ──────────────────────────────────
@main.route('/vault/<int:cred_id>/permissions', methods=['GET', 'POST'])
@login_required
def credential_permissions(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('main.vault'))

    if request.method == 'POST':
        # Atualizar permissões
        members = User.query.filter_by(org_id=current_user.org_id, is_active_member=True).all()
        for member in members:
            if member.id == cred.created_by:
                continue
            perm_value = request.form.get(f'perm_{member.id}', 'none')
            perm = CredentialPermission.query.filter_by(
                credential_id=cred.id, user_id=member.id
            ).first()

            if perm_value == 'none':
                if perm:
                    db.session.delete(perm)
            else:
                if not perm:
                    perm = CredentialPermission(credential_id=cred.id, user_id=member.id)
                    db.session.add(perm)
                perm.can_view_password = (perm_value == 'view')

        db.session.commit()
        flash('Permissões atualizadas.', 'success')
        return redirect(url_for('main.vault'))

    members = User.query.filter_by(org_id=current_user.org_id, is_active_member=True).all()
    perms = {p.user_id: p for p in CredentialPermission.query.filter_by(credential_id=cred.id).all()}
    return render_template('permissions.html', cred=cred, members=members, perms=perms)


# ─── Logs ───────────────────────────────────────────────────────
@main.route('/logs')
@login_required
def logs():
    org = current_user.organization
    if not org:
        return redirect(url_for('main.dashboard'))

    all_logs = (AccessLog.query
                .join(User).join(Credential)
                .filter(Credential.org_id == org.id)
                .order_by(AccessLog.accessed_at.desc())
                .limit(200)
                .all())
    return render_template('logs.html', logs=all_logs)


# ─── MFA Setup ──────────────────────────────────────────────────
@main.route('/profile/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        secret = session.get('mfa_setup_secret')

        if not secret:
            flash('Sessão expirada. Tente novamente.', 'error')
            return redirect(url_for('main.mfa_setup'))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            current_user.totp_secret = encrypt_password(secret)
            current_user.mfa_enabled = True
            db.session.commit()
            session.pop('mfa_setup_secret', None)
            flash('Autenticação de dois fatores ativada com sucesso!', 'success')
            return redirect(url_for('main.profile'))

        flash('Código inválido. Escaneie o QR Code e tente novamente.', 'error')

    # Gerar secret e QR Code
    secret = pyotp.random_base32()
    session['mfa_setup_secret'] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name='Keyflow')

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template('mfa_setup.html', qr_code=qr_b64, secret=secret)


@main.route('/profile/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    code = request.form.get('code', '').strip()

    if current_user.totp_secret:
        try:
            secret = decrypt_password(current_user.totp_secret)
        except Exception:
            flash('Erro ao desativar MFA.', 'error')
            return redirect(url_for('main.profile'))

        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            flash('Código inválido. MFA não foi desativado.', 'error')
            return redirect(url_for('main.profile'))

    current_user.mfa_enabled = False
    current_user.totp_secret = None
    db.session.commit()
    flash('Autenticação de dois fatores desativada.', 'success')
    return redirect(url_for('main.profile'))


# ─── Dashboard Stats API ────────────────────────────────────────
@main.route('/api/dashboard-stats')
@login_required
def dashboard_stats():
    from datetime import timedelta
    org = current_user.organization
    if not org:
        return jsonify({})

    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    # Acessos por dia (últimos 7 dias)
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

    # Ações por tipo
    all_logs = (AccessLog.query
                .join(Credential)
                .filter(Credential.org_id == org.id)
                .all())
    actions = {}
    for log in all_logs:
        action = log.action
        actions[action] = actions.get(action, 0) + 1

    # Top 5 credenciais mais acessadas
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


# ─── Perfil ─────────────────────────────────────────────────────
@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')

        if name and name != current_user.name:
            current_user.name = name
            db.session.commit()
            flash('Nome atualizado.', 'success')

        if new_pw:
            if not bcrypt.checkpw(current_pw.encode(), current_user.password_hash.encode()):
                flash('Senha atual incorreta.', 'error')
                return render_template('profile.html')
            if len(new_pw) < 6:
                flash('A nova senha deve ter pelo menos 6 caracteres.', 'error')
                return render_template('profile.html')
            current_user.password_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            db.session.commit()
            flash('Senha alterada com sucesso.', 'success')

        return redirect(url_for('main.profile'))

    return render_template('profile.html')


# ─── Health Score ───────────────────────────────────────────────
@main.route('/api/health-score')
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

        # Verificar senha fraca
        if len(pw) < 8:
            issues.append({'type': 'weak', 'message': f'{cred.name}: senha com menos de 8 caracteres'})
            total_score -= 10
        elif len(pw) < 12:
            total_score -= 3

        # Verificar complexidade
        has_upper = any(c.isupper() for c in pw)
        has_lower = any(c.islower() for c in pw)
        has_digit = any(c.isdigit() for c in pw)
        has_symbol = any(not c.isalnum() for c in pw)
        complexity = sum([has_upper, has_lower, has_digit, has_symbol])
        if complexity < 3:
            issues.append({'type': 'simple', 'message': f'{cred.name}: senha pouco complexa'})
            total_score -= 5

    # Verificar senhas repetidas
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


# ─── Verificar Vazamentos (HaveIBeenPwned) ─────────────────────
@main.route('/api/check-breaches')
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

        # k-Anonymity: SHA-1 hash, enviar só os 5 primeiros chars
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

            time.sleep(0.2)  # Respeitar rate limit
        except Exception:
            continue

    return jsonify({
        'total_checked': len(credentials),
        'breached': len(results),
        'results': results
    })


# ─── Exportar Logs CSV ─────────────────────────────────────────
@main.route('/logs/export')
@login_required
def logs_export():
    org = current_user.organization
    if not org:
        return redirect(url_for('main.dashboard'))

    all_logs = (AccessLog.query
                .join(User).join(Credential)
                .filter(Credential.org_id == org.id)
                .order_by(AccessLog.accessed_at.desc())
                .all())

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Data/Hora', 'Usuario', 'E-mail', 'Credencial', 'Acao'])

    for log in all_logs:
        writer.writerow([
            log.accessed_at.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.name,
            log.user.email,
            log.credential.name,
            log.action
        ])

    output.seek(0)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=keyflow_logs_{timestamp}.csv'}
    )


# ─── Exportar Logs PDF ──────────────────────────────────────────
@main.route('/logs/export-pdf')
@login_required
def logs_export_pdf():
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    org = current_user.organization
    if not org:
        return redirect(url_for('main.dashboard'))

    days = int(request.args.get('days', 30))
    from datetime import timedelta
    since = datetime.now(timezone.utc) - timedelta(days=days)

    all_logs = (AccessLog.query
                .join(User).join(Credential)
                .filter(Credential.org_id == org.id,
                        AccessLog.accessed_at >= since)
                .order_by(AccessLog.accessed_at.desc())
                .all())

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('Title', parent=styles['Title'],
                                  fontSize=18, textColor=colors.HexColor('#ea580c'))
    subtitle_style = ParagraphStyle('Sub', parent=styles['Normal'],
                                     fontSize=10, textColor=colors.grey)

    elements = []

    # Cabeçalho
    elements.append(Paragraph('Keyflow — Relatório de Auditoria', title_style))
    elements.append(Paragraph(f'Organização: {org.name}', subtitle_style))
    elements.append(Paragraph(
        f'Período: últimos {days} dias | Gerado em: {datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M")} UTC',
        subtitle_style))
    elements.append(Spacer(1, 0.5 * cm))

    # Resumo
    total = len(all_logs)
    user_counts = {}
    cred_counts = {}
    for log in all_logs:
        user_counts[log.user.name] = user_counts.get(log.user.name, 0) + 1
        cred_counts[log.credential.name] = cred_counts.get(log.credential.name, 0) + 1

    most_active = max(user_counts, key=user_counts.get) if user_counts else '-'
    most_accessed = max(cred_counts, key=cred_counts.get) if cred_counts else '-'

    summary_data = [
        ['Total de acessos', str(total)],
        ['Usuário mais ativo', most_active],
        ['Credencial mais acessada', most_accessed],
        ['Total de membros', str(User.query.filter_by(org_id=org.id, is_active_member=True).count())],
    ]
    summary_table = Table(summary_data, colWidths=[8 * cm, 8 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#fff7ed')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e7e5e4')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.75 * cm))

    # Tabela de logs
    elements.append(Paragraph('Registro de acessos', styles['Heading2']))
    elements.append(Spacer(1, 0.25 * cm))

    table_data = [['Data/Hora', 'Usuário', 'E-mail', 'Credencial', 'Ação']]
    for log in all_logs[:500]:
        table_data.append([
            log.accessed_at.strftime('%d/%m/%Y %H:%M'),
            log.user.name,
            log.user.email,
            log.credential.name,
            log.action
        ])

    log_table = Table(table_data, colWidths=[3.2 * cm, 3.2 * cm, 4 * cm, 3.2 * cm, 2.8 * cm])
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ea580c')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e7e5e4')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]
    # Zebra striping
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fafaf9')))
    log_table.setStyle(TableStyle(style_cmds))
    elements.append(log_table)

    # Rodapé
    elements.append(Spacer(1, 1 * cm))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'],
                                   fontSize=7, textColor=colors.grey, alignment=1)
    elements.append(Paragraph(
        'Relatório gerado automaticamente pelo Keyflow — Documento para fins de auditoria — LGPD Lei 13.709/2018',
        footer_style))

    doc.build(elements)
    buffer.seek(0)

    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename=keyflow_relatorio_{timestamp}.pdf'}
    )


# ─── Busca no Cofre ────────────────────────────────────────────
@main.route('/vault/search')
@login_required
def vault_search():
    query = request.args.get('q', '').strip()
    org = current_user.organization
    if not org:
        return redirect(url_for('main.vault'))

    if query:
        credentials = Credential.query.filter(
            Credential.org_id == org.id,
            (Credential.name.ilike(f'%{query}%') | Credential.login.ilike(f'%{query}%'))
        ).order_by(Credential.created_at.desc()).all()
    else:
        credentials = Credential.query.filter_by(org_id=org.id).order_by(Credential.created_at.desc()).all()

    return render_template('vault.html', credentials=credentials, search_query=query)


# ─── Convite por E-mail ─────────────────────────────────────────
@main.route('/members/invite-email', methods=['POST'])
@login_required
def invite_email():
    import threading
    from flask_mail import Message
    from app import mail

    email_to = request.form.get('email', '').strip().lower()
    if not email_to:
        flash('Informe o e-mail para enviar o convite.', 'error')
        return redirect(url_for('main.members'))

    org = current_user.organization
    if not org:
        flash('Você não pertence a uma organização.', 'error')
        return redirect(url_for('main.members'))

    msg = Message(
        subject=f'Você foi convidado para {org.name} no Keyflow',
        recipients=[email_to]
    )
    msg.html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:2rem;">
        <h1 style="color:#ea580c;font-size:1.5rem;">Keyflow</h1>
        <h2 style="color:#292524;">Você foi convidado!</h2>
        <p style="color:#57534e;">{current_user.name} convidou você para a organização <strong>{org.name}</strong> no Keyflow.</p>
        <p style="color:#57534e;">Use o código de convite abaixo para se cadastrar:</p>
        <div style="background:#fff7ed;border:2px dashed #fdba74;border-radius:8px;padding:1rem;text-align:center;margin:1.5rem 0;">
            <span style="font-size:1.5rem;font-weight:800;color:#ea580c;letter-spacing:3px;">{org.invite_code}</span>
        </div>
        <p style="color:#78716c;font-size:0.85rem;">Se você não esperava este e-mail, pode ignorá-lo com segurança.</p>
        <hr style="border:none;border-top:1px solid #e7e5e4;margin:2rem 0;">
        <p style="color:#a8a29e;font-size:0.75rem;text-align:center;">Keyflow — Cofre de Senhas Colaborativo</p>
    </div>
    """

    def send_async(app_ctx, message):
        with app_ctx:
            try:
                mail.send(message)
            except Exception:
                pass

    from flask import current_app
    thread = threading.Thread(target=send_async, args=(current_app._get_current_object().app_context(), msg))
    thread.start()

    flash(f'Convite enviado para {email_to}!', 'success')
    return redirect(url_for('main.members'))


# ─── Helpers ────────────────────────────────────────────────────
def _log_access(user_id, credential_id, action):
    log = AccessLog(user_id=user_id, credential_id=credential_id, action=action)
    db.session.add(log)
    db.session.commit()
