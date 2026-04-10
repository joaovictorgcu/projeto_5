import base64
import csv
import io
import threading

import bcrypt
import pyotp
import qrcode
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response, current_app
from flask_login import login_required, current_user

from models import db, User, Organization, Credential, CredentialPermission, AccessLog
from crypto_utils import encrypt_password, decrypt_password
from datetime import datetime, timezone

org = Blueprint('org', __name__)


# ─── Landing ────────────────────────────────────────────────────
@org.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('org.dashboard'))
    return render_template('landing.html')


# ─── Dashboard ──────────────────────────────────────────────────
@org.route('/dashboard')
@login_required
def dashboard():
    organization = current_user.organization
    if not organization:
        flash('Você não pertence a nenhuma organização.', 'error')
        return redirect(url_for('org.landing'))

    total_credentials = Credential.query.filter_by(org_id=organization.id).count()
    total_members = User.query.filter_by(org_id=organization.id, is_active_member=True).count()
    recent_logs = (AccessLog.query
                   .join(User).join(Credential)
                   .filter(Credential.org_id == organization.id)
                   .order_by(AccessLog.accessed_at.desc())
                   .limit(10)
                   .all())
    members = User.query.filter_by(org_id=organization.id).order_by(User.created_at).all()

    return render_template('dashboard.html',
                           org=organization,
                           total_credentials=total_credentials,
                           total_members=total_members,
                           recent_logs=recent_logs,
                           members=members)


# ─── Segurança ─────────────────────────────────────────────────
@org.route('/dashboard/security')
@login_required
def security_dashboard():
    if current_user.role != 'admin':
        flash('Apenas administradores podem acessar o painel de segurança.', 'error')
        return redirect(url_for('vault.index'))

    organization = current_user.organization
    if not organization:
        flash('Você não pertence a nenhuma organização.', 'error')
        return redirect(url_for('org.landing'))

    from security import ensure_default_policies, calculate_security_score, maybe_save_snapshot
    from models import PasswordPolicy, SecurityScore, BreachResult

    ensure_default_policies(organization.id)
    score_data = calculate_security_score(organization.id)
    maybe_save_snapshot(organization.id)

    policies = PasswordPolicy.query.filter_by(org_id=organization.id).order_by(PasswordPolicy.category).all()

    from datetime import timedelta
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    snapshots = (SecurityScore.query
                 .filter_by(org_id=organization.id)
                 .filter(SecurityScore.recorded_at >= thirty_days_ago)
                 .order_by(SecurityScore.recorded_at)
                 .all())

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

    try:
        min_len = max(4, min(128, int(request.form.get('min_length', 8))))
        max_age = max(1, min(3650, int(request.form.get('max_age_days', 365))))
    except (ValueError, TypeError):
        flash('Valores inválidos.', 'error')
        return redirect(url_for('org.security_dashboard'))

    policy.min_length = min_len
    policy.require_uppercase = request.form.get('require_uppercase') == 'on'
    policy.require_numbers = request.form.get('require_numbers') == 'on'
    policy.require_special = request.form.get('require_special') == 'on'
    policy.max_age_days = max_age
    policy.is_default = False

    db.session.commit()
    flash('Política atualizada.', 'success')
    return redirect(url_for('org.security_dashboard'))


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
        flash('Já existe uma política para essa categoria.', 'error')
        return redirect(url_for('org.security_dashboard'))

    try:
        min_len = max(4, min(128, int(request.form.get('min_length', 8))))
        max_age = max(1, min(3650, int(request.form.get('max_age_days', 365))))
    except (ValueError, TypeError):
        flash('Valores inválidos.', 'error')
        return redirect(url_for('org.security_dashboard'))

    policy = PasswordPolicy(
        org_id=current_user.org_id,
        category=category,
        min_length=min_len,
        require_uppercase=request.form.get('require_uppercase') == 'on',
        require_numbers=request.form.get('require_numbers') == 'on',
        require_special=request.form.get('require_special') == 'on',
        max_age_days=max_age,
        is_default=False
    )
    db.session.add(policy)
    db.session.commit()
    flash('Nova política criada.', 'success')
    return redirect(url_for('org.security_dashboard'))


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
    flash('Políticas restauradas para os padrões.', 'success')
    return redirect(url_for('org.security_dashboard'))


# ─── Membros ────────────────────────────────────────────────────
@org.route('/members')
@login_required
def members():
    organization = current_user.organization
    if not organization:
        return redirect(url_for('org.dashboard'))
    all_members = User.query.filter_by(org_id=organization.id).order_by(User.created_at).all()
    return render_template('members.html', members=all_members, org=organization)


@org.route('/members/<int:user_id>/remove', methods=['POST'])
@login_required
def member_remove(user_id):
    if current_user.role != 'admin':
        flash('Apenas administradores podem remover membros.', 'error')
        return redirect(url_for('org.members'))

    member = User.query.get_or_404(user_id)
    if member.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('org.members'))

    if member.id == current_user.id:
        flash('Você não pode remover a si mesmo.', 'error')
        return redirect(url_for('org.members'))

    member.is_active_member = False
    db.session.commit()
    flash(f'{member.name} foi removido da organização.', 'success')
    return redirect(url_for('org.members'))


@org.route('/members/<int:user_id>/reactivate', methods=['POST'])
@login_required
def member_reactivate(user_id):
    if current_user.role != 'admin':
        flash('Apenas administradores podem reativar membros.', 'error')
        return redirect(url_for('org.members'))

    member = User.query.get_or_404(user_id)
    if member.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('org.members'))

    member.is_active_member = True
    db.session.commit()
    flash(f'{member.name} foi reativado.', 'success')
    return redirect(url_for('org.members'))


@org.route('/members/invite-email', methods=['POST'])
@login_required
def invite_email():
    from flask_mail import Message
    from app import mail

    email_to = request.form.get('email', '').strip().lower()
    if not email_to:
        flash('Informe o e-mail para enviar o convite.', 'error')
        return redirect(url_for('org.members'))

    organization = current_user.organization
    if not organization:
        flash('Você não pertence a uma organização.', 'error')
        return redirect(url_for('org.members'))

    msg = Message(
        subject=f'Você foi convidado para {organization.name} no Keyflow',
        recipients=[email_to]
    )
    msg.html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:2rem;">
        <h1 style="color:#ea580c;font-size:1.5rem;">Keyflow</h1>
        <h2 style="color:#292524;">Você foi convidado!</h2>
        <p style="color:#57534e;">{current_user.name} convidou você para a organização <strong>{organization.name}</strong> no Keyflow.</p>
        <p style="color:#57534e;">Use o código de convite abaixo para se cadastrar:</p>
        <div style="background:#fff7ed;border:2px dashed #fdba74;border-radius:8px;padding:1rem;text-align:center;margin:1.5rem 0;">
            <span style="font-size:1.5rem;font-weight:800;color:#ea580c;letter-spacing:3px;">{organization.invite_code}</span>
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

    thread = threading.Thread(
        target=send_async,
        args=(current_app._get_current_object().app_context(), msg)
    )
    thread.start()

    flash(f'Convite enviado para {email_to}!', 'success')
    return redirect(url_for('org.members'))


# ─── Logs ───────────────────────────────────────────────────────
@org.route('/logs')
@login_required
def logs():
    organization = current_user.organization
    if not organization:
        return redirect(url_for('org.dashboard'))

    all_logs = (AccessLog.query
                .join(User).join(Credential)
                .filter(Credential.org_id == organization.id)
                .order_by(AccessLog.accessed_at.desc())
                .limit(200)
                .all())
    return render_template('logs.html', logs=all_logs)


@org.route('/logs/export')
@login_required
def logs_export():
    organization = current_user.organization
    if not organization:
        return redirect(url_for('org.dashboard'))

    all_logs = (AccessLog.query
                .join(User).join(Credential)
                .filter(Credential.org_id == organization.id)
                .order_by(AccessLog.accessed_at.desc())
                .all())

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Data/Hora', 'Usuário', 'E-mail', 'Credencial', 'Ação'])

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


@org.route('/logs/export-pdf')
@login_required
def logs_export_pdf():
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from datetime import timedelta

    organization = current_user.organization
    if not organization:
        return redirect(url_for('org.dashboard'))

    days = int(request.args.get('days', 30))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    all_logs = (AccessLog.query
                .join(User).join(Credential)
                .filter(Credential.org_id == organization.id,
                        AccessLog.accessed_at >= since)
                .order_by(AccessLog.accessed_at.desc())
                .all())

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                  fontSize=18, textColor=colors.HexColor('#ea580c'))
    subtitle_style = ParagraphStyle('CustomSub', parent=styles['Normal'],
                                     fontSize=10, textColor=colors.grey)

    elements = []
    elements.append(Paragraph('Keyflow — Relatório de Auditoria', title_style))
    elements.append(Paragraph(f'Organização: {organization.name}', subtitle_style))
    elements.append(Paragraph(
        f'Período: últimos {days} dias | Gerado em: {datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M")} UTC',
        subtitle_style))
    elements.append(Spacer(1, 0.5 * cm))

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
        ['Total de membros', str(User.query.filter_by(org_id=organization.id, is_active_member=True).count())],
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
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fafaf9')))
    log_table.setStyle(TableStyle(style_cmds))
    elements.append(log_table)

    elements.append(Spacer(1, 1 * cm))
    footer_style = ParagraphStyle('CustomFooter', parent=styles['Normal'],
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


# ─── Perfil ─────────────────────────────────────────────────────
@org.route('/profile', methods=['GET', 'POST'])
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

        return redirect(url_for('org.profile'))

    return render_template('profile.html')


# ─── MFA Setup ──────────────────────────────────────────────────
@org.route('/profile/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        secret = session.get('mfa_setup_secret')

        if not secret:
            flash('Sessão expirada. Tente novamente.', 'error')
            return redirect(url_for('org.mfa_setup'))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            current_user.totp_secret = encrypt_password(secret)
            current_user.mfa_enabled = True
            db.session.commit()
            session.pop('mfa_setup_secret', None)
            flash('Autenticação de dois fatores ativada com sucesso!', 'success')
            return redirect(url_for('org.profile'))

        flash('Código inválido. Escaneie o QR Code e tente novamente.', 'error')

    secret = pyotp.random_base32()
    session['mfa_setup_secret'] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name='Keyflow')

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template('mfa_setup.html', qr_code=qr_b64, secret=secret)


@org.route('/profile/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    code = request.form.get('code', '').strip()

    if current_user.totp_secret:
        try:
            secret = decrypt_password(current_user.totp_secret)
        except Exception:
            flash('Erro ao desativar MFA.', 'error')
            return redirect(url_for('org.profile'))

        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            flash('Código inválido. MFA não foi desativado.', 'error')
            return redirect(url_for('org.profile'))

    current_user.mfa_enabled = False
    current_user.totp_secret = None
    db.session.commit()
    flash('Autenticação de dois fatores desativada.', 'success')
    return redirect(url_for('org.profile'))
