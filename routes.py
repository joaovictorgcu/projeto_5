import csv
import io
import uuid
from datetime import datetime, timezone

import bcrypt
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response
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
            login_user(user)
            return redirect(url_for('main.dashboard'))

        flash('E-mail ou senha incorretos.', 'error')

    return render_template('login.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
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

        if not name or not login_val or not password:
            flash('Preencha nome, login e senha.', 'error')
            return render_template('credential_form.html', editing=False)

        cred = Credential(
            org_id=current_user.org_id,
            name=name,
            login=login_val,
            encrypted_password=encrypt_password(password),
            notes=notes,
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


# ─── Helpers ────────────────────────────────────────────────────
def _log_access(user_id, credential_id, action):
    log = AccessLog(user_id=user_id, credential_id=credential_id, action=action)
    db.session.add(log)
    db.session.commit()
