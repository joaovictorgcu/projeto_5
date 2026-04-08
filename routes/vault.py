from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user

from models import db, User, Credential, CredentialPermission
from crypto_utils import encrypt_password, decrypt_password

vault = Blueprint('vault', __name__)


def _log(user_id, cred_id, action):
    from routes import _log_access
    _log_access(user_id, cred_id, action)


@vault.route('/vault')
@login_required
def index():
    org = current_user.organization
    if not org:
        return redirect(url_for('org.dashboard'))
    credentials = Credential.query.filter_by(org_id=org.id).order_by(Credential.created_at.desc()).all()
    from models import UserFavorite
    fav_ids = {f.credential_id for f in UserFavorite.query.filter_by(user_id=current_user.id).all()}
    credentials.sort(key=lambda c: (c.id not in fav_ids, c.created_at), reverse=False)
    return render_template('vault.html', credentials=credentials, fav_ids=fav_ids)


@vault.route('/vault/new', methods=['GET', 'POST'])
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
        _log(current_user.id, cred.id, 'criou')

        flash('Credencial salva com sucesso!', 'success')
        return redirect(url_for('vault.index'))

    return render_template('credential_form.html', editing=False)


@vault.route('/vault/<int:cred_id>/edit', methods=['GET', 'POST'])
@login_required
def credential_edit(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('vault.index'))

    if request.method == 'POST':
        cred.name = request.form.get('name', '').strip()
        cred.login = request.form.get('login', '').strip()
        new_password = request.form.get('password', '')
        cred.notes = request.form.get('notes', '').strip()
        cred.category = request.form.get('category', 'outros')

        if new_password:
            cred.encrypted_password = encrypt_password(new_password)

        db.session.commit()
        _log(current_user.id, cred.id, 'editou')
        flash('Credencial atualizada.', 'success')
        return redirect(url_for('vault.index'))

    return render_template('credential_form.html', editing=True, cred=cred)


@vault.route('/vault/<int:cred_id>/delete', methods=['POST'])
@login_required
def credential_delete(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('vault.index'))

    _log(current_user.id, cred.id, 'deletou')
    db.session.delete(cred)
    db.session.commit()
    flash('Credencial removida.', 'success')
    return redirect(url_for('vault.index'))


@vault.route('/vault/<int:cred_id>/reveal', methods=['POST'])
@login_required
def credential_reveal(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        return jsonify({'error': 'Acesso negado'}), 403

    if cred.created_by != current_user.id:
        perm = CredentialPermission.query.filter_by(
            credential_id=cred.id, user_id=current_user.id
        ).first()
        if perm and not perm.can_view_password:
            return jsonify({'error': 'Você não tem permissão para ver esta senha'}), 403

    _log(current_user.id, cred.id, 'visualizou senha')

    try:
        plain = decrypt_password(cred.encrypted_password)
    except Exception:
        return jsonify({'error': 'Erro ao descriptografar'}), 500

    return jsonify({'password': plain})


@vault.route('/vault/<int:cred_id>/permissions', methods=['GET', 'POST'])
@login_required
def credential_permissions(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('vault.index'))

    if request.method == 'POST':
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
        return redirect(url_for('vault.index'))

    members = User.query.filter_by(org_id=current_user.org_id, is_active_member=True).all()
    perms = {p.user_id: p for p in CredentialPermission.query.filter_by(credential_id=cred.id).all()}
    return render_template('permissions.html', cred=cred, members=members, perms=perms)


@vault.route('/vault/<int:cred_id>/favorite', methods=['POST'])
@login_required
def toggle_favorite(cred_id):
    from models import UserFavorite
    cred = Credential.query.get_or_404(cred_id)
    if cred.org_id != current_user.org_id:
        return jsonify({'error': 'Acesso negado'}), 403

    fav = UserFavorite.query.filter_by(user_id=current_user.id, credential_id=cred_id).first()
    if fav:
        db.session.delete(fav)
        db.session.commit()
        return jsonify({'favorited': False})
    else:
        db.session.add(UserFavorite(user_id=current_user.id, credential_id=cred_id))
        db.session.commit()
        return jsonify({'favorited': True})


@vault.route('/vault/search')
@login_required
def vault_search():
    query = request.args.get('q', '').strip()
    org = current_user.organization
    if not org:
        return redirect(url_for('vault.index'))

    if query:
        credentials = Credential.query.filter(
            Credential.org_id == org.id,
            (Credential.name.ilike(f'%{query}%') | Credential.login.ilike(f'%{query}%'))
        ).order_by(Credential.created_at.desc()).all()
    else:
        credentials = Credential.query.filter_by(org_id=org.id).order_by(Credential.created_at.desc()).all()

    from models import UserFavorite
    fav_ids = {f.credential_id for f in UserFavorite.query.filter_by(user_id=current_user.id).all()}
    credentials.sort(key=lambda c: (c.id not in fav_ids, c.created_at), reverse=False)
    return render_template('vault.html', credentials=credentials, search_query=query, fav_ids=fav_ids)
