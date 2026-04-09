import uuid

import bcrypt
import pyotp
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User, Organization
from rate_limit import limiter

auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('org.dashboard'))

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
            org_obj = Organization.query.filter_by(invite_code=invite_code).first()
            if not org_obj:
                flash('Código de convite inválido.', 'error')
                return render_template('register.html')
            user = User(name=name, email=email, password_hash=pw_hash,
                        org_id=org_obj.id, role='member')
        else:
            if not org_name:
                flash('Informe o nome da organização ou um código de convite.', 'error')
                return render_template('register.html')
            org_obj = Organization(name=org_name, invite_code=str(uuid.uuid4())[:8])
            db.session.add(org_obj)
            db.session.flush()
            user = User(name=name, email=email, password_hash=pw_hash,
                        org_id=org_obj.id, role='admin')

        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Conta criada com sucesso!', 'success')
        return redirect(url_for('org.dashboard'))

    return render_template('register.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('org.dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr
        if limiter.is_blocked(ip):
            flash('Muitas tentativas. Aguarde 15 minutos.', 'error')
            return render_template('login.html'), 429

        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            if not user.is_active_member:
                flash('Sua conta foi desativada. Contate o administrador.', 'error')
                return render_template('login.html')

            limiter.reset(ip)

            if user.mfa_enabled and user.totp_secret:
                session['mfa_user_id'] = user.id
                return redirect(url_for('auth.login_mfa'))

            login_user(user)
            if user.role == 'admin' and user.org_id:
                from security import run_breach_check_background
                run_breach_check_background(current_app._get_current_object(), user.org_id)
            return redirect(url_for('org.dashboard'))

        limiter.record_failure(ip)
        remaining = limiter.remaining_attempts(ip)
        if remaining > 0:
            flash(f'E-mail ou senha incorretos. {remaining} tentativa(s) restante(s).', 'error')
        else:
            flash('Muitas tentativas. Aguarde 15 minutos.', 'error')

    return render_template('login.html')


@auth.route('/login/mfa', methods=['GET', 'POST'])
def login_mfa():
    from crypto_utils import decrypt_password

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
                if user.role == 'admin' and user.org_id:
                    from security import run_breach_check_background
                    run_breach_check_background(current_app._get_current_object(), user.org_id)
                return redirect(url_for('org.dashboard'))

        flash('Código inválido. Tente novamente.', 'error')
        return render_template('mfa_verify.html')

    return render_template('mfa_verify.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('mfa_user_id', None)
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('org.landing'))
