import os
import random
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import Flask, render_template, session
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect

from config import Config
from models import (
    db, User, Organization, Credential, CredentialPermission,
    AccessLog, UserFavorite, PasswordPolicy, BreachResult, SecurityScore,
)

mail = Mail()


_DEMO_MEMBERS = [
    ('Bruno Costa', 'bruno@keyflow.local', 'member', True),
    ('Carla Mendes', 'carla@keyflow.local', 'member', True),
    ('Diego Ferreira', 'diego@keyflow.local', 'member', True),
    ('Eduardo Silva', 'eduardo@keyflow.local', 'member', False),
]

_DEMO_CREDENTIALS = [
    ('Instagram Empresa', 'social@empresa.com', 'SenhaForte!2026', 'rede_social', 15),
    ('LinkedIn Empresa', 'rh@empresa.com', 'Linked#2025Safe', 'rede_social', 40),
    ('Twitter/X Corp', 'social@empresa.com', 'senha123', 'rede_social', 200),
    ('TikTok Marketing', 'marketing@empresa.com', 'Tik@Tok2026', 'rede_social', 60),
    ('AWS Console', 'devops@empresa.com', 'Cloud#Secret42Xp', 'cloud', 10),
    ('Google Cloud Platform', 'devops@empresa.com', 'GCP@Seguro2026', 'cloud', 25),
    ('Azure Portal', 'devops@empresa.com', 'azure2024', 'cloud', 150),
    ('DigitalOcean', 'devops@empresa.com', 'Ocean!2026Strong', 'cloud', 12),
    ('Banco Itau', 'financeiro@empresa.com', 'Bc@2026Seguro!', 'financeiro', 5),
    ('Nubank PJ', 'financeiro@empresa.com', 'Nu#PJ2026Safe', 'financeiro', 18),
    ('PagBank', 'financeiro@empresa.com', 'Pag@Bank2026$', 'financeiro', 30),
    ('Gmail Marketing', 'marketing@empresa.com', 'Email@Keyflow1', 'email', 45),
    ('Outlook Suporte', 'suporte@empresa.com', 'Out#Look2026', 'email', 20),
    ('Notion Workspace', 'time@empresa.com', 'Notion#Team24', 'outros', 8),
    ('Figma Design', 'design@empresa.com', 'Fig@ma2026Safe', 'outros', 14),
    ('Slack Team', 'time@empresa.com', 'admin123', 'outros', 220),
    ('GitHub Org', 'devops@empresa.com', 'Gh@Hub2026!Sec', 'outros', 22),
]

_DEMO_POLICIES = [
    ('financeiro', 14, True, True, True, 90),
    ('cloud', 16, True, True, True, 120),
    ('email', 12, True, True, False, 180),
    ('rede_social', 10, True, True, False, 365),
    ('outros', 8, False, True, False, 365),
]


def _bootstrap_demo():
    """Dataset completo de demo. Idempotente: só cria se a org estiver vazia."""
    email = os.getenv('BOOTSTRAP_ADMIN_EMAIL', 'admin@keyflow.local')
    password = os.getenv('BOOTSTRAP_ADMIN_PASSWORD', 'adm123')
    org_name = os.getenv('BOOTSTRAP_ORG_NAME', 'KeyFlow Demo')

    admin = User.query.filter_by(email=email).first()
    if admin and Credential.query.filter_by(org_id=admin.org_id).count() > 0:
        return

    org = Organization.query.filter_by(name=org_name).first()
    if not org:
        org = Organization(name=org_name, invite_code=str(uuid.uuid4())[:8])
        db.session.add(org)
        db.session.flush()

    admin_pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    if not admin:
        admin = User(
            name='Ana Silva',
            email=email,
            password_hash=admin_pw_hash,
            org_id=org.id,
            role='admin',
            is_active_member=True,
        )
        db.session.add(admin)
        db.session.flush()

    members = [admin]
    for name, member_email, role, active in _DEMO_MEMBERS:
        existing = User.query.filter_by(email=member_email).first()
        if existing:
            members.append(existing)
            continue
        member = User(
            name=name,
            email=member_email,
            password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            org_id=org.id,
            role=role,
            is_active_member=active,
        )
        db.session.add(member)
        db.session.flush()
        members.append(member)

    from crypto_utils import encrypt_password
    now = datetime.now(timezone.utc)
    credentials = []
    for name, login, pwd, category, age_days in _DEMO_CREDENTIALS:
        creator = random.choice(members[:3])
        changed_at = now - timedelta(days=age_days)
        cred = Credential(
            org_id=org.id,
            name=name,
            login=login,
            encrypted_password=encrypt_password(pwd),
            category=category,
            created_by=creator.id,
            created_at=changed_at,
            password_changed_at=changed_at,
        )
        db.session.add(cred)
        db.session.flush()
        credentials.append(cred)

        db.session.add(CredentialPermission(
            credential_id=cred.id, user_id=admin.id, can_view_password=True,
        ))
        shared_with = random.sample(members[1:], k=random.randint(1, min(3, len(members) - 1)))
        for u in shared_with:
            db.session.add(CredentialPermission(
                credential_id=cred.id,
                user_id=u.id,
                can_view_password=random.random() > 0.4,
            ))

    favorite_pairs = [
        (admin.id, credentials[0].id),
        (admin.id, credentials[4].id),
        (admin.id, credentials[8].id),
        (members[1].id, credentials[4].id),
        (members[1].id, credentials[13].id),
        (members[2].id, credentials[0].id),
    ]
    for user_id, cred_id in favorite_pairs:
        db.session.add(UserFavorite(user_id=user_id, credential_id=cred_id))

    for category, min_length, req_upper, req_num, req_special, max_age in _DEMO_POLICIES:
        db.session.add(PasswordPolicy(
            org_id=org.id,
            category=category,
            min_length=min_length,
            require_uppercase=req_upper,
            require_numbers=req_num,
            require_special=req_special,
            max_age_days=max_age,
            is_default=(category == 'outros'),
        ))

    breach_targets = [credentials[2], credentials[6], credentials[15]]
    for cred in breach_targets:
        db.session.add(BreachResult(
            org_id=org.id,
            credential_id=cred.id,
            is_breached=True,
            breach_count=random.randint(150, 50000),
            checked_at=now - timedelta(days=random.randint(1, 5)),
        ))

    actions = ['criou', 'editou', 'visualizou senha', 'visualizou senha', 'visualizou senha', 'editou', 'deletou']
    active_members = [m for m in members if m.is_active_member]
    for day_offset in range(30):
        daily_events = random.randint(8, 25)
        for _ in range(daily_events):
            user = random.choice(active_members)
            cred = random.choice(credentials)
            action = random.choice(actions)
            when = now - timedelta(
                days=day_offset,
                hours=random.randint(8, 20),
                minutes=random.randint(0, 59),
            )
            db.session.add(AccessLog(
                user_id=user.id,
                credential_id=cred.id,
                action=action,
                accessed_at=when,
            ))

    for day_offset in range(30, -1, -1):
        base_score = 62 + (30 - day_offset) * 1.1
        noise = random.randint(-4, 4)
        score = max(0, min(100, int(base_score + noise)))
        db.session.add(SecurityScore(
            org_id=org.id,
            score=score,
            weak_count=max(0, 5 - (30 - day_offset) // 6),
            reused_count=max(0, 3 - (30 - day_offset) // 10),
            old_count=max(0, 6 - (30 - day_offset) // 5),
            breached_count=len(breach_targets) if day_offset < 10 else 0,
            recorded_at=now - timedelta(days=day_offset),
        ))

    db.session.commit()


_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', 'static')


def create_app():
    app = Flask(__name__, static_folder=_STATIC_DIR, static_url_path='/static')
    app.config.from_object(Config)

    db.init_app(app)
    CSRFProtect(app)
    mail.init_app(app)

    # Auto-logout por inatividade (30 minutos)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

    @app.before_request
    def make_session_permanent():
        session.permanent = True

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Faça login para acessar esta página.'
    login_manager.login_message_category = 'error'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from routes import auth, org, vault, api
    app.register_blueprint(auth)
    app.register_blueprint(org)
    app.register_blueprint(vault)
    app.register_blueprint(api)

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    with app.app_context():
        db.create_all()

        # migrate: add password_changed_at if missing (SQLite only — Postgres cria via db.create_all)
        if db.engine.dialect.name == 'sqlite':
            with db.engine.connect() as conn:
                from sqlalchemy import text
                result = conn.execute(text("PRAGMA table_info(credentials)"))
                cols = [row[1] for row in result]
                if 'password_changed_at' not in cols:
                    conn.execute(text('ALTER TABLE credentials ADD COLUMN password_changed_at DATETIME'))
                    conn.execute(text('UPDATE credentials SET password_changed_at = created_at WHERE password_changed_at IS NULL'))
                    conn.commit()

        _bootstrap_demo()

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
