from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class Organization(db.Model):
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    invite_code = db.Column(db.String(36), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    users = db.relationship('User', backref='organization', lazy=True)
    credentials = db.relationship('Credential', backref='organization', lazy=True)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    role = db.Column(db.String(20), default='member')  # 'admin' ou 'member'
    is_active_member = db.Column(db.Boolean, default=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Credential(db.Model):
    __tablename__ = 'credentials'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    login = db.Column(db.String(200), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, default='')
    category = db.Column(db.String(30), default='outros')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    creator = db.relationship('User', backref='created_credentials')
    permissions = db.relationship('CredentialPermission', backref='credential',
                                 lazy=True, cascade='all, delete-orphan')


class CredentialPermission(db.Model):
    __tablename__ = 'credential_permissions'

    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.Integer, db.ForeignKey('credentials.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    can_view_password = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='permissions')


class AccessLog(db.Model):
    __tablename__ = 'access_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    credential_id = db.Column(db.Integer, db.ForeignKey('credentials.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    accessed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='access_logs')
    credential = db.relationship('Credential', backref='access_logs')
