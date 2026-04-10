"""Suite de testes basica do KeyFlow."""
import pytest
from app import create_app
from models import db, User, Organization, Credential


@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SERVER_NAME'] = 'localhost'

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(app, client):
    """Cliente autenticado como admin."""
    with app.app_context():
        import bcrypt
        org = Organization(name='Test Org', invite_code='TEST1234')
        db.session.add(org)
        db.session.flush()
        pw = bcrypt.hashpw('senha123'.encode(), bcrypt.gensalt()).decode()
        user = User(name='Admin', email='admin@test.com', password_hash=pw,
                    org_id=org.id, role='admin')
        db.session.add(user)
        db.session.commit()

    client.post('/login', data={'email': 'admin@test.com', 'password': 'senha123'})
    return client


# ─── Testes de rotas publicas ─────────────────────────────────

class TestPublicRoutes:
    def test_landing_page(self, client):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'KeyFlow' in resp.data

    def test_login_page(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_register_page(self, client):
        resp = client.get('/register')
        assert resp.status_code == 200

    def test_404(self, client):
        resp = client.get('/pagina-que-nao-existe')
        assert resp.status_code == 404


# ─── Testes de autenticacao ───────────────────────────────────

class TestAuth:
    def test_register_new_org(self, client):
        resp = client.post('/register', data={
            'name': 'Joao', 'email': 'joao@test.com',
            'password': 'senha123', 'org_name': 'Minha Org'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'dashboard' in resp.data.lower() or b'Conta criada' in resp.data

    def test_register_with_invite(self, app, client):
        with app.app_context():
            org = Organization(name='Org Existente', invite_code='INV12345')
            db.session.add(org)
            db.session.commit()

        resp = client.post('/register', data={
            'name': 'Maria', 'email': 'maria@test.com',
            'password': 'senha123', 'invite_code': 'INV12345'
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_login_wrong_password(self, app, client):
        with app.app_context():
            import bcrypt
            org = Organization(name='Org', invite_code='CODE1234')
            db.session.add(org)
            db.session.flush()
            pw = bcrypt.hashpw('correta'.encode(), bcrypt.gensalt()).decode()
            user = User(name='User', email='user@test.com', password_hash=pw,
                        org_id=org.id, role='admin')
            db.session.add(user)
            db.session.commit()

        resp = client.post('/login', data={
            'email': 'user@test.com', 'password': 'errada'
        })
        assert b'incorretos' in resp.data

    def test_login_success(self, auth_client):
        resp = auth_client.get('/dashboard')
        assert resp.status_code == 200

    def test_protected_route_redirect(self, client):
        resp = client.get('/vault')
        assert resp.status_code == 302


# ─── Testes do cofre ──────────────────────────────────────────

class TestVault:
    def test_create_credential(self, auth_client):
        resp = auth_client.post('/vault/new', data={
            'name': 'Instagram', 'login': 'admin@ig.com',
            'password': 'S3nh@F0rt3!', 'category': 'rede_social'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'Instagram' in resp.data

    def test_create_credential_validation(self, auth_client):
        resp = auth_client.post('/vault/new', data={
            'name': '', 'login': '', 'password': ''
        }, follow_redirects=True)
        assert b'Preencha' in resp.data

    def test_create_credential_too_long(self, auth_client):
        resp = auth_client.post('/vault/new', data={
            'name': 'x' * 201, 'login': 'admin',
            'password': 'senha123'
        }, follow_redirects=True)
        assert b'200 caracteres' in resp.data

    def test_vault_list(self, auth_client):
        resp = auth_client.get('/vault')
        assert resp.status_code == 200


# ─── Testes de permissao ──────────────────────────────────────

class TestPermissions:
    def test_reveal_own_credential(self, app, auth_client):
        auth_client.post('/vault/new', data={
            'name': 'Test', 'login': 'test',
            'password': 'minha_senha', 'category': 'outros'
        })
        with app.app_context():
            cred = Credential.query.filter_by(name='Test').first()
            assert cred is not None
            resp = auth_client.post(f'/vault/{cred.id}/reveal',
                                    content_type='application/json')
            data = resp.get_json()
            assert data['password'] == 'minha_senha'

    def test_reveal_no_permission_denied(self, app, auth_client):
        """Membro sem permissao explicita nao pode ver senha."""
        import bcrypt
        with app.app_context():
            org = Organization.query.first()
            pw = bcrypt.hashpw('senha123'.encode(), bcrypt.gensalt()).decode()
            member = User(name='Membro', email='membro@test.com',
                          password_hash=pw, org_id=org.id, role='member')
            db.session.add(member)
            db.session.commit()

            auth_client.post('/vault/new', data={
                'name': 'Segredo', 'login': 'sec',
                'password': 'top_secret', 'category': 'outros'
            })
            cred = Credential.query.filter_by(name='Segredo').first()

        # Login como membro
        auth_client.get('/logout')
        auth_client.post('/login', data={
            'email': 'membro@test.com', 'password': 'senha123'
        })

        with app.app_context():
            cred = Credential.query.filter_by(name='Segredo').first()
            resp = auth_client.post(f'/vault/{cred.id}/reveal',
                                    content_type='application/json')
            assert resp.status_code == 403


# ─── Testes de API ────────────────────────────────────────────

class TestAPI:
    def test_health_score(self, auth_client):
        resp = auth_client.get('/api/health-score')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'score' in data

    def test_dashboard_stats(self, auth_client):
        resp = auth_client.get('/api/dashboard-stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'daily_access' in data

    def test_security_score_admin(self, auth_client):
        resp = auth_client.get('/api/security-score')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'score' in data


# ─── Testes de crypto ─────────────────────────────────────────

class TestCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        from crypto_utils import encrypt_password, decrypt_password
        original = 'M1nh@Senh@S3cur@!'
        encrypted = encrypt_password(original)
        assert encrypted != original
        decrypted = decrypt_password(encrypted)
        assert decrypted == original

    def test_different_passwords_different_ciphertext(self):
        from crypto_utils import encrypt_password
        a = encrypt_password('senha1')
        b = encrypt_password('senha2')
        assert a != b
