import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _get_fernet():
    """Gera chave Fernet a partir da SECRET_KEY do ambiente."""
    secret = os.getenv('SECRET_KEY', 'dev-key-troque-em-producao').encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'keyflow-salt-fixo',
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret))
    return Fernet(key)


def encrypt_password(plain_text: str) -> str:
    """Criptografa uma senha para armazenamento."""
    f = _get_fernet()
    return f.encrypt(plain_text.encode()).decode()


def decrypt_password(encrypted_text: str) -> str:
    """Descriptografa uma senha armazenada."""
    f = _get_fernet()
    return f.decrypt(encrypted_text.encode()).decode()
