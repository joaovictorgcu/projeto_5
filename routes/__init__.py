from models import db, AccessLog
from routes.auth import auth
from routes.vault import vault
from routes.org import org
from routes.api import api


def _log_access(user_id, credential_id, action):
    """Helper compartilhado: registra acesso no log de auditoria."""
    log = AccessLog(user_id=user_id, credential_id=credential_id, action=action)
    db.session.add(log)
    db.session.commit()
