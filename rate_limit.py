"""
Rate limiter para proteção contra brute force no login.
Armazena tentativas em memória (sem dependência externa).
"""
from datetime import datetime, timezone, timedelta


class LoginRateLimiter:
    def __init__(self, max_attempts=5, window_minutes=15):
        self.max_attempts = max_attempts
        self.window = timedelta(minutes=window_minutes)
        self._attempts = {}  # {ip: {'count': int, 'first_attempt': datetime, 'blocked_until': datetime|None}}

    def _cleanup(self, ip):
        """Remove entradas expiradas."""
        if ip in self._attempts:
            entry = self._attempts[ip]
            now = datetime.now(timezone.utc)
            if entry.get('blocked_until') and now >= entry['blocked_until']:
                del self._attempts[ip]
            elif now - entry['first_attempt'] > self.window:
                del self._attempts[ip]

    def is_blocked(self, ip):
        """Verifica se o IP está bloqueado."""
        self._cleanup(ip)
        if ip not in self._attempts:
            return False
        entry = self._attempts[ip]
        if entry.get('blocked_until'):
            return datetime.now(timezone.utc) < entry['blocked_until']
        return False

    def record_failure(self, ip):
        """Registra uma tentativa falha."""
        self._cleanup(ip)
        now = datetime.now(timezone.utc)

        if ip not in self._attempts:
            self._attempts[ip] = {'count': 1, 'first_attempt': now, 'blocked_until': None}
        else:
            self._attempts[ip]['count'] += 1

        if self._attempts[ip]['count'] >= self.max_attempts:
            self._attempts[ip]['blocked_until'] = now + self.window

    def remaining_attempts(self, ip):
        """Retorna quantas tentativas restam."""
        self._cleanup(ip)
        if ip not in self._attempts:
            return self.max_attempts
        return max(0, self.max_attempts - self._attempts[ip]['count'])

    def reset(self, ip):
        """Reseta o contador após login bem-sucedido."""
        self._attempts.pop(ip, None)


limiter = LoginRateLimiter()
