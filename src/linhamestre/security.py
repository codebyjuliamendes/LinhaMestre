"""Hash de senhas, política de senha e limitação de tentativas de login."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


@dataclass(frozen=True, slots=True)
class PasswordHash:
    """Par (hash, salt) gravado nas colunas ``users.password`` e ``users.salt``."""

    hashed: str
    salt: str


def hash_password(password: str, *, iterations: int | None = None) -> PasswordHash:
    """Gera hash PBKDF2-HMAC-SHA256 com salt aleatório de 16 bytes.

    O formato de ``hashed`` é ``pbkdf2_sha256$<iterações>$<hex>``, o que permite
    distinguir hashes novos dos hashes legados (SHA-256 simples) já gravados.
    """
    iterations = iterations or PBKDF2_ITERATIONS
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return PasswordHash(f"{PBKDF2_ALGORITHM}${iterations}${digest.hex()}", salt.hex())


def verify_password(password: str, stored_hash: str | None, stored_salt: str | None) -> bool:
    """Verifica a senha em tempo constante. Aceita hashes PBKDF2 e o formato legado."""
    if not stored_hash or stored_salt is None:
        return False
    try:
        salt = bytes.fromhex(stored_salt)
    except ValueError:
        return False

    if stored_hash.startswith(f"{PBKDF2_ALGORITHM}$"):
        try:
            _, iterations_raw, expected = stored_hash.split("$", 2)
            iterations = int(iterations_raw)
        except ValueError:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()
        return hmac.compare_digest(digest, expected)

    # Formato legado (versão 1.0): sha256(salt + senha) em hexadecimal.
    legacy = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy, stored_hash)


def needs_rehash(stored_hash: str | None) -> bool:
    """Indica se o hash gravado deve ser regravado no formato atual."""
    if not stored_hash or not stored_hash.startswith(f"{PBKDF2_ALGORITHM}$"):
        return True
    try:
        return int(stored_hash.split("$", 2)[1]) < PBKDF2_ITERATIONS
    except (IndexError, ValueError):
        return True


def password_problems(password: str) -> list[str]:
    """Retorna a lista de problemas da senha (vazia se a senha for aceitável)."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres.")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"A senha deve ter no máximo {MAX_PASSWORD_LENGTH} caracteres.")
    if password.strip() != password:
        problems.append("A senha não pode começar nem terminar com espaços.")
    if password.isdigit() or password.isalpha():
        problems.append("A senha deve combinar letras e números ou símbolos.")
    return problems


def generate_password(length: int = 16) -> str:
    """Senha aleatória forte para o administrador inicial."""
    return secrets.token_urlsafe(length)[:length] + "9a"


@dataclass
class LoginThrottle:
    """Bloqueia um usuário após ``max_attempts`` falhas seguidas por ``lockout_seconds``.

    O estado fica em memória do processo (compartilhado entre sessões do Streamlit).
    """

    max_attempts: int = 5
    lockout_seconds: float = 15 * 60
    clock: Callable[[], float] = time.monotonic
    _failures: dict[str, list[float]] = field(default_factory=dict)
    _locked_until: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @staticmethod
    def _key(username: str) -> str:
        return username.strip().lower()

    def seconds_locked(self, username: str) -> float:
        key = self._key(username)
        with self._lock:
            until = self._locked_until.get(key)
            if until is None:
                return 0.0
            remaining = until - self.clock()
            if remaining <= 0:
                del self._locked_until[key]
                self._failures.pop(key, None)
                return 0.0
            return remaining

    def register_failure(self, username: str) -> bool:
        """Registra falha. Retorna ``True`` se o usuário acabou de ser bloqueado."""
        key = self._key(username)
        now = self.clock()
        with self._lock:
            window_start = now - self.lockout_seconds
            attempts = [t for t in self._failures.get(key, []) if t >= window_start]
            attempts.append(now)
            self._failures[key] = attempts
            if len(attempts) >= self.max_attempts:
                self._locked_until[key] = now + self.lockout_seconds
                return True
            return False

    def register_success(self, username: str) -> None:
        key = self._key(username)
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)
