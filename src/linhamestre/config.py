"""Configuração da aplicação lida de variáveis de ambiente e validada no boot."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class ConfigError(ValueError):
    """Configuração inválida detectada na inicialização."""


@dataclass(frozen=True, slots=True)
class Settings:
    db_path: Path
    timezone: ZoneInfo
    log_level: str
    log_format: str
    admin_username: str
    admin_password: str | None
    max_login_attempts: int
    lockout_minutes: int

    @property
    def timezone_name(self) -> str:
        return self.timezone.key


def _int(env: Mapping[str, str], name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} deve ser um número inteiro (recebido: {raw!r}).") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} deve estar entre {minimum} e {maximum} (recebido: {value}).")
    return value


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Lê e valida as variáveis ``LINHAMESTRE_*``. Lança ``ConfigError`` se inválidas."""
    env = os.environ if env is None else env

    db_path = Path(env.get("LINHAMESTRE_DB_PATH", "linhamestre.db")).expanduser()
    if db_path.exists() and db_path.is_dir():
        raise ConfigError(f"LINHAMESTRE_DB_PATH aponta para um diretório: {db_path}")

    tz_name = env.get("LINHAMESTRE_TZ", "America/Sao_Paulo")
    try:
        timezone = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"LINHAMESTRE_TZ inválido: {tz_name!r}") from exc

    log_level = env.get("LINHAMESTRE_LOG_LEVEL", "INFO").upper()
    if log_level not in _LOG_LEVELS:
        raise ConfigError(f"LINHAMESTRE_LOG_LEVEL inválido: {log_level!r}")

    log_format = env.get("LINHAMESTRE_LOG_FORMAT", "json").lower()
    if log_format not in {"json", "text"}:
        raise ConfigError("LINHAMESTRE_LOG_FORMAT deve ser 'json' ou 'text'.")

    admin_username = env.get("LINHAMESTRE_ADMIN_USERNAME", "admin").strip()
    if not admin_username:
        raise ConfigError("LINHAMESTRE_ADMIN_USERNAME não pode ser vazio.")

    admin_password = env.get("LINHAMESTRE_ADMIN_PASSWORD") or None

    return Settings(
        db_path=db_path,
        timezone=timezone,
        log_level=log_level,
        log_format=log_format,
        admin_username=admin_username,
        admin_password=admin_password,
        max_login_attempts=_int(env, "LINHAMESTRE_MAX_LOGIN_ATTEMPTS", 5, minimum=1, maximum=100),
        lockout_minutes=_int(env, "LINHAMESTRE_LOCKOUT_MINUTES", 15, minimum=1, maximum=1440),
    )
