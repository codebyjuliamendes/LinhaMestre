from datetime import date
from pathlib import Path

import pytest

from linhamestre import domain
from linhamestre.config import ConfigError, load_settings
from linhamestre.domain import AccessLevel, ProductInput, ValidationError


def test_permission_hierarchy() -> None:
    assert domain.has_permission("Administrador", AccessLevel.GERENTE)
    assert domain.has_permission("Supervisor", AccessLevel.SUPERVISOR)
    assert not domain.has_permission("Operacional", AccessLevel.SUPERVISOR)
    assert not domain.has_permission(None, AccessLevel.OPERACIONAL)
    assert not domain.has_permission("Desconhecido", AccessLevel.OPERACIONAL)


def test_product_accepts_zero_quantities() -> None:
    # Na versão 1.0 quantidade 0 era rejeitada como "campo obrigatório vazio".
    p = ProductInput(name=" Parafuso ", category="Fixadores", quantity=0, min_quantity=0, unit="Unidade").validated()
    assert p.name == "Parafuso"
    assert p.quantity == 0


def test_product_validation_errors() -> None:
    bad = ProductInput(
        name=" ",
        category="",
        quantity=-1,
        min_quantity=-2,
        unit="Galão",
        quality_status="Ótimo",
        cost=-1,
        production_date=date(2024, 5, 2),
        expiry_date=date(2024, 5, 1),
    )
    with pytest.raises(ValidationError) as exc:
        bad.validated()
    assert len(exc.value.problems) == 8


def test_stock_helpers() -> None:
    assert domain.stock_status(5, 5) == "Crítico"
    assert domain.stock_status(6, 5) == "Normal"
    assert domain.stock_ratio_pct(5, 10) == 50.0
    assert domain.stock_ratio_pct(0, 0) is None


def test_expiry_status() -> None:
    today = date(2026, 1, 10)
    assert domain.expiry_status(None, today, 30) == "Sem data"
    assert domain.expiry_status(date(2026, 1, 9), today, 30) == "Vencido"
    assert domain.expiry_status(date(2026, 1, 10), today, 30) == "Próximo"
    assert domain.expiry_status(date(2026, 2, 9), today, 30) == "Próximo"
    assert domain.expiry_status(date(2026, 2, 10), today, 30) == "Válido"


def test_task_deadline_label() -> None:
    today = date(2026, 1, 10)
    assert domain.task_deadline_label(None, today) == "Sem prazo definido"
    assert domain.task_deadline_label(date(2026, 1, 8), today) == "Atrasada há 2 dia(s)"
    assert domain.task_deadline_label(today, today) == "Vence hoje"
    assert domain.task_deadline_label(date(2026, 1, 13), today) == "Vence em 3 dia(s)"


def test_validate_user_fields() -> None:
    assert domain.validate_user_fields("maria.silva", "Maria", "maria@exemplo.com") == []
    assert len(domain.validate_user_fields("a b", " ", "invalido")) == 3


def test_load_settings_defaults() -> None:
    s = load_settings({})
    assert s.db_path == Path("linhamestre.db")
    assert s.timezone_name == "America/Sao_Paulo"
    assert s.admin_password is None
    assert s.max_login_attempts == 5


def test_load_settings_custom(tmp_path: Path) -> None:
    s = load_settings(
        {
            "LINHAMESTRE_DB_PATH": str(tmp_path / "x.db"),
            "LINHAMESTRE_TZ": "UTC",
            "LINHAMESTRE_LOG_LEVEL": "debug",
            "LINHAMESTRE_ADMIN_PASSWORD": "segredo-123",
            "LINHAMESTRE_MAX_LOGIN_ATTEMPTS": "3",
        }
    )
    assert s.db_path == tmp_path / "x.db"
    assert s.log_level == "DEBUG"
    assert s.admin_password == "segredo-123"
    assert s.max_login_attempts == 3


@pytest.mark.parametrize(
    "env",
    [
        {"LINHAMESTRE_TZ": "Marte/Base"},
        {"LINHAMESTRE_LOG_LEVEL": "VERBOSE"},
        {"LINHAMESTRE_LOG_FORMAT": "xml"},
        {"LINHAMESTRE_MAX_LOGIN_ATTEMPTS": "zero"},
        {"LINHAMESTRE_LOCKOUT_MINUTES": "0"},
        {"LINHAMESTRE_ADMIN_USERNAME": "  "},
    ],
)
def test_load_settings_invalid(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        load_settings(env)


def test_load_settings_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings({"LINHAMESTRE_DB_PATH": str(tmp_path)})
