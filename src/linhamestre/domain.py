"""Regras de negócio puras: perfis de acesso, produtos, validade e tarefas."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from enum import StrEnum


class AccessLevel(StrEnum):
    OPERACIONAL = "Operacional"
    SUPERVISOR = "Supervisor"
    GERENTE = "Gerente"
    CEO = "CEO"
    ADMINISTRADOR = "Administrador"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    AccessLevel.OPERACIONAL: 1,
    AccessLevel.SUPERVISOR: 2,
    AccessLevel.GERENTE: 3,
    AccessLevel.CEO: 4,
    AccessLevel.ADMINISTRADOR: 5,
}

ACCESS_LEVELS_DESC = sorted(AccessLevel, key=lambda lvl: -lvl.rank)


def has_permission(user_level: str | None, required: AccessLevel) -> bool:
    """Hierarquia: um nível tem todas as permissões dos níveis abaixo dele."""
    if user_level is None:
        return False
    try:
        return AccessLevel(user_level).rank >= required.rank
    except ValueError:
        return False


UNITS = ("Unidade", "Kg", "Litro", "Caixa", "Pacote", "Metro")
QUALITY_STATUSES = ("Aprovado", "Reprovado", "Em Análise")
TASK_PRIORITIES = ("Alta", "Média", "Baixa")
TASK_PENDING = "Pendente"
TASK_DONE = "Concluída"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


class ValidationError(ValueError):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True, slots=True)
class ProductInput:
    name: str
    category: str
    quantity: int
    min_quantity: int
    unit: str
    location: str = ""
    supplier: str = ""
    cost: float = 0.0
    price: float = 0.0
    barcode: str = ""
    production_date: date | None = None
    expiry_date: date | None = None
    quality_status: str = "Em Análise"
    notes: str = ""

    def validated(self) -> ProductInput:
        """Retorna uma cópia normalizada ou lança ``ValidationError``."""
        problems: list[str] = []
        name = self.name.strip()
        category = self.category.strip()
        if not name:
            problems.append("Informe o nome do produto.")
        if not category:
            problems.append("Informe a categoria.")
        if self.quantity < 0:
            problems.append("A quantidade em estoque não pode ser negativa.")
        if self.min_quantity < 0:
            problems.append("A quantidade mínima não pode ser negativa.")
        if self.unit not in UNITS:
            problems.append("Unidade de medida inválida.")
        if self.quality_status not in QUALITY_STATUSES:
            problems.append("Status de qualidade inválido.")
        if self.cost < 0 or self.price < 0:
            problems.append("Custo e preço não podem ser negativos.")
        if self.production_date and self.expiry_date and self.expiry_date < self.production_date:
            problems.append("A data de validade não pode ser anterior à data de produção.")
        if problems:
            raise ValidationError(problems)
        return ProductInput(
            name=name,
            category=category,
            quantity=int(self.quantity),
            min_quantity=int(self.min_quantity),
            unit=self.unit,
            location=self.location.strip(),
            supplier=self.supplier.strip(),
            cost=round(float(self.cost), 2),
            price=round(float(self.price), 2),
            barcode=self.barcode.strip(),
            production_date=self.production_date,
            expiry_date=self.expiry_date,
            quality_status=self.quality_status,
            notes=self.notes.strip(),
        )


def is_critical_stock(quantity: int, min_quantity: int) -> bool:
    return quantity <= min_quantity


def stock_status(quantity: int, min_quantity: int) -> str:
    return "Crítico" if is_critical_stock(quantity, min_quantity) else "Normal"


def stock_ratio_pct(quantity: int, min_quantity: int) -> float | None:
    """Percentual do estoque mínimo; ``None`` quando o mínimo é zero."""
    if min_quantity <= 0:
        return None
    return quantity * 100.0 / min_quantity


def expiry_status(expiry: date | None, today: date, warning_days: int) -> str:
    if expiry is None:
        return "Sem data"
    if expiry < today:
        return "Vencido"
    if (expiry - today).days <= warning_days:
        return "Próximo"
    return "Válido"


def task_deadline_label(due: date | None, today: date) -> str:
    if due is None:
        return "Sem prazo definido"
    days_left = (due - today).days
    if days_left < 0:
        return f"Atrasada há {-days_left} dia(s)"
    if days_left == 0:
        return "Vence hoje"
    return f"Vence em {days_left} dia(s)"


def validate_user_fields(username: str, name: str, email: str) -> list[str]:
    problems: list[str] = []
    if not _USERNAME_RE.match(username):
        problems.append("Usuário deve ter 3 a 50 caracteres: letras, números, '.', '_' ou '-'.")
    if not name.strip():
        problems.append("Informe o nome completo.")
    if email and not _EMAIL_RE.match(email):
        problems.append("E-mail inválido.")
    return problems
