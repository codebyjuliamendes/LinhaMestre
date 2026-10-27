"""Controle Estatístico de Processo (CEP): limites de controle, regras e capacidade.

Funções puras, sem dependência de Streamlit ou banco, para facilitar testes.
Constantes de Shewhart conforme tabelas usuais (ISO 7870-2 / ABNT NBR 5479).
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum


@dataclass(frozen=True, slots=True)
class ChartFactors:
    A2: float
    A3: float
    D3: float
    D4: float
    B3: float
    B4: float
    d2: float


# n: tamanho do subgrupo (amostra).
CONTROL_CHART_CONSTANTS: dict[int, ChartFactors] = {
    2: ChartFactors(A2=1.880, A3=2.659, D3=0.0, D4=3.267, B3=0.0, B4=3.267, d2=1.128),
    3: ChartFactors(A2=1.023, A3=1.954, D3=0.0, D4=2.574, B3=0.0, B4=2.568, d2=1.693),
    4: ChartFactors(A2=0.729, A3=1.628, D3=0.0, D4=2.282, B3=0.0, B4=2.266, d2=2.059),
    5: ChartFactors(A2=0.577, A3=1.427, D3=0.0, D4=2.114, B3=0.0, B4=2.089, d2=2.326),
    6: ChartFactors(A2=0.483, A3=1.287, D3=0.0, D4=2.004, B3=0.030, B4=1.970, d2=2.534),
    7: ChartFactors(A2=0.419, A3=1.182, D3=0.076, D4=1.924, B3=0.118, B4=1.882, d2=2.704),
    8: ChartFactors(A2=0.373, A3=1.099, D3=0.136, D4=1.864, B3=0.185, B4=1.815, d2=2.847),
    9: ChartFactors(A2=0.337, A3=1.032, D3=0.184, D4=1.816, B3=0.239, B4=1.761, d2=2.970),
    10: ChartFactors(A2=0.308, A3=0.975, D3=0.223, D4=1.777, B3=0.284, B4=1.716, d2=3.078),
}

MIN_SUBGROUP_SIZE = min(CONTROL_CHART_CONSTANTS)
MAX_SUBGROUP_SIZE = max(CONTROL_CHART_CONSTANTS)

# Para I-MR o subgrupo da amplitude móvel tem n = 2.
_IMR = CONTROL_CHART_CONSTANTS[2]


class SpcError(ValueError):
    """Dados insuficientes ou inválidos para o cálculo solicitado."""


@dataclass(frozen=True, slots=True)
class ControlLimits:
    center: float
    ucl: float
    lcl: float

    @property
    def sigma(self) -> float:
        """Desvio padrão estimado da estatística plotada (distância de 1σ)."""
        return (self.ucl - self.center) / 3.0


def factors_for(n: int) -> ChartFactors:
    try:
        return CONTROL_CHART_CONSTANTS[int(n)]
    except KeyError as exc:
        raise SpcError(
            f"Tamanho de amostra {n} sem constantes tabeladas (suportado: {MIN_SUBGROUP_SIZE} a {MAX_SUBGROUP_SIZE})."
        ) from exc


def _mean(values: Sequence[float]) -> float:
    if not values:
        raise SpcError("É necessário pelo menos um subgrupo.")
    return math.fsum(values) / len(values)


def common_subgroup_size(sizes: Sequence[int]) -> int:
    """Retorna o tamanho de amostra comum; erro se os subgrupos tiverem tamanhos diferentes."""
    distinct = {int(s) for s in sizes}
    if not distinct:
        raise SpcError("É necessário pelo menos um subgrupo.")
    if len(distinct) > 1:
        raise SpcError(
            "Os subgrupos têm tamanhos de amostra diferentes "
            f"({', '.join(str(s) for s in sorted(distinct))}); "
            "os gráficos de Shewhart exigem tamanho constante."
        )
    return distinct.pop()


def xbar_r_limits(means: Sequence[float], ranges: Sequence[float], n: int) -> tuple[ControlLimits, ControlLimits]:
    """Limites para os gráficos X-barra e R."""
    f = factors_for(n)
    xbarbar = _mean(means)
    rbar = _mean(ranges)
    xbar = ControlLimits(xbarbar, xbarbar + f.A2 * rbar, xbarbar - f.A2 * rbar)
    r = ControlLimits(rbar, f.D4 * rbar, f.D3 * rbar)
    return xbar, r


def xbar_s_limits(means: Sequence[float], std_devs: Sequence[float], n: int) -> tuple[ControlLimits, ControlLimits]:
    """Limites para os gráficos X-barra e S (usa A3, B3 e B4)."""
    f = factors_for(n)
    xbarbar = _mean(means)
    sbar = _mean(std_devs)
    xbar = ControlLimits(xbarbar, xbarbar + f.A3 * sbar, xbarbar - f.A3 * sbar)
    s = ControlLimits(sbar, f.B4 * sbar, f.B3 * sbar)
    return xbar, s


def moving_ranges(values: Sequence[float]) -> list[float]:
    return [abs(b - a) for a, b in itertools.pairwise(values)]


def imr_limits(values: Sequence[float]) -> tuple[ControlLimits, ControlLimits]:
    """Limites para os gráficos de Indivíduos (I) e Amplitude Móvel (MR)."""
    if len(values) < 2:
        raise SpcError("São necessárias pelo menos 2 medições para I-MR.")
    mrbar = _mean(moving_ranges(values))
    center = _mean(values)
    spread = 3.0 * mrbar / _IMR.d2
    individuals = ControlLimits(center, center + spread, center - spread)
    mr = ControlLimits(mrbar, _IMR.D4 * mrbar, _IMR.D3 * mrbar)
    return individuals, mr


class Rule(StrEnum):
    BEYOND_3_SIGMA = "Regra 1"
    TWO_OF_THREE_BEYOND_2_SIGMA = "Regra 2"
    FOUR_OF_FIVE_BEYOND_1_SIGMA = "Regra 3"
    EIGHT_SAME_SIDE = "Regra 4"


RULE_DESCRIPTIONS: dict[Rule, str] = {
    Rule.BEYOND_3_SIGMA: "ponto além dos limites de controle (3σ)",
    Rule.TWO_OF_THREE_BEYOND_2_SIGMA: "2 de 3 pontos consecutivos além de 2σ do mesmo lado",
    Rule.FOUR_OF_FIVE_BEYOND_1_SIGMA: "4 de 5 pontos consecutivos além de 1σ do mesmo lado",
    Rule.EIGHT_SAME_SIDE: "8 pontos consecutivos do mesmo lado da linha central",
}


@dataclass(frozen=True, slots=True)
class Violation:
    rule: Rule
    index: int
    """Índice (0-based) do ponto em que a regra foi disparada."""

    @property
    def description(self) -> str:
        return RULE_DESCRIPTIONS[self.rule]


def western_electric(values: Sequence[float], limits: ControlLimits) -> list[Violation]:
    """Avalia as quatro regras de Western Electric sobre toda a série.

    Retorna uma violação por ponto/regra disparada, em ordem de índice.
    """
    sigma = limits.sigma
    if sigma <= 0:
        return []
    z = [(v - limits.center) / sigma for v in values]
    violations: list[Violation] = []

    def window_hits(i: int, size: int, need: int, threshold: float) -> bool:
        if i + 1 < size:
            return False
        window = z[i + 1 - size : i + 1]
        above = sum(1 for x in window if x > threshold)
        below = sum(1 for x in window if x < -threshold)
        # O ponto atual precisa participar do padrão para não repetir alertas antigos.
        current = z[i]
        return (above >= need and current > threshold) or (below >= need and current < -threshold)

    for i, zi in enumerate(z):
        if abs(zi) > 3:
            violations.append(Violation(Rule.BEYOND_3_SIGMA, i))
        if window_hits(i, 3, 2, 2):
            violations.append(Violation(Rule.TWO_OF_THREE_BEYOND_2_SIGMA, i))
        if window_hits(i, 5, 4, 1):
            violations.append(Violation(Rule.FOUR_OF_FIVE_BEYOND_1_SIGMA, i))
        if i >= 7:
            window = z[i - 7 : i + 1]
            if all(x > 0 for x in window) or all(x < 0 for x in window):
                violations.append(Violation(Rule.EIGHT_SAME_SIDE, i))
    return violations


@dataclass(frozen=True, slots=True)
class Capability:
    sigma_within: float
    cp: float
    cpk: float


def capability(mean: float, sigma_within: float, lsl: float, usl: float) -> Capability:
    """Índices Cp e Cpk a partir dos limites de especificação informados (LIE/LSE)."""
    if usl <= lsl:
        raise SpcError("O limite superior de especificação deve ser maior que o inferior.")
    if sigma_within <= 0:
        raise SpcError("Desvio padrão do processo deve ser positivo para calcular a capacidade.")
    cp = (usl - lsl) / (6 * sigma_within)
    cpk = min(usl - mean, mean - lsl) / (3 * sigma_within)
    return Capability(sigma_within, cp, cpk)


def sigma_within_from_ranges(ranges: Sequence[float], n: int) -> float:
    """Estimativa de σ dentro dos subgrupos: R̄ / d2."""
    return _mean(ranges) / factors_for(n).d2


@dataclass(frozen=True, slots=True)
class ParetoRow:
    label: str
    count: int
    cumulative_pct: float


def pareto(counts: dict[str, int]) -> list[ParetoRow]:
    """Ordena categorias por frequência e calcula a porcentagem acumulada."""
    items = sorted(((k, v) for k, v in counts.items() if v > 0), key=lambda kv: (-kv[1], kv[0]))
    total = sum(v for _, v in items)
    rows: list[ParetoRow] = []
    running = 0
    for label, count in items:
        running += count
        rows.append(ParetoRow(label, count, running * 100.0 / total))
    return rows
