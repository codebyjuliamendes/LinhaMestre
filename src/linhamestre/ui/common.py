"""Utilitários compartilhados pelas páginas Streamlit."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from zoneinfo import ZoneInfo

import plotly.graph_objects as go
import streamlit as st

from ..config import Settings
from ..db import Repository, User
from ..domain import AccessLevel, has_permission
from ..spc import ControlLimits, Violation

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$=:])")


def md(text: object) -> str:
    """Escapa texto do usuário para uso seguro em ``st.markdown`` (sem links, imagens, LaTeX ou HTML)."""
    escaped = _MD_SPECIAL.sub(r"\\\1", str(text))
    return escaped.replace("\n", "  \n")


@dataclass(frozen=True, slots=True)
class Context:
    repo: Repository
    user: User
    settings: Settings
    today: date
    warning_days: int
    default_min_quantity: int

    def can(self, level: AccessLevel) -> bool:
        return has_permission(self.user.access_level, level)


def deny(message: str = "Você não tem permissão para acessar esta área.") -> None:
    st.warning(message, icon=":material/lock:")


def parse_date(value: object) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def local_dt(value: object, tz: ZoneInfo) -> datetime | None:
    """Converte um ``CURRENT_TIMESTAMP`` do SQLite (UTC) para o fuso configurado."""
    if value in (None, ""):
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(tz)


def fmt_dt(value: object, tz: ZoneInfo) -> str:
    dt = local_dt(value, tz)
    return dt.strftime("%d/%m/%Y %H:%M") if dt else "—"


def fmt_date(value: object) -> str:
    d = parse_date(value)
    return d.strftime("%d/%m/%Y") if d else "—"


def index_of(options: Sequence[str], value: object, default: int = 0) -> int:
    try:
        return list(options).index(str(value))
    except ValueError:
        return default


def control_chart(
    x: Sequence[object],
    y: Sequence[float],
    limits: ControlLimits,
    *,
    title: str,
    y_title: str,
    violations: Sequence[Violation] = (),
) -> go.Figure:
    """Gráfico de controle com LC/LSC/LIC e pontos de violação destacados."""
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=list(x), y=list(y), mode="lines+markers", name=y_title))
    for value, name, dash, color in (
        (limits.center, "LC", "dash", "#16a34a"),
        (limits.ucl, "LSC", "dot", "#dc2626"),
        (limits.lcl, "LIC", "dot", "#dc2626"),
    ):
        fig.add_hline(
            y=value,
            line_dash=dash,
            line_color=color,
            annotation_text=f"{name} {value:.4g}",
            annotation_position="top left",
            annotation_font_color=color,
        )
    flagged = sorted({v.index for v in violations})
    if flagged:
        fig.add_trace(
            go.Scatter(
                x=[x[i] for i in flagged],
                y=[y[i] for i in flagged],
                mode="markers",
                name="Violação",
                marker={"size": 13, "symbol": "x", "color": "#dc2626"},
            )
        )
    fig.update_layout(
        title=title,
        xaxis_title="Data",
        yaxis_title=y_title,
        margin={"l": 10, "r": 10, "t": 50, "b": 10},
        legend={"orientation": "h", "y": -0.25},
    )
    return fig
