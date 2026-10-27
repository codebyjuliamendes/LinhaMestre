"""Configurações do sistema (Gerente+), backup e auditoria (Administrador)."""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st

from ..domain import AccessLevel
from .common import Context, deny, fmt_dt


def render(ctx: Context) -> None:
    if not ctx.can(AccessLevel.GERENTE):
        deny()
        return
    st.title("Configurações")
    is_admin = ctx.can(AccessLevel.ADMINISTRADOR)
    tabs = st.tabs(["Parâmetros", "Backup", "Auditoria"] if is_admin else ["Parâmetros"])
    with tabs[0]:
        _parameters(ctx)
    if is_admin:
        with tabs[1]:
            _backup(ctx)
        with tabs[2]:
            _audit(ctx)


def _parameters(ctx: Context) -> None:
    flash = st.session_state.pop("settings_flash", None)
    if flash:
        st.success(flash)
    current = ctx.repo.get_app_settings()
    with st.form("system_settings_form"):
        min_qty = st.number_input(
            "Quantidade mínima padrão para novos produtos",
            min_value=0,
            max_value=1_000_000,
            value=current["default_min_quantity"],
            step=1,
        )
        warning_days = st.number_input(
            "Antecedência do aviso de validade (dias)",
            min_value=1,
            max_value=365,
            value=current["expiry_warning_days"],
            step=1,
        )
        submitted = st.form_submit_button("Salvar configurações", type="primary")
    if submitted:
        ctx.repo.save_app_settings(
            ctx.user.id, {"default_min_quantity": int(min_qty), "expiry_warning_days": int(warning_days)}
        )
        st.session_state["settings_flash"] = "Configurações salvas."
        st.rerun()


def _backup(ctx: Context) -> None:
    st.write(
        "Gera uma cópia consistente do banco SQLite (inclui hashes de senha: guarde o arquivo em local seguro). "
        "Para restaurar, pare a aplicação e substitua o arquivo indicado em `LINHAMESTRE_DB_PATH`."
    )
    if st.button("Preparar backup", icon=":material/database:"):
        st.session_state["backup_bytes"] = ctx.repo.backup_bytes()
        ctx.repo.log_audit(ctx.user.id, "BACKUP_CREATE", "Backup do banco gerado para download.")
    data = st.session_state.get("backup_bytes")
    if data:
        stamp = datetime.now(ctx.settings.timezone).strftime("%Y%m%d-%H%M")
        st.download_button(
            "Baixar backup",
            data=data,
            file_name=f"linhamestre-{stamp}.db",
            mime="application/vnd.sqlite3",
            icon=":material/download:",
            on_click="ignore",
        )


def _audit(ctx: Context) -> None:
    rows = ctx.repo.list_audit(limit=500)
    if not rows:
        st.info("Nenhum evento de auditoria registrado.")
        return
    df = pd.DataFrame(
        [
            {
                "Data": fmt_dt(r["created_at"], ctx.settings.timezone),
                "Usuário": r["username"],
                "Ação": r["action"],
                "Detalhes": r["details"],
            }
            for r in rows
        ]
    )
    st.caption("Últimos 500 eventos.")
    st.dataframe(df, hide_index=True)
