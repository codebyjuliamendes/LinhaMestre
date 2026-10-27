"""Gestão de usuários (somente Administrador)."""

from __future__ import annotations

import sqlite3

import pandas as pd
import streamlit as st

from ..domain import ACCESS_LEVELS_DESC, AccessLevel, validate_user_fields
from ..security import hash_password, password_problems
from .common import Context, deny, fmt_dt, index_of, md

LEVELS = [lvl.value for lvl in ACCESS_LEVELS_DESC]


def render(ctx: Context) -> None:
    if not ctx.can(AccessLevel.ADMINISTRADOR):
        deny()
        return
    st.title("Usuários")
    flash = st.session_state.pop("user_flash", None)
    if flash:
        st.success(flash)
    list_tab, add_tab, edit_tab = st.tabs(["Lista", "Adicionar", "Editar"])
    with list_tab:
        rows = ctx.repo.list_users()
        df = pd.DataFrame(
            [
                {
                    "Usuário": r["username"],
                    "Nome": r["name"],
                    "E-mail": r["email"],
                    "Nível de acesso": r["access_level"],
                    "Criado em": fmt_dt(r["created_at"], ctx.settings.timezone),
                }
                for r in rows
            ]
        )
        st.dataframe(df, hide_index=True)
    with add_tab:
        _add(ctx)
    with edit_tab:
        _edit(ctx)


def _add(ctx: Context) -> None:
    with st.form("add_user_form", clear_on_submit=True):
        username = st.text_input("Nome de usuário *", max_chars=50)
        password = st.text_input(
            "Senha *", type="password", max_chars=128, help="Mínimo de 8 caracteres, com letras e números ou símbolos."
        )
        name = st.text_input("Nome completo *", max_chars=100)
        email = st.text_input("E-mail", max_chars=100)
        level = st.selectbox("Nível de acesso *", LEVELS, index=len(LEVELS) - 1)
        submitted = st.form_submit_button("Cadastrar usuário", type="primary")
    if not submitted:
        return
    problems = validate_user_fields(username.strip(), name, email.strip()) + password_problems(password)
    if problems:
        st.error("\n".join(f"- {p}" for p in problems))
        return
    try:
        ctx.repo.create_user(ctx.user.id, username.strip(), hash_password(password), name.strip(), email.strip(), level)
    except sqlite3.IntegrityError:
        st.error("Nome de usuário já existe. Escolha outro.")
    else:
        st.session_state["user_flash"] = f"Usuário “{md(username.strip())}” cadastrado."
        st.rerun()


def _edit(ctx: Context) -> None:
    rows = ctx.repo.list_users()
    if not rows:
        st.info("Nenhum usuário cadastrado.")
        return
    labels = {f"{r['username']} (ID {r['id']})": int(r["id"]) for r in rows}
    user_id = labels[st.selectbox("Usuário", list(labels))]
    user = ctx.repo.get_user(user_id)
    if user is None:
        st.error("Usuário não encontrado.")
        return
    is_self = user.id == ctx.user.id

    with st.form(f"edit_user_form_{user_id}"):
        new_username = st.text_input("Nome de usuário *", value=user.username, max_chars=50)
        new_password = st.text_input("Nova senha (deixe em branco para manter)", type="password", max_chars=128)
        new_name = st.text_input("Nome completo *", value=user.name, max_chars=100)
        new_email = st.text_input("E-mail", value=user.email, max_chars=100)
        new_level = st.selectbox(
            "Nível de acesso *", LEVELS, index=index_of(LEVELS, user.access_level, len(LEVELS) - 1)
        )
        submitted = st.form_submit_button("Salvar alterações", type="primary")
    if submitted:
        problems = validate_user_fields(new_username.strip(), new_name, new_email.strip())
        if new_password:
            problems += password_problems(new_password)
        demoting_admin = user.access_level == AccessLevel.ADMINISTRADOR.value and new_level != user.access_level
        if demoting_admin and ctx.repo.count_admins() <= 1:
            problems.append("Não é possível remover o perfil do último administrador.")
        if problems:
            st.error("\n".join(f"- {p}" for p in problems))
        else:
            try:
                ctx.repo.update_user(
                    ctx.user.id,
                    user_id,
                    new_username.strip(),
                    new_name.strip(),
                    new_email.strip(),
                    new_level,
                    hash_password(new_password) if new_password else None,
                )
            except sqlite3.IntegrityError:
                st.error("Nome de usuário já existe. Escolha outro.")
            else:
                st.session_state["user_flash"] = "Usuário atualizado."
                st.rerun()

    with st.expander("Excluir usuário", icon=":material/person_remove:"):
        if is_self:
            st.info("Você não pode excluir o próprio usuário.")
            return
        if user.access_level == AccessLevel.ADMINISTRADOR.value and ctx.repo.count_admins() <= 1:
            st.info("Não é possível excluir o último administrador.")
            return
        st.write("Mensagens e tarefas do usuário são mantidas e aparecem como “usuário removido”.")
        confirm = st.checkbox("Confirmo a exclusão deste usuário", key=f"confirm_user_delete_{user_id}")
        if st.button("Excluir definitivamente", disabled=not confirm, key=f"user_delete_{user_id}"):
            ctx.repo.delete_user(ctx.user.id, user_id)
            st.session_state["user_flash"] = "Usuário excluído."
            st.rerun()
