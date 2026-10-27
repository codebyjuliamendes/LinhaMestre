"""Mensagens internas entre usuários."""

from __future__ import annotations

import sqlite3

import streamlit as st

from .common import Context, fmt_dt, md

READ_FILTERS = {"Todas": None, "Não lidas": False, "Lidas": True}


def render(ctx: Context) -> None:
    st.title("Mensagens")
    inbox_tab, send_tab, sent_tab = st.tabs(["Caixa de entrada", "Nova mensagem", "Enviadas"])
    with inbox_tab:
        _inbox(ctx)
    with send_tab:
        _compose(ctx)
    with sent_tab:
        _sent(ctx)


def _send(ctx: Context, receiver_id: int, subject: str, content: str) -> bool:
    try:
        ctx.repo.send_message(ctx.user.id, receiver_id, subject, content)
    except (ValueError, LookupError) as exc:
        st.error(str(exc))
        return False
    return True


def _inbox(ctx: Context) -> None:
    flash = st.session_state.pop("message_flash", None)
    if flash:
        st.success(flash)
    others = ctx.repo.other_users(ctx.user.id)
    c1, c2 = st.columns(2)
    read_label = c1.selectbox("Status", list(READ_FILTERS))
    senders = {f"{u.name} ({u.username})": u.id for u in others}
    sender_label = c2.selectbox("Remetente", ["Todos", *senders])
    rows = ctx.repo.inbox(
        ctx.user.id,
        read=READ_FILTERS[read_label],
        sender_id=None if sender_label == "Todos" else senders[sender_label],
    )
    if not rows:
        st.info("Nenhuma mensagem encontrada com os filtros selecionados.")
        return
    for msg in rows:
        _inbox_item(ctx, msg)


def _inbox_item(ctx: Context, msg: sqlite3.Row) -> None:
    with st.container(border=True):
        badge = " · **não lida**" if not msg["is_read"] else ""
        st.markdown(f"**{md(msg['sender'])}**: {md(msg['subject'])}{badge}")
        st.caption(f"Recebida em {fmt_dt(msg['created_at'], ctx.settings.timezone)}")
        with st.expander("Ver mensagem"):
            st.markdown(md(msg["content"]))
        if not msg["is_read"] and st.button("Marcar como lida", key=f"read_{msg['id']}"):
            ctx.repo.mark_read(msg["id"], ctx.user.id)
            st.rerun()
        if msg["sender_id"] is not None and ctx.repo.get_user(msg["sender_id"]) is not None:
            with st.expander("Responder"), st.form(f"reply_form_{msg['id']}", clear_on_submit=True):
                subject = str(msg["subject"] or "")
                reply_subject = subject if subject.startswith("Re:") else f"Re: {subject}"
                content = st.text_area("Resposta *", max_chars=5000, key=f"reply_text_{msg['id']}")
                if st.form_submit_button("Enviar resposta", type="primary") and _send(
                    ctx, int(msg["sender_id"]), reply_subject[:100], content
                ):
                    ctx.repo.mark_read(msg["id"], ctx.user.id)
                    st.session_state["message_flash"] = "Resposta enviada."
                    st.rerun()


def _compose(ctx: Context) -> None:
    recipients = {f"{u.name} ({u.access_level})": u.id for u in ctx.repo.other_users(ctx.user.id)}
    if not recipients:
        st.info("Não há outros usuários cadastrados para receber mensagens.")
        return
    with st.form("send_message_form", clear_on_submit=True):
        recipient = st.selectbox("Destinatário *", list(recipients))
        subject = st.text_input("Assunto *", max_chars=100)
        content = st.text_area("Mensagem *", height=200, max_chars=5000)
        submitted = st.form_submit_button("Enviar mensagem", type="primary")
    if submitted and _send(ctx, recipients[recipient], subject, content):
        st.success("Mensagem enviada com sucesso.")


def _sent(ctx: Context) -> None:
    rows = ctx.repo.sent(ctx.user.id)
    if not rows:
        st.info("Você ainda não enviou nenhuma mensagem.")
        return
    for msg in rows:
        with st.container(border=True):
            st.markdown(f"Para **{md(msg['recipient'])}**: {md(msg['subject'])}")
            status = "lida" if msg["is_read"] else "não lida"
            st.caption(f"Enviada em {fmt_dt(msg['created_at'], ctx.settings.timezone)} · {status}")
            with st.expander("Ver mensagem"):
                st.markdown(md(msg["content"]))
