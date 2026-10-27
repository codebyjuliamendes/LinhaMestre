"""Página inicial: indicadores, alertas, mensagens e tarefas do usuário."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from ..domain import TASK_PENDING, stock_ratio_pct, task_deadline_label
from .common import Context, fmt_date, fmt_dt, md, parse_date


def render(ctx: Context) -> None:
    st.title("Dashboard")
    st.caption(f"Bem-vindo(a), {md(ctx.user.name)} · perfil {md(ctx.user.access_level)}")

    counts = ctx.repo.dashboard_counts(ctx.user.id, ctx.today, ctx.warning_days)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total de produtos", counts["products"], border=True)
    c2.metric("Estoque crítico", counts["critical"], border=True)
    c3.metric(f"Vencem em {ctx.warning_days} dias", counts["expiring"], border=True)
    c4.metric("Minhas tarefas pendentes", counts["pending_tasks"], border=True)

    left, right = st.columns(2)
    with left:
        st.subheader("Estoque por categoria")
        rows = ctx.repo.stock_by_category()
        if rows:
            df = pd.DataFrame([dict(r) for r in rows])
            fig = px.pie(df, values="total_quantity", names="category", labels={"total_quantity": "Quantidade"})
            fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10})
            st.plotly_chart(fig)
        else:
            st.info("Nenhum produto cadastrado ainda.")
    with right:
        st.subheader("Próximos da validade")
        rows = ctx.repo.expiring_products(ctx.today, ctx.warning_days)
        if rows:
            df = pd.DataFrame([dict(r) for r in rows])
            df["Validade"] = df["expiry_date"].map(fmt_date)
            fig = px.bar(
                df, x="name", y="quantity", color="Validade", labels={"name": "Produto", "quantity": "Quantidade"}
            )
            fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10})
            st.plotly_chart(fig)
        else:
            st.info(f"Nenhum produto vence nos próximos {ctx.warning_days} dias.")

    st.subheader("Alertas de estoque crítico")
    critical = ctx.repo.critical_products(limit=5)
    if critical:
        for item in critical:
            pct = stock_ratio_pct(item["quantity"], item["min_quantity"])
            pct_txt = f"{pct:.0f}% do mínimo" if pct is not None else "mínimo zero"
            st.warning(
                f"**{md(item['name'])}**: {item['quantity']} {md(item['unit'])} "
                f"(mínimo {item['min_quantity']}, {pct_txt}) · local: {md(item['location'] or '—')}"
            )
    else:
        st.success("Nenhum item em estoque crítico no momento.")

    st.subheader("Mensagens não lidas")
    unread = ctx.repo.inbox(ctx.user.id, read=False)[:5]
    if unread:
        for msg in unread:
            with st.container(border=True):
                st.markdown(f"**{md(msg['sender'])}** · {md(msg['subject'])}")
                with st.expander("Ver mensagem"):
                    st.markdown(md(msg["content"]))
                    st.caption(f"Enviada em {fmt_dt(msg['created_at'], ctx.settings.timezone)}")
                if st.button("Marcar como lida", key=f"dash_read_{msg['id']}"):
                    ctx.repo.mark_read(msg["id"], ctx.user.id)
                    st.rerun()
    else:
        st.info("Nenhuma mensagem não lida.")

    st.subheader("Minhas tarefas pendentes")
    pending = ctx.repo.tasks(ctx.today, assigned_to=ctx.user.id, status=TASK_PENDING)[:5]
    if pending:
        for task in pending:
            due = parse_date(task["due_date"])
            with st.expander(f"{md(task['title'])} · {task_deadline_label(due, ctx.today)}"):
                st.markdown(md(task["description"] or ""))
                st.caption(f"Prazo: {fmt_date(due)} · criada por {md(task['creator'])}")
                if st.button("Marcar como concluída", key=f"dash_done_{task['id']}"):
                    ctx.repo.complete_task(ctx.user.id, task["id"])
                    st.rerun()
    else:
        st.success("Nenhuma tarefa pendente.")
