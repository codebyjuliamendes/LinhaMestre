"""Tarefas: minhas tarefas, criação (Supervisor+) e visão geral com Gantt (Gerente+)."""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

from ..domain import TASK_DONE, TASK_PENDING, TASK_PRIORITIES, AccessLevel, task_deadline_label
from .common import Context, deny, fmt_date, local_dt, md, parse_date

STATUS_FILTERS = ["Todas", TASK_PENDING, TASK_DONE, "Atrasada"]
PRIORITY_ICON = {
    "Alta": ":material/priority_high:",
    "Média": ":material/drag_handle:",
    "Baixa": ":material/low_priority:",
}


def render(ctx: Context) -> None:
    st.title("Tarefas")
    mine_tab, create_tab, all_tab = st.tabs(["Minhas tarefas", "Criar tarefa", "Todas as tarefas"])
    with mine_tab:
        _mine(ctx)
    with create_tab:
        if ctx.can(AccessLevel.SUPERVISOR):
            _create(ctx)
        else:
            deny("Você não tem permissão para criar tarefas.")
    with all_tab:
        if ctx.can(AccessLevel.GERENTE):
            _all(ctx)
        else:
            deny("Você não tem permissão para visualizar todas as tarefas.")


def _filters(prefix: str) -> tuple[str | None, str | None]:
    c1, c2 = st.columns(2)
    status = c1.selectbox("Status", STATUS_FILTERS, key=f"{prefix}_status")
    priority = c2.selectbox("Prioridade", ["Todas", *TASK_PRIORITIES], key=f"{prefix}_priority")
    return (None if status == "Todas" else status), (None if priority == "Todas" else priority)


def _task_card(ctx: Context, task: sqlite3.Row, *, show_assignee: bool, any_task: bool) -> None:
    due = parse_date(task["due_date"])
    with st.container(border=True):
        icon = PRIORITY_ICON.get(task["priority"], "")
        st.markdown(f"**{md(task['title'])}** · {icon} {md(task['priority'] or '—')}")
        if task["status"] == TASK_DONE:
            done = local_dt(task["completed_at"], ctx.settings.timezone)
            done_txt = done.strftime("%d/%m/%Y") if done else "—"
            st.caption(f"Concluída em {done_txt} · prazo original {fmt_date(due)}")
        else:
            label = task_deadline_label(due, ctx.today)
            overdue = due is not None and due < ctx.today
            st.caption(("⚠️ " if overdue else "") + f"{label} · prazo {fmt_date(due)}")
        who = f"Atribuída a {md(task['assignee'])} · " if show_assignee else ""
        st.caption(f"{who}criada por {md(task['creator'])}")
        with st.expander("Detalhes"):
            st.markdown(md(task["description"] or ""))
        if task["status"] == TASK_PENDING and st.button(
            "Marcar como concluída", key=f"{'all' if any_task else 'mine'}_done_{task['id']}"
        ):
            ctx.repo.complete_task(ctx.user.id, task["id"], any_task=any_task)
            st.rerun()


def _mine(ctx: Context) -> None:
    status, priority = _filters("mine")
    rows = ctx.repo.tasks(ctx.today, assigned_to=ctx.user.id, status=status, priority=priority)
    if not rows:
        st.info("Nenhuma tarefa encontrada com os filtros selecionados.")
        return
    for task in rows:
        _task_card(ctx, task, show_assignee=False, any_task=False)


def _create(ctx: Context) -> None:
    flash = st.session_state.pop("task_flash", None)
    if flash:
        st.success(flash)
    assignees = {f"{u.name} ({u.access_level})": u.id for u in ctx.repo.other_users(ctx.user.id)}
    assignees = {f"Eu mesmo(a) ({ctx.user.access_level})": ctx.user.id, **assignees}
    with st.form("create_task_form", clear_on_submit=True):
        title = st.text_input("Título *", max_chars=100)
        description = st.text_area("Descrição *", height=150, max_chars=5000)
        c1, c2, c3 = st.columns(3)
        priority = c1.selectbox("Prioridade *", TASK_PRIORITIES)
        due = c2.date_input("Prazo", value=None, min_value=ctx.today, format="DD/MM/YYYY")
        assignee = c3.selectbox("Atribuir a *", list(assignees))
        submitted = st.form_submit_button("Criar tarefa", type="primary")
    if submitted:
        try:
            ctx.repo.create_task(
                ctx.user.id, title, description, assignees[assignee], priority, due if isinstance(due, date) else None
            )
        except (ValueError, LookupError) as exc:
            st.error(str(exc))
        else:
            st.session_state["task_flash"] = "Tarefa criada com sucesso."
            st.rerun()


def _all(ctx: Context) -> None:
    status, priority = _filters("all")
    users = {f"{r['name']} ({r['username']})": int(r["id"]) for r in ctx.repo.list_users()}
    who = st.selectbox("Atribuída a", ["Todos", *users])
    rows = ctx.repo.tasks(
        ctx.today, assigned_to=None if who == "Todos" else users[who], status=status, priority=priority
    )
    if rows:
        for task in rows:
            _task_card(ctx, task, show_assignee=True, any_task=True)
    else:
        st.info("Nenhuma tarefa encontrada com os filtros selecionados.")

    st.subheader("Linha do tempo (Gantt)")
    gantt = gantt_frame(rows, ctx)
    if gantt.empty:
        st.info("Nenhuma tarefa com prazo para exibir na linha do tempo.")
        return
    fig = px.timeline(
        gantt,
        x_start="Início",
        x_end="Fim",
        y="Tarefa",
        color="Responsável",
        hover_data=["Prioridade", "Status", "Prazo"],
    )
    fig.update_yaxes(autorange="reversed", title="")
    fig.update_layout(
        height=max(300, 40 * len(gantt) + 120), xaxis_title="", margin={"l": 10, "r": 10, "t": 10, "b": 10}
    )
    st.plotly_chart(fig)


def gantt_frame(rows: list[sqlite3.Row], ctx: Context) -> pd.DataFrame:
    """Barra de cada tarefa: da criação até a conclusão (ou até o prazo, se pendente)."""
    records = []
    for t in rows:
        due = parse_date(t["due_date"])
        if due is None:
            continue
        created = local_dt(t["created_at"], ctx.settings.timezone)
        start = created.date() if created else ctx.today
        done = local_dt(t["completed_at"], ctx.settings.timezone)
        end = done.date() if (t["status"] == TASK_DONE and done) else max(due, ctx.today)
        if end <= start:
            end = start + timedelta(days=1)
        records.append(
            {
                "Tarefa": t["title"],
                "Responsável": t["assignee"],
                "Início": datetime.combine(start, datetime.min.time()),
                "Fim": datetime.combine(end, datetime.min.time()),
                "Prioridade": t["priority"],
                "Status": t["status"],
                "Prazo": fmt_date(due),
            }
        )
    return pd.DataFrame(records)
