"""Cadastro, edição, listagem e relatórios de produtos."""

from __future__ import annotations

import io
from datetime import date
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ..domain import (
    QUALITY_STATUSES,
    UNITS,
    AccessLevel,
    ProductInput,
    ValidationError,
    expiry_status,
    stock_status,
)
from ..spc import pareto
from .common import Context, deny, index_of, md, parse_date

STOCK_FILTERS = ["Todos", "Crítico", "Normal"]
EXPIRY_FILTERS = ["Todos", "Válidos", "Próximos da Validade", "Vencidos"]


def render(ctx: Context) -> None:
    st.title("Gerenciamento de produtos")
    tab_list, tab_add, tab_edit, tab_reports = st.tabs(["Lista", "Adicionar", "Editar", "Relatórios"])
    with tab_list:
        _list(ctx)
    with tab_add:
        if ctx.can(AccessLevel.SUPERVISOR):
            _add(ctx)
        else:
            deny("Você não tem permissão para adicionar produtos.")
    with tab_edit:
        if ctx.can(AccessLevel.SUPERVISOR):
            _edit(ctx)
        else:
            deny("Você não tem permissão para editar produtos.")
    with tab_reports:
        _reports(ctx)


def _list(ctx: Context) -> None:
    c1, c2, c3 = st.columns(3)
    category = c1.selectbox("Categoria", ["Todas", *ctx.repo.categories()])
    stock = c2.selectbox("Estoque", STOCK_FILTERS)
    expiry = c3.selectbox("Validade", EXPIRY_FILTERS)
    rows = ctx.repo.list_products(
        ctx.today,
        ctx.warning_days,
        category=None if category == "Todas" else category,
        stock=None if stock == "Todos" else stock,
        expiry=None if expiry == "Todos" else expiry,
    )
    if not rows:
        st.info("Nenhum produto encontrado com os filtros selecionados.")
        return

    df = pd.DataFrame(
        [
            {
                "Nome": r["name"],
                "Categoria": r["category"],
                "Quantidade": r["quantity"],
                "Mínimo": r["min_quantity"],
                "Unidade": r["unit"],
                "Validade": parse_date(r["expiry_date"]),
                "Qualidade": r["quality_status"],
                "Localização": r["location"],
                "Status estoque": stock_status(r["quantity"], r["min_quantity"]),
                "Status validade": expiry_status(parse_date(r["expiry_date"]), ctx.today, ctx.warning_days),
            }
            for r in rows
        ]
    )
    max_qty = max(int(df["Quantidade"].max()), 1)
    st.dataframe(
        df,
        hide_index=True,
        column_config={
            "Quantidade": st.column_config.ProgressColumn(
                "Quantidade", format="%d", min_value=0, max_value=int(max_qty * 1.2)
            ),
            "Validade": st.column_config.DateColumn("Validade", format="DD/MM/YYYY"),
        },
    )
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Produtos")
    st.download_button(
        "Exportar para Excel",
        data=buffer.getvalue(),
        file_name="produtos.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        icon=":material/download:",
        on_click="ignore",
    )


def _product_form(ctx: Context, key: str, current: dict[str, Any] | None = None) -> ProductInput | None:
    """Renderiza os campos do produto dentro de um formulário; retorna os dados se enviados."""
    cur = current or {}
    c1, c2 = st.columns(2)
    with c1:
        name = st.text_input("Nome do produto *", value=str(cur.get("name") or ""), max_chars=100)
        category = st.text_input("Categoria *", value=str(cur.get("category") or ""), max_chars=50)
        quantity = st.number_input(
            "Quantidade em estoque *",
            min_value=0,
            step=1,
            value=int(cur.get("quantity") or 0),
        )
        min_quantity = st.number_input(
            "Quantidade mínima *",
            min_value=0,
            step=1,
            value=int(cur["min_quantity"]) if cur.get("min_quantity") is not None else ctx.default_min_quantity,
        )
        unit = st.selectbox("Unidade de medida *", UNITS, index=index_of(UNITS, cur.get("unit")))
    with c2:
        location = st.text_input("Localização no armazém", value=str(cur.get("location") or ""), max_chars=50)
        supplier = st.text_input("Fornecedor", value=str(cur.get("supplier") or ""), max_chars=100)
        cost = st.number_input("Custo unitário (R$)", min_value=0.0, format="%.2f", value=float(cur.get("cost") or 0.0))
        price = st.number_input(
            "Preço de venda (R$)", min_value=0.0, format="%.2f", value=float(cur.get("price") or 0.0)
        )
        barcode = st.text_input("Código de barras", value=str(cur.get("barcode") or ""), max_chars=50)
    d1, d2, d3 = st.columns(3)
    production_date = d1.date_input(
        "Data de produção", value=parse_date(cur.get("production_date")), format="DD/MM/YYYY"
    )
    expiry_date = d2.date_input("Data de validade", value=parse_date(cur.get("expiry_date")), format="DD/MM/YYYY")
    quality_status = d3.selectbox(
        "Status de qualidade", QUALITY_STATUSES, index=index_of(QUALITY_STATUSES, cur.get("quality_status"), 2)
    )
    notes = st.text_area("Observações", value=str(cur.get("notes") or ""), max_chars=1000)
    submitted = st.form_submit_button("Salvar produto", type="primary", key=f"{key}_submit")
    if not submitted:
        return None
    return ProductInput(
        name=name,
        category=category,
        quantity=int(quantity),
        min_quantity=int(min_quantity),
        unit=unit,
        location=location,
        supplier=supplier,
        cost=float(cost),
        price=float(price),
        barcode=barcode,
        production_date=production_date if isinstance(production_date, date) else None,
        expiry_date=expiry_date if isinstance(expiry_date, date) else None,
        quality_status=quality_status,
        notes=notes,
    )


def _show_validation(exc: ValidationError) -> None:
    st.error("\n".join(f"- {p}" for p in exc.problems))


def _add(ctx: Context) -> None:
    st.subheader("Adicionar novo produto")
    st.caption("Campos marcados com * são obrigatórios. Datas podem ficar em branco.")
    flash = st.session_state.pop("product_added", None)
    if flash:
        st.success(f"Produto “{md(flash)}” cadastrado com sucesso.")
    nonce = st.session_state.get("product_form_nonce", 0)
    with st.form(f"add_product_form_{nonce}"):
        data = _product_form(ctx, f"add_{nonce}")
    if data is not None:
        try:
            ctx.repo.create_product(ctx.user.id, data)
        except ValidationError as exc:
            _show_validation(exc)
        else:
            # Novo formulário vazio: evita cadastro duplicado por reenvio.
            st.session_state["product_added"] = data.name.strip()
            st.session_state["product_form_nonce"] = nonce + 1
            st.rerun()


def _edit(ctx: Context) -> None:
    st.subheader("Editar produto existente")
    options = ctx.repo.product_options()
    if not options:
        st.info("Nenhum produto cadastrado para editar.")
        return
    labels = {f"{p['name']} (ID {p['id']})": int(p["id"]) for p in options}
    selected = st.selectbox("Produto", list(labels))
    product_id = labels[selected]
    row = ctx.repo.get_product(product_id)
    if row is None:
        st.error("Produto não encontrado.")
        return

    with st.form(f"edit_product_form_{product_id}"):
        data = _product_form(ctx, f"edit_{product_id}", dict(row))
    if data is not None:
        try:
            ctx.repo.update_product(ctx.user.id, product_id, data)
        except ValidationError as exc:
            _show_validation(exc)
        except LookupError as exc:
            st.error(str(exc))
        else:
            st.success("Produto atualizado com sucesso.")

    with st.expander("Excluir produto", icon=":material/delete:"):
        st.write("A exclusão remove também as medições de controle de qualidade do produto e não pode ser desfeita.")
        confirm = st.checkbox("Confirmo que desejo excluir este produto", key=f"confirm_delete_{product_id}")
        if st.button("Excluir definitivamente", disabled=not confirm, key=f"delete_{product_id}"):
            try:
                ctx.repo.delete_product(ctx.user.id, product_id)
            except LookupError as exc:
                st.error(str(exc))
            else:
                st.toast("Produto excluído.")
                st.rerun()


def _reports(ctx: Context) -> None:
    report = st.selectbox(
        "Tipo de relatório",
        ["Estoque por Categoria", "Produtos Críticos", "Validade de Produtos", "Qualidade de Produtos"],
    )
    df: pd.DataFrame
    if report == "Estoque por Categoria":
        df = pd.DataFrame(
            [dict(r) for r in ctx.repo.stock_by_category()],
            columns=["category", "total_quantity", "product_count", "avg_price"],
        ).rename(
            columns={
                "category": "Categoria",
                "total_quantity": "Quantidade total",
                "product_count": "Produtos",
                "avg_price": "Preço médio (R$)",
            }
        )
        if not df.empty:
            df["Preço médio (R$)"] = df["Preço médio (R$)"].astype(float).round(2)
            st.plotly_chart(
                px.bar(df, x="Categoria", y="Quantidade total", color="Produtos", hover_data=["Preço médio (R$)"])
            )
    elif report == "Produtos Críticos":
        df = pd.DataFrame(
            [dict(r) for r in ctx.repo.critical_products()],
            columns=["name", "category", "quantity", "min_quantity", "unit", "location", "pct"],
        ).rename(
            columns={
                "name": "Produto",
                "category": "Categoria",
                "quantity": "Quantidade",
                "min_quantity": "Mínimo",
                "unit": "Unidade",
                "location": "Localização",
                "pct": "% do mínimo",
            }
        )
        if not df.empty:
            df["% do mínimo"] = df["% do mínimo"].astype(float).round(1)
            fig = px.bar(df, x="Produto", y="% do mínimo", color="Categoria", hover_data=["Quantidade", "Mínimo"])
            fig.update_yaxes(range=[0, 100])
            st.plotly_chart(fig)
    elif report == "Validade de Produtos":
        df = pd.DataFrame(
            [dict(r) for r in ctx.repo.expiry_report(ctx.today, ctx.warning_days)],
            columns=["status", "count", "total_quantity"],
        ).rename(columns={"status": "Status", "count": "Produtos", "total_quantity": "Quantidade total"})
        if not df.empty:
            st.plotly_chart(px.pie(df, values="Produtos", names="Status", hover_data=["Quantidade total"]))
    else:
        df = pd.DataFrame(
            [dict(r) for r in ctx.repo.quality_status_counts()],
            columns=["quality_status", "count", "total_quantity"],
        ).rename(
            columns={"quality_status": "Status de qualidade", "count": "Produtos", "total_quantity": "Quantidade total"}
        )
        if not df.empty:
            st.plotly_chart(
                pareto_figure({str(k): int(v) for k, v in zip(df["Status de qualidade"], df["Produtos"], strict=True)})
            )

    if df.empty:
        st.info("Nenhum dado disponível para este relatório.")
        return
    st.dataframe(df, hide_index=True)
    st.download_button(
        "Exportar relatório (CSV)",
        data=df.to_csv(index=False).encode("utf-8-sig"),
        file_name=f"{report.lower().replace(' ', '_')}.csv",
        mime="text/csv",
        icon=":material/download:",
        on_click="ignore",
    )


def pareto_figure(counts: dict[str, int], title: str = "Análise de Pareto") -> go.Figure:
    rows = pareto(counts)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=[r.label for r in rows], y=[r.count for r in rows], name="Ocorrências"))
    fig.add_trace(
        go.Scatter(
            x=[r.label for r in rows],
            y=[r.cumulative_pct for r in rows],
            name="% acumulada",
            yaxis="y2",
            mode="lines+markers",
        )
    )
    fig.update_layout(
        title=title,
        yaxis={"title": {"text": "Ocorrências"}},
        yaxis2={"title": {"text": "% acumulada"}, "overlaying": "y", "side": "right", "range": [0, 110]},
        legend={"orientation": "h", "y": -0.2},
        margin={"l": 10, "r": 10, "t": 50, "b": 10},
    )
    return fig
