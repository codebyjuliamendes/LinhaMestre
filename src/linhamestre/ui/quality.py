"""Gráficos de controle estatístico (X-barra/R, X-barra/S, I-MR), Pareto e capacidade."""

from __future__ import annotations

from datetime import date

import pandas as pd
import plotly.express as px
import streamlit as st

from .. import spc
from ..domain import AccessLevel
from .common import Context, control_chart, deny, fmt_date, md
from .products import pareto_figure


def render(ctx: Context) -> None:
    if not ctx.can(AccessLevel.SUPERVISOR):
        deny()
        return
    st.title("Controle estatístico de qualidade")

    options = ctx.repo.product_options()
    if not options:
        st.info("Nenhum produto cadastrado. Cadastre produtos antes de registrar medições.")
        return
    labels = {f"{p['name']} (ID {p['id']})": int(p["id"]) for p in options}
    with_data = ctx.repo.products_with_qc()
    default = next((i for i, pid in enumerate(labels.values()) if pid in with_data), 0)
    product_id = labels[st.selectbox("Produto", list(labels), index=default, key="qc_product_selector")]

    _add_measurement(ctx, product_id)

    rows = ctx.repo.qc_rows(product_id)
    df = pd.DataFrame(
        [dict(r) for r in rows], columns=["control_date", "sample_size", "mean_value", "range_value", "std_dev"]
    )
    df["Data"] = df["control_date"].map(fmt_date)

    t_xr, t_xs, t_imr, t_pareto, t_hist = st.tabs(
        ["X-barra & R", "X-barra & S", "I-MR", "Pareto", "Histograma e capacidade"]
    )
    with t_pareto:
        _pareto(ctx)
    if df.empty:
        for tab in (t_xr, t_xs, t_imr, t_hist):
            with tab:
                st.info("Nenhuma medição registrada para este produto. Use “Registrar medição” acima.")
        return

    try:
        n = spc.common_subgroup_size([int(s) for s in df["sample_size"]])
        spc.factors_for(n)
        n_error = None
    except spc.SpcError as exc:
        n, n_error = 0, str(exc)

    with t_xr:
        if n_error:
            st.warning(n_error)
        else:
            _xbar_r(df, n)
    with t_xs:
        if n_error:
            st.warning(n_error)
        else:
            _xbar_s(df, n)
    with t_imr:
        _imr(df)
    with t_hist:
        _histogram(df, n if not n_error else None)


def _add_measurement(ctx: Context, product_id: int) -> None:
    flash = st.session_state.pop("qc_flash", None)
    if flash:
        st.success(flash)
    with (
        st.expander("Registrar medição", icon=":material/add:"),
        st.form(f"qc_form_{product_id}", clear_on_submit=True),
    ):
        c1, c2 = st.columns(2)
        control_date = c1.date_input("Data do controle", value=ctx.today, max_value=ctx.today, format="DD/MM/YYYY")
        sample_size = c2.number_input(
            "Tamanho da amostra (n)",
            min_value=spc.MIN_SUBGROUP_SIZE,
            max_value=spc.MAX_SUBGROUP_SIZE,
            value=5,
            step=1,
        )
        c3, c4, c5 = st.columns(3)
        mean_value = c3.number_input("Média da amostra", format="%.4f", value=0.0)
        range_value = c4.number_input("Amplitude (máx − mín)", min_value=0.0, format="%.4f", value=0.0)
        std_dev = c5.number_input("Desvio padrão da amostra", min_value=0.0, format="%.4f", value=0.0)
        submitted = st.form_submit_button("Registrar medição", type="primary")
    if submitted:
        try:
            if not isinstance(control_date, date):
                raise ValueError("Informe a data do controle.")
            ctx.repo.add_qc(
                ctx.user.id,
                product_id,
                control_date,
                int(sample_size),
                float(mean_value),
                float(range_value),
                float(std_dev),
            )
        except (ValueError, LookupError) as exc:
            st.error(str(exc))
        else:
            st.session_state["qc_flash"] = "Medição registrada."
            st.rerun()


def _violations_report(violations: list[spc.Violation], dates: list[str]) -> None:
    if not violations:
        st.success("Processo sob controle estatístico: nenhuma regra de Western Electric foi violada.")
        return
    st.error("Sinais de instabilidade (regras de Western Electric)")
    by_rule: dict[spc.Rule, list[str]] = {}
    for v in violations:
        by_rule.setdefault(v.rule, []).append(dates[v.index])
    for rule, at in sorted(by_rule.items(), key=lambda kv: kv[0].value):
        shown = ", ".join(at[-5:]) + (" …" if len(at) > 5 else "")
        st.markdown(f"- **{rule.value}** — {spc.RULE_DESCRIPTIONS[rule]}: {md(shown)}")


def _xbar_r(df: pd.DataFrame, n: int) -> None:
    means = [float(v) for v in df["mean_value"]]
    ranges = [float(v) for v in df["range_value"].fillna(0)]
    xbar, r = spc.xbar_r_limits(means, ranges, n)
    violations = spc.western_electric(means, xbar)
    dates = list(df["Data"])
    x = list(df["control_date"])
    st.plotly_chart(control_chart(x, means, xbar, title="X-barra (médias)", y_title="Média", violations=violations))
    _violations_report(violations, dates)
    st.plotly_chart(control_chart(x, ranges, r, title="R (amplitudes)", y_title="Amplitude"))
    st.caption(f"n = {n} · constantes A2, D3 e D4 tabeladas para o tamanho de amostra.")
    st.dataframe(
        df[["Data", "sample_size", "mean_value", "range_value"]].rename(
            columns={"sample_size": "n", "mean_value": "Média", "range_value": "Amplitude"}
        ),
        hide_index=True,
    )


def _xbar_s(df: pd.DataFrame, n: int) -> None:
    valid = df.dropna(subset=["std_dev"])
    if valid.empty:
        st.info("Nenhuma medição com desvio padrão registrado.")
        return
    means = [float(v) for v in valid["mean_value"]]
    stds = [float(v) for v in valid["std_dev"]]
    xbar, s = spc.xbar_s_limits(means, stds, n)
    x = list(valid["control_date"])
    violations = spc.western_electric(means, xbar)
    st.plotly_chart(
        control_chart(x, means, xbar, title="X-barra (médias, limites via S)", y_title="Média", violations=violations)
    )
    _violations_report(violations, list(valid["Data"]))
    st.plotly_chart(control_chart(x, stds, s, title="S (desvios padrão)", y_title="Desvio padrão"))
    st.caption(f"n = {n} · constantes A3, B3 e B4 tabeladas para o tamanho de amostra.")


def _imr(df: pd.DataFrame) -> None:
    values = [float(v) for v in df["mean_value"]]
    if len(values) < 2:
        st.info("São necessárias pelo menos 2 medições para os gráficos I-MR.")
        return
    st.caption("Cada ponto é a média registrada do subgrupo, tratada como valor individual.")
    individuals, mr = spc.imr_limits(values)
    x = list(df["control_date"])
    violations = spc.western_electric(values, individuals)
    st.plotly_chart(
        control_chart(x, values, individuals, title="I (valores individuais)", y_title="Valor", violations=violations)
    )
    _violations_report(violations, list(df["Data"]))
    st.plotly_chart(
        control_chart(x[1:], spc.moving_ranges(values), mr, title="MR (amplitude móvel)", y_title="Amplitude móvel")
    )


def _pareto(ctx: Context) -> None:
    rows = ctx.repo.quality_status_counts()
    counts = {str(r["quality_status"]): int(r["count"]) for r in rows}
    if not counts:
        st.info("Nenhum produto cadastrado.")
        return
    st.caption("Distribuição dos produtos por status de qualidade (todos os produtos).")
    st.plotly_chart(pareto_figure(counts, "Pareto por status de qualidade"))


def _histogram(df: pd.DataFrame, n: int | None) -> None:
    means = [float(v) for v in df["mean_value"]]
    st.caption(
        "Distribuição das médias registradas. Informe os limites de especificação do produto "
        "para calcular Cp e Cpk (σ estimado por R̄/d2)."
    )
    fig = px.histogram(pd.DataFrame({"Média": means}), x="Média", nbins=min(20, max(5, len(means))))
    fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10}, yaxis_title="Frequência")

    c1, c2 = st.columns(2)
    lsl = c1.number_input("Limite inferior de especificação (LIE)", value=None, format="%.4f", key="qc_lsl")
    usl = c2.number_input("Limite superior de especificação (LSE)", value=None, format="%.4f", key="qc_usl")
    for value, name in ((lsl, "LIE"), (usl, "LSE")):
        if value is not None:
            fig.add_vline(x=value, line_dash="dash", line_color="#dc2626", annotation_text=name)
    st.plotly_chart(fig)

    mean = sum(means) / len(means)
    m1, m2, m3 = st.columns(3)
    m1.metric("Média geral", f"{mean:.4f}", border=True)
    if n is None or df["range_value"].isna().all():
        m2.metric("σ dentro dos subgrupos", "—", border=True)
        m3.metric("Cp / Cpk", "—", border=True)
        return
    sigma = spc.sigma_within_from_ranges([float(v) for v in df["range_value"].fillna(0)], n)
    m2.metric("σ dentro dos subgrupos", f"{sigma:.4f}", border=True)
    if lsl is None or usl is None:
        m3.metric("Cp / Cpk", "informe LIE e LSE", border=True)
        return
    try:
        cap = spc.capability(mean, sigma, float(lsl), float(usl))
    except spc.SpcError as exc:
        m3.metric("Cp / Cpk", "—", border=True)
        st.warning(str(exc))
    else:
        m3.metric("Cp / Cpk", f"{cap.cp:.2f} / {cap.cpk:.2f}", border=True)
