import pytest

from linhamestre import spc


def test_constants_cover_supported_sizes() -> None:
    assert sorted(spc.CONTROL_CHART_CONSTANTS) == list(range(2, 11))
    # Valores de referência das tabelas de Shewhart.
    f4 = spc.factors_for(4)
    assert f4.B4 == pytest.approx(2.266)
    assert f4.A3 == pytest.approx(1.628)
    assert spc.factors_for(5).A2 == pytest.approx(0.577)


def test_factors_for_unsupported_size() -> None:
    with pytest.raises(spc.SpcError):
        spc.factors_for(11)


def test_xbar_r_limits() -> None:
    xbar, r = spc.xbar_r_limits([10.0, 12.0], [1.0, 3.0], 5)
    assert xbar.center == pytest.approx(11.0)
    assert xbar.ucl == pytest.approx(11.0 + 0.577 * 2.0)
    assert xbar.lcl == pytest.approx(11.0 - 0.577 * 2.0)
    assert r.center == pytest.approx(2.0)
    assert r.ucl == pytest.approx(2.114 * 2.0)
    assert r.lcl == 0.0


def test_xbar_s_uses_a3_not_a2() -> None:
    xbar, s = spc.xbar_s_limits([5.0, 5.0], [0.5, 0.5], 5)
    assert xbar.ucl == pytest.approx(5.0 + 1.427 * 0.5)
    assert s.ucl == pytest.approx(2.089 * 0.5)
    assert s.lcl == 0.0


def test_imr_limits() -> None:
    values = [10.0, 12.0, 11.0, 13.0]
    individuals, mr = spc.imr_limits(values)
    mrbar = (2 + 1 + 2) / 3
    assert spc.moving_ranges(values) == [2.0, 1.0, 2.0]
    assert individuals.center == pytest.approx(11.5)
    assert individuals.ucl == pytest.approx(11.5 + 3 * mrbar / 1.128)
    assert mr.ucl == pytest.approx(3.267 * mrbar)


def test_imr_requires_two_points() -> None:
    with pytest.raises(spc.SpcError):
        spc.imr_limits([1.0])


def test_common_subgroup_size() -> None:
    assert spc.common_subgroup_size([5, 5, 5]) == 5
    with pytest.raises(spc.SpcError, match="diferentes"):
        spc.common_subgroup_size([5, 4])
    with pytest.raises(spc.SpcError):
        spc.common_subgroup_size([])


LIMITS = spc.ControlLimits(center=0.0, ucl=3.0, lcl=-3.0)  # σ = 1


def _rules(values: list[float]) -> set[tuple[spc.Rule, int]]:
    return {(v.rule, v.index) for v in spc.western_electric(values, LIMITS)}


def test_rule_1_any_point_beyond_3_sigma() -> None:
    assert (spc.Rule.BEYOND_3_SIGMA, 1) in _rules([0.0, 3.5, 0.0])
    assert (spc.Rule.BEYOND_3_SIGMA, 0) in _rules([-4.0, 0.0])


def test_rule_2_two_of_three_beyond_2_sigma() -> None:
    assert (spc.Rule.TWO_OF_THREE_BEYOND_2_SIGMA, 2) in _rules([2.5, 0.0, 2.2])
    # Lados opostos não contam.
    assert not any(r == spc.Rule.TWO_OF_THREE_BEYOND_2_SIGMA for r, _ in _rules([2.5, 0.0, -2.2]))


def test_rule_3_four_of_five_beyond_1_sigma() -> None:
    assert (spc.Rule.FOUR_OF_FIVE_BEYOND_1_SIGMA, 4) in _rules([1.5, 1.2, 0.0, 1.1, 1.3])


def test_rule_4_eight_same_side() -> None:
    values = [0.5] * 8
    assert (spc.Rule.EIGHT_SAME_SIDE, 7) in _rules(values)
    assert not any(r == spc.Rule.EIGHT_SAME_SIDE for r, _ in _rules([0.5] * 7))


def test_stable_process_has_no_violations() -> None:
    assert _rules([0.5, -0.5, 0.2, -0.3, 0.1, -0.1, 0.4, -0.2, 0.3]) == set()


def test_zero_sigma_returns_no_violations() -> None:
    assert spc.western_electric([1.0, 1.0], spc.ControlLimits(1.0, 1.0, 1.0)) == []


def test_capability() -> None:
    cap = spc.capability(mean=10.0, sigma_within=0.5, lsl=7.0, usl=13.0)
    assert cap.cp == pytest.approx(2.0)
    assert cap.cpk == pytest.approx(2.0)
    off_center = spc.capability(mean=12.0, sigma_within=0.5, lsl=7.0, usl=13.0)
    assert off_center.cpk == pytest.approx(1 / 1.5)


@pytest.mark.parametrize(("sigma", "lsl", "usl"), [(0.0, 1.0, 2.0), (1.0, 2.0, 2.0), (1.0, 3.0, 2.0)])
def test_capability_invalid(sigma: float, lsl: float, usl: float) -> None:
    with pytest.raises(spc.SpcError):
        spc.capability(0.0, sigma, lsl, usl)


def test_sigma_within_from_ranges() -> None:
    assert spc.sigma_within_from_ranges([2.326, 2.326], 5) == pytest.approx(1.0)


def test_pareto() -> None:
    rows = spc.pareto({"A": 1, "B": 3, "C": 0, "D": 1})
    assert [r.label for r in rows] == ["B", "A", "D"]
    assert rows[0].cumulative_pct == pytest.approx(60.0)
    assert rows[-1].cumulative_pct == pytest.approx(100.0)
    assert spc.pareto({}) == []
