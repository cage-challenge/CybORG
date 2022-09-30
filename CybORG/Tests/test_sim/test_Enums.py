import pytest

from CybORG.Shared.Enums import TrinaryEnum


@pytest.mark.parametrize(["value", "expected"], [(True, TrinaryEnum.TRUE), (False, TrinaryEnum.FALSE), (None, TrinaryEnum.UNKNOWN), ("No Idea", TrinaryEnum.UNKNOWN)])
def test_parse_bool(value, expected):
    v = TrinaryEnum.parse_bool(value)
    assert type(v) is TrinaryEnum
    assert v == expected


@pytest.mark.parametrize(["value1", "value2", "expected"], [(True, True, True), (False, False, True), (False, True, False), (True, False, False)])
def test_eq(value1, value2, expected):
    v = TrinaryEnum.parse_bool(value1)
    assert type(v) is TrinaryEnum
    assert (v == value2) == expected


def test_eq_unknown():
    assert TrinaryEnum.UNKNOWN == TrinaryEnum.UNKNOWN
