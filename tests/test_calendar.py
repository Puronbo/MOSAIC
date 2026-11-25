from pydantic import ValidationError
import pytest

from mosaic.core.calendar import (
    CivilTime,
    GregorianDate,
    MonthAdditionPolicy,
    days_in_month,
    days_in_year,
    is_gregorian_leap_year,
)


@pytest.mark.parametrize(
    "year,expected",
    [(1600, True), (1700, False), (1800, False), (1900, False),
     (2000, True), (2024, True), (2025, False), (2100, False), (2400, True)],
)
def test_gregorian_leap_year_century_rule(year, expected):
    assert is_gregorian_leap_year(year) is expected
    assert days_in_year(year) == (366 if expected else 365)


def test_month_lengths_and_february_validation():
    assert days_in_month(2024, 2) == 29
    assert days_in_month(2025, 2) == 28
    assert days_in_month(2024, 4) == 30
    assert days_in_month(2024, 1) == 31
    assert GregorianDate(year=2024, month=2, day=29)
    with pytest.raises(ValidationError):
        GregorianDate(year=2025, month=2, day=29)


def test_ordinal_and_weekday_reference():
    assert GregorianDate(year=1, month=1, day=1).ordinal == 1
    assert GregorianDate(year=1, month=1, day=1).weekday_monday_zero == 0
    assert GregorianDate(year=2024, month=1, day=1).weekday_monday_zero == 0
    assert GregorianDate(year=2024, month=12, day=31).day_of_year == 366


@pytest.mark.parametrize(
    "start,delta,expected",
    [
        (GregorianDate(year=2024, month=2, day=28), 1, GregorianDate(year=2024, month=2, day=29)),
        (GregorianDate(year=2024, month=2, day=29), 1, GregorianDate(year=2024, month=3, day=1)),
        (GregorianDate(year=2023, month=12, day=31), 1, GregorianDate(year=2024, month=1, day=1)),
        (GregorianDate(year=2024, month=1, day=1), -1, GregorianDate(year=2023, month=12, day=31)),
    ],
)
def test_add_days_across_boundaries(start, delta, expected):
    assert start.add_days(delta) == expected


def test_add_days_rejects_range_overflow():
    with pytest.raises(ValueError):
        GregorianDate(year=1, month=1, day=1).add_days(-1)
    with pytest.raises(ValueError):
        GregorianDate(year=9999, month=12, day=31).add_days(1)


def test_add_months_has_explicit_clamp_and_reject_semantics():
    jan31 = GregorianDate(year=2023, month=1, day=31)
    assert jan31.add_months(1) == GregorianDate(year=2023, month=2, day=28)
    assert jan31.add_months(1, MonthAdditionPolicy.CLAMP) == GregorianDate(year=2023, month=2, day=28)
    with pytest.raises(ValueError, match="does not contain"):
        jan31.add_months(1, MonthAdditionPolicy.REJECT)
    leap_day = GregorianDate(year=2024, month=2, day=29)
    assert leap_day.add_months(12) == GregorianDate(year=2025, month=2, day=28)


def test_add_months_across_year_and_reject_invalid_policy():
    assert GregorianDate(year=2024, month=12, day=15).add_months(2) == GregorianDate(year=2025, month=2, day=15)
    with pytest.raises(ValueError, match="unsupported"):
        GregorianDate(year=2024, month=1, day=1).add_months(1, "ROLL")


def test_civil_time_numeric_offset_conversion():
    local = CivilTime(
        date=GregorianDate(year=2024, month=1, day=1),
        hour=8, minute=0, second=0, utc_offset_minutes=480,
    )
    utc = CivilTime(
        date=GregorianDate(year=2024, month=1, day=1),
        hour=0, minute=0, second=0, utc_offset_minutes=0,
    )
    assert local.utc_coordinate_seconds == utc.utc_coordinate_seconds


def test_civil_time_validates_clock_fields_and_offset():
    with pytest.raises(ValidationError):
        CivilTime(date=GregorianDate(year=2024, month=1, day=1), hour=24, minute=0, second=0, utc_offset_minutes=0)
    with pytest.raises(ValidationError):
        CivilTime(date=GregorianDate(year=2024, month=1, day=1), hour=0, minute=0, second=60, utc_offset_minutes=0)
    with pytest.raises(ValidationError):
        CivilTime(date=GregorianDate(year=2024, month=1, day=1), hour=0, minute=0, second=0, utc_offset_minutes=900)


def test_ordinal_round_trip_over_complete_gregorian_400_year_cycle():
    # The Gregorian leap-year pattern repeats every 400 years (146097 days).
    # Check every ordinal in the cycle, not just selected dates.
    from datetime import date

    cycle_days = 146097
    for ordinal in range(1, cycle_days + 1):
        actual = GregorianDate.from_ordinal(ordinal)
        expected = date.fromordinal(ordinal)
        assert (actual.year, actual.month, actual.day) == (
            expected.year, expected.month, expected.day
        )
        assert actual.ordinal == ordinal
        assert actual.weekday_monday_zero == expected.weekday()


def test_ordinal_round_trip_at_supported_range_edges():
    first = GregorianDate(year=1, month=1, day=1)
    last = GregorianDate(year=9999, month=12, day=31)
    assert GregorianDate.from_ordinal(first.ordinal) == first
    assert GregorianDate.from_ordinal(last.ordinal) == last
    with pytest.raises(ValueError):
        GregorianDate.from_ordinal(0)
    with pytest.raises(ValueError):
        GregorianDate.from_ordinal(last.ordinal + 1)


def test_calendar_integer_inputs_reject_booleans():
    with pytest.raises(TypeError):
        is_gregorian_leap_year(True)
    with pytest.raises(TypeError):
        days_in_month(2024, False)
    with pytest.raises(TypeError):
        GregorianDate.from_ordinal(True)
    with pytest.raises(ValidationError):
        GregorianDate(year=True, month=1, day=1)
    with pytest.raises(TypeError):
        GregorianDate(year=2024, month=1, day=1).add_days(True)


def test_add_days_round_trip_and_weekday_periodicity():
    start = GregorianDate(year=2000, month=2, day=29)
    for delta in range(-800, 801):
        moved = start.add_days(delta)
        assert moved.add_days(-delta) == start
        assert moved.weekday_monday_zero == (
            start.weekday_monday_zero + delta
        ) % 7
