"""Proleptic Gregorian calendar arithmetic, separate from clock time.

The model uses years 1..9999 (no year zero), exact integer arithmetic, and an
explicit month-addition policy. It does not implement time zones, UTC, leap
seconds, or physical elapsed-time conversion.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


def is_gregorian_leap_year(year: int) -> bool:
    """Return whether a positive Gregorian year has 366 days."""
    if year < 1:
        raise ValueError("year must be in the supported range 1..9999")
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def days_in_month(year: int, month: int) -> int:
    """Number of days in a Gregorian month."""
    if not 1 <= year <= 9999:
        raise ValueError("year must be in the supported range 1..9999")
    if not 1 <= month <= 12:
        raise ValueError("month must be in the range 1..12")
    if month == 2:
        return 29 if is_gregorian_leap_year(year) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def days_in_year(year: int) -> int:
    return 366 if is_gregorian_leap_year(year) else 365


class MonthAdditionPolicy:
    """Named policies for adding calendar months."""
    CLAMP = "CLAMP"
    REJECT = "REJECT"


class GregorianDate(BaseModel):
    """A valid proleptic Gregorian date, independent of any time zone."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    year: int = Field(ge=1, le=9999)
    month: int = Field(ge=1, le=12)
    day: int = Field(ge=1, le=31)

    @model_validator(mode="after")
    def validate_day(self):
        if self.day > days_in_month(self.year, self.month):
            raise ValueError("day does not exist in the specified Gregorian month")
        return self

    @property
    def ordinal(self) -> int:
        """One-based day number since 0001-01-01 in the proleptic calendar."""
        y = self.year - 1
        days_before_year = 365 * y + y // 4 - y // 100 + y // 400
        days_before_month = sum(days_in_month(self.year, m) for m in range(1, self.month))
        return days_before_year + days_before_month + self.day

    @property
    def day_of_year(self) -> int:
        return self.ordinal - (GregorianDate(year=self.year, month=1, day=1).ordinal - 1)

    @property
    def weekday_monday_zero(self) -> int:
        """Monday=0 through Sunday=6; 0001-01-01 is Monday."""
        return (self.ordinal - 1) % 7

    def add_days(self, amount: int) -> GregorianDate:
        """Add an integer number of calendar days, rejecting range overflow."""
        target = self.ordinal + amount
        if target < 1:
            raise ValueError("result precedes supported year 1")
        # Invert the ordinal by bounded binary search over supported years.
        lo, hi = 1, 9999
        while lo <= hi:
            mid = (lo + hi) // 2
            first = GregorianDate(year=mid, month=1, day=1).ordinal
            after = first + days_in_year(mid)
            if target < first:
                hi = mid - 1
            elif target >= after:
                lo = mid + 1
            else:
                day_of_year = target - first + 1
                month = 1
                while day_of_year > days_in_month(mid, month):
                    day_of_year -= days_in_month(mid, month)
                    month += 1
                return GregorianDate(year=mid, month=month, day=day_of_year)
        raise ValueError("result exceeds supported year 9999")

    def add_months(
        self, amount: int, policy: str = MonthAdditionPolicy.CLAMP
    ) -> GregorianDate:
        """Add calendar months using explicit CLAMP or REJECT overflow policy."""
        if policy not in (MonthAdditionPolicy.CLAMP, MonthAdditionPolicy.REJECT):
            raise ValueError("unsupported month-addition policy")
        absolute_month = (self.year - 1) * 12 + (self.month - 1) + amount
        if not 0 <= absolute_month < 9999 * 12:
            raise ValueError("result exceeds supported year range")
        year, month0 = divmod(absolute_month, 12)
        month = month0 + 1
        last_day = days_in_month(year + 1, month)
        if self.day > last_day and policy == MonthAdditionPolicy.REJECT:
            raise ValueError("target month does not contain the source day")
        return GregorianDate(year=year + 1, month=month, day=min(self.day, last_day))


class CivilTime(BaseModel):
    """A local clock reading attached to a date and numeric UTC offset.

    The offset is metadata, not a time-zone rule set. DST transitions and
    historical offset changes require a separate IANA time-zone database layer.
    Leap-second value 60 is deliberately unsupported in this initial model.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    date: GregorianDate
    hour: int = Field(ge=0, le=23)
    minute: int = Field(ge=0, le=59)
    second: int = Field(ge=0, le=59)
    utc_offset_minutes: int = Field(ge=-14 * 60, le=14 * 60)

    @property
    def local_seconds_of_day(self) -> int:
        return self.hour * 3600 + self.minute * 60 + self.second

    @property
    def utc_coordinate_seconds(self) -> int:
        """Integer coordinate relative to 0001-01-01T00:00:00Z.

        This is a civil-coordinate conversion ignoring leap seconds. It is not
        a claim about SI elapsed seconds across historical UTC leap seconds.
        """
        return (
            (self.date.ordinal - 1) * 86400
            + self.local_seconds_of_day
            - self.utc_offset_minutes * 60
        )
