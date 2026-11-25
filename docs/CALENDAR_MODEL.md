# MOSAIC calendar model (initial implementation)

## Purpose and boundary

The calendar layer extends the temporal model without redefining its clock semantics. A calendar date identifies a civil day under a calendar convention. A clock reading identifies a coordinate on a declared clock. An elapsed duration is a measurement between clock readings. These are related concepts, not synonyms.

The initial implementation provides a **proleptic Gregorian** date model over years 1 through 9999, exact ordinal arithmetic, weekday calculation, calendar-day addition, and calendar-month addition with an explicit overflow policy. It also provides a civil clock reading with a numeric UTC offset. It does not silently load a timezone database or infer historical offsets.

## Gregorian rule

A positive year is a leap year exactly when

```text
(year mod 4 = 0) and ((year mod 100 != 0) or (year mod 400 = 0)).
```

Thus 1600 and 2000 are leap years; 1700, 1800, 1900, and 2100 are not. This is the Gregorian rule described in RFC 3339 section 5.7 and appendix C. The implementation's year range excludes year zero and negative years; this is an explicit product boundary, not a claim that proleptic calendar mathematics cannot extend further.

## Implemented API

- `is_gregorian_leap_year(year)`
- `days_in_month(year, month)` and `days_in_year(year)`
- `GregorianDate(year, month, day)`, validated at construction
- `GregorianDate.ordinal`: one-based day count from 0001-01-01
- `GregorianDate.from_ordinal(n)`: inverse ordinal mapping, with bounded year search
- `GregorianDate.day_of_year` and `weekday_monday_zero`
- `GregorianDate.add_days(n)`: exact calendar-day arithmetic, implemented through the ordinal inverse
- `GregorianDate.add_months(n, policy)`: explicit `CLAMP` or `REJECT` semantics
- `CivilTime(date, hour, minute, second, utc_offset_minutes)`
- `CivilTime.utc_coordinate_seconds`: a nominal civil-coordinate conversion that deliberately does not model leap seconds

Month addition is not uniquely determined for dates such as January 31 plus one month. MOSAIC therefore makes the policy explicit: `CLAMP` selects the final valid day of the target month; `REJECT` refuses an invalid target day. Neither policy is hidden in a generic duration operation.

## Separation of calendar and elapsed time

Adding one calendar day means moving to the next date under the calendar rules. It does not assert that every such transition spans exactly 86,400 SI seconds. A local civil day can be affected by time-zone offset changes; UTC can include announced leap seconds. RFC 3339 explicitly allows a leap-second value of 60 in qualifying timestamps and describes the Gregorian leap-year rule. The current `CivilTime` type intentionally accepts seconds 0 through 59 only, so leap-second support remains an explicit future extension.

The numeric offset is not an IANA time zone. It is insufficient to resolve daylight-saving transitions, historical local-time changes, or future political rule changes. A future `ZonedCivilTime` should carry an IANA zone identifier and a versioned timezone-database provenance record, and should distinguish ambiguous and nonexistent local times at transitions.

## Verification plan

Calendar integer fields reject booleans rather than accepting Python's `bool`-is-an-`int` behavior. The Python regression suite exercises:
- century leap-year edge cases (1600, 1700, 1800, 1900, 2000, 2100, 2400);
- valid and invalid month/day combinations;
- ordinal and weekday reference points;
- every date in a complete 400-year Gregorian cycle against Python's independent standard-library date implementation;
- ordinal inversion at the supported range boundaries and day-addition inverse/weekday periodicity;
- rejection of boolean values in integer calendar inputs;
- day arithmetic across leap days and year boundaries;
- range overflow;
- month-addition clamp/reject behavior;
- equivalence of two local readings representing the same nominal UTC coordinate;
- invalid clock fields and offsets.

These tests are executable checks, not formal proofs. Next formalization targets are the leap-year equivalence, month-length sum, ordinal successor law, weekday periodicity modulo seven, and round-trip date/ordinal conversion. The timezone layer should be added only with explicit transition and database-version semantics.

## References

- RFC 3339, *Date and Time on the Internet: Timestamps*, especially section 5.7 and appendix C: https://www.rfc-editor.org/rfc/rfc3339.html
- ISO 8601-1 defines Gregorian calendar identification and notes the proleptic Gregorian convention for dates preceding its historical introduction. The implementation here deliberately uses a narrower positive-year range.
