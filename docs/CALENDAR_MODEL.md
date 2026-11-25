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

## Extended temporal semantics (research specification)

The next layer must keep four different objects distinct:

1. **Civil date/time**: a label in a calendar and local clock convention.
2. **Zone rule set**: an IANA zone identifier interpreted against a particular tzdb release. An offset is the result of applying those rules at an instant, not a permanent property of the zone.
3. **Instant / timescale coordinate**: a point on a declared scale such as UTC, TAI, or POSIX time. Conversions must state their leap-second policy.
4. **Duration or calendar period**: elapsed seconds are measured on a timescale; a period such as one day, one month, or one year is applied in calendar space and needs explicit resolution rules.

### Local-time resolution

Converting a local date/time plus an IANA zone into an instant is not always a function with exactly one result. A forward clock transition can make a local time nonexistent; a backward transition can make it ambiguous. The API must return a typed resolution outcome (unique, ambiguous with both candidates, or nonexistent with the transition gap) and require an explicit policy before selecting or shifting a result. It must never silently pick a candidate.

Every resolved value should retain the zone identifier, tzdb release, original local input, chosen disambiguation policy, and resulting offset. This makes historical and future conversions reproducible even when political rules later change.

RFC 3339 numeric offsets encode a relationship to UTC for one timestamp; they do not encode the rule history of a named time zone. The TZif specification defines the interchange format used for compiled time-zone data and describes local offsets as dependent on date and time.

### Leap seconds and clock uncertainty

Leap-second handling must be a separately versioned timescale layer. A timestamp with second 60 is valid only when supported by the applicable leap-second table and the declared timescale/representation. The current model intentionally rejects it. Do not approximate leap seconds by silently stretching every day or by treating every civil day as exactly 86,400 SI seconds.

Clock readings may also be uncertain. A future synchronized-clock observation should represent an estimate and an error bound (or interval), plus its source and synchronization epoch. Ordering two uncertain observations is only justified when their intervals do not overlap; otherwise their order is indeterminate at the stated precision. This uncertainty must not be confused with timezone ambiguity.

### Recurrence semantics

A recurring event must declare whether it is:
- **wall-clock recurrence** (for example, every Monday at 09:00 in a named zone), preserving local intent across offset changes; or
- **elapsed recurrence** (for example, every 168 elapsed hours), preserving fixed elapsed spacing.

A wall-clock recurrence must additionally define behavior for nonexistent and ambiguous local occurrences, month-end overflow (clamp, reject, or another named policy), calendar, zone, and tzdb version/update policy. A recurrence engine should produce an occurrence together with its resolution provenance rather than only a timestamp.

### Formalization sequence

The Lean calendar development should proceed in dependency order:

1. Prove the 400-year leap predicate periodicity and the 146,097-day year-prefix periodicity.
2. Define month-prefix lengths and prove their sum is the year length.
3. Define the ordinal of a valid date and prove the successor law.
4. Prove ordinal injectivity and date/ordinal round trips over the supported domain.
5. Derive weekday periodicity modulo seven from ordinal arithmetic.
6. Only then formalize timezone transition and leap-second layers, each with explicit finite/versioned input data.

Python exhaustive tests and independent implementations are evidence of implementation behavior, not substitutes for these kernel-checked theorems.

## References

- RFC 3339, *Date and Time on the Internet: Timestamps*, especially section 5.7 and appendix C: https://www.rfc-editor.org/rfc/rfc3339.html
- ISO 8601-1 defines Gregorian calendar identification and notes the proleptic Gregorian convention for dates preceding its historical introduction. The implementation here deliberately uses a narrower positive-year range.
