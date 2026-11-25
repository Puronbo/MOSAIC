import Mathlib

/-!
# MOSAIC Gregorian calendar arithmetic

This file formalizes the arithmetic core of the proleptic Gregorian calendar.
It deliberately does not identify a civil day with 86,400 SI seconds and does
not model time zones or leap seconds.
-/

namespace MosaicCalendar

/-- Gregorian leap-year predicate on natural-number year labels. -/
def isLeapYear (year : Nat) : Prop :=
  year % 4 = 0 ∧ (year % 100 ≠ 0 ∨ year % 400 = 0)

/-- The leap-year rule is periodic with period 400 years. -/
theorem leapYear_period_400 (year : Nat) :
    isLeapYear (year + 400) ↔ isLeapYear year := by
  simp [isLeapYear, Nat.add_mod]

/-- Reference cases for the Gregorian century exception. -/
theorem year_1600_is_leap : isLeapYear 1600 := by
  norm_num [isLeapYear]

theorem year_1700_is_common : ¬ isLeapYear 1700 := by
  norm_num [isLeapYear]

theorem year_1900_is_common : ¬ isLeapYear 1900 := by
  norm_num [isLeapYear]

theorem year_2000_is_leap : isLeapYear 2000 := by
  norm_num [isLeapYear]

theorem year_2100_is_common : ¬ isLeapYear 2100 := by
  norm_num [isLeapYear]

theorem year_2400_is_leap : isLeapYear 2400 := by
  norm_num [isLeapYear]

/-- Number of days preceding year y+1, where y=0 denotes year 1. -/
def daysBeforeYear (y : Nat) : Nat :=
  365 * y + y / 4 - y / 100 + y / 400

/-- A complete Gregorian 400-year cycle contains exactly 146097 days. -/
theorem days_in_400_year_cycle :
    daysBeforeYear 400 = 146097 := by
  norm_num [daysBeforeYear]

/-- Advancing by 400 years advances the ordinal by exactly 146097 days. -/
theorem daysBeforeYear_period_400 (y : Nat) :
    daysBeforeYear (y + 400) = daysBeforeYear y + 146097 := by
  unfold daysBeforeYear
  omega

/-- The Gregorian leap-year predicate and year-length formula agree. -/
theorem leap_year_day_count (year : Nat)
    [Decidable (isLeapYear year)] :
    (if isLeapYear year then 366 else 365) =
      365 + (if isLeapYear year then 1 else 0) := by
  by_cases h : isLeapYear year <;> simp [h]

/-- Advancing the year index adds the exact length of the next Gregorian year. -/
theorem daysBeforeYear_succ (y : Nat)
    [Decidable (isLeapYear (y + 1))] :
    daysBeforeYear (y + 1) =
      daysBeforeYear y +
        (if isLeapYear (y + 1) then 366 else 365) := by
  unfold daysBeforeYear isLeapYear
  have h4 := Nat.mod_add_div y 4
  have h100 := Nat.mod_add_div y 100
  have h400 := Nat.mod_add_div y 400
  have h4' := Nat.mod_add_div (y + 1) 4
  have h100' := Nat.mod_add_div (y + 1) 100
  have h400' := Nat.mod_add_div (y + 1) 400
  have b4 : y % 4 < 4 := Nat.mod_lt y (by omega)
  have b100 : y % 100 < 100 := Nat.mod_lt y (by omega)
  have b400 : y % 400 < 400 := Nat.mod_lt y (by omega)
  have b4' : (y + 1) % 4 < 4 := Nat.mod_lt (y + 1) (by omega)
  have b100' : (y + 1) % 100 < 100 := Nat.mod_lt (y + 1) (by omega)
  have b400' : (y + 1) % 400 < 400 := Nat.mod_lt (y + 1) (by omega)
  omega


/-- A complete Gregorian cycle preserves the weekday residue modulo seven. -/
theorem daysBeforeYear_weekday_period_400 (y : Nat) :
    daysBeforeYear (y + 400) % 7 = daysBeforeYear y % 7 := by
  rw [daysBeforeYear_period_400]
  simp [Nat.add_mod]

end MosaicCalendar
