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

/-- Successor quotient identity for division by four. -/
theorem div_succ_4 (n : Nat) :
    (n + 1) / 4 = n / 4 + (if n % 4 = 3 then 1 else 0) := by
  rw [Nat.succ_div]
  have h : (4 : Nat) ∣ n + 1 ↔ n % 4 = 3 := by
    rw [Nat.dvd_iff_mod_eq_zero, Nat.succ_mod_succ_eq_zero_iff]
  simp only [h]

/-- Successor quotient identity for division by one hundred. -/
theorem div_succ_100 (n : Nat) :
    (n + 1) / 100 = n / 100 + (if n % 100 = 99 then 1 else 0) := by
  rw [Nat.succ_div]
  have h : (100 : Nat) ∣ n + 1 ↔ n % 100 = 99 := by
    rw [Nat.dvd_iff_mod_eq_zero, Nat.succ_mod_succ_eq_zero_iff]
  simp only [h]

/-- Successor quotient identity for division by four hundred. -/
theorem div_succ_400 (n : Nat) :
    (n + 1) / 400 = n / 400 + (if n % 400 = 399 then 1 else 0) := by
  rw [Nat.succ_div]
  have h : (400 : Nat) ∣ n + 1 ↔ n % 400 = 399 := by
    rw [Nat.dvd_iff_mod_eq_zero, Nat.succ_mod_succ_eq_zero_iff]
  simp only [h]

/-- A complete Gregorian cycle preserves the weekday residue modulo seven. -/
theorem daysBeforeYear_weekday_period_400 (y : Nat) :
    daysBeforeYear (y + 400) % 7 = daysBeforeYear y % 7 := by
  rw [daysBeforeYear_period_400]
  simp [Nat.add_mod]

end MosaicCalendar
