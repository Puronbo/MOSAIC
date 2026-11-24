import Mathlib.Analysis.SpecificLimits.Basic
import Mathlib.Tactic.Ring

/-!
MOSAIC's real-kernel acceptance probes.

The polynomial identities below are universally quantified over the integers.
The rapid-series development formalizes the positive-term series
sum_{k >= 0} 1 / (k+1)^k, which is the original sum
sum_{n >= 1} 1 / n^(n-1) after reindexing k = n - 1.
It proves summability by comparison with the geometric series and gives
an explicit geometric bound for every shifted tail.
-/

namespace MosaicPolynomial

theorem square_add_one (x : Int) :
    (x + 1)^2 = x^2 + 2*x + 1 := by
  ring

theorem difference_of_squares (x y : Int) :
    (x + y) * (x - y) = x^2 - y^2 := by
  ring

theorem collect_terms (x y : Int) :
    3*x + 2*y + x - y = 4*x + y := by
  ring

/-- Natural-number exponentiation preserves the order of its base. -/
theorem nat_pow_mono {a b k : Nat} (h : a ≤ b) : a^k ≤ b^k := by
  induction k with
  | zero =>
      simp
  | succ k ih =>
      rw [Nat.pow_succ, Nat.pow_succ]
      exact Nat.mul_le_mul ih h

/-- The denominator comparison used by the rapid-series estimate. -/
theorem rapid_series_power_comparison (n : Nat) (hn : 2 ≤ n) :
    2^(n - 1) ≤ n^(n - 1) :=
  nat_pow_mono hn

/-- Reindexed term: this is 1 / n^(n-1) with n = k+1. -/
def rapidSeriesTerm (k : Nat) : ℝ :=
  1 / (((k + 1 : Nat) : ℝ) ^ k)

theorem rapid_series_term_pos (k : Nat) : 0 < rapidSeriesTerm k := by
  unfold rapidSeriesTerm
  positivity

/-- Each term is bounded by the corresponding term of a geometric series. -/
theorem rapid_series_term_le_geometric (k : Nat) :
    rapidSeriesTerm k ≤ (1 / 2 : ℝ) ^ k := by
  have hpowNat : 2 ^ k ≤ (k + 1) ^ k :=
    nat_pow_mono (by omega : 2 ≤ k + 1)
  have hpow : (2 : ℝ) ^ k ≤ (((k + 1 : Nat) : ℝ) ^ k) := by
    exact_mod_cast hpowNat
  have hpos : 0 < (2 : ℝ) ^ k := by positivity
  have h := one_div_le_one_div_of_le hpos hpow
  simpa [rapidSeriesTerm, div_pow] using h

/-- The reindexed rapid series converges, by comparison with sum (1/2)^k. -/
theorem rapid_series_summable : Summable rapidSeriesTerm := by
  apply Summable.of_nonneg_of_le
  · intro k
    exact le_of_lt (rapid_series_term_pos k)
  · exact summable_geometric_of_lt_one (by norm_num) (by norm_num)
  · intro k
    exact rapid_series_term_le_geometric k

/-- The whole rapid series is at most the sum of its geometric majorant, 2. -/
theorem rapid_series_total_le_two :
    (∑' k : Nat, rapidSeriesTerm k) ≤ 2 := by
  calc
    (∑' k : Nat, rapidSeriesTerm k) ≤
        ∑' k : Nat, (1 / 2 : ℝ) ^ k := by
      apply tsum_le_tsum
      · intro k
        exact rapid_series_term_le_geometric k
      · exact rapid_series_summable
      · exact summable_geometric_of_lt_one (by norm_num) (by norm_num)
    _ = 2 := tsum_geometric_of_lt_one (by norm_num) (by norm_num)

/-- The tail beginning at index N is bounded by the geometric tail
2 * (1/2)^N. This is the shifted form of the usual 2^(1-N) bound. -/
theorem rapid_series_tail_bound (N : Nat) :
    (∑' k : Nat, rapidSeriesTerm (N + k)) ≤
      2 * (1 / 2 : ℝ) ^ N := by
  have hleft : Summable (fun k : Nat => rapidSeriesTerm (N + k)) :=
    rapid_series_summable.comp_injective (Nat.add_left_injective N)
  have hright : Summable (fun k : Nat => (1 / 2 : ℝ) ^ (N + k)) := by
    have hbase := summable_geometric_of_lt_one
      (by norm_num : 0 ≤ (1 / 2 : ℝ))
      (by norm_num : (1 / 2 : ℝ) < 1)
    have hmul := hbase.mul_left ((1 / 2 : ℝ) ^ N)
    convert hmul using 1
    ext k
    rw [pow_add]
  calc
    (∑' k : Nat, rapidSeriesTerm (N + k)) ≤
        ∑' k : Nat, (1 / 2 : ℝ) ^ (N + k) := by
      apply tsum_le_tsum
      · intro k
        exact rapid_series_term_le_geometric (N + k)
      · exact hleft
      · exact hright
    _ = 2 * (1 / 2 : ℝ) ^ N := by
      rw [show (fun k : Nat => (1 / 2 : ℝ) ^ (N + k)) =
        (fun k => (1 / 2 : ℝ) ^ N * (1 / 2 : ℝ) ^ k) by
          funext k
          rw [pow_add]]
      rw [tsum_mul_left, tsum_geometric_of_lt_one] <;> norm_num

end MosaicPolynomial
