import Mathlib

/-!
MOSAIC's real-kernel acceptance probes.

The polynomial identities below are universally quantified over the integers.
The natural-number power monotonicity lemma is a small independently checked
arithmetic fact used in the rapid-series comparison example.
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

/-- For n ≥ 2, the geometric comparison denominator is no larger
than the corresponding denominator n^(n-1). -/
theorem rapid_series_power_comparison (n : Nat) (hn : 2 ≤ n) :
    2^(n - 1) ≤ n^(n - 1) :=
  nat_pow_mono hn

/-- Powers of two are at least four from exponent two onward. -/
theorem four_le_two_pow (k : Nat) (hk : 2 ≤ k) : 4 ≤ 2^k := by
  have hbound : ∀ m : Nat, 2 ≤ m → 4 ≤ 2^m := by
    intro m
    induction m with
    | zero =>
        intro hm
        omega
    | succ m ih =>
        intro hm
        by_cases hm2 : 2 ≤ m
        · have hprev := ih hm2
          rw [Nat.pow_succ]
          nlinarith
        · have hmEq : m = 1 := by omega
          subst m
          norm_num
  exact hbound k hk

/-- The natural-number equation n^n = 3 has no solution.
This is the discrete counterpart of n^n - 1 = 2. -/
theorem no_nat_solution_n_pow_eq_three (n : Nat) : n^n ≠ 3 := by
  intro h
  by_cases hn : n < 2
  · interval_cases n <;> norm_num at h
  · have hn2 : 2 ≤ n := by omega
    have hpow2 : 4 ≤ 2^n := four_le_two_pow n hn2
    have hpow : 2^n ≤ n^n := nat_pow_mono hn2
    omega

/-- The map x ↦ x * log x is strictly increasing for x > 1. -/
theorem strictMonoOn_mul_log : StrictMonoOn (fun x : ℝ => x * Real.log x) (Set.Ioi 1) := by
  intro a ha b hb hab
  have ha' : 1 < a := ha
  have hb' : 1 < b := hb
  have hloga : 0 < Real.log a := Real.log_pos ha'
  have hlogab : Real.log a < Real.log b :=
    Real.log_lt_log (by linarith) hab
  calc
    a * Real.log a < b * Real.log a :=
      mul_lt_mul_of_pos_right hab hloga
    _ < b * Real.log b :=
      mul_lt_mul_of_pos_left hlogab (by linarith)

/-- Any positive real solution of x^x = 3 is greater than one. -/
theorem one_lt_of_pos_rpow_eq_three {x : ℝ}
    (hx : 0 < x) (heq : x ^ x = 3) : 1 < x := by
  by_contra h
  have hle : x ≤ 1 := le_of_not_gt h
  have hlog : x * Real.log x = Real.log 3 := by
    calc
      x * Real.log x = Real.log (x ^ x) := by
        rw [Real.log_rpow hx x]
      _ = Real.log 3 := congrArg Real.log heq
  have hlogx : Real.log x ≤ 0 := Real.log_nonpos hx.le hle
  have hprod : x * Real.log x ≤ 0 := mul_nonpos_of_nonneg_of_nonpos hx.le hlogx
  have hthree : 0 < Real.log 3 := Real.log_pos (by norm_num)
  linarith

/-- The equation x^x = 3 has at most one positive real solution. -/
theorem eq_of_pos_rpow_eq_three {x y : ℝ}
    (hx : 0 < x) (hy : 0 < y)
    (hxeq : x ^ x = 3) (hyeq : y ^ y = 3) : x = y := by
  have hxgt : 1 < x := one_lt_of_pos_rpow_eq_three hx hxeq
  have hygt : 1 < y := one_lt_of_pos_rpow_eq_three hy hyeq
  have hxlog : x * Real.log x = Real.log 3 := by
    calc
      x * Real.log x = Real.log (x ^ x) := by
        rw [Real.log_rpow hx x]
      _ = Real.log 3 := congrArg Real.log hxeq
  have hylog : y * Real.log y = Real.log 3 := by
    calc
      y * Real.log y = Real.log (y ^ y) := by
        rw [Real.log_rpow hy y]
      _ = Real.log 3 := congrArg Real.log hyeq
  exact strictMonoOn_mul_log.injOn
    (Set.mem_Ioi.mpr hxgt) (Set.mem_Ioi.mpr hygt) (hxlog.trans hylog.symm)

end MosaicPolynomial


/-! ## Exponent-increment system

The exponent shift is represented with a natural-number index.  Keeping the
base as a natural number makes the exponent unambiguous, while the value is
embedded in the reals so that differences and strict growth are ordinary
ordered-real statements.  This theorem family deliberately excludes zero and
negative bases from the real-valued monotonicity claim.
-/

namespace MosaicExponentShift

/-- The k-th unit increment of n^n. -/
def value (n k : Nat) : ℝ := (n : ℝ) ^ (n + k)

/-- One unit of exponent increment multiplies the value by the base. -/
theorem successor (n k : Nat) :
    value n (k + 1) = (n : ℝ) * value n k := by
  simp only [value]
  rw [show n + (k + 1) = (n + k) + 1 by omega]
  rw [pow_succ]
  ring

/-- The first forward difference is (n - 1) times the current value. -/
theorem first_difference (n k : Nat) :
    value n (k + 1) - value n k =
      ((n : ℝ) - 1) * value n k := by
  rw [successor]
  ring

/-- For natural bases at least two, every unit increment is strictly positive. -/
theorem strictly_increasing (n k : Nat) (hn : 2 ≤ n) :
    value n k < value n (k + 1) := by
  rw [successor]
  have hn' : 1 < (n : ℝ) := by exact_mod_cast (show 1 < n by omega)
  have hvalue : 0 < value n k := by
    unfold value
    exact pow_pos (by exact_mod_cast (show 0 < n by omega)) _
  nlinarith

/-- At base one, every exponent shift is stationary. -/
theorem one_is_fixed (k : Nat) : value 1 k = 1 := by
  simp [value]

/-- At base zero, the initial term uses 0^0 and is intentionally not given
a blanket real-valued recurrence theorem. -/
theorem zero_base_after_first_step (k : Nat) (hk : 1 ≤ k) :
    value 0 k = 0 := by
  unfold value
  have hk0 : k ≠ 0 := by omega
  simp [hk0]


/-- One forward finite difference of a sequence. -/
def forwardDifference (f : Nat → ℝ) (k : Nat) : ℝ :=
  f (k + 1) - f k

/-- The r-th iterated forward difference of the exponent-shift sequence. -/
def iteratedDifference (n : Nat) : Nat → Nat → ℝ
  | 0, k => value n k
  | r + 1, k => forwardDifference (iteratedDifference n r) k

/-- Every order of forward difference has the same geometric form. -/
theorem iterated_difference (n k r : Nat) :
    iteratedDifference n r k =
      ((n : ℝ) - 1) ^ r * value n k := by
  induction r generalizing k with
  | zero =>
      simp [iteratedDifference, value]
  | succ r ih =>
      simp only [iteratedDifference, forwardDifference]
      rw [ih (k + 1), ih k, successor]
      ring

/-- The second forward difference is the square of the base-minus-one
multiplier times the current value. -/
theorem second_difference (n k : Nat) :
    forwardDifference (fun j => forwardDifference (fun i => value n i) j) k =
      ((n : ℝ) - 1) ^ 2 * value n k := by
  simpa [forwardDifference, iteratedDifference] using
    (iterated_difference n k 2)

/-- All iterated differences are strictly positive when n ≥ 2. -/
theorem iterated_difference_pos (n k r : Nat) (hn : 2 ≤ n) :
    0 < iteratedDifference n r k := by
  rw [iterated_difference]
  have hbase : 1 < (n : ℝ) := by
    exact_mod_cast (show 1 < n by omega)
  have hvalue : 0 < value n k := by
    unfold value
    exact pow_pos (by exact_mod_cast (show 0 < n by omega)) _
  exact mul_pos (pow_pos (by linarith) _) hvalue



/-- Shifting the exponent index by m multiplies the value by n^m. -/
theorem arbitrary_shift (n k m : Nat) :
    value n (k + m) = (n : ℝ) ^ m * value n k := by
  unfold value
  rw [show n + (k + m) = (n + k) + m by omega, pow_add]
  ring

/-- A forward difference over an arbitrary natural-number step. -/
def forwardDifferenceBy (f : Nat → ℝ) (m k : Nat) : ℝ :=
  f (k + m) - f k

/-- The r-th iterated m-step forward difference. -/
def iteratedDifferenceBy (n m : Nat) : Nat → Nat → ℝ
  | 0, k => value n k
  | r + 1, k => forwardDifferenceBy (iteratedDifferenceBy n m r) m k

/-- Every order of m-step difference has multiplier (n^m - 1)^r. -/
theorem iterated_difference_by (n m k r : Nat) :
    iteratedDifferenceBy n m r k =
      ((n : ℝ) ^ m - 1) ^ r * value n k := by
  induction r generalizing k with
  | zero =>
      simp [iteratedDifferenceBy, value]
  | succ r ih =>
      simp only [iteratedDifferenceBy, forwardDifferenceBy]
      rw [ih (k + m), ih k, arbitrary_shift]
      ring




/-- Shift an arbitrary natural-indexed sequence forward by m places. -/
def shiftOperator (f : Nat → ℝ) (m k : Nat) : ℝ :=
  f (k + m)

/-- Zero shift is the identity operator. -/
theorem shift_zero (f : Nat → ℝ) (k : Nat) :
    shiftOperator f 0 k = f k := by
  simp [shiftOperator]

/-- Forward shifts compose by adding their offsets. -/
theorem shift_compose (f : Nat → ℝ) (a b k : Nat) :
    shiftOperator (fun j => shiftOperator f b j) a k =
      shiftOperator f (a + b) k := by
  simp [shiftOperator, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm]

/-- The shift operator acts on the exponent-increment sequence by
multiplication with the corresponding base power. -/
theorem shift_value (n m k : Nat) :
    shiftOperator (value n) m k =
      (n : ℝ) ^ m * value n k := by
  exact arbitrary_shift n k m

/-- A forward difference commutes with a forward shift. -/
theorem difference_shift_commute (f : Nat → ℝ) (m k : Nat) :
    forwardDifference (fun j => shiftOperator f m j) k =
      shiftOperator (fun j => forwardDifference f j) m k := by
  simp [forwardDifference, shiftOperator, Nat.add_assoc,
    Nat.add_left_comm, Nat.add_comm]



/-- The first m-step difference is the base-power increment times the value. -/
theorem arbitrary_step_first_difference (n m k : Nat) :
    value n (k + m) - value n k =
      ((n : ℝ) ^ m - 1) * value n k := by
  rw [arbitrary_shift]
  ring

/-- A zero-sized step has zero difference at every positive iteration order. -/
theorem zero_step_difference (n k r : Nat) :
    iteratedDifferenceBy n 0 (r + 1) k = 0 := by
  simp [iteratedDifferenceBy, forwardDifferenceBy]

end MosaicExponentShift


/-! ## Bi-infinite integer shift group

Unlike natural-indexed sequences, integer-indexed sequences have values in
both directions. Translation by an integer therefore has a genuine inverse.
This layer is stated for arbitrary real-valued sequences; it does not assume
that every sequence is an exponent-power sequence.
-/

namespace MosaicIntegerShift

/-- Translate a bi-infinite sequence by an integer offset. -/
def shiftOperator (f : ℤ → ℝ) (m k : ℤ) : ℝ :=
  f (k + m)

/-- Translation by zero is the identity. -/
theorem shift_zero (f : ℤ → ℝ) (k : ℤ) :
    shiftOperator f 0 k = f k := by
  simp [shiftOperator]

/-- Integer translations compose by addition. -/
theorem shift_compose (f : ℤ → ℝ) (a b k : ℤ) :
    shiftOperator (fun j => shiftOperator f b j) a k =
      shiftOperator f (a + b) k := by
  simp [shiftOperator, Int.add_assoc]

/-- Translation by the negative offset is a left inverse. -/
theorem shift_inverse_left (f : ℤ → ℝ) (m k : ℤ) :
    shiftOperator (fun j => shiftOperator f (-m) j) m k = f k := by
  simp [shiftOperator, Int.add_assoc]

/-- Translation by the negative offset is a right inverse. -/
theorem shift_inverse_right (f : ℤ → ℝ) (m k : ℤ) :
    shiftOperator (fun j => shiftOperator f m j) (-m) k = f k := by
  simp [shiftOperator, Int.add_assoc]

/-- The unit forward difference on a bi-infinite sequence. -/
def forwardDifference (f : ℤ → ℝ) (k : ℤ) : ℝ :=
  f (k + 1) - f k

/-- Integer translations commute with the unit forward difference. -/
theorem difference_shift_commute (f : ℤ → ℝ) (m k : ℤ) :
    forwardDifference (fun j => shiftOperator f m j) k =
      shiftOperator (fun j => forwardDifference f j) m k := by
  simp only [forwardDifference, shiftOperator]
  congr 1 <;> ring

/-- The integer translations form a group action on bi-infinite sequences:
the inverse law is witnessed by translation through the negated offset. -/
theorem translation_group_laws (f : ℤ → ℝ) (m k : ℤ) :
    shiftOperator (fun j => shiftOperator f (-m) j) m k = f k ∧
    shiftOperator (fun j => shiftOperator f m j) (-m) k = f k := by
  exact ⟨shift_inverse_left f m k, shift_inverse_right f m k⟩

end MosaicIntegerShift


/-! ## Continuous positive-real exponent shifts

For a fixed positive base, the real-indexed family has a genuine derivative.
This is the infinitesimal limit of its finite-step difference quotient.
-/

namespace MosaicRealExponentShift

/-- The real-parameter exponent family, written with the translated
parameter first so the derivative is a direct constant-base rpow chain rule. -/
noncomputable def value (x t : ℝ) : ℝ :=
  x ^ (t + x)

/-- For every positive base, the derivative with respect to the exponent
parameter is the value multiplied by the natural logarithm of the base. -/
theorem derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => value x s)
      (value x t * Real.log x) t := by
  have hlinear : HasDerivAt (fun s : ℝ => s + x) 1 t := by
    simpa using (hasDerivAt_id t).add_const x
  simpa [value, mul_comm, mul_left_comm, mul_assoc] using
    (HasDerivAt.const_rpow hx hlinear)

/-- The derivative is positive above base one, zero at base one, and
negative between zero and one, since the family itself is positive. -/
theorem derivative_sign (x t : ℝ) (hx : 0 < x) :
    (0 < Real.log x → 0 < (value x t * Real.log x)) ∧
    (Real.log x = 0 → value x t * Real.log x = 0) ∧
    (Real.log x < 0 → value x t * Real.log x < 0) := by
  have hvalue : 0 < value x t := by
    unfold value
    exact Real.rpow_pos_of_pos hx _
  constructor
  · intro hlog
    exact mul_pos hvalue hlog
  constructor
  · intro hlog
    rw [hlog, mul_zero]
  · intro hlog
    exact mul_neg_of_pos_of_neg hvalue hlog


/-- The secant slope based at t with nonzero real step h. -/
noncomputable def secantSlope (x t h : ℝ) : ℝ :=
  h⁻¹ • (value x (t + h) - value x t)

/-- As the nonzero step tends to zero, the secant slope converges to the
tangent slope. This is the explicit difference-quotient limit behind the
derivative theorem. -/
theorem secant_slope_limit (x t : ℝ) (hx : 0 < x) :
    Filter.Tendsto (fun h : ℝ => secantSlope x t h)
      (nhdsWithin 0 ({0}ᶜ))
      (nhds (value x t * Real.log x)) := by
  simpa [secantSlope] using (derivative x t hx).tendsto_slope_zero

/-- The same limiting slope is obtained from positive steps (approaching
from the right). -/
theorem secant_slope_limit_right (x t : ℝ) (hx : 0 < x) :
    Filter.Tendsto (fun h : ℝ => secantSlope x t h)
      (nhdsWithin 0 (Set.Ioi 0))
      (nhds (value x t * Real.log x)) := by
  simpa [secantSlope] using (derivative x t hx).tendsto_slope_zero_right

/-- The same limiting slope is obtained from negative steps (approaching
from the left). -/
theorem secant_slope_limit_left (x t : ℝ) (hx : 0 < x) :
    Filter.Tendsto (fun h : ℝ => secantSlope x t h)
      (nhdsWithin 0 (Set.Iio 0))
      (nhds (value x t * Real.log x)) := by
  simpa [secantSlope] using (derivative x t hx).tendsto_slope_zero_left


/-- The r-th formal derivative function of the fixed-base exponent family. -/
noncomputable def iteratedDerivative (x : ℝ) : Nat → ℝ → ℝ
  | 0, t => value x t
  | r + 1, t => iteratedDerivative x r t * Real.log x

/-- Every order of derivative exists, and differentiating once more
multiplies the current derivative by log x. -/
theorem iterated_derivative (x t : ℝ) (r : Nat) (hx : 0 < x) :
    HasDerivAt (fun s => iteratedDerivative x r s)
      (iteratedDerivative x r t * Real.log x) t := by
  induction r generalizing t with
  | zero =>
      simpa [iteratedDerivative] using derivative x t hx
  | succ r ih =>
      have h := (ih t).mul_const (Real.log x)
      simpa [iteratedDerivative, mul_assoc] using h

/-- Closed form for every iterated derivative:
the r-th derivative is (log x)^r times the original value. -/
theorem iterated_derivative_formula (x t : ℝ) (r : Nat) :
    iteratedDerivative x r t = (Real.log x) ^ r * value x t := by
  induction r with
  | zero =>
      simp [iteratedDerivative]
  | succ r ih =>
      rw [iteratedDerivative, ih]
      ring


/-- The joint positive-base exponent family, with both base and exponent
parameter visible. -/
noncomputable def jointValue (x t : ℝ) : ℝ :=
  x ^ (x + t)

/-- Differentiating the joint family with respect to its base gives the
power-rule contribution plus the logarithmic contribution from the
base-dependent exponent. -/
theorem base_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => jointValue s t)
      ((x + t) * x ^ (x + t - 1) +
        jointValue x t * Real.log x) x := by
  have hbase : HasDerivAt (fun s : ℝ => s) 1 x := hasDerivAt_id x
  have hexponent : HasDerivAt (fun s : ℝ => s + t) 1 x := by
    simpa using (hasDerivAt_id x).add_const t
  simpa [jointValue, mul_comm, mul_left_comm, mul_assoc] using
    hbase.rpow hexponent hx

/-- The exponent-parameter partial derivative of the joint family. -/
theorem exponent_partial_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => jointValue x s)
      (jointValue x t * Real.log x) t := by
  simpa [jointValue, value, add_comm] using derivative x t hx


/-- Evaluate the joint exponent family along a differentiable base path. -/
noncomputable def alongBasePath (u : ℝ → ℝ) (t : ℝ) : ℝ :=
  u t ^ (u t + t)

/-- Chain rule along a differentiable positive-base path. This combines
the changing-base and changing-exponent contributions in one derivative. -/
theorem along_base_path_derivative
    (u : ℝ → ℝ) (u' t : ℝ)
    (hu : HasDerivAt u u' t) (hx : 0 < u t) :
    HasDerivAt (fun s : ℝ => alongBasePath u s)
      (u' * (u t + t) * u t ^ (u t + t - 1) +
        (u' + 1) * alongBasePath u t * Real.log (u t)) t := by
  have hexponent : HasDerivAt (fun s : ℝ => u s + s) (u' + 1) t := by
    convert hu.add (hasDerivAt_id t) using 1 <;> funext s <;> simp
  simpa [alongBasePath, mul_assoc] using hu.rpow hexponent hx


/-- Evaluate the positive-base exponent family along two differentiable
coordinate paths. -/
noncomputable def alongJointPath (u v : ℝ → ℝ) (s : ℝ) : ℝ :=
  u s ^ (u s + v s)

/-- General two-coordinate path chain rule. The derivative separates into
the changing-base contribution and the changing-exponent contribution. -/
theorem along_joint_path_derivative
    (u v : ℝ → ℝ) (u' v' t : ℝ)
    (hu : HasDerivAt u u' t) (hv : HasDerivAt v v' t)
    (hx : 0 < u t) :
    HasDerivAt (fun s : ℝ => alongJointPath u v s)
      (u' * (u t + v t) * u t ^ (u t + v t - 1) +
        (u' + v') * alongJointPath u v t * Real.log (u t)) t := by
  have hexponent : HasDerivAt (fun s : ℝ => u s + v s) (u' + v') t := by
    convert hu.add hv using 1 <;> funext s <;> simp
  simpa [alongJointPath, mul_assoc] using hu.rpow hexponent hx


/-- Joint exponentiation of two differentiable real-valued coordinate maps
on an arbitrary real normed space. -/
noncomputable def jointMap {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E]
    (f g : E → ℝ) (z : E) : ℝ :=
  f z ^ (f z + g z)

/-- Full Fréchet chain rule for the joint exponent map. This is stronger than
a one-dimensional path theorem: the domain may be any real normed space, and
the derivative is a continuous linear map on that domain. -/
theorem joint_map_fderiv
    {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E]
    (f g : E → ℝ) (f' g' : E →L[ℝ] ℝ) (z : E)
    (hf : HasFDerivAt f f' z) (hg : HasFDerivAt g g' z)
    (hx : 0 < f z) :
    HasFDerivAt (fun w : E => jointMap f g w)
      (((f z + g z) * f z ^ (f z + g z - 1)) • f' +
        (f z ^ (f z + g z) * Real.log (f z)) • (f' + g')) z := by
  have hexponent : HasFDerivAt (fun w : E => f w + g w) (f' + g') z := by
    exact hf.add hg
  have h := hf.rpow hexponent hx
  convert h using 1 <;> simp [jointMap, smul_add, add_smul, mul_comm,
    mul_left_comm, mul_assoc]

end MosaicRealExponentShift
