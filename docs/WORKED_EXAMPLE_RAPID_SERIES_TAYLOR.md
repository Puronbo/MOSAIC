# Worked example: a rapidly convergent series and Taylor expansion

This note records a small mathematical example in the style used by MOSAIC: separate symbolic transformations, numerical evidence, and proof obligations. The arguments below are ordinary mathematical proofs; this document does not claim that they have all been checked by Lean.

## 1. Normalize the expression

For positive integers `n`,
\[
\frac{n}{n^n}=n^{1-n}=\frac{1}{n^{n-1}}.
\]

Define
\[
S_N=\sum_{n=1}^{N}\frac{1}{n^{n-1}},\qquad
S=\sum_{n=1}^{\infty}\frac{1}{n^{n-1}}.
\]
The first terms are
\[
1+\frac12+\frac19+\frac1{64}+\frac1{625}+\cdots.
\]
A floating-point evaluation gives approximately
\[
S_{30}\approx 1.6284737129015845.
\]
This decimal is numerical evidence, not an exact representation of the infinite sum.

## 2. Convergence and a quantitative tail estimate

For every integer \(n\ge2\), monotonicity of natural powers gives
\[
2^{n-1}\le n^{n-1},
\qquad
0<\frac1{n^{n-1}}\le\frac1{2^{n-1}}.
\]
Since
\[
\sum_{n=2}^{\infty}\frac1{2^{n-1}}=1,
\]
the comparison test proves that \(S\) converges and \(1<S\le2\).

For every \(N\ge1\),
\[
0<S-S_N
\le\sum_{n=N+1}^{\infty}\frac1{2^{n-1}}
=2^{1-N}.
\]
This bound is conservative but gives an explicit error guarantee.

## 3. Comparison with e

For every \(n\ge1\),
\[
(n-1)!\le n^{n-1},
\qquad
\frac1{n^{n-1}}\le\frac1{(n-1)!}.
\]
Reindexing the exponential series yields \(S\le e\). This is a comparison bound, not an identity.

## 4. Taylor series

The exponential function has the expansion
\[
e^x=\sum_{k=0}^{\infty}\frac{x^k}{k!},
\]
which converges for every real (indeed complex) \(x\). A function having derivatives of all orders is not by itself enough to guarantee that its Taylor series equals the function; analyticity or a suitable remainder argument is additionally required.

The series \(S\) and the Taylor series for \(e^x\) are distinct series.

## 5. Recurrence for numerical evaluation

Let \(a_n=n^{1-n}\). Then \(a_1=1\) and
\[
\frac{a_{n+1}}{a_n}=\frac{n^{n-1}}{(n+1)^n}.
\]
A recurrence can reduce repeated exponentiation, but floating-point evaluation still needs an error policy.

## 6. Formal verification status

The currently green Lean entrypoint proves the polynomial identities and the natural-number power-monotonicity lemma
\[
a\le b\Longrightarrow a^k\le b^k.
\]
It also proves the denominator inequality \(2^{n-1}\le n^{n-1}\) for \(n\ge2\). These arithmetic facts are kernel-checked by the pinned Lean/Mathlib CI job.

**The infinite-series formalization is not yet verified.** An attempted extension introduced real-valued terms, summability, a total-sum bound, and a shifted-tail bound, but the Lean CI run failed during theorem elaboration. The attempted source has been withdrawn rather than reported as a proof. In particular, the claims of summability, \(S\le2\), and the infinite tail estimate above currently rest on the written mathematical comparison argument, not on a Lean theorem in this repository.

The quotient-law normalization, factorial comparison with \(e\), Taylor's theorem, and a certified decimal interval also remain separate formalization tasks. Numerical computation, an ordinary mathematical argument, and a kernel-checked proof are distinct evidence levels.

## 7. A real-exponent equation and a constant substitution

The nearby equation
\[
x^x-1=2
\]
is equivalent (for real \(x>0\)) to \(x^x=3\). It has no natural-number
solution, as established by the Lean theorem in formal/polynomial/Main.lean.
Over the positive reals it has exactly one solution. Indeed, \(x^x=3\)
implies \(x>1\), and
\[
\frac{d}{dx}(x^x)=x^x(\ln x+1)>0
\]
for \(x>1\), so the function is strictly increasing there. Solving
\(x\ln x=\ln 3\) with the Lambert \(W\) function gives
\[
x=\exp(W(\ln 3))=\frac{\ln 3}{W(\ln 3)}
\approx1.82545502292483004.
\]
The Lambert \(W\) expression is an analytic characterization; the decimal
is a numerical approximation.

For the constant substitution \(x=\pi\), the two different expressions are
\[
\pi^{\pi-1}\approx11.60626587458556,
\qquad
\pi^\pi-1\approx35.46215960720791.
\]
The parentheses are mathematically significant: \(\pi^{\pi-1}\) is not
\(\pi^\pi-1\).
