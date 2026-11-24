# Worked example: a rapidly convergent series and Taylor expansion

This note records a small mathematical example in the style used by MOSAIC: separate symbolic transformations, numerical evidence, and proof obligations. The arguments below are ordinary mathematical proofs; this document does not claim that they have been checked by Lean.

## 1. Normalize the expression

For positive integers `n`,

\[
\frac{n}{n^n}=n^{1-n}=\frac{1}{n^{n-1}}.
\]

The first equality uses the quotient law for integer exponents. The reciprocal form makes positivity and comparison easier to see.

Define the partial sums

\[
S_N=\sum_{n=1}^{N}\frac{1}{n^{n-1}}.
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

## 2. Prove convergence by comparison

For every integer \(n\ge 2\), we have \(n\ge 2\), hence

\[
n^{n-1}\ge 2^{n-1}
\quad\Longrightarrow\quad
0<\frac{1}{n^{n-1}}\le \frac{1}{2^{n-1}}.
\]

The comparison series is geometric:

\[
\sum_{n=2}^{\infty}\frac{1}{2^{n-1}}=1.
\]

Adding the initial term \(1\), the comparison test proves that

\[
S=\sum_{n=1}^{\infty}\frac{1}{n^{n-1}}
\]

converges and satisfies \(1<S\le 2\).

The same comparison gives a simple tail bound. For every integer \(N\ge 1\),

\[
0<S-S_N
=\sum_{n=N+1}^{\infty}\frac{1}{n^{n-1}}
\le \sum_{n=N+1}^{\infty}\frac{1}{2^{n-1}}
=2^{1-N}.
\]

This bound is valid but deliberately conservative. It is useful because it turns a qualitative convergence claim into an explicit error guarantee.

## 3. Compare the sum with the constant e

For every integer \(n\ge 1\),

\[
(n-1)!=1\cdot2\cdots(n-1)\le n^{n-1},
\]

where \(0!=1\) handles \(n=1\). Therefore

\[
\frac{1}{n^{n-1}}\le\frac{1}{(n-1)!}.
\]

Summing and reindexing with \(k=n-1\),

\[
S\le\sum_{n=1}^{\infty}\frac{1}{(n-1)!}
=\sum_{k=0}^{\infty}\frac{1}{k!}=e.
\]

Thus \(1<S\le e\). This is a comparison bound, not an identity for \(S\).

## 4. Taylor series: a related but distinct construction

The exponential function has the Taylor expansion

\[
e^x=\sum_{k=0}^{\infty}\frac{x^k}{k!}
=1+x+\frac{x^2}{2!}+\frac{x^3}{3!}+\cdots,
\]

which converges for every real (indeed complex) \(x\). Its coefficients follow because every derivative of \(e^x\) is \(e^x\), and every derivative evaluated at zero equals one.

For a general function, having derivatives of all orders is not by itself enough to guarantee that its Taylor series equals the function. Equality requires an additional condition, such as analyticity in a neighborhood of the expansion point (or a suitable Taylor-remainder argument).

The series \(S\) above and the Taylor series for \(e^x\) are related through factorial comparison, but they are different series with different terms.

## 5. A recurrence for numerical evaluation

Let

\[
a_n=\frac{1}{n^{n-1}}.
\]

Then \(a_1=1\), and for \(n\ge 1\),

\[
\frac{a_{n+1}}{a_n}
=\frac{n^{n-1}}{(n+1)^n}.
\]

This recurrence can be used to generate terms without separately constructing powers from scratch. In floating-point software, the recurrence still needs a numerical error policy; a computed decimal does not replace the convergence proof.

## 6. Formal verification status

The isolated Lean entrypoint at formal/polynomial/Main.lean now kernel-checks the core convergence argument for the reindexed series

\\[
a_k=\\frac{1}{(k+1)^k},\\qquad k\\ge0.
\\]

The reindexing \\(k=n-1\\) identifies this with the original terms \\(1/n^{n-1}\\). The Lean development proves:

1. **Term positivity:** \\(a_k>0\\) for every natural number \\(k\\).
2. **Denominator comparison:** \\(2^k\\le(k+1)^k\\), using natural-power monotonicity.
3. **Geometric domination:** \\(a_k\\le(1/2)^k\\).
4. **Summability:** \\(\\sum_{k=0}^{\\infty}a_k\\) is summable, by comparison with the geometric series.
5. **Total bound:** \\(\\sum_{k=0}^{\\infty}a_k\\le2\\).
6. **Shifted tail bound:** for every \\(N\\ge0\\),
   \\(\\sum_{k=0}^{\\infty}a_{N+k}\\le2(1/2)^N\\).
   For \\(N\\ge1\\), this is the same as the stated \\(2^{1-N}\\) bound.

These are Lean theorems checked by the pinned Mathlib/Lean CI job. The Lean development does **not** yet formalize the quotient-law normalization as a theorem, the factorial comparison with \\(e\\), Taylor's theorem, or a certified decimal interval for the numerical approximation. Those remain separate proof obligations.

A numerical computation, an ordinary mathematical argument, and a kernel-checked proof are three different evidence levels. The source code and successful CI run establish only the exact propositions encoded in the Lean theorems; they do not certify claims left in this explanatory note.
