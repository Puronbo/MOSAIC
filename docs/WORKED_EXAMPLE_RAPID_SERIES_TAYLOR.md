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

## 6. Verification obligations

A checker or formalization of this example should keep the following claims separate:

1. **Algebraic normalization:** prove \(n/n^n=n^{1-n}\) under explicit domain assumptions.
2. **Term positivity:** prove \(1/n^{n-1}>0\) for positive integer \(n\).
3. **Geometric domination:** prove \(1/n^{n-1}\le 1/2^{n-1}\) for \(n\ge2\).
4. **Convergence:** apply a formally stated comparison test to the positive series.
5. **Tail estimate:** derive \(0<S-S_N\le 2^{1-N}\).
6. **Factorial comparison:** prove \((n-1)!\le n^{n-1}\) and use the exponential-series identity for \(e\).
7. **Numerical approximation:** specify precision, rounding behavior, and a certified remainder bound if a decimal is to be presented as a guaranteed interval.

A numerical computation, a mathematical argument, and a kernel-checked proof are three different evidence levels. A future Lean development should prove the obligations it claims to cover rather than treating this explanatory note or its decimal output as a certificate.
