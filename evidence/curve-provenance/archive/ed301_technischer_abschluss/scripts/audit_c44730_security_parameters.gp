\\ Independent security-parameter audit for candidate c=44730.
\\ This script reconstructs the curve, verifies the supplied group orders with
\\ PARI/GP SEA, proves the q-1 and qt-1 factorizations, and derives exact
\\ embedding degrees and generic ECDLP security metrics.

default(timer, 0);
default(realprecision, 120);
default(parisize, 536870912);
default(parisizemax, 4294967296);
default(factor_proven, 1);

output_path = "ed301_technischer_abschluss/rohresultate/audit_c44730_security_parameters_pari.txt";
out = fileopen(output_path, "w");

emit(x) =
{
  print(x);
  filewrite(out, x);
};

must(condition, message) =
{
  if (!condition, error(message));
};

prove_factorization(F, n, label) =
{
  my(rows = matsize(F)[1]);
  must(factorback(F) == n, Str(label, ": factor product mismatch"));
  for (i = 1, rows,
    must(isprime(F[i, 1]), Str(label, ": non-proven factor ", F[i, 1]));
  );
  1;
};

factor_primality_vector(F) =
{
  vector(matsize(F)[1], i, isprime(F[i, 1]));
};

factor_bitlength_vector(F) =
{
  vector(matsize(F)[1], i, logint(F[i, 1], 2) + 1);
};

order_witnesses(base, modulus, multiple, F, label) =
{
  my(rows = matsize(F)[1], witnesses = vector(rows));
  must(lift(Mod(base, modulus)^multiple) == 1,
       Str(label, ": Fermat/order multiple check failed"));
  for (i = 1, rows,
    witnesses[i] = [F[i, 1], lift(Mod(base, modulus)^(multiple / F[i, 1]))];
    must(witnesses[i][2] != 1,
         Str(label, ": order witness failed for prime divisor ", F[i, 1]));
  );
  witnesses;
};

\\ Fixed input parameters.
p = 2^301 - 2^99 + 947;
d = 301;
c = 44730;
s = 947 + c;
a = 2086388329;

q = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403;
qt = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103;
N = 4 * q;
Nt = 4 * qt;

must(s == 45677 && a == s^2, "candidate derivation mismatch");
must(isprime(p) && isprime(q) && isprime(qt), "p, q, or qt is not proven prime");
must(kronecker(a, p) == 1 && kronecker(d, p) == -1, "Edwards residue conditions failed");
must(a != 0 && d != 0 && a != d, "singular Edwards parameters");

\\ Reconstruct the Montgomery and Weierstrass models used by the primary audit.
A = lift(Mod(2 * (a + d), p) / Mod(a - d, p));
B = lift(Mod(4, p) / Mod(a - d, p));
must(A != 2 && A != p - 2 && B != 0, "invalid Montgomery parameters");
must(kronecker(A^2 - 4, p) == -1, "unexpected Montgomery discriminant character");

a2 = lift(Mod(A * B, p));
a4 = lift(Mod(B^2, p));
E = ellinit([0, Mod(a2, p), 0, Mod(a4, p), 0]);

twist_z = 2;
must(kronecker(twist_z, p) == -1, "twist_z is not a quadratic non-residue");
Et = ellinit([0, Mod(twist_z * a2, p), 0, Mod(twist_z^2 * a4, p), 0]);

\\ Independently rerun the point counts inside this audit artifact.
t_sea_start = getwalltime();
N_sea = ellsea(E);
t_sea_curve = getwalltime();
Nt_sea = ellsea(Et);
t_sea_twist = getwalltime();
must(N_sea == N, "curve SEA count differs from 4*q");
must(Nt_sea == Nt, "twist SEA count differs from 4*qt");
must(N + Nt == 2 * p + 2, "quadratic-twist order relation failed");

\\ Full, proven factorizations of q-1 and qt-1.
t_factor_start = getwalltime();
F_q_minus_1 = factor(q - 1);
t_factor_q = getwalltime();
F_qt_minus_1 = factor(qt - 1);
t_factor_qt = getwalltime();
must(prove_factorization(F_q_minus_1, q - 1, "q-1"), "q-1 proof failed");
must(prove_factorization(F_qt_minus_1, qt - 1, "qt-1"), "qt-1 proof failed");

\\ Exact multiplicative orders.  The witness for every prime r | (q-1)
\\ checks p^((q-1)/r) != 1 mod q; together with Fermat this proves maximal order.
W_q = order_witnesses(p, q, q - 1, F_q_minus_1, "ord_q(p)");
W_qt = order_witnesses(p, qt, qt - 1, F_qt_minus_1, "ord_qt(p)");
k_q = znorder(Mod(p, q), F_q_minus_1);
k_qt = znorder(Mod(p, qt), F_qt_minus_1);
must(k_q == q - 1, "embedding degree for q is not q-1");
must(k_qt == qt - 1, "embedding degree for qt is not qt-1");

\\ Trace, anomalous-curve, supersingularity, and CM checks.
t = p + 1 - N;
tt = p + 1 - Nt;
must(tt == -t, "twist trace is not -t");
must(t^2 <= 4 * p, "Hasse bound failed");

Delta_pi = t^2 - 4 * p;
cm_data = coredisc(Delta_pi, 1);
D_K = cm_data[1];
f_pi = cm_data[2];
must(Delta_pi == D_K * f_pi^2, "Frobenius discriminant decomposition failed");
must(isfundamental(D_K), "D_K is not a fundamental discriminant");
must(f_pi == 2, "unexpected Frobenius conductor");

j = lift(E.j);
must(j == lift(Et.j), "twist j-invariant mismatch");

log2_p = log(p) / log(2);
log2_q = log(q) / log(2);
log2_qt = log(qt) / log(2);
rho_bits_q = log2_q / 2;
rho_bits_qt = log2_qt / 2;
cm_nonscalar_degree_lower_bound = (abs(D_K) + 3) \ 4;

emit(Str("pari_version=", version()));
emit(Str("factor_proven=", default(factor_proven)));
emit(Str("p=", p));
emit(Str("bitlen_p=", logint(p, 2) + 1));
emit(Str("c=", c));
emit(Str("s=", s));
emit(Str("a=", a));
emit(Str("d=", d));
emit(Str("p_isprime=", isprime(p)));
emit(Str("q=", q));
emit(Str("q_isprime=", isprime(q)));
emit(Str("qt=", qt));
emit(Str("qt_isprime=", isprime(qt)));
emit(Str("N=", N));
emit(Str("N_factorization=", [2, 2; q, 1]));
emit(Str("N_twist=", Nt));
emit(Str("N_twist_factorization=", [2, 2; qt, 1]));
emit(Str("curve_cofactor=4"));
emit(Str("twist_cofactor=4"));
emit(Str("twist_relation_pass=", N + Nt == 2 * p + 2));
emit(Str("sea_curve_order=", N_sea));
emit(Str("sea_twist_order=", Nt_sea));
emit(Str("sea_curve_ms=", t_sea_curve - t_sea_start));
emit(Str("sea_twist_ms=", t_sea_twist - t_sea_curve));

emit(Str("factor_q_minus_1=", F_q_minus_1));
emit(Str("factor_q_minus_1_prime_proofs=", factor_primality_vector(F_q_minus_1)));
emit(Str("factor_q_minus_1_factor_bitlengths=", factor_bitlength_vector(F_q_minus_1)));
emit(Str("factor_q_minus_1_complete=", factorback(F_q_minus_1) == q - 1));
emit(Str("factor_q_minus_1_ms=", t_factor_q - t_factor_start));
emit(Str("factor_qt_minus_1=", F_qt_minus_1));
emit(Str("factor_qt_minus_1_prime_proofs=", factor_primality_vector(F_qt_minus_1)));
emit(Str("factor_qt_minus_1_factor_bitlengths=", factor_bitlength_vector(F_qt_minus_1)));
emit(Str("factor_qt_minus_1_complete=", factorback(F_qt_minus_1) == qt - 1));
emit(Str("factor_qt_minus_1_ms=", t_factor_qt - t_factor_q));

emit(Str("embedding_degree_q=", k_q));
emit(Str("embedding_degree_q_equals_q_minus_1=", k_q == q - 1));
emit(Str("embedding_degree_q_bitlength=", logint(k_q, 2) + 1));
emit(Str("embedding_degree_q_prime_divisor_witnesses=", W_q));
emit(Str("embedding_degree_qt=", k_qt));
emit(Str("embedding_degree_qt_equals_qt_minus_1=", k_qt == qt - 1));
emit(Str("embedding_degree_qt_bitlength=", logint(k_qt, 2) + 1));
emit(Str("embedding_degree_qt_prime_divisor_witnesses=", W_qt));
emit(Str("mov_no_embedding_degree_le_2pow64_curve=", k_q > 2^64));
emit(Str("mov_no_embedding_degree_le_2pow64_twist=", k_qt > 2^64));
emit(Str("mov_target_field_log2_cardinality_curve=", k_q * log2_p));
emit(Str("mov_target_field_log2_cardinality_twist=", k_qt * log2_p));

emit(Str("log2_q=", log2_q));
emit(Str("rho_security_bits_sqrt_q=", rho_bits_q));
emit(Str("floor_sqrt_q=", sqrtint(q)));
emit(Str("log2_qt=", log2_qt));
emit(Str("rho_security_bits_sqrt_qt=", rho_bits_qt));
emit(Str("floor_sqrt_qt=", sqrtint(qt)));

emit(Str("trace=", t));
emit(Str("trace_twist=", tt));
emit(Str("hasse_pass=", t^2 <= 4 * p));
emit(Str("anomalous_curve=", N == p));
emit(Str("anomalous_twist=", Nt == p));
emit(Str("trace_zero=", t == 0));
emit(Str("supersingular_curve=", ellissupersingular(E)));
emit(Str("supersingular_twist=", ellissupersingular(Et)));
emit(Str("j=", j));
emit(Str("j_is_zero=", j == 0));
emit(Str("j_is_1728=", j == lift(Mod(1728, p))));

emit(Str("frobenius_discriminant=", Delta_pi));
emit(Str("frobenius_discriminant_bitlength=", logint(abs(Delta_pi), 2) + 1));
emit(Str("fundamental_cm_discriminant=", D_K));
emit(Str("fundamental_cm_discriminant_is_fundamental=", isfundamental(D_K)));
emit(Str("fundamental_cm_discriminant_bitlength=", logint(abs(D_K), 2) + 1));
emit(Str("frobenius_conductor=", f_pi));
emit(Str("possible_endomorphism_ring_discriminants=", [D_K, Delta_pi]));
emit(Str("cm_nonscalar_degree_lower_bound=", cm_nonscalar_degree_lower_bound));
emit(Str("cm_nonscalar_degree_lower_bound_log2=", log(cm_nonscalar_degree_lower_bound) / log(2)));

emit(Str("q_distinct_from_qt=", q != qt));
emit(Str("gcd_q_qt=", gcd(q, qt)));
emit(Str("gcd_q_minus_1_qt_minus_1=", gcd(q - 1, qt - 1)));
emit(Str("edwards_a_legendre=", kronecker(a, p)));
emit(Str("edwards_d_legendre=", kronecker(d, p)));
emit(Str("montgomery_A_squared_minus_4_legendre=", kronecker(A^2 - 4, p)));
emit(Str("field_modulus_pseudo_mersenne_relation_pass=", 2^301 == p + 2^99 - 947));
emit("audit_pass=1");

fileclose(out);
quit;
