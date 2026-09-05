\\ Full, read-only PARI/GP reproducibility audit for the ED301 candidate c=44730.
\\
\\ The script writes no files and does not trust stored point counts or
\\ factorizations.  Capture stdout explicitly, for example:
\\   gp -q -f ed301_technischer_abschluss/scripts/audit_c44730_full_reproducibility.gp
\\
\\ All costly claims are recomputed: ECPP primality certificates, SEA point
\\ counts, complete factorizations, exact embedding degrees, and CM data.

default(timer, 0);
default(realprecision, 120);
default(parisize, 536870912);
default(parisizemax, 4294967296);
default(factor_proven, 1);

must(condition, message) =
{
  if (!condition, error(message));
  1;
};

all_factor_bases_prime(F) =
{
  my(rows = matsize(F)[1]);
  for (i = 1, rows,
    if (!isprime(F[i, 1]), return(0));
  );
  1;
};

factor_degrees(F) =
{
  vector(matsize(F)[1], i, poldegree(F[i, 1]));
};

full_order_witnesses_pass(base, modulus, order, F) =
{
  my(rows = matsize(F)[1]);
  if (lift(Mod(base, modulus)^order) != 1, return(0));
  for (i = 1, rows,
    if (lift(Mod(base, modulus)^(order / F[i, 1])) == 1, return(0));
  );
  1;
};

small_order_hits(base, modulus, bound) =
{
  my(hits = List());
  for (i = 1, bound,
    if (lift(Mod(base, modulus)^i) == 1, listput(hits, i));
  );
  Vec(hits);
};

print("audit_script=ed301_technischer_abschluss/scripts/audit_c44730_full_reproducibility.gp");
print("pari_version=", version());
print("pari_datadir=", default(datadir));
print("pari_nbthreads=", default(nbthreads));
print("factor_proven=", default(factor_proven));
print("realprecision=", default(realprecision));

\\ -------------------------------------------------------------------------
\\ Field modulus and formal primality proof.
\\ -------------------------------------------------------------------------
p = 2^301 - 2^99 + 947;
p_expected = 4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011;
must(p == p_expected, "field modulus derivation mismatch");

t0 = getwalltime();
cert_p = primecert(p, 0);
t1 = getwalltime();
p_certificate_valid = primecertisvalid(cert_p);
t2 = getwalltime();
must(p_certificate_valid, "p ECPP certificate did not validate");

print("p=", p);
print("p_hex=0x", Strprintf("%x", p));
print("p_bitlength=", logint(p, 2) + 1);
print("p_mod_4=", p % 4);
print("p_mod_8=", p % 8);
print("p_ecpp_steps=", #cert_p);
print("p_ecpp_generation_ms=", t1 - t0);
print("p_ecpp_validation_ms=", t2 - t1);
print("p_ecpp_certificate_valid=", p_certificate_valid);

\\ -------------------------------------------------------------------------
\\ Deterministic Edwards candidate and equivalent curve models.
\\ -------------------------------------------------------------------------
d = 301;
c = 44730;
s = 947 + c;
a = s^2;
must(s == 45677 && a == 2086388329, "candidate derivation mismatch");
must(a != 0 && d != 0 && a != d, "singular Edwards parameters");
must(kronecker(a, p) == 1, "a is not a quadratic residue");
must(kronecker(d, p) == -1, "d is not a quadratic non-residue");

A = lift(Mod(2 * (a + d), p) / Mod(a - d, p));
B = lift(Mod(4, p) / Mod(a - d, p));
A24_plus = lift(Mod(A + 2, p) / Mod(4, p));
A24_minus = lift(Mod(A - 2, p) / Mod(4, p));
A_squared_minus_4 = lift(Mod(A^2 - 4, p));
must(A != 2 && A != p - 2 && B != 0, "singular Montgomery model");
must(kronecker(A_squared_minus_4, p) == -1, "unexpected character of A^2-4");
must(A_squared_minus_4 == lift(Mod(16 * a * d, p) / Mod((a - d)^2, p)), "Montgomery discriminant identity failed");

\\ For B*v^2 = u^3 + A*u^2 + u, use X=B*u and Y=B^2*v.
a2w = lift(Mod(A * B, p));
a4w = lift(Mod(B^2, p));
E = ellinit([0, Mod(a2w, p), 0, Mod(a4w, p), 0]);

twist_z = 2;
must(kronecker(twist_z, p) == -1, "z=2 is not a quadratic non-residue");
a2wt = lift(Mod(twist_z * a2w, p));
a4wt = lift(Mod(twist_z^2 * a4w, p));
Et = ellinit([0, Mod(a2wt, p), 0, Mod(a4wt, p), 0]);

disc_E = lift(E.disc);
disc_Et = lift(Et.disc);
must(disc_E != 0 && disc_Et != 0, "singular Weierstrass model");

\\ Completeness preconditions and an explicit Edwards order-4 point.
x_order4 = lift(Mod(1, p) / Mod(s, p));
must(lift(Mod(a * x_order4^2, p)) == 1, "order-4 point is off curve");
order4_double_x = 0;
order4_double_y = lift(Mod(-a * x_order4^2, p));
must(order4_double_y == p - 1, "order-4 point does not double to (0,-1)");

print("c=", c);
print("s=", s);
print("edwards_a=", a);
print("edwards_d=", d);
print("edwards_a_legendre=", kronecker(a, p));
print("edwards_d_legendre=", kronecker(d, p));
print("edwards_complete_addition_preconditions_pass=1");
print("montgomery_A=", A);
print("montgomery_A_hex=0x", Strprintf("%x", A));
print("montgomery_B=", B);
print("montgomery_B_hex=0x", Strprintf("%x", B));
print("montgomery_A24_plus=", A24_plus);
print("montgomery_A24_plus_hex=0x", Strprintf("%x", A24_plus));
print("montgomery_A24_minus=", A24_minus);
print("montgomery_A24_minus_hex=0x", Strprintf("%x", A24_minus));
print("montgomery_A_squared_minus_4=", A_squared_minus_4);
print("montgomery_A_squared_minus_4_legendre=", kronecker(A_squared_minus_4, p));
print("weierstrass_coefficients=", [0, a2w, 0, a4w, 0]);
print("weierstrass_discriminant=", disc_E);
print("twist_nonresidue=", twist_z);
print("twist_weierstrass_coefficients=", [0, a2wt, 0, a4wt, 0]);
print("twist_weierstrass_discriminant=", disc_Et);
print("edwards_order4_x=", x_order4);
print("edwards_order4_y=0");
print("edwards_order4_double=", [order4_double_x, order4_double_y]);

\\ -------------------------------------------------------------------------
\\ Exact curve and twist orders, rerun with both ellsea and ellcard.
\\ -------------------------------------------------------------------------
N_expected = 4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612;
Nt_expected = 4074071952668972172536891376818756322102936785292475840710068942732788076946225991873048412;
q_expected = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403;
qt_expected = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103;

t0 = getwalltime();
N_sea = ellsea(E);
t1 = getwalltime();
Nt_sea = ellsea(Et);
t2 = getwalltime();
N_card = ellcard(E);
t3 = getwalltime();
Nt_card = ellcard(Et);
t4 = getwalltime();

must(N_sea == N_expected && Nt_sea == Nt_expected, "SEA point count mismatch");
must(N_card == N_sea && Nt_card == Nt_sea, "ellcard cross-check mismatch");
must(N_sea + Nt_sea == 2 * p + 2, "quadratic-twist relation failed");

N = N_sea;
Nt = Nt_sea;
q = N / 4;
qt = Nt / 4;
must(q == q_expected && qt == qt_expected, "prime subgroup order mismatch");

t_factor_order_0 = getwalltime();
F_N = factor(N);
t_factor_order_1 = getwalltime();
F_Nt = factor(Nt);
t_factor_order_2 = getwalltime();
must(F_N == [2, 2; q, 1], "curve-order factorization mismatch");
must(F_Nt == [2, 2; qt, 1], "twist-order factorization mismatch");
must(all_factor_bases_prime(F_N) && all_factor_bases_prime(F_Nt), "unproven factor in group orders");

t0_cert = getwalltime();
cert_q = primecert(q, 0);
t1_cert = getwalltime();
cert_qt = primecert(qt, 0);
t2_cert = getwalltime();
q_certificate_valid = primecertisvalid(cert_q);
t3_cert = getwalltime();
qt_certificate_valid = primecertisvalid(cert_qt);
t4_cert = getwalltime();
must(q_certificate_valid && qt_certificate_valid, "subgroup ECPP certificate validation failed");

t_group_0 = getwalltime();
group_E = ellgroup(E);
t_group_1 = getwalltime();
group_Et = ellgroup(Et);
t_group_2 = getwalltime();
must(group_E == [N] && group_Et == [Nt], "unexpected group structure");

print("curve_order=", N);
print("curve_order_hex=0x", Strprintf("%x", N));
print("curve_order_factorization=", F_N);
print("curve_cofactor=", N / q);
print("curve_group_structure=", group_E);
print("curve_subgroup_q=", q);
print("curve_subgroup_q_hex=0x", Strprintf("%x", q));
print("curve_subgroup_q_bitlength=", logint(q, 2) + 1);
print("curve_subgroup_q_log2=", log(q) / log(2));
print("curve_subgroup_q_ecpp_steps=", #cert_q);
print("curve_subgroup_q_ecpp_certificate_valid=", q_certificate_valid);
print("twist_order=", Nt);
print("twist_order_hex=0x", Strprintf("%x", Nt));
print("twist_order_factorization=", F_Nt);
print("twist_cofactor=", Nt / qt);
print("twist_group_structure=", group_Et);
print("twist_subgroup_q=", qt);
print("twist_subgroup_q_hex=0x", Strprintf("%x", qt));
print("twist_subgroup_q_bitlength=", logint(qt, 2) + 1);
print("twist_subgroup_q_log2=", log(qt) / log(2));
print("twist_subgroup_q_ecpp_steps=", #cert_qt);
print("twist_subgroup_q_ecpp_certificate_valid=", qt_certificate_valid);
print("twist_order_relation_pass=", N + Nt == 2 * p + 2);
print("ellsea_curve_ms=", t1 - t0);
print("ellsea_twist_ms=", t2 - t1);
print("ellcard_curve_ms=", t3 - t2);
print("ellcard_twist_ms=", t4 - t3);
print("factor_curve_order_ms=", t_factor_order_1 - t_factor_order_0);
print("factor_twist_order_ms=", t_factor_order_2 - t_factor_order_1);
print("q_ecpp_generation_ms=", t1_cert - t0_cert);
print("qt_ecpp_generation_ms=", t2_cert - t1_cert);
print("q_ecpp_validation_ms=", t3_cert - t2_cert);
print("qt_ecpp_validation_ms=", t4_cert - t3_cert);
print("ellgroup_curve_ms=", t_group_1 - t_group_0);
print("ellgroup_twist_ms=", t_group_2 - t_group_1);

\\ -------------------------------------------------------------------------
\\ Trace, ordinary/CM data, and complete Frobenius-discriminant factorization.
\\ -------------------------------------------------------------------------
t = p + 1 - N;
tt = p + 1 - Nt;
Delta_pi = t^2 - 4 * p;
must(tt == -t, "twist trace is not -t");
must(t^2 <= 4 * p, "Hasse bound failed");

F_Delta_expected = [2, 2; 92377, 1; 35332661563307, 1; 10858182674212290997273094143007, 1; 85616869318705925510845993428767960358607, 1];
t_delta_0 = getwalltime();
F_Delta = factor(abs(Delta_pi));
t_delta_1 = getwalltime();
must(F_Delta == F_Delta_expected, "Frobenius-discriminant factorization mismatch");
must(factorback(F_Delta) == abs(Delta_pi) && all_factor_bases_prime(F_Delta), "Frobenius-discriminant factorization not complete/proven");

t_cm_0 = getwalltime();
cm_data = coredisc(Delta_pi, 1);
t_cm_1 = getwalltime();
D_K = cm_data[1];
f_pi = cm_data[2];
must(Delta_pi == D_K * f_pi^2, "CM discriminant decomposition failed");
must(isfundamental(D_K) && f_pi == 2, "unexpected CM data");

j = lift(E.j);
must(j == lift(Et.j), "twist j-invariant mismatch");
phi2_at_j = polmodular(2, 0, Mod(j, p), 'y);
F_phi2 = factor(phi2_at_j);
phi2_degree_pattern = factor_degrees(F_phi2);
must(phi2_degree_pattern == [1, 2], "unexpected rational 2-isogeny pattern");

print("trace=", t);
print("twist_trace=", tt);
print("hasse_bound_pass=", t^2 <= 4 * p);
print("anomalous_curve=", N == p);
print("anomalous_twist=", Nt == p);
print("trace_zero=", t == 0);
print("supersingular_curve=", ellissupersingular(E));
print("supersingular_twist=", ellissupersingular(Et));
print("j_invariant=", j);
print("j_invariant_hex=0x", Strprintf("%x", j));
print("j_is_zero=", j == 0);
print("j_is_1728=", j == lift(Mod(1728, p)));
print("frobenius_discriminant=", Delta_pi);
print("frobenius_discriminant_bitlength=", logint(abs(Delta_pi), 2) + 1);
print("frobenius_discriminant_factorization=", F_Delta);
print("frobenius_discriminant_factorization_complete=1");
print("fundamental_cm_discriminant=", D_K);
print("fundamental_cm_discriminant_bitlength=", logint(abs(D_K), 2) + 1);
print("fundamental_cm_discriminant_is_fundamental=", isfundamental(D_K));
print("frobenius_conductor=", f_pi);
print("possible_endomorphism_ring_discriminants=", [D_K, Delta_pi]);
print("phi2_at_j_factor_degrees=", phi2_degree_pattern);
print("rational_2_isogeny_count=1");
print("factor_frobenius_discriminant_ms=", t_delta_1 - t_delta_0);
print("coredisc_ms_after_factorization=", t_cm_1 - t_cm_0);

\\ -------------------------------------------------------------------------
\\ Exact embedding degrees and generic ECDLP work factors.
\\ -------------------------------------------------------------------------
F_q_minus_1_expected = [2, 1; 3, 1; 83, 1; 103, 1; 487, 1; 8071538763312550939901261, 1; 10140257736222944349715877, 1; 498158843412220847318631521539897, 1];
F_qt_minus_1_expected = [2, 1; 11, 1; 46296272189420138324282856554758594569351554378323589098978056167418046328934386271284641, 1];

t_factor_k_0 = getwalltime();
F_q_minus_1 = factor(q - 1);
t_factor_k_1 = getwalltime();
F_qt_minus_1 = factor(qt - 1);
t_factor_k_2 = getwalltime();
must(F_q_minus_1 == F_q_minus_1_expected, "q-1 factorization mismatch");
must(F_qt_minus_1 == F_qt_minus_1_expected, "qt-1 factorization mismatch");
must(factorback(F_q_minus_1) == q - 1 && all_factor_bases_prime(F_q_minus_1), "q-1 factorization not complete/proven");
must(factorback(F_qt_minus_1) == qt - 1 && all_factor_bases_prime(F_qt_minus_1), "qt-1 factorization not complete/proven");

order_witnesses_q_pass = full_order_witnesses_pass(p, q, q - 1, F_q_minus_1);
order_witnesses_qt_pass = full_order_witnesses_pass(p, qt, qt - 1, F_qt_minus_1);
must(order_witnesses_q_pass && order_witnesses_qt_pass, "multiplicative-order witness failed");
k_q = znorder(Mod(p, q), F_q_minus_1);
k_qt = znorder(Mod(p, qt), F_qt_minus_1);
must(k_q == q - 1 && k_qt == qt - 1, "embedding degree is not maximal");
hits_q_100 = small_order_hits(p, q, 100);
hits_qt_100 = small_order_hits(p, qt, 100);
must(#hits_q_100 == 0 && #hits_qt_100 == 0, "small embedding degree found");

log2_p = log(p) / log(2);
rho_q = sqrt(Pi * q / 2);
rho_qt = sqrt(Pi * qt / 2);
rho_q_negation = sqrt(Pi * q / 4);
rho_qt_negation = sqrt(Pi * qt / 4);

print("factor_q_minus_1=", F_q_minus_1);
print("factor_q_minus_1_complete=1");
print("factor_q_minus_1_ms=", t_factor_k_1 - t_factor_k_0);
print("factor_twist_q_minus_1=", F_qt_minus_1);
print("factor_twist_q_minus_1_complete=1");
print("factor_twist_q_minus_1_ms=", t_factor_k_2 - t_factor_k_1);
print("embedding_degree_q=", k_q);
print("embedding_degree_q_equals_q_minus_1=", k_q == q - 1);
print("embedding_degree_q_full_order_witnesses_pass=", order_witnesses_q_pass);
print("embedding_degree_q_small_hits_1_through_100=", hits_q_100);
print("embedding_degree_twist_q=", k_qt);
print("embedding_degree_twist_q_equals_q_minus_1=", k_qt == qt - 1);
print("embedding_degree_twist_q_full_order_witnesses_pass=", order_witnesses_qt_pass);
print("embedding_degree_twist_q_small_hits_1_through_100=", hits_qt_100);
print("mov_target_field_log2_cardinality_curve=", k_q * log2_p);
print("mov_target_field_log2_cardinality_twist=", k_qt * log2_p);
print("pollard_rho_curve_expected_group_ops=", rho_q);
print("pollard_rho_curve_expected_group_ops_ceil=", ceil(rho_q));
print("pollard_rho_curve_security_bits=", log(rho_q) / log(2));
print("pollard_rho_curve_with_negation_security_bits=", log(rho_q_negation) / log(2));
print("pollard_rho_twist_expected_group_ops=", rho_qt);
print("pollard_rho_twist_expected_group_ops_ceil=", ceil(rho_qt));
print("pollard_rho_twist_security_bits=", log(rho_qt) / log(2));
print("pollard_rho_twist_with_negation_security_bits=", log(rho_qt_negation) / log(2));
print("strict_150_bit_generic_security_curve=", log(rho_q) / log(2) >= 150);
print("strict_150_bit_generic_security_twist=", log(rho_qt) / log(2) >= 150);
print("approximately_150_bit_generic_security=1");

print("audit_pass=1");
quit;
