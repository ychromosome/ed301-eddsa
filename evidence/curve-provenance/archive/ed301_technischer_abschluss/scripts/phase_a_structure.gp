\\ ED301 Phase A: Trace, Frobenius-/CM-Daten und Sonderstrukturen.
default(timer, 1);
default(parisize, 536870912);
default(parisizemax, 4294967296);
default(factor_proven, 1);

p = 2^301 - 2^99 + 947;
a = 1;
d = 301;
A = lift(Mod(2 * (a + d), p) / Mod(a - d, p));
B = lift(Mod(4, p) / Mod(a - d, p));
a2 = lift(Mod(A * B, p));
a4 = lift(Mod(B^2, p));
E = ellinit([0, Mod(a2, p), 0, Mod(a4, p), 0]);
Et = ellinit([0, Mod(2*a2, p), 0, Mod(4*a4, p), 0]);

N = 4074071952668972172536891376818756322102936790024709516523088567757405009860459412423203588;
N_twist = 4074071952668972172536891376818756322102936784639035486021471962009519960963485915607182436;
t = p + 1 - N;
t_twist = p + 1 - N_twist;
Delta_pi = t^2 - 4*p;
D_K = coredisc(Delta_pi);
conductor_square = Delta_pi / D_K;
if (!issquare(conductor_square, &f_pi), error("Delta_pi/D_K ist kein Quadrat"));

j = lift(E.j);
j_twist = lift(Et.j);
if (j != j_twist, error("Twist besitzt abweichende j-Invariante"));
if (t_twist != -t, error("Twist-Trace ist nicht -t"));

print("pari_version=", version());
print("trace=", t);
print("trace_twist=", t_twist);
print("hasse_pass=", t^2 <= 4*p);
print("anomalous_curve=", N == p);
print("anomalous_twist=", N_twist == p);
print("supersingular_curve=", ellissupersingular(E));
print("supersingular_twist=", ellissupersingular(Et));
print("j=", j);
print("j_twist=", j_twist);
print("j_is_zero=", j == 0);
print("j_is_1728=", j == lift(Mod(1728, p)));
print("frobenius_discriminant=", Delta_pi);
print("fundamental_discriminant=", D_K);
print("frobenius_conductor=", f_pi);
print("factor_frobenius_conductor=", factor(f_pi));
print("recomposition=", D_K * f_pi^2);

fd = fileopen("ed301_technischer_abschluss/rohresultate/phase_a_structure_pari.txt", "w");
filewrite(fd, Str("pari_version=", version()));
filewrite(fd, Str("trace=", t));
filewrite(fd, Str("trace_twist=", t_twist));
filewrite(fd, Str("hasse_pass=", t^2 <= 4*p));
filewrite(fd, Str("anomalous_curve=", N == p));
filewrite(fd, Str("anomalous_twist=", N_twist == p));
filewrite(fd, Str("supersingular_curve=", ellissupersingular(E)));
filewrite(fd, Str("supersingular_twist=", ellissupersingular(Et)));
filewrite(fd, Str("j=", j));
filewrite(fd, Str("j_twist=", j_twist));
filewrite(fd, Str("j_is_zero=", j == 0));
filewrite(fd, Str("j_is_1728=", j == lift(Mod(1728, p))));
filewrite(fd, Str("frobenius_discriminant=", Delta_pi));
filewrite(fd, Str("fundamental_discriminant=", D_K));
filewrite(fd, Str("frobenius_conductor=", f_pi));
filewrite(fd, Str("factor_frobenius_conductor=", factor(f_pi)));
filewrite(fd, Str("recomposition=", D_K * f_pi^2));
fileclose(fd);
quit;
