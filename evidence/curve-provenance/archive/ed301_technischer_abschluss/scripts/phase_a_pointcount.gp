\\ ED301 Phase A: direktes SEA-Point-Counting fuer Kurve und expliziten Twist.
default(timer, 1);
default(parisizemax, 17179869184);

p = 2^301 - 2^99 + 947;
a = 1;
d = 301;
A = lift(Mod(2 * (a + d), p) / Mod(a - d, p));
B = lift(Mod(4, p) / Mod(a - d, p));

\\ Aus B*v^2=u^3+A*u^2+u wird mit X=B*u, Y=B^2*v:
\\ Y^2=X^3+(A*B)X^2+B^2*X.
a2 = lift(Mod(A * B, p));
a4 = lift(Mod(B^2, p));
E = ellinit([0, Mod(a2, p), 0, Mod(a4, p), 0]);

\\ z=2 ist ein quadratischer Nichtrest. Das explizite Twistmodell lautet:
\\ Y^2=X^3+(z*a2)X^2+(z^2*a4)X.
z = 2;
if (kronecker(z, p) != -1, error("z ist kein quadratischer Nichtrest"));
Et = ellinit([0, Mod(z * a2, p), 0, Mod(z^2 * a4, p), 0]);

print("pari_version=", version());
print("p=", p);
print("A=", A);
print("B=", B);
print("weierstrass_coefficients=", [0, a2, 0, a4, 0]);
print("twist_z=", z);
print("twist_coefficients=", [0, lift(Mod(z*a2,p)), 0, lift(Mod(z^2*a4,p)), 0]);

gettime();
N = ellsea(E);
time_E_ms = gettime();
print("N=", N);
print("time_E_ms=", time_E_ms);

gettime();
N_twist = ellsea(Et);
time_twist_ms = gettime();
print("N_twist=", N_twist);
print("time_twist_ms=", time_twist_ms);

if (N + N_twist != 2*p + 2, error("Twistrelation verletzt"));
t = p + 1 - N;
if (t^2 > 4*p, error("Hasse-Schranke verletzt"));

print("twist_relation=1");
print("trace=", t);
print("trace_square=", t^2);
print("four_p=", 4*p);
print("hasse_bound=1");

fd = fileopen("ed301_technischer_abschluss/rohresultate/phase_a_pointcount_pari.txt", "w");
filewrite(fd, Str("pari_version=", version()));
filewrite(fd, Str("p=", p));
filewrite(fd, Str("A=", A));
filewrite(fd, Str("B=", B));
filewrite(fd, Str("weierstrass_coefficients=", [0, a2, 0, a4, 0]));
filewrite(fd, Str("twist_z=", z));
filewrite(fd, Str("twist_coefficients=", [0, lift(Mod(z*a2,p)), 0, lift(Mod(z^2*a4,p)), 0]));
filewrite(fd, Str("N=", N));
filewrite(fd, Str("N_twist=", N_twist));
filewrite(fd, Str("time_E_ms=", time_E_ms));
filewrite(fd, Str("time_twist_ms=", time_twist_ms));
filewrite(fd, "twist_relation=1");
filewrite(fd, Str("trace=", t));
filewrite(fd, Str("trace_square=", t^2));
filewrite(fd, Str("four_p=", 4*p));
filewrite(fd, "hasse_bound=1");
fileclose(fd);
quit;
