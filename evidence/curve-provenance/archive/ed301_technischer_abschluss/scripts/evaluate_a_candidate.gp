\\ Diagnostischer ED301-Kandidatentest. ED301_A wird als Umgebung gesetzt.
default(parisize, 536870912);
default(parisizemax, 4294967296);
default(factor_proven, 1);

p = 2^301 - 2^99 + 947;
a_text = getenv("ED301_A");
if (a_text == 0, error("ED301_A fehlt"));
a = eval(a_text);
d = 301;
if (a == 0 || a == d, error("singulaerer Parameter"));
if (kronecker(a, p) != 1, error("a ist kein quadratischer Rest"));
if (kronecker(d, p) != -1, error("d ist kein quadratischer Nichtrest"));

A = lift(Mod(2 * (a + d), p) / Mod(a - d, p));
B = lift(Mod(4, p) / Mod(a - d, p));
a2 = lift(Mod(A * B, p));
a4 = lift(Mod(B^2, p));
E = ellinit([0, Mod(a2, p), 0, Mod(a4, p), 0]);
Et = ellinit([0, Mod(2*a2, p), 0, Mod(4*a4, p), 0]);

t0 = getwalltime();
N = ellsea(E);
t1 = getwalltime();
N_twist = ellsea(Et);
t2 = getwalltime();
fN = factor(N);
fN_twist = factor(N_twist);
q = fN[matsize(fN)[1], 1];
q_twist = fN_twist[matsize(fN_twist)[1], 1];
h = N / q;
h_twist = N_twist / q_twist;

print("a=", a);
print("A=", A);
print("B=", B);
print("N=", N);
print("factor_N=", fN);
print("q_bits=", logint(q, 2) + 1);
print("h=", h);
print("N_twist=", N_twist);
print("factor_N_twist=", fN_twist);
print("q_twist_bits=", logint(q_twist, 2) + 1);
print("h_twist=", h_twist);
print("time_curve_ms=", t1-t0);
print("time_twist_ms=", t2-t1);
print("ideal_main=", N == 4*q && isprime(q));
print("ideal_twist=", N_twist == 4*q_twist && isprime(q_twist));
quit;
