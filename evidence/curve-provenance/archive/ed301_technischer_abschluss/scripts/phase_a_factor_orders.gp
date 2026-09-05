\\ ED301 Phase A: vollstaendige Faktorisierung und Primzahlzertifikate.
default(timer, 1);
default(parisize, 536870912);
default(parisizemax, 4294967296);
default(factor_proven, 1);

p = 2^301 - 2^99 + 947;
N = 4074071952668972172536891376818756322102936790024709516523088567757405009860459412423203588;
N_twist = 4074071952668972172536891376818756322102936784639035486021471962009519960963485915607182436;

if (N + N_twist != 2*p + 2, error("Twistrelation verletzt"));

fN = factor(N);
fN_twist = factor(N_twist);
if (factorback(fN) != N, error("Faktorisierung von N rekonstruiert N nicht"));
if (factorback(fN_twist) != N_twist, error("Faktorisierung von N_twist rekonstruiert die Ordnung nicht"));

q = fN[matsize(fN)[1], 1];
q_twist = fN_twist[matsize(fN_twist)[1], 1];
if (!isprime(q), error("q ist nicht prim"));
if (!isprime(q_twist), error("q_twist ist nicht prim"));
h = N / q;
h_twist = N_twist / q_twist;
if (h*q != N || h_twist*q_twist != N_twist, error("Untergruppenzerlegung fehlerhaft"));

cert_q = primecert(q, 0);
cert_q_twist = primecert(q_twist, 0);
if (!primecertisvalid(cert_q), error("ECPP-Zertifikat fuer q ungueltig"));
if (!primecertisvalid(cert_q_twist), error("ECPP-Zertifikat fuer q_twist ungueltig"));

fd = fileopen("ed301_technischer_abschluss/zertifikate/q_ecpp_internal.pari", "w");
filewrite(fd, cert_q);
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/q_ecpp_human.txt", "w");
filewrite(fd, primecertexport(cert_q, 0));
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/q_ecpp_primo.txt", "w");
filewrite(fd, primecertexport(cert_q, 1));
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/q_ecpp_magma.m", "w");
filewrite(fd, primecertexport(cert_q, 2));
fileclose(fd);

fd = fileopen("ed301_technischer_abschluss/zertifikate/q_twist_ecpp_internal.pari", "w");
filewrite(fd, cert_q_twist);
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/q_twist_ecpp_human.txt", "w");
filewrite(fd, primecertexport(cert_q_twist, 0));
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/q_twist_ecpp_primo.txt", "w");
filewrite(fd, primecertexport(cert_q_twist, 1));
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/q_twist_ecpp_magma.m", "w");
filewrite(fd, primecertexport(cert_q_twist, 2));
fileclose(fd);

print("pari_version=", version());
print("factor_proven=", default(factor_proven));
print("factor_N=", fN);
print("factor_N_twist=", fN_twist);
print("q=", q);
print("bitlen_q=", logint(q, 2) + 1);
print("h=", h);
print("bitlen_h=", logint(h, 2) + 1);
print("factor_h=", factor(h));
print("q_twist=", q_twist);
print("bitlen_q_twist=", logint(q_twist, 2) + 1);
print("h_twist=", h_twist);
print("bitlen_h_twist=", logint(h_twist, 2) + 1);
print("factor_h_twist=", factor(h_twist));
print("gcd_h_q=", gcd(h, q));
print("gcd_h_twist_q_twist=", gcd(h_twist, q_twist));
print("signature_threshold_bitlen_q_ge_299=", logint(q, 2) + 1 >= 299);
print("signature_threshold_h_le_8=", h <= 8);
print("q_primecertisvalid=1");
print("q_twist_primecertisvalid=1");

fd = fileopen("ed301_technischer_abschluss/rohresultate/phase_a_factor_orders_pari.txt", "w");
filewrite(fd, Str("pari_version=", version()));
filewrite(fd, Str("factor_N=", fN));
filewrite(fd, Str("factor_N_twist=", fN_twist));
filewrite(fd, Str("q=", q));
filewrite(fd, Str("bitlen_q=", logint(q, 2) + 1));
filewrite(fd, Str("h=", h));
filewrite(fd, Str("bitlen_h=", logint(h, 2) + 1));
filewrite(fd, Str("factor_h=", factor(h)));
filewrite(fd, Str("q_twist=", q_twist));
filewrite(fd, Str("bitlen_q_twist=", logint(q_twist, 2) + 1));
filewrite(fd, Str("h_twist=", h_twist));
filewrite(fd, Str("bitlen_h_twist=", logint(h_twist, 2) + 1));
filewrite(fd, Str("factor_h_twist=", factor(h_twist)));
filewrite(fd, Str("gcd_h_q=", gcd(h, q)));
filewrite(fd, Str("gcd_h_twist_q_twist=", gcd(h_twist, q_twist)));
filewrite(fd, Str("signature_threshold_bitlen_q_ge_299=", logint(q, 2) + 1 >= 299));
filewrite(fd, Str("signature_threshold_h_le_8=", h <= 8));
filewrite(fd, "q_primecertisvalid=1");
filewrite(fd, "q_twist_primecertisvalid=1");
fileclose(fd);
quit;
