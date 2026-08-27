\\ Read-only PARI cross-check for the c=44730 subgroup certificates.
default(realprecision, 150);
default(parisize, 536870912);
default(parisizemax, 4294967296);
default(factor_proven, 1);

q = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403;
qt = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103;

Cq = read("ed301_technischer_abschluss/zertifikate/c44730_q_ecpp_internal.pari");
Cqt = read("ed301_technischer_abschluss/zertifikate/c44730_q_twist_ecpp_internal.pari");
Nq = read("ed301_technischer_abschluss/zertifikate/c44730_q_nminus1_bls_internal.pari");
Nqt = read("ed301_technischer_abschluss/zertifikate/c44730_q_twist_nminus1_bls_internal.pari");

if (Cq[1][1] != q || Cqt[1][1] != qt, error("ECPP root mismatch"));
if (Nq[1] != q || Nqt[1] != qt, error("N-1 root mismatch"));
t0 = getwalltime(); vq = primecertisvalid(Cq); t1 = getwalltime();
vqt = primecertisvalid(Cqt); t2 = getwalltime();
if (!vq || !vqt, error("invalid ECPP certificate"));

Fq = [2,1; 3,1; 83,1; 103,1; 487,1; 8071538763312550939901261,1; 10140257736222944349715877,1; 498158843412220847318631521539897,1];
Fqt = [2,1; 11,1; 46296272189420138324282856554758594569351554378323589098978056167418046328934386271284641,1];
if (factorback(Fq) != q-1 || factorback(Fqt) != qt-1, error("N-1 factor recomposition mismatch"));
for(i = 1, matsize(Fq)[1], C = primecert(Fq[i,1]); if (!primecertisvalid(C), error("unproved q-1 factor")));
for(i = 1, matsize(Fqt)[1], C = primecert(Fqt[i,1]); if (!primecertisvalid(C), error("unproved qt-1 factor")));

two299 = 2^299;
print("pari_version=", version());
print("q=", q);
print("q_twist=", qt);
print("q_ecpp_steps=", #Cq);
print("q_twist_ecpp_steps=", #Cqt);
print("q_primecertisvalid_fresh=", vq);
print("q_twist_primecertisvalid_fresh=", vqt);
print("q_ecpp_validation_ms=", t1-t0);
print("q_twist_ecpp_validation_ms=", t2-t1);
print("q_nminus1_certificate=", Nq);
print("q_twist_nminus1_certificate=", Nqt);
print("factor_q_minus_1=", Fq);
print("factor_q_twist_minus_1=", Fqt);
print("q_minus_1_recomposition=", factorback(Fq)==q-1);
print("q_twist_minus_1_recomposition=", factorback(Fqt)==qt-1);
print("q_minus_1_all_factors_proven=1");
print("q_twist_minus_1_all_factors_proven=1");
print("two_pow_299=", two299);
print("q_minus_two_pow_299=", q-two299);
print("two_pow_299_minus_q_twist=", two299-qt);
print("q_bit_length=", logint(q,2)+1);
print("q_twist_bit_length=", logint(qt,2)+1);
print("q_log2=", log(q)/log(2));
print("q_twist_log2=", log(qt)/log(2));
print("q_pollard_rho_sqrt_pi_q_over_2=", sqrt(Pi*q/2));
print("q_pollard_rho_ceil=", ceil(sqrt(Pi*q/2)));
print("q_pollard_rho_log2=", log(sqrt(Pi*q/2))/log(2));
print("q_pollard_rho_negation_log2=", log(sqrt(Pi*q/4))/log(2));
print("q_twist_pollard_rho_sqrt_pi_q_over_2=", sqrt(Pi*qt/2));
print("q_twist_pollard_rho_ceil=", ceil(sqrt(Pi*qt/2)));
print("q_twist_pollard_rho_log2=", log(sqrt(Pi*qt/2))/log(2));
print("q_twist_pollard_rho_negation_log2=", log(sqrt(Pi*qt/4))/log(2));
print("certificate_audit_pass=1");
quit;
