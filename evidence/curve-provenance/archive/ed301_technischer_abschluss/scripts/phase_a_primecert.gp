\\ ED301 Phase A: formales ECPP-Zertifikat fuer p.
default(timer, 1);
default(parisize, 536870912);
default(parisizemax, 4294967296);

p = 2^301 - 2^99 + 947;
print("pari_version=", version());
print("p=", p);
print("bitlen_p=", logint(p, 2) + 1);

cert = primecert(p, 0);
if (cert == 0, error("primecert meldet p als zusammengesetzt"));
if (!primecertisvalid(cert), error("erzeugtes ECPP-Zertifikat ist ungueltig"));

fd = fileopen("ed301_technischer_abschluss/zertifikate/p_ecpp_internal.pari", "w");
filewrite(fd, cert);
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/p_ecpp_human.txt", "w");
filewrite(fd, primecertexport(cert, 0));
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/p_ecpp_primo.txt", "w");
filewrite(fd, primecertexport(cert, 1));
fileclose(fd);
fd = fileopen("ed301_technischer_abschluss/zertifikate/p_ecpp_magma.m", "w");
filewrite(fd, primecertexport(cert, 2));
fileclose(fd);

print("primecertisvalid=1");
print("certificate_internal=", cert);
print("certificate_human_begin");
print(primecertexport(cert, 0));
print("certificate_human_end");
print("certificate_primo_begin");
print(primecertexport(cert, 1));
print("certificate_primo_end");
print("certificate_magma_begin");
print(primecertexport(cert, 2));
print("certificate_magma_end");
quit;
