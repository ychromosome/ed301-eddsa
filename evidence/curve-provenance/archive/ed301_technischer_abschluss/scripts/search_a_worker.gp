\\ Paralleler ED301-a-Suchworker.
\\ Eingaben: ED301_COUNTER_START, ED301_COUNTER_END, ED301_WORKER_ID.
\\ Starre Folge: s=947+c; a=s^2 mod p. Der kleinste gueltige c gewinnt.
default(parisize, 268435456);
default(parisizemax, 2147483648);

p = 2^301 - 2^99 + 947;
d = 301;
start_text = getenv("ED301_COUNTER_START");
end_text = getenv("ED301_COUNTER_END");
worker_text = getenv("ED301_WORKER_ID");
if (start_text == 0 || end_text == 0 || worker_text == 0, error("Worker-Umgebung unvollstaendig"));
counter_start = eval(start_text);
counter_end = eval(end_text);
worker_id = eval(worker_text);
if (counter_start < 0 || counter_end < counter_start, error("ungueltiger Zaehlerbereich"));
if (kronecker(d, p) != -1, error("d=301 ist nicht der erwartete Nichtrest"));

mov_small_pass(base, subgroup_order) = {
  my(v = Mod(1, subgroup_order), multiplier = Mod(base, subgroup_order));
  for (k = 1, 100, v *= multiplier; if (v == 1, return(0)));
  return(1);
};

test_candidate(c) = {
  my(s = 947 + c, a, A, B, a2, a4, E, N, N_twist, q, q_twist, t, D_K);
  a = lift(Mod(s, p)^2);
  if (a == 0 || a == d, return(0));
  if (kronecker(a, p) != 1, return(0));

  A = lift(Mod(2 * (a + d), p) / Mod(a - d, p));
  B = lift(Mod(4, p) / Mod(a - d, p));
  if (A == 2 || A == p - 2 || B == 0, return(0));
  if (kronecker(A^2 - 4, p) != -1, return(0));

  a2 = lift(Mod(A * B, p));
  a4 = lift(Mod(B^2, p));
  E = ellinit([0, Mod(a2, p), 0, Mod(a4, p), 0]);
  if (E.j == Mod(0, p) || E.j == Mod(1728, p), return(0));

  \\ tors=-2 erlaubt Zweierpotenz-Cofaktoren und bricht bei erkannten
  \\ kleinen ungeraden Teilern der Hauptkurve oder des Twists frueh ab.
  \\ Ein Ergebnis !=0 ist trotzdem nur ein exaktes N, kein Cofaktorbeweis.
  N = ellsea(E, -2);
  if (N == 0, return(0));
  N_twist = 2*p + 2 - N;
  if (N % 8 != 4 || N_twist % 8 != 4, return(0));

  q = N / 4;
  q_twist = N_twist / 4;
  if (logint(q, 2) + 1 < 299 || logint(q_twist, 2) + 1 < 299, return(0));
  if (!ispseudoprime(q) || !ispseudoprime(q_twist), return(0));
  if (!isprime(q) || !isprime(q_twist), return(0));
  if (!mov_small_pass(p, q) || !mov_small_pass(p, q_twist), return(0));

  t = p + 1 - N;
  if (t^2 > 4*p || N == p || N_twist == p, return(0));
  D_K = coredisc(t^2 - 4*p);
  if (abs(D_K) <= 2^100, return(0));

  return([c, s, a, A, B, N, q, N_twist, q_twist, t, D_K]);
};

hits = List();
t0 = getwalltime();
for (c = counter_start, counter_end, candidate = test_candidate(c); if (candidate != 0, listput(hits, candidate); print("HIT=", candidate)));
elapsed_ms = getwalltime() - t0;

print("worker_id=", worker_id);
print("counter_start=", counter_start);
print("counter_end=", counter_end);
print("tested=", counter_end-counter_start+1);
print("elapsed_ms=", elapsed_ms);
print("hits=", Vec(hits));

output_path = Str("ed301_technischer_abschluss/rohresultate/search_", counter_start, "_", counter_end, "_worker_", worker_id, ".txt");
fd = fileopen(output_path, "w");
filewrite(fd, Str("worker_id=", worker_id));
filewrite(fd, Str("counter_start=", counter_start));
filewrite(fd, Str("counter_end=", counter_end));
filewrite(fd, Str("tested=", counter_end-counter_start+1));
filewrite(fd, Str("elapsed_ms=", elapsed_ms));
filewrite(fd, Str("hits=", Vec(hits)));
fileclose(fd);
quit;
