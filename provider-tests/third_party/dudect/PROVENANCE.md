# dudect (vendored, test-only)

| | |
| --- | --- |
| Upstream | https://github.com/oreparaz/dudect |
| Commit | `dc269651fb2567e46755cfb2a13d3875592968b5` (2024-03-19) |
| Files | `src/dudect.h` -> `dudect.h`; `LICENSE` -> `LICENSE` |
| Local change | AArch64 uses `clock_gettime(CLOCK_MONOTONIC_RAW)` because upstream exposes only x86 `RDTSC`. The statistical code is unchanged. |
| Upstream header SHA-256 | `3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da` |
| Local header SHA-256 | `6dcf713c9e43ac1d736e21e84af738013fb2a4b05b66931dddc971bb43e899f5` |
| `LICENSE` SHA-256 | `ee7cd5d500ab72e03a6c8aefe69c6311d698c83e732b19d152a6fa38fd521720` |
| License | MIT, Copyright (c) 2016-today Oscar Reparaz |
| Method | Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", DATE 2017 |

Used only by `provider-tests/provider_timing.c` in the timing lane
(`scripts/check-provider-timing.sh`). The header is compiled into the test
harness; nothing from it enters a provider module or package.
