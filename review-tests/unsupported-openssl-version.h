#include <openssl/opensslv.h>

/* Exercise the rejected-header branch with the installed header surface. */
#undef OPENSSL_VERSION_MAJOR
#undef OPENSSL_VERSION_MINOR
#undef OPENSSL_VERSION_PATCH
#define OPENSSL_VERSION_MAJOR 3
#define OPENSSL_VERSION_MINOR 0
#define OPENSSL_VERSION_PATCH 0
