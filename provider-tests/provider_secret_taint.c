/*
 * Secret-taint lane across EVP -> provider shim -> Rust FFI -> Ed301 core.
 *
 * The instrumented test module declassifies only reviewed public outputs.
 * Memcheck therefore reports any secret-dependent branch or address reached
 * from the undefined 38-byte seed. A clean run is evidence for the exercised
 * binary/toolchain/path, not a general constant-time proof.
 */

#include <stdint.h>

#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>

#include "harness_common.h"
#include "vectors.h"

static int seed_vbits_match(const unsigned char *seed, size_t seed_len,
    int expect_undefined)
{
    unsigned char vbits[ED301V1_SEED_BYTES];
    size_t index;

    if (seed_len != sizeof(vbits)
            || VALGRIND_GET_VBITS(seed, vbits, seed_len) != 1) {
        fprintf(stderr, "Valgrind V-bit query failed\n");
        return 0;
    }
    for (index = 0; index < sizeof(vbits); index++) {
        unsigned char expected = expect_undefined ? 0xffU : 0x00U;

        if (vbits[index] != expected) {
            fprintf(stderr,
                "seed V-bit mismatch at byte %zu: got=0x%02x expected=0x%02x\n",
                index, (unsigned int)vbits[index], (unsigned int)expected);
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1;
    const POSITIVE_CASE *test_case = &POSITIVE_CASES[0];
    unsigned char seed[ED301V1_SEED_BYTES];
    unsigned char public_key[ED301V1_PUB_BYTES];
    unsigned char signature[ED301V1_SIG_BYTES];
    unsigned char repeated[ED301V1_SIG_BYTES];
    size_t public_len = 0;
    EVP_PKEY *pkey;
    int tainted;
    int ok;

    ED301V1_REQUIRE_RUNTIME_BINDING();
    if (RUNNING_ON_VALGRIND == 0) {
        fprintf(stderr, "provider_secret_taint requires Valgrind\n");
        return 2;
    }
    if (argc != 2
            || (strcmp(argv[1], "defined") != 0
                && strcmp(argv[1], "tainted") != 0)) {
        fprintf(stderr, "usage: %s <defined|tainted>\n", argv[0]);
        return 2;
    }
    tainted = strcmp(argv[1], "tainted") == 0;
    libctx = OSSL_LIB_CTX_new();
    v1 = ed301v1_load(libctx, &deflt);
    if (v1 == NULL) {
        fprintf(stderr, "instrumented provider load failed\n");
        return 2;
    }

    memcpy(seed, test_case->seed, sizeof(seed));
    if (tainted) {
        VALGRIND_MAKE_MEM_UNDEFINED(seed, sizeof(seed));
    } else {
        VALGRIND_MAKE_MEM_DEFINED(seed, sizeof(seed));
    }
    /* GET_VBITS observes shadow state; it does not define the seed. Thus the
     * tainted lane still carries undefined V-bits into EVP key import. */
    if (!seed_vbits_match(seed, sizeof(seed), tainted)) {
        VALGRIND_MAKE_MEM_DEFINED(seed, sizeof(seed));
        fprintf(stderr, "provider secret-taint activation check failed\n");
        return 2;
    }
    pkey = ed301v1_key_from_seed(libctx, seed);
    if (pkey == NULL) {
        fprintf(stderr, "seed import failed\n");
        return 2;
    }

    ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
            public_key, sizeof(public_key), &public_len) == 1
        && public_len == sizeof(public_key)
        && memcmp(public_key, test_case->public_key, sizeof(public_key)) == 0
        && ed301v1_digest_sign(libctx, pkey, test_case->message,
            test_case->message_len, signature)
        && memcmp(signature, test_case->signature, sizeof(signature)) == 0
        && ed301v1_digest_sign(libctx, pkey, test_case->message,
            test_case->message_len, repeated)
        && memcmp(repeated, signature, sizeof(repeated)) == 0;
    VALGRIND_MAKE_MEM_DEFINED(seed, sizeof(seed));
    if (!ok) {
        fprintf(stderr, "taint-path KAT or determinism failure\n");
        return 2;
    }

    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    printf("provider_secret_taint: mode=%s pass=1\n", argv[1]);
    return 0;
}
