/*
 * Acceptance section 6 (hardening boundary): allocation-failure sweeps
 * through the public CRYPTO_set_mem_functions interface, every Rust-side
 * allocation failpoint through public EVP/provider paths, duplicate/free/
 * unload ordering, and injected Rust panics across the C ABI boundary via
 * the provider's test-only fail-closed diagnostic environment variable.
 *
 * Instrumentation statement: this binary instruments OpenSSL heap
 * allocations for every component that allocates through OPENSSL_malloc
 * (libcrypto, the provider shim's core-upcall allocations); Rust-side
 * allocations inside the cdylib are exercised by the named allocation and
 * panic failpoints and by whole-process Valgrind in the focused gate.
 */

#include "harness_common.h"
#include "vectors.h"

static unsigned long allocation_countdown; /* 0 = no injected failure */
static unsigned long allocation_total;

static int capability_count(const OSSL_PARAM *params, void *argument)
{
    int *count = argument;

    (void)params;
    if (count == NULL)
        return 0;
    (*count)++;
    return 1;
}

static int set_alloc_failpoint(const char *site)
{
    return setenv("ED301_EDDSA_DRAFT00_ALLOC_FAILPOINT", site, 1) == 0;
}

static void clear_alloc_failpoint(void)
{
    unsetenv("ED301_EDDSA_DRAFT00_ALLOC_FAILPOINT");
}

static void *counting_malloc(size_t size, const char *file, int line)
{
    (void)file;
    (void)line;
    allocation_total++;
    if (allocation_countdown > 0 && --allocation_countdown == 0)
        return NULL;
    return malloc(size);
}

static void *counting_realloc(
    void *pointer,
    size_t size,
    const char *file,
    int line)
{
    (void)file;
    (void)line;
    allocation_total++;
    if (allocation_countdown > 0 && --allocation_countdown == 0)
        return NULL;
    return realloc(pointer, size);
}

static void counting_free(void *pointer, const char *file, int line)
{
    (void)file;
    (void)line;
    free(pointer);
}

static int full_cycle(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char sig[76];
    int ok = 0;

    if (libctx == NULL)
        goto done;
    draft = d00_load(libctx, &deflt);
    if (draft == NULL)
        goto done;
    pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    if (pkey == NULL)
        goto done;
    if (!d00_digest_sign(libctx, pkey, POSITIVE_CASES[0].message,
            POSITIVE_CASES[0].message_len, sig))
        goto done;
    ok = memcmp(sig, POSITIVE_CASES[0].signature, sizeof(sig)) == 0;

done:
    EVP_PKEY_free(pkey);
    if (draft != NULL)
        OSSL_PROVIDER_unload(draft);
    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    return ok;
}

static int allocation_fail_key_new(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = NULL;
    int failed = 0;

    if (set_alloc_failpoint("key_new")) {
        pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
        failed = pkey == NULL;
    }
    clear_alloc_failpoint();
    EVP_PKEY_free(pkey);

    pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    failed = failed && pkey != NULL;
    EVP_PKEY_free(pkey);
    return failed;
}

static int allocation_fail_key_generate(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = NULL;
    int failed = 0;

    if (set_alloc_failpoint("key_generate")) {
        pkey = d00_keygen(libctx);
        failed = pkey == NULL;
    }
    clear_alloc_failpoint();
    EVP_PKEY_free(pkey);

    pkey = d00_keygen(libctx);
    failed = failed && pkey != NULL;
    EVP_PKEY_free(pkey);
    return failed;
}

static int allocation_fail_key_import(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = NULL;
    int failed = 0;

    if (set_alloc_failpoint("key_import")) {
        pkey = d00_key_from_public(libctx, POSITIVE_CASES[0].public_key,
            D00_PUB_BYTES);
        failed = pkey == NULL;
    }
    clear_alloc_failpoint();
    EVP_PKEY_free(pkey);

    pkey = d00_key_from_public(libctx, POSITIVE_CASES[0].public_key,
        D00_PUB_BYTES);
    failed = failed && pkey != NULL;
    EVP_PKEY_free(pkey);
    return failed;
}

static int allocation_fail_key_set_encoded_public(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = d00_key_from_public(libctx,
        POSITIVE_CASES[0].public_key, D00_PUB_BYTES);
    int failed = 0;

    if (pkey == NULL)
        return 0;
    if (set_alloc_failpoint("key_set_encoded_public")) {
        failed = EVP_PKEY_set1_encoded_public_key(pkey,
            POSITIVE_CASES[0].public_key, D00_PUB_BYTES) != 1;
    }
    clear_alloc_failpoint();
    failed = failed
        && EVP_PKEY_set1_encoded_public_key(pkey,
            POSITIVE_CASES[0].public_key, D00_PUB_BYTES) == 1;
    EVP_PKEY_free(pkey);
    return failed;
}

static int allocation_fail_key_duplicate(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    EVP_PKEY *copy = NULL;
    int failed = 0;

    if (pkey == NULL)
        return 0;
    if (set_alloc_failpoint("key_duplicate")) {
        copy = EVP_PKEY_dup(pkey);
        failed = copy == NULL;
    }
    clear_alloc_failpoint();
    EVP_PKEY_free(copy);

    copy = EVP_PKEY_dup(pkey);
    failed = failed && copy != NULL;
    EVP_PKEY_free(copy);
    EVP_PKEY_free(pkey);
    return failed;
}

static int allocation_fail_signature_new(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char signature[D00_SIG_BYTES];
    size_t signature_length = sizeof(signature);
    int failed = 0;

    if (pkey == NULL)
        return 0;
    if (set_alloc_failpoint("signature_new")) {
        pctx = EVP_PKEY_CTX_new_from_pkey(
            libctx, pkey, D00_FAILPOINT_PROP);
        failed = pctx == NULL
            || !d00_sign_message_init(libctx, pctx, NULL);
    }
    clear_alloc_failpoint();
    EVP_PKEY_CTX_free(pctx);

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_FAILPOINT_PROP);
    failed = failed
        && pctx != NULL
        && d00_sign_message_init(libctx, pctx, NULL)
        && EVP_PKEY_sign(pctx, signature, &signature_length,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len) == 1
        && signature_length == D00_SIG_BYTES
        && memcmp(signature, POSITIVE_CASES[0].signature,
            D00_SIG_BYTES) == 0;
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return failed;
}

static int allocation_fail_signature_duplicate(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    EVP_MD_CTX *mctx = NULL;
    EVP_MD_CTX *copy = NULL;
    unsigned char signature[D00_SIG_BYTES];
    size_t signature_length = sizeof(signature);
    int failed = 0;

    if (pkey == NULL)
        return 0;
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL
            || EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                D00_FAILPOINT_PROP, pkey, NULL) != 1)
        goto done;

    if (set_alloc_failpoint("signature_duplicate")) {
        copy = EVP_MD_CTX_new();
        failed = copy != NULL && EVP_MD_CTX_copy_ex(copy, mctx) != 1;
    }
    clear_alloc_failpoint();
    EVP_MD_CTX_free(copy);
    copy = EVP_MD_CTX_new();
    failed = failed
        && copy != NULL
        && EVP_MD_CTX_copy_ex(copy, mctx) == 1
        && EVP_DigestSign(copy, signature, &signature_length,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len) == 1
        && signature_length == D00_SIG_BYTES
        && memcmp(signature, POSITIVE_CASES[0].signature,
            D00_SIG_BYTES) == 0;

done:
    clear_alloc_failpoint();
    EVP_MD_CTX_free(copy);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return failed;
}

int main(void)
{
    const int rust_alloc_only =
        getenv("ED301D00_RUST_ALLOC_ONLY") != NULL;

    D00_REQUIRE_RUNTIME_BINDING();
    if (!rust_alloc_only
            && CRYPTO_set_mem_functions(counting_malloc, counting_realloc,
                counting_free) != 1) {
        fprintf(stderr, "cannot install counting allocator\n");
        return 2;
    }

    /* Baseline cycle without injected failures. */
    D00_CHECK(full_cycle(), "baseline cycle under the counting allocator");

    /*
     * Allocation-failure sweep: fail the k-th OpenSSL allocation for a
     * range of k.  Every attempt must either succeed or fail cleanly;
     * crashes and aborts end the test binary itself.
     */
    if (!rust_alloc_only) {
        unsigned long fail_at;
        unsigned long injected = 0;
        unsigned long clean_failures = 0;
        unsigned long survivals = 0;

        for (fail_at = 1; fail_at <= 400; fail_at += 7) {
            allocation_countdown = fail_at;
            injected++;
            if (full_cycle())
                survivals++;
            else
                clean_failures++;
            allocation_countdown = 0;
        }
        D00_CHECK(clean_failures > 0,
            "allocation-failure sweep injected failures "
            "(%lu attempts, %lu clean failures, %lu survivals)",
            injected, clean_failures, survivals);
        D00_CHECK(full_cycle(),
            "full cycle recovers after the allocation sweep");
    }

    /* Injected Rust panics fail closed across the C ABI boundary. */
    {
        static const struct {
            const char *failpoint;
            const char *description;
        } cases[] = {
            { "key_generate", "key generation" },
            { "key_import", "key import" },
            { "signature_sign", "signing" },
            { "signature_verify", "verification" },
        };
        size_t index;
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = NULL;
        OSSL_PROVIDER *draft;
        int tls_capabilities = 0;

        /*
         * FBL-02: the ordinary module contains no failpoint; the
         * injected-panic lane runs against the separately named
         * test-only failpoint artifact.
         */
        draft = d00_load_named(libctx, &deflt, D00_FAILPOINT_PROVIDER);
        d00_property = D00_FAILPOINT_PROP;
        D00_CHECK(draft != NULL, "failpoint artifact for panic tests");

        /* The separately named failpoint artifact has no TLS capability. */
        D00_CHECK(draft != NULL
                && OSSL_PROVIDER_get_capabilities(draft, "TLS-SIGALG",
                    capability_count, &tls_capabilities) == 1
                && tls_capabilities == 0,
            "failpoint artifact does not advertise TLS-SIGALG");

        /* R1A: every Rust allocation site is reached through public EVP. */
        D00_CHECK(allocation_fail_key_new(libctx),
            "key_new allocation failpoint returns null and recovers");
        D00_CHECK(allocation_fail_key_generate(libctx),
            "key_generate allocation failpoint returns null and recovers");
        D00_CHECK(allocation_fail_key_import(libctx),
            "key_import shared-state allocation fails closed and recovers");
        D00_CHECK(allocation_fail_key_set_encoded_public(libctx),
            "encoded-public shared-state allocation fails closed and recovers");
        D00_CHECK(allocation_fail_key_duplicate(libctx),
            "key_duplicate allocation failpoint returns null and recovers");
        D00_CHECK(allocation_fail_signature_new(libctx),
            "signature_new allocation failpoint fails closed and recovers");
        D00_CHECK(allocation_fail_signature_duplicate(libctx),
            "signature_duplicate allocation failpoint fails closed and recovers");

        /*
         * A deliberately injected Rust panic!() unwinds cleanly across the
         * C ABI (catch_unwind), but the default panic hook captures a
         * backtrace whose lazy DWARF symbolizer (gimli via dl_iterate_phdr)
         * retains an allocation cache that whole-process Valgrind reports as
         * "definitely/possibly lost" at exit -- a tooling artifact of Rust's
         * backtrace machinery, not a provider leak.  The panic fail-closed
         * property is exercised in full by the ordinary (non-Valgrind)
         * provider_hardening gate and the ASan lane; under the
         * ED301D00_RUST_ALLOC_ONLY Valgrind lane only the panic-free
         * allocation-failpoint paths above are exercised, so the leak-check
         * stays meaningful.
         */
        for (index = 0;
                !rust_alloc_only
                    && index < sizeof(cases) / sizeof(cases[0]); index++) {
            int failed_closed = 0;

            setenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT",
                cases[index].failpoint, 1);
            if (strcmp(cases[index].failpoint, "key_generate") == 0) {
                EVP_PKEY *pkey = d00_keygen(libctx);

                failed_closed = pkey == NULL;
                EVP_PKEY_free(pkey);
            } else if (strcmp(cases[index].failpoint, "key_import")
                    == 0) {
                EVP_PKEY *pkey = d00_key_from_seed(
                    libctx, POSITIVE_CASES[0].seed);

                failed_closed = pkey == NULL;
                EVP_PKEY_free(pkey);
            } else if (strcmp(cases[index].failpoint, "signature_sign")
                    == 0) {
                EVP_PKEY *pkey;
                unsigned char sig[76];

                unsetenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT");
                pkey = d00_key_from_seed(libctx,
                    POSITIVE_CASES[0].seed);
                setenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT",
                    cases[index].failpoint, 1);
                failed_closed = pkey != NULL
                    && !d00_digest_sign(libctx, pkey,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len, sig);
                EVP_PKEY_free(pkey);
            } else {
                EVP_PKEY *pkey;
                int verify_result;

                unsetenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT");
                pkey = d00_key_from_seed(libctx,
                    POSITIVE_CASES[0].seed);
                setenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT",
                    cases[index].failpoint, 1);
                ERR_clear_error();
                verify_result = pkey == NULL ? 0
                    : d00_digest_verify_result(libctx, pkey,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len,
                        POSITIVE_CASES[0].signature, D00_SIG_BYTES);
                failed_closed = pkey != NULL && verify_result < 0
                    && ERR_peek_error() != 0;
                EVP_PKEY_free(pkey);
            }
            unsetenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT");
            ERR_clear_error();
            D00_CHECK(failed_closed,
                "injected panic in %s fails closed without aborting",
                cases[index].description);
        }

        /* The same context still works after every injected panic. */
        if (!rust_alloc_only) {
            EVP_PKEY *pkey = d00_key_from_seed(
                libctx, POSITIVE_CASES[0].seed);
            unsigned char sig[76];

            D00_CHECK(pkey != NULL
                    && d00_digest_sign(libctx, pkey,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len, sig)
                    && memcmp(sig, POSITIVE_CASES[0].signature,
                        sizeof(sig)) == 0,
                "provider fully functional after injected panics");
            EVP_PKEY_free(pkey);
        }

        OSSL_PROVIDER_unload(draft);
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
        d00_property = D00_PROP;
    }

    /*
     * FBL-02 inert control: the ORDINARY module ignores the failpoint
     * environment variable entirely (the hook is compiled out).
     */
    {
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = NULL;
        OSSL_PROVIDER *draft = d00_load(libctx, &deflt);
        EVP_PKEY *pkey;
        unsigned char sig[76];

        setenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT", "signature_sign",
            1);
        setenv("ED301_EDDSA_DRAFT00_ALLOC_FAILPOINT", "signature_new",
            1);
        pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
        D00_CHECK(draft != NULL && pkey != NULL
                && d00_digest_sign(libctx, pkey,
                    POSITIVE_CASES[0].message,
                    POSITIVE_CASES[0].message_len, sig)
                && memcmp(sig, POSITIVE_CASES[0].signature,
                    sizeof(sig)) == 0,
            "ordinary module is fully functional with the failpoint "
            "variable set (hook compiled out)");
        unsetenv("ED301_EDDSA_DRAFT00_PANIC_FAILPOINT");
        clear_alloc_failpoint();
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(draft);
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
    }

    /* Duplicate/free/unload ordering. */
    {
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = NULL;
        OSSL_PROVIDER *draft = d00_load(libctx, &deflt);
        OSSL_PROVIDER *second_handle =
            OSSL_PROVIDER_load(libctx, D00_PROVIDER);
        EVP_PKEY *pkey = d00_key_from_seed(libctx,
            POSITIVE_CASES[1].seed);
        EVP_PKEY *copy = pkey == NULL ? NULL : EVP_PKEY_dup(pkey);
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        EVP_MD_CTX *mctx_copy = EVP_MD_CTX_new();
        unsigned char first_sig[76];
        unsigned char second_sig[76];
        size_t sig_len;

        D00_CHECK(draft != NULL && second_handle != NULL
                && pkey != NULL && copy != NULL,
            "objects for ordering tests");

        /* Duplicated one-shot context signs identically. */
        sig_len = sizeof(first_sig);
        D00_CHECK(mctx != NULL && mctx_copy != NULL && pkey != NULL
                && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                    D00_PROP, pkey, NULL) == 1
                && EVP_MD_CTX_copy_ex(mctx_copy, mctx) == 1
                && EVP_DigestSign(mctx, first_sig, &sig_len,
                    POSITIVE_CASES[1].message,
                    POSITIVE_CASES[1].message_len) == 1
                && (sig_len = sizeof(second_sig), 1)
                && EVP_DigestSign(mctx_copy, second_sig, &sig_len,
                    POSITIVE_CASES[1].message,
                    POSITIVE_CASES[1].message_len) == 1
                && memcmp(first_sig, second_sig, sizeof(first_sig)) == 0
                && memcmp(first_sig, POSITIVE_CASES[1].signature,
                    sizeof(first_sig)) == 0,
            "duplicated signing context is independent and exact");
        EVP_MD_CTX_free(mctx_copy);
        EVP_MD_CTX_free(mctx);

        /* Unload one provider handle; the duplicate key still signs. */
        OSSL_PROVIDER_unload(second_handle);
        sig_len = sizeof(first_sig);
        D00_CHECK(copy != NULL
                && d00_digest_sign(libctx, copy,
                    POSITIVE_CASES[1].message,
                    POSITIVE_CASES[1].message_len, first_sig),
            "duplicate key signs after one handle is unloaded");

        /* Free the original before the duplicate. */
        EVP_PKEY_free(pkey);
        D00_CHECK(copy != NULL
                && d00_digest_sign(libctx, copy,
                    POSITIVE_CASES[1].message,
                    POSITIVE_CASES[1].message_len, second_sig)
                && memcmp(first_sig, second_sig,
                    sizeof(first_sig)) == 0,
            "duplicate key outlives the original");
        EVP_PKEY_free(copy);

        OSSL_PROVIDER_unload(draft);
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
    }

    if (rust_alloc_only)
        printf("OpenSSL allocation sweep: NOT RUN (Rust allocation gate)\n");
    else
        printf("openssl allocations observed: %lu\n", allocation_total);
    return d00_summary("provider_hardening");
}
