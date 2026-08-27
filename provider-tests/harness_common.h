#ifndef ED301D00_HARNESS_COMMON_H
#define ED301D00_HARNESS_COMMON_H

/*
 * Shared helpers for the Ed301-EdDSA-draft-00 provider acceptance
 * harnesses.  Test-harness patterns are adapted from the historical
 * provider's C test suite (see the result provenance map).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>

#define D00_ALG "Ed301-EdDSA-draft-00"
#define D00_OID_TEXT "1.3.6.1.4.1.66282.301.3"
#define D00_PROVIDER "ed301_eddsa_draft00"
#define D00_PROP "provider=ed301_eddsa_draft00"
#define D00_FAILPOINT_PROVIDER "ed301_eddsa_draft00_failpoint"
#define D00_FAILPOINT_PROP "provider=ed301_eddsa_draft00_failpoint"
#define D00_PKI_PROVIDER "ed301_eddsa_draft00_pki_test"
#define D00_PKI_PROP "provider=ed301_eddsa_draft00_pki_test"
#define D00_TLS_PROVIDER "ed301_eddsa_draft00_tls_test"
#define D00_TLS_PROP "provider=ed301_eddsa_draft00_tls_test"
#define D00_TLS_COLLIDER_PROVIDER "ed301_eddsa_draft00_tls_collider"
#define D00_TLS_COLLIDER_PROP "provider=ed301_eddsa_draft00_tls_collider"
#define D00_SEED_BYTES ((size_t)38)
#define D00_PUB_BYTES ((size_t)38)
#define D00_SIG_BYTES ((size_t)76)

#define D00_CALLER_SENTINEL_A ((unsigned int)0x2d01)
#define D00_CALLER_SENTINEL_B ((unsigned int)0x2d02)
#define D00_ERROR_QUEUE_CAPACITY ((size_t)64)

static inline void d00_seed_error_sentinel(void)
{
    ERR_clear_error();
    ERR_raise(ERR_LIB_USER, D00_CALLER_SENTINEL_A);
    ERR_raise(ERR_LIB_USER, D00_CALLER_SENTINEL_B);
}

static inline size_t d00_drain_error_queue(
    unsigned long *errors,
    size_t capacity)
{
    size_t count = 0;
    unsigned long error;

    while ((error = ERR_get_error()) != 0) {
        if (count < capacity)
            errors[count] = error;
        count++;
    }
    return count;
}

static inline int d00_queue_is_sentinel_only(void)
{
    unsigned long errors[D00_ERROR_QUEUE_CAPACITY];
    const size_t count = d00_drain_error_queue(
        errors, D00_ERROR_QUEUE_CAPACITY);

    return count == 2
        && ERR_GET_LIB(errors[0]) == ERR_LIB_USER
        && ERR_GET_REASON(errors[0]) == D00_CALLER_SENTINEL_A
        && ERR_GET_LIB(errors[1]) == ERR_LIB_USER
        && ERR_GET_REASON(errors[1]) == D00_CALLER_SENTINEL_B;
}

static inline int d00_provider_has_dispatch(
    const OSSL_PROVIDER *provider,
    int function_id)
{
    const OSSL_DISPATCH *dispatch;

    if (provider == NULL
            || (dispatch = OSSL_PROVIDER_get0_dispatch(provider)) == NULL)
        return 0;
    for (; dispatch->function_id != 0; dispatch++) {
        if (dispatch->function_id == function_id)
            return 1;
    }
    return 0;
}

static inline int d00_provider_has_reason_dispatch(
    const OSSL_PROVIDER *provider)
{
    return d00_provider_has_dispatch(
        provider, OSSL_FUNC_PROVIDER_GET_REASON_STRINGS);
}

enum d00_registry_state {
    D00_REGISTRY_CONFLICT = -1,
    D00_REGISTRY_FREE = 0,
    D00_REGISTRY_EXACT = 1
};

static inline enum d00_registry_state d00_registry_identity_state(
    int *nid_out)
{
    char numeric_oid[96];
    int nid = OBJ_txt2nid(D00_OID_TEXT);
    int short_nid = OBJ_sn2nid(D00_ALG);
    int long_nid = OBJ_ln2nid(D00_ALG);
    ASN1_OBJECT *object;
    const char *short_name;
    const char *long_name;

    if (nid_out == NULL)
        return D00_REGISTRY_CONFLICT;
    *nid_out = NID_undef;
    if (nid == NID_undef && short_nid == NID_undef
            && long_nid == NID_undef)
        return D00_REGISTRY_FREE;
    if (nid == NID_undef || short_nid != nid || long_nid != nid)
        return D00_REGISTRY_CONFLICT;
    object = OBJ_nid2obj(nid);
    short_name = OBJ_nid2sn(nid);
    long_name = OBJ_nid2ln(nid);
    if (object == NULL || short_name == NULL || long_name == NULL
            || strcmp(short_name, D00_ALG) != 0
            || strcmp(long_name, D00_ALG) != 0
            || OBJ_obj2txt(numeric_oid, sizeof(numeric_oid), object, 1)
                != (int)strlen(D00_OID_TEXT)
            || strcmp(numeric_oid, D00_OID_TEXT) != 0)
        return D00_REGISTRY_CONFLICT;
    *nid_out = nid;
    return D00_REGISTRY_EXACT;
}

static inline enum d00_registry_state d00_registry_sigid_state(int nid)
{
    int digest_nid = NID_undef;
    int public_key_nid = NID_undef;
    int reverse_nid = NID_undef;
    int next_nid;
    int signature_nid;
    int found = 0;

    if (nid == NID_undef)
        return D00_REGISTRY_FREE;
    next_nid = OBJ_new_nid(0);
    if (next_nid == NID_undef)
        return D00_REGISTRY_CONFLICT;
    for (signature_nid = 1; signature_nid < next_nid; signature_nid++) {
        if (OBJ_find_sigid_algs(
                signature_nid, &digest_nid, &public_key_nid) != 1)
            continue;
        if (signature_nid != nid && digest_nid != nid
                && public_key_nid != nid)
            continue;
        if (signature_nid != nid || digest_nid != NID_undef
                || public_key_nid != nid || found)
            return D00_REGISTRY_CONFLICT;
        found = 1;
    }
    if (!found)
        return D00_REGISTRY_FREE;
    if (OBJ_find_sigid_by_algs(&reverse_nid, NID_undef, nid) != 1
            || reverse_nid != nid)
        return D00_REGISTRY_CONFLICT;
    return D00_REGISTRY_EXACT;
}

static inline int d00_registry_preflight_ok(void)
{
    int nid = NID_undef;
    enum d00_registry_state identity = d00_registry_identity_state(&nid);
    enum d00_registry_state sigid;

    if (identity == D00_REGISTRY_CONFLICT)
        return 0;
    sigid = d00_registry_sigid_state(nid);
    return sigid != D00_REGISTRY_CONFLICT
        && ((identity == D00_REGISTRY_FREE && sigid == D00_REGISTRY_FREE)
            || (identity == D00_REGISTRY_EXACT
                && sigid == D00_REGISTRY_EXACT));
}

static inline int d00_registry_is_exact(void)
{
    int nid = NID_undef;

    return d00_registry_identity_state(&nid) == D00_REGISTRY_EXACT
        && d00_registry_sigid_state(nid) == D00_REGISTRY_EXACT;
}

static inline int d00_registry_ensure_exact(void)
{
    int nid = NID_undef;
    enum d00_registry_state identity = d00_registry_identity_state(&nid);
    enum d00_registry_state sigid;

    if (identity == D00_REGISTRY_CONFLICT)
        return 0;
    sigid = d00_registry_sigid_state(nid);
    if (sigid == D00_REGISTRY_CONFLICT)
        return 0;
    if (identity == D00_REGISTRY_EXACT || sigid == D00_REGISTRY_EXACT)
        return identity == D00_REGISTRY_EXACT
            && sigid == D00_REGISTRY_EXACT;

    nid = OBJ_create(D00_OID_TEXT, D00_ALG, D00_ALG);
    if (nid == NID_undef || OBJ_add_sigid(nid, NID_undef, nid) != 1)
        return 0;
    return d00_registry_is_exact();
}

static inline int d00_provider_requires_test_registry(
    const char *provider_name)
{
    return provider_name != NULL
        && (strcmp(provider_name, D00_PKI_PROVIDER) == 0
            || strcmp(provider_name, D00_TLS_PROVIDER) == 0
            || strcmp(provider_name, D00_TLS_COLLIDER_PROVIDER) == 0);
}

/*
 * Provider property used by the shared helpers.  The hardening harness
 * repoints this at the separately named failpoint artifact for its
 * injected-panic lane; everything else uses the ordinary module.
 */
static const char *d00_property = D00_PROP;

static int d00_pass_count;
static int d00_fail_count;
static CRYPTO_ONCE d00_registry_once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *d00_registry_lock;

static void d00_registry_lock_init(void)
{
    d00_registry_lock = CRYPTO_THREAD_lock_new();
}

/*
 * Every harness requires the supported ABI major.  The DSO provenance check
 * below still requires the configured lane directory.
 */
static inline int d00_runtime_is_compatible(void)
{
    const unsigned long runtime = OpenSSL_version_num();
    const unsigned int major = (unsigned int)((runtime >> 28) & 0xfUL);

    return major == OPENSSL_VERSION_MAJOR;
}

static inline const char *d00_dso_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash == NULL ? path : slash + 1;
}

static inline int d00_dso_name_matches(
    const char *path,
    const char *name)
{
    const char *base = d00_dso_basename(path);
    const size_t name_len = strlen(name);

    return strncmp(base, name, name_len) == 0
        && (base[name_len] == '\0' || base[name_len] == '.');
}

/*
 * Resolve a symbol through the dynamic linker and require that its genuine
 * DSO is in the canonical lane/lib directory.  Comparing the parent
 * directory after realpath(), instead of strncmp() against the prefix,
 * rejects both sibling prefixes (for example /lane-evil) and lib/lib64
 * lookalikes.  The basename check also prevents a same-directory shim from
 * satisfying the libcrypto/libssl check under an unrelated DSO name.
 */
static inline int d00_runtime_dso_bound(
    const char *symbol,
    const char *dso_name,
    const char *label)
{
    const char *expected = getenv("D00_EXPECT_OPENSSL_PREFIX");
    char canonical_prefix[PATH_MAX];
    char expected_lib[PATH_MAX];
    char canonical_lib[PATH_MAX];
    char canonical_dso[PATH_MAX];
    void *sym;
    Dl_info info;
    char *slash;
    int length;

    if (expected == NULL || expected[0] == '\0') {
        fprintf(stderr,
            "FATAL: %s resolved without D00_EXPECT_OPENSSL_PREFIX\n",
            label);
        return 0;
    }
    if (realpath(expected, canonical_prefix) == NULL) {
        fprintf(stderr,
            "FATAL: %s resolved but lane prefix '%s' is not canonical\n",
            label, expected);
        return 0;
    }
    length = snprintf(expected_lib, sizeof(expected_lib), "%s/lib",
        canonical_prefix);
    if (length < 0 || (size_t)length >= sizeof(expected_lib)) {
        fprintf(stderr,
            "FATAL: %s resolved but lane lib directory is too long\n",
            label);
        return 0;
    }
    if (realpath(expected_lib, canonical_lib) == NULL) {
        fprintf(stderr,
            "FATAL: %s resolved but lane lib directory '%s' is not canonical\n",
            label, expected_lib);
        return 0;
    }

    /* dlsym() avoids validating this executable's PLT address. */
    sym = dlsym(RTLD_DEFAULT, symbol);
    if (sym == NULL || dladdr(sym, &info) == 0
            || info.dli_fname == NULL
            || realpath(info.dli_fname, canonical_dso) == NULL) {
        fprintf(stderr,
            "FATAL: %s resolved symbol '%s' without a canonical DSO\n",
            label, symbol);
        return 0;
    }
    if (!d00_dso_name_matches(canonical_dso, dso_name)) {
        fprintf(stderr,
            "FATAL: %s resolved to '%s', expected genuine %s DSO\n",
            label, info.dli_fname, dso_name);
        return 0;
    }
    slash = strrchr(canonical_dso, '/');
    if (slash == NULL) {
        fprintf(stderr,
            "FATAL: %s resolved to '%s' without a parent directory\n",
            label, info.dli_fname);
        return 0;
    }
    *slash = '\0';
    if (strcmp(canonical_dso, canonical_lib) != 0) {
        fprintf(stderr,
            "FATAL: %s resolved to '%s', expected exact lane/lib '%s'\n",
            label, info.dli_fname, canonical_lib);
        return 0;
    }
    return 1;
}

static inline int d00_runtime_library_bound(void)
{
    return d00_runtime_dso_bound(
        "OpenSSL_version", "libcrypto.so", "libcrypto");
}

static inline int d00_runtime_tls_library_bound(void)
{
    return d00_runtime_dso_bound(
        "SSL_version", "libssl.so", "libssl");
}

#define D00_REQUIRE_RUNTIME_BINDING()                                    \
    do {                                                                 \
        if (!d00_runtime_is_compatible()) {                              \
            fprintf(stderr,                                              \
                "FATAL: runtime OpenSSL '%s' is not compatible with "    \
                "the compile-time headers '%s'\n",                       \
                OpenSSL_version(OPENSSL_VERSION), OPENSSL_VERSION_TEXT); \
            return 3;                                                    \
        }                                                                \
        if (!d00_runtime_library_bound())                                \
            return 3;                                                    \
    } while (0)

#define D00_REQUIRE_TLS_RUNTIME_BINDING()                                \
    do {                                                                 \
        if (!d00_runtime_tls_library_bound())                             \
            return 3;                                                    \
    } while (0)

#define D00_CHECK(condition, ...)                                        \
    do {                                                                 \
        if (condition) {                                                 \
            d00_pass_count++;                                            \
        } else {                                                         \
            d00_fail_count++;                                            \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);         \
            fprintf(stderr, __VA_ARGS__);                                \
            fprintf(stderr, "\n");                                       \
            ERR_print_errors_fp(stderr);                                 \
        }                                                                \
        ERR_clear_error();                                               \
    } while (0)

static inline int d00_summary(const char *name)
{
    printf("%s: %d passed, %d failed\n", name, d00_pass_count,
        d00_fail_count);
    return d00_fail_count == 0 ? 0 : 1;
}

/* Load the default provider and a draft-00 module into a context. */
static inline OSSL_PROVIDER *d00_load_named(
    OSSL_LIB_CTX *libctx,
    OSSL_PROVIDER **defp,
    const char *provider_name)
{
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    const int requires_registry =
        d00_provider_requires_test_registry(provider_name);

    if (defp != NULL)
        *defp = NULL;
    /*
     * This lock belongs to the host test integration helper, not to the
     * provider DSO.  It serializes this executable's preflight/load/
     * postflight sequence using OpenSSL's portable thread primitive.  It is
     * not claimed to coordinate unrelated providers or processes.
     */
    if (CRYPTO_THREAD_run_once(&d00_registry_once,
            d00_registry_lock_init) != 1
            || d00_registry_lock == NULL
            || CRYPTO_THREAD_write_lock(d00_registry_lock) != 1)
        return NULL;
    if (requires_registry && !d00_registry_preflight_ok())
        goto done;
    if (requires_registry && !d00_registry_ensure_exact())
        goto done;
    deflt = OSSL_PROVIDER_load(libctx, "default");
    if (deflt == NULL)
        goto done;
    draft = OSSL_PROVIDER_load(libctx, provider_name);
    if (draft == NULL
            || (requires_registry && !d00_registry_is_exact())) {
        OSSL_PROVIDER_unload(draft);
        draft = NULL;
        OSSL_PROVIDER_unload(deflt);
        deflt = NULL;
        goto done;
    }
    if (defp != NULL)
        *defp = deflt;
    else
        OSSL_PROVIDER_unload(deflt);
done:
    CRYPTO_THREAD_unlock(d00_registry_lock);
    return draft;
}

static inline OSSL_PROVIDER *d00_load(OSSL_LIB_CTX *libctx, OSSL_PROVIDER **defp)
{
    return d00_load_named(libctx, defp, D00_PROVIDER);
}

static inline EVP_PKEY *d00_key_from_params(
    OSSL_LIB_CTX *libctx,
    int selection,
    const unsigned char *seed,
    size_t seed_len,
    const unsigned char *public_key,
    size_t public_len)
{
    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_from_name(libctx, D00_ALG, d00_property);
    OSSL_PARAM params[3];
    size_t count = 0;
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (seed != NULL)
        params[count++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, (void *)seed, seed_len);
    if (public_key != NULL)
        params[count++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, (void *)public_key, public_len);
    params[count] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) != 1
            || EVP_PKEY_fromdata(ctx, &pkey, selection, params) != 1)
        pkey = NULL;
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static inline EVP_PKEY *d00_key_from_seed(
    OSSL_LIB_CTX *libctx,
    const unsigned char seed[38])
{
    return d00_key_from_params(
        libctx, EVP_PKEY_KEYPAIR, seed, D00_SEED_BYTES, NULL, 0);
}

static inline EVP_PKEY *d00_key_from_public(
    OSSL_LIB_CTX *libctx,
    const unsigned char *public_key,
    size_t public_len)
{
    return d00_key_from_params(
        libctx, EVP_PKEY_PUBLIC_KEY, NULL, 0, public_key, public_len);
}

static inline EVP_PKEY *d00_keygen(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_from_name(libctx, D00_ALG, d00_property);
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) != 1
            || EVP_PKEY_keygen(ctx, &pkey) != 1)
        pkey = NULL;
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/*
 * Initialize OpenSSL's complete-message signature operations.  The explicit
 * fetch is required by EVP_PKEY_{sign,verify}_message_init(); the EVP context
 * retains its own reference after a successful initialization.
 */
static inline int d00_sign_message_init(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY_CTX *pctx,
    const OSSL_PARAM *params)
{
    EVP_SIGNATURE *algorithm =
        EVP_SIGNATURE_fetch(libctx, D00_ALG, d00_property);
    int ok = algorithm != NULL
        && EVP_PKEY_sign_message_init(pctx, algorithm, params) == 1;

    EVP_SIGNATURE_free(algorithm);
    return ok;
}

static inline int d00_verify_message_init(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY_CTX *pctx,
    const OSSL_PARAM *params)
{
    EVP_SIGNATURE *algorithm =
        EVP_SIGNATURE_fetch(libctx, D00_ALG, d00_property);
    int ok = algorithm != NULL
        && EVP_PKEY_verify_message_init(pctx, algorithm, params) == 1;

    EVP_SIGNATURE_free(algorithm);
    return ok;
}

/* One-shot EVP_DigestSign; returns 1 and fills sig[76] on success. */
static inline int d00_digest_sign(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey,
    const unsigned char *message,
    size_t message_len,
    unsigned char sig[76])
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    size_t sig_len = D00_SIG_BYTES;
    int ok = 0;

    if (mctx == NULL)
        return 0;
    ok = EVP_DigestSignInit_ex(
             mctx, NULL, NULL, libctx, d00_property, pkey, NULL) == 1
        && EVP_DigestSign(mctx, sig, &sig_len, message, message_len) == 1
        && sig_len == D00_SIG_BYTES;
    EVP_MD_CTX_free(mctx);
    return ok;
}

/* One-shot EVP_DigestVerify with the complete OpenSSL tri-state result. */
static inline int d00_digest_verify_result(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *sig,
    size_t sig_len)
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int result = -1;

    if (mctx == NULL)
        return -1;
    if (EVP_DigestVerifyInit_ex(
            mctx, NULL, NULL, libctx, d00_property, pkey, NULL) == 1)
        result = EVP_DigestVerify(
            mctx, sig, sig_len, message, message_len);
    EVP_MD_CTX_free(mctx);
    return result;
}

/* One-shot EVP_DigestVerify; returns 1 only on acceptance. */
static inline int d00_digest_verify(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *sig,
    size_t sig_len)
{
    return d00_digest_verify_result(
        libctx, pkey, message, message_len, sig, sig_len) == 1;
}

/*
 * Fail-closed verification of one (public key, message, signature) triple
 * through the provider: an unimportable public key counts as rejection.
 * message may be NULL with nonzero length for the NULL-message mapping.
 */
static inline int d00_triple_accepts(
    OSSL_LIB_CTX *libctx,
    const unsigned char *public_key,
    size_t public_len,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *sig,
    size_t sig_len)
{
    EVP_PKEY *pkey = d00_key_from_public(libctx, public_key, public_len);
    int ok;

    if (pkey == NULL) {
        ERR_clear_error();
        return 0;
    }
    ok = d00_digest_verify(libctx, pkey, message, message_len, sig, sig_len);
    EVP_PKEY_free(pkey);
    ERR_clear_error();
    return ok;
}

#endif
