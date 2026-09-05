/*
 * Positive context/domain-separation contract for the repaired provider.
 * Exact KAT bytes are intentionally deferred until the normative domain
 * transcript is frozen and independently implemented.
 */

#include <stdint.h>

#include "harness_common.h"

static int sign_message(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
    const unsigned char *message, size_t message_len,
    int context_present, const unsigned char *context, size_t context_len,
    int set_after_init, unsigned char signature[ED301V1_SIG_BYTES])
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
    OSSL_PARAM params[2];
    unsigned char empty = 0;
    size_t signature_len = ED301V1_SIG_BYTES;
    int ok;

    if (pctx == NULL)
        return 0;
    if (context_present) {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            (void *)(context == NULL ? &empty : context), context_len);
        params[1] = OSSL_PARAM_construct_end();
    }
    if (set_after_init) {
        ok = ed301v1_sign_message_init(libctx, pctx, NULL)
            && (!context_present
                || EVP_PKEY_CTX_set_params(pctx, params) == 1);
    } else {
        ok = ed301v1_sign_message_init(
            libctx, pctx, context_present ? params : NULL);
    }
    ok = ok
        && EVP_PKEY_sign(pctx, signature, &signature_len,
            message, message_len) == 1
        && signature_len == ED301V1_SIG_BYTES;
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

static int verify_message(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
    const unsigned char *message, size_t message_len,
    int context_present, const unsigned char *context, size_t context_len,
    const unsigned char signature[ED301V1_SIG_BYTES])
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
    OSSL_PARAM params[2];
    unsigned char empty = 0;
    int result = -2;

    if (pctx == NULL)
        return -2;
    if (context_present) {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            (void *)(context == NULL ? &empty : context), context_len);
        params[1] = OSSL_PARAM_construct_end();
    }
    if (ed301v1_verify_message_init(
            libctx, pctx, context_present ? params : NULL))
        result = EVP_PKEY_verify(pctx, signature, ED301V1_SIG_BYTES,
            message, message_len);
    EVP_PKEY_CTX_free(pctx);
    ERR_clear_error();
    return result;
}

static int sign_digest(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
    const unsigned char *message, size_t message_len,
    const unsigned char *context, size_t context_len,
    unsigned char signature[ED301V1_SIG_BYTES])
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    OSSL_PARAM params[2];
    size_t signature_len = ED301V1_SIG_BYTES;
    int ok;

    if (mctx == NULL)
        return 0;
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)context, context_len);
    params[1] = OSSL_PARAM_construct_end();
    ok = EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx, ED301V1_PROP,
             pkey, params) == 1
        && EVP_DigestSign(mctx, signature, &signature_len,
            message, message_len) == 1
        && signature_len == ED301V1_SIG_BYTES;
    EVP_MD_CTX_free(mctx);
    return ok;
}

static int verify_digest(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
    const unsigned char *message, size_t message_len,
    const unsigned char *context, size_t context_len,
    const unsigned char signature[ED301V1_SIG_BYTES])
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    OSSL_PARAM params[2];
    int result = -2;

    if (mctx == NULL)
        return -2;
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)context, context_len);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_DigestVerifyInit_ex(mctx, NULL, NULL, libctx, ED301V1_PROP,
            pkey, params) == 1)
        result = EVP_DigestVerify(mctx, signature, ED301V1_SIG_BYTES,
            message, message_len);
    EVP_MD_CTX_free(mctx);
    ERR_clear_error();
    return result;
}

int main(void)
{
    static const unsigned char message[] = { 0x00, 0x01, 0x02, 0x00, 0xff };
    static const unsigned char alpha[] = "alpha";
    static const unsigned char beta[] = "beta";
    static const unsigned char binary[] = { 0x00, 0x01, 0x00, 0xff };
    unsigned char seed[ED301V1_SEED_BYTES];
    unsigned char no_context[ED301V1_SIG_BYTES] = { 0 };
    unsigned char empty_init[ED301V1_SIG_BYTES] = { 0 };
    unsigned char empty_set[ED301V1_SIG_BYTES] = { 0 };
    unsigned char alpha_init[ED301V1_SIG_BYTES] = { 0 };
    unsigned char alpha_set[ED301V1_SIG_BYTES] = { 0 };
    unsigned char alpha_repeat[ED301V1_SIG_BYTES] = { 0 };
    unsigned char alpha_digest[ED301V1_SIG_BYTES] = { 0 };
    unsigned char beta_init[ED301V1_SIG_BYTES] = { 0 };
    unsigned char binary_init[ED301V1_SIG_BYTES] = { 0 };
    unsigned char max_init[ED301V1_SIG_BYTES] = { 0 };
    unsigned char max_context[255];
    unsigned char overlong_context[256];
    unsigned char rejected_output[ED301V1_SIG_BYTES];
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *provider;
    EVP_PKEY *pkey;
    size_t index;

    ED301V1_REQUIRE_RUNTIME_BINDING();
    for (index = 0; index < sizeof(seed); index++)
        seed[index] = (unsigned char)index;
    for (index = 0; index < sizeof(max_context); index++)
        max_context[index] = (unsigned char)index;
    memset(overlong_context, 0xa5, sizeof(overlong_context));
    memset(rejected_output, 0x5a, sizeof(rejected_output));

    libctx = OSSL_LIB_CTX_new();
    provider = ed301v1_load(libctx, &deflt);
    pkey = provider == NULL ? NULL : ed301v1_key_from_seed(libctx, seed);
    ED301V1_CHECK(provider != NULL, "provider load");
    ED301V1_CHECK(pkey != NULL, "fixed key import");
    if (pkey == NULL)
        goto done;

    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            0, NULL, 0, 0, no_context),
        "omitted context signs");
    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, NULL, 0, 0, empty_init),
        "explicit empty context signs at init");
    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, NULL, 0, 1, empty_set),
        "explicit empty context signs after set_params");
    ED301V1_CHECK(memcmp(no_context, empty_init, ED301V1_SIG_BYTES) == 0
            && memcmp(no_context, empty_set, ED301V1_SIG_BYTES) == 0,
        "omitted and explicitly empty contexts have one transcript");

    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, alpha, sizeof(alpha) - 1, 0, alpha_init),
        "alpha context signs at init");
    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, alpha, sizeof(alpha) - 1, 1, alpha_set),
        "alpha context signs after set_params");
    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, alpha, sizeof(alpha) - 1, 0, alpha_repeat),
        "alpha context repeat signs");
    ED301V1_CHECK(sign_digest(libctx, pkey, message, sizeof(message),
            alpha, sizeof(alpha) - 1, alpha_digest),
        "alpha context signs through DigestSign");
    ED301V1_CHECK(memcmp(alpha_init, alpha_set, ED301V1_SIG_BYTES) == 0
            && memcmp(alpha_init, alpha_repeat, ED301V1_SIG_BYTES) == 0
            && memcmp(alpha_init, alpha_digest, ED301V1_SIG_BYTES) == 0,
        "all alpha one-shot paths are deterministic and identical");

    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, beta, sizeof(beta) - 1, 0, beta_init),
        "beta context signs");
    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, binary, sizeof(binary), 0, binary_init),
        "binary context including NUL signs as octets");
    ED301V1_CHECK(sign_message(libctx, pkey, message, sizeof(message),
            1, max_context, sizeof(max_context), 0, max_init),
        "255-byte context signs");
    ED301V1_CHECK(!sign_message(libctx, pkey, message, sizeof(message),
            1, overlong_context, sizeof(overlong_context), 0,
            rejected_output),
        "256-byte context is rejected");

    ED301V1_CHECK(memcmp(no_context, alpha_init, ED301V1_SIG_BYTES) != 0
            && memcmp(alpha_init, beta_init, ED301V1_SIG_BYTES) != 0
            && memcmp(alpha_init, binary_init, ED301V1_SIG_BYTES) != 0
            && memcmp(alpha_init, max_init, ED301V1_SIG_BYTES) != 0,
        "distinct contexts produce distinct signatures");

    ED301V1_CHECK(verify_message(libctx, pkey, message, sizeof(message),
            0, NULL, 0, no_context) == 1,
        "omitted-context signature verifies without context");
    ED301V1_CHECK(verify_message(libctx, pkey, message, sizeof(message),
            1, NULL, 0, no_context) == 1,
        "omitted-context signature verifies with explicit empty context");
    ED301V1_CHECK(verify_message(libctx, pkey, message, sizeof(message),
            1, alpha, sizeof(alpha) - 1, alpha_init) == 1
            && verify_digest(libctx, pkey, message, sizeof(message),
                alpha, sizeof(alpha) - 1, alpha_init) == 1,
        "alpha signature verifies through both one-shot APIs");
    ED301V1_CHECK(verify_message(libctx, pkey, message, sizeof(message),
            1, beta, sizeof(beta) - 1, beta_init) == 1,
        "beta signature verifies in beta context");
    ED301V1_CHECK(verify_message(libctx, pkey, message, sizeof(message),
            1, binary, sizeof(binary), binary_init) == 1,
        "binary-context signature verifies");

    ED301V1_CHECK(verify_message(libctx, pkey, message, sizeof(message),
            0, NULL, 0, alpha_init) == 0
            && verify_message(libctx, pkey, message, sizeof(message),
                1, beta, sizeof(beta) - 1, alpha_init) == 0
            && verify_message(libctx, pkey, message, sizeof(message),
                1, alpha, sizeof(alpha) - 1, beta_init) == 0,
        "cross-context verification fails closed");

done:
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return ed301v1_summary("provider_context_contract");
}
