/*
 * Acceptance section 3 (signature contract): four positive v1
 * vectors byte-for-byte, 14 point / 6 scalar / 22 verification edge cases,
 * the 77 deterministic negative mutations from the reference lane,
 * determinism, exact size query, undersized buffers without partial
 * signatures, S + L malleability, mode rejections (external digest,
 * prehash, streaming and randomized signing) plus native context handling
 * and the demonstration
 * that historical Ed301-Sig-v1 material does not verify.
 */

#include <stdint.h>

#include "harness_common.h"
#include "vectors.h"

static const unsigned char ED301V1_EXPECTED_ALGORITHM_ID[15] = {
    0x30, 0x0d, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x84, 0x85, 0x6a, 0x82, 0x2d, 0x04
};

/*
 * FBL-08 mutation control: with ED301V1_POLICY_MUTATE=1 every expected
 * parser/policy result of the point, scalar, verification and commitment
 * lanes is inverted and this harness MUST fail; the matrix runner asserts
 * that failure.
 */
static int ed301v1_policy_invert(void)
{
    const char *value = getenv("ED301V1_POLICY_MUTATE");

    return value != NULL && strcmp(value, "1") == 0;
}

/*
 * A parameter array that must be refused at sign init; used for every
 * malformed or non-advertised tls-version shape on both lanes.
 */
static int ed301v1_message_sign_init_rejects(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
    const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
    int rejected = pctx != NULL
        && !ed301v1_sign_message_init(libctx, pctx, params);

    ERR_clear_error();
    EVP_PKEY_CTX_free(pctx);
    return rejected;
}

int main(void)
{
    ED301V1_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = ed301v1_load(libctx, &deflt);
    size_t index;
    const int invert = ed301v1_policy_invert();

    ED301V1_CHECK(v1 != NULL, "provider load");

    /*
     * S1/S8 -- Ed301-v1 pure-EdDSA contract and OpenSSL
     * test/evp_extra_test.c Ed25519/Ed448 pattern: one-shot whole-message and
     * DigestSign/DigestVerify paths, including the zero-byte KAT, are positive.
     * S2 -- Provider contract: the size query is exactly 76 bytes and an
     * undersized output buffer is rejected without a partial signature.
     */
    for (index = 0; index < 4; index++) {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[index];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char sig[76] = { 0 };
        unsigned char sig_again[76] = { 0 };
        size_t sig_len = 0;

        ED301V1_CHECK(pkey != NULL, "%s: key", tc->id);
        if (pkey == NULL)
            continue;

        /* The pre-digested TBS API must not create an accidental Ed301ph. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL && EVP_PKEY_sign_init(pctx) != 1,
            "%s: pre-digested sign init rejected", tc->id);
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);

        /* Complete-message EVP path with exact size query. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL
                && ed301v1_sign_message_init(libctx, pctx, NULL),
            "%s: whole-message sign init", tc->id);
        sig_len = 0;
        ED301V1_CHECK(pctx != NULL
                && EVP_PKEY_sign(pctx, NULL, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == ED301V1_SIG_BYTES,
            "%s: size query returns exactly 76", tc->id);

        /* A 75-byte output buffer fails without a partial signature. */
        {
            unsigned char small[75];
            unsigned char canary[75];

            memset(small, 0x5a, sizeof(small));
            memset(canary, 0x5a, sizeof(canary));
            sig_len = sizeof(small);
            ED301V1_CHECK(pctx != NULL
                    && EVP_PKEY_sign(pctx, small, &sig_len, tc->message,
                        tc->message_len) != 1
                    && memcmp(small, canary, sizeof(small)) == 0,
                "%s: 75-byte buffer rejected without partial write",
                tc->id);
            ERR_clear_error();
        }

        sig_len = sizeof(sig);
        ED301V1_CHECK(pctx != NULL
                && EVP_PKEY_sign(pctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == ED301V1_SIG_BYTES
                && memcmp(sig, tc->signature, ED301V1_SIG_BYTES) == 0,
            "%s: whole-message EVP_PKEY_sign matches the vector byte-for-byte",
            tc->id);

        /* Determinism. */
        sig_len = sizeof(sig_again);
        ED301V1_CHECK(pctx != NULL
                && EVP_PKEY_sign(pctx, sig_again, &sig_len, tc->message,
                    tc->message_len) == 1
                && memcmp(sig, sig_again, ED301V1_SIG_BYTES) == 0,
            "%s: deterministic", tc->id);
        EVP_PKEY_CTX_free(pctx);

        /* One-shot DigestSign agrees exactly. */
        memset(sig_again, 0, sizeof(sig_again));
        ED301V1_CHECK(ed301v1_digest_sign(libctx, pkey, tc->message,
                tc->message_len, sig_again)
                && memcmp(sig_again, tc->signature, ED301V1_SIG_BYTES) == 0,
            "%s: one-shot DigestSign matches the vector", tc->id);

        /*
         * S2 must also bind OpenSSL's high-level DigestSign entry point, not
         * only the provider-native whole-message EVP_PKEY operation.
         */
        {
            EVP_MD_CTX *size_context = EVP_MD_CTX_new();
            EVP_MD_CTX *small_context = EVP_MD_CTX_new();
            unsigned char small[ED301V1_SIG_BYTES - 1];
            unsigned char canary[ED301V1_SIG_BYTES - 1];
            size_t digest_sig_len = 0;

            ED301V1_CHECK(size_context != NULL
                    && EVP_DigestSignInit_ex(size_context, NULL, NULL,
                        libctx, ed301v1_property, pkey, NULL) == 1
                    && EVP_DigestSign(size_context, NULL, &digest_sig_len,
                        tc->message, tc->message_len) == 1
                    && digest_sig_len == ED301V1_SIG_BYTES,
                "%s: DigestSign size query returns exactly 76", tc->id);

            memset(small, 0x5a, sizeof(small));
            memset(canary, 0x5a, sizeof(canary));
            digest_sig_len = sizeof(small);
            ED301V1_CHECK(small_context != NULL
                    && EVP_DigestSignInit_ex(small_context, NULL, NULL,
                        libctx, ed301v1_property, pkey, NULL) == 1
                    && EVP_DigestSign(small_context, small,
                        &digest_sig_len, tc->message, tc->message_len) != 1
                    && memcmp(small, canary, sizeof(small)) == 0,
                "%s: DigestSign 75-byte buffer rejects without write",
                tc->id);
            ERR_clear_error();
            EVP_MD_CTX_free(small_context);
            EVP_MD_CTX_free(size_context);
        }

        /* The TBS verify API is likewise unavailable; message APIs accept. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL && EVP_PKEY_verify_init(pctx) != 1,
            "%s: pre-digested verify init rejected", tc->id);
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);

        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL
                && ed301v1_verify_message_init(libctx, pctx, NULL)
                && EVP_PKEY_verify(pctx, tc->signature, ED301V1_SIG_BYTES,
                    tc->message, tc->message_len) == 1,
            "%s: whole-message EVP_PKEY_verify accepts", tc->id);
        EVP_PKEY_CTX_free(pctx);
        ED301V1_CHECK(ed301v1_digest_verify(libctx, pkey, tc->message,
                tc->message_len, tc->signature, ED301V1_SIG_BYTES),
            "%s: DigestVerify accepts", tc->id);

        EVP_PKEY_free(pkey);
    }

    /* Ed448 pattern translated to Ed301-v1: the one-octet length binds
     * binary contexts of length 0 through 255 into both transcripts. */
    for (index = 0;
            index < sizeof(CONTEXT_CASES) / sizeof(CONTEXT_CASES[0]);
            index++) {
        const CONTEXT_CASE *tc = &CONTEXT_CASES[index];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        EVP_PKEY_CTX *sign_ctx = NULL;
        EVP_PKEY_CTX *verify_ctx = NULL;
        EVP_PKEY_CTX *duplicate = NULL;
        EVP_MD_CTX *digest_ctx = NULL;
        OSSL_PARAM params[2];
        OSSL_PARAM query[2];
        unsigned char signature[ED301V1_SIG_BYTES] = { 0 };
        unsigned char duplicate_signature[ED301V1_SIG_BYTES] = { 0 };
        unsigned char queried_context[255] = { 0 };
        unsigned char wrong_context[255] = { 0 };
        size_t signature_length = sizeof(signature);
        size_t duplicate_length = sizeof(duplicate_signature);

        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            (void *)tc->context, tc->context_len);
        params[1] = OSSL_PARAM_construct_end();
        query[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            queried_context, sizeof(queried_context));
        query[1] = OSSL_PARAM_construct_end();

        sign_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(sign_ctx != NULL
                && ed301v1_sign_message_init(libctx, sign_ctx, params)
                && EVP_PKEY_CTX_get_params(sign_ctx, query) == 1
                && query[0].return_size == tc->context_len
                && memcmp(queried_context, tc->context,
                    tc->context_len) == 0
                && EVP_PKEY_sign(sign_ctx, signature, &signature_length,
                    tc->message, tc->message_len) == 1
                && signature_length == ED301V1_SIG_BYTES
                && memcmp(signature, tc->signature, ED301V1_SIG_BYTES) == 0,
            "%s: native-context sign and get_params match vector", tc->id);

        duplicate = sign_ctx == NULL ? NULL : EVP_PKEY_CTX_dup(sign_ctx);
        ED301V1_CHECK(duplicate != NULL
                && EVP_PKEY_sign(duplicate, duplicate_signature,
                    &duplicate_length, tc->message, tc->message_len) == 1
                && duplicate_length == ED301V1_SIG_BYTES
                && memcmp(duplicate_signature, tc->signature,
                    ED301V1_SIG_BYTES) == 0,
            "%s: duplicated context preserves native domain", tc->id);

        signature_length = sizeof(signature);
        ED301V1_CHECK(sign_ctx != NULL
                && ed301v1_sign_message_init(libctx, sign_ctx, params)
                && EVP_PKEY_sign(sign_ctx, signature, &signature_length,
                    tc->message, tc->message_len) == 1
                && memcmp(signature, tc->signature, ED301V1_SIG_BYTES) == 0,
            "%s: message reinit reapplies native domain", tc->id);

        memset(signature, 0, sizeof(signature));
        signature_length = sizeof(signature);
        ED301V1_CHECK(sign_ctx != NULL
                && ed301v1_sign_message_init(libctx, sign_ctx, NULL)
                && EVP_PKEY_CTX_get_params(sign_ctx, query) == 1
                && query[0].return_size == 0
                && EVP_PKEY_sign(sign_ctx, signature, &signature_length,
                    tc->message, tc->message_len) == 1
                && signature_length == ED301V1_SIG_BYTES
                && memcmp(signature, tc->empty_context_signature,
                    ED301V1_SIG_BYTES) == 0,
            "%s: message reinit without params restores empty context",
            tc->id);

        verify_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(verify_ctx != NULL
                && ed301v1_verify_message_init(libctx, verify_ctx, params)
                && EVP_PKEY_verify(verify_ctx, tc->signature,
                    ED301V1_SIG_BYTES, tc->message, tc->message_len) == 1,
            "%s: matching native context verifies", tc->id);

        ED301V1_CHECK(tc->context_len != 0,
            "%s: context fixture is nonempty", tc->id);
        memcpy(wrong_context, tc->context, tc->context_len);
        wrong_context[0] ^= 1;
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            wrong_context, tc->context_len);
        ED301V1_CHECK(verify_ctx != NULL
                && EVP_PKEY_CTX_set_params(verify_ctx, params) == 1
                && EVP_PKEY_verify(verify_ctx, tc->signature,
                    ED301V1_SIG_BYTES, tc->message, tc->message_len) == 0,
            "%s: altered native context is a non-match", tc->id);

        digest_ctx = EVP_MD_CTX_new();
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            (void *)tc->context, tc->context_len);
        signature_length = sizeof(signature);
        ED301V1_CHECK(digest_ctx != NULL
                && EVP_DigestSignInit_ex(digest_ctx, NULL, NULL, libctx,
                    ED301V1_PROP, pkey, params) == 1
                && EVP_DigestSign(digest_ctx, signature, &signature_length,
                    tc->message, tc->message_len) == 1
                && signature_length == ED301V1_SIG_BYTES
                && memcmp(signature, tc->signature, ED301V1_SIG_BYTES) == 0,
            "%s: DigestSign native-context vector", tc->id);

        EVP_MD_CTX_free(digest_ctx);
        EVP_PKEY_CTX_free(duplicate);
        EVP_PKEY_CTX_free(verify_ctx);
        EVP_PKEY_CTX_free(sign_ctx);
        EVP_PKEY_free(pkey);
    }

    /* Context bounds and type checks are fail-closed and invalidate any
     * previously bound operation so an old domain can never be reused. */
    {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[0];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(
            libctx, pkey, ED301V1_PROP);
        unsigned char oversized[256] = { 0 };
        unsigned char output[ED301V1_SIG_BYTES];
        unsigned char canary[ED301V1_SIG_BYTES];
        char wrong_type[] = "ctx";
        OSSL_PARAM params[3];
        size_t output_length = sizeof(output);

        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            oversized, sizeof(oversized));
        params[1] = OSSL_PARAM_construct_end();
        memset(output, 0xa5, sizeof(output));
        memcpy(canary, output, sizeof(canary));
        ED301V1_CHECK(pctx != NULL
                && ed301v1_sign_message_init(libctx, pctx, NULL)
                && EVP_PKEY_CTX_set_params(pctx, params) != 1
                && EVP_PKEY_sign(pctx, output, &output_length,
                    tc->message, tc->message_len) != 1
                && memcmp(output, canary, sizeof(output)) == 0,
            "256-byte context rejected and prior operation invalidated");
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);

        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, wrong_type, 0);
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL
                && !ed301v1_sign_message_init(libctx, pctx, params),
            "context parameter with UTF8 type rejected");
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);

        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, wrong_type, 1);
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, wrong_type, 1);
        params[2] = OSSL_PARAM_construct_end();
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL
                && !ed301v1_sign_message_init(libctx, pctx, params),
            "duplicate context parameters rejected atomically");
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
    }

    /*
     * S4 -- Ed301-v1 deterministic-signing contract: five independent one-shot
     * operations over the same key/message produce the exact KAT bytes.
     */
    {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[0];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        unsigned char signatures[5][ED301V1_SIG_BYTES];
        int deterministic = pkey != NULL;
        size_t repetition;

        for (repetition = 0; deterministic && repetition < 5; repetition++)
            deterministic = ed301v1_digest_sign(libctx, pkey,
                    tc->message, tc->message_len, signatures[repetition])
                && memcmp(signatures[repetition], tc->signature,
                    ED301V1_SIG_BYTES) == 0
                && (repetition == 0
                    || memcmp(signatures[repetition], signatures[0],
                        ED301V1_SIG_BYTES) == 0);
        ED301V1_CHECK(deterministic,
            "five independent signatures are byte-identical to the KAT");
        EVP_PKEY_free(pkey);
    }

    /* Match Ed448: every DigestSign/DigestVerify init requires a key. */
    {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[0];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        EVP_MD_CTX *sign_context = EVP_MD_CTX_new();
        EVP_MD_CTX *verify_context = EVP_MD_CTX_new();
        unsigned char signature[ED301V1_SIG_BYTES] = { 0 };
        size_t signature_length = sizeof(signature);

        ED301V1_CHECK(pkey != NULL && sign_context != NULL
                && EVP_DigestSignInit_ex(sign_context, NULL, NULL, libctx,
                    ED301V1_PROP, pkey, NULL) == 1
                && EVP_DigestSign(sign_context, signature,
                    &signature_length, tc->message, tc->message_len) == 1
                && signature_length == ED301V1_SIG_BYTES
                && memcmp(signature, tc->signature, ED301V1_SIG_BYTES) == 0,
            "DigestSign initializes and signs with an explicit Ed301 key");

        ED301V1_CHECK(sign_context != NULL
                && EVP_DigestSignInit_ex(sign_context, NULL, NULL, libctx,
                    ED301V1_PROP, NULL, NULL) != 1,
            "DigestSign rejects NULL-key reinitialization");
        ERR_clear_error();

        memset(signature, 0, sizeof(signature));
        signature_length = sizeof(signature);
        ED301V1_CHECK(sign_context != NULL
                && EVP_DigestSign(sign_context, signature,
                    &signature_length, tc->message, tc->message_len) != 1,
            "rejected DigestSign reinit invalidates the prior operation");
        ERR_clear_error();

        ED301V1_CHECK(pkey != NULL && verify_context != NULL
                && EVP_DigestVerifyInit_ex(verify_context, NULL, NULL,
                    libctx, ED301V1_PROP, pkey, NULL) == 1
                && EVP_DigestVerify(verify_context, tc->signature,
                    ED301V1_SIG_BYTES, tc->message, tc->message_len) == 1,
            "DigestVerify initializes and verifies with an explicit key");
        ED301V1_CHECK(verify_context != NULL
                && EVP_DigestVerifyInit_ex(verify_context, NULL, NULL,
                    libctx, ED301V1_PROP, NULL, NULL) != 1,
            "DigestVerify rejects NULL-key reinitialization");
        ERR_clear_error();
        ED301V1_CHECK(verify_context != NULL
                && EVP_DigestVerify(verify_context, tc->signature,
                    ED301V1_SIG_BYTES, tc->message, tc->message_len) != 1,
            "rejected DigestVerify reinit invalidates the prior operation");
        ERR_clear_error();

        EVP_MD_CTX_free(verify_context);
        EVP_MD_CTX_free(sign_context);
        EVP_PKEY_free(pkey);
    }

    /*
     * Verification preserves OpenSSL's 1 / 0 / negative distinction: a
     * well-formed signature over a different message is a normal non-match,
     * not an internal provider failure.
     */
    {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[0];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        unsigned char changed_message[1] = { 0x01 };
        unsigned char malformed[ED301V1_SIG_BYTES];
        unsigned char overlong[ED301V1_SIG_BYTES + 1];
        int result;

        ERR_clear_error();
        result = pkey == NULL ? -1
            : ed301v1_digest_verify_result(libctx, pkey,
                changed_message, sizeof(changed_message),
                tc->signature, ED301V1_SIG_BYTES);
        ED301V1_CHECK(result == 0,
            "cryptographic non-match returns exactly zero");

        memset(malformed, 0xff, sizeof(malformed));
        ERR_clear_error();
        result = pkey == NULL ? -1
            : ed301v1_digest_verify_result(libctx, pkey,
                tc->message, tc->message_len,
                malformed, sizeof(malformed));
        ED301V1_CHECK(result == 0,
            "noncanonical signature returns exactly zero");

        /* S3 -- Ed301-v1 signature encoding is exactly 76 bytes. */
        ERR_clear_error();
        result = pkey == NULL ? -1
            : ed301v1_digest_verify_result(libctx, pkey,
                tc->message, tc->message_len,
                tc->signature, ED301V1_SIG_BYTES - 1);
        ED301V1_CHECK(result == 0,
            "75-byte signature returns exactly zero");

        memcpy(overlong, tc->signature, ED301V1_SIG_BYTES);
        overlong[ED301V1_SIG_BYTES] = 0;
        ERR_clear_error();
        result = pkey == NULL ? -1
            : ed301v1_digest_verify_result(libctx, pkey,
                tc->message, tc->message_len,
                overlong, sizeof(overlong));
        ED301V1_CHECK(result == 0,
            "77-byte signature returns exactly zero");

        ERR_clear_error();
        result = pkey == NULL ? 0
            : ed301v1_digest_verify_result(libctx, pkey,
                tc->message, tc->message_len,
                NULL, ED301V1_SIG_BYTES);
        ED301V1_CHECK(result < 0 && ERR_peek_error() != 0,
            "NULL signature buffer returns negative with provider error");
        ERR_clear_error();

        result = pkey == NULL ? 0
            : ed301v1_digest_verify_result(libctx, pkey,
                NULL, 1, tc->signature, ED301V1_SIG_BYTES);
        ED301V1_CHECK(result < 0 && ERR_peek_error() != 0,
            "NULL message buffer returns negative with provider error");
        ERR_clear_error();
        EVP_PKEY_free(pkey);
    }

    /* R1A: reject an opaque message length above isize::MAX before Rust
     * forms a slice, using a one-byte pointer as the bounded storage. */
    {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[0];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char output[ED301V1_SIG_BYTES];
        unsigned char canary[ED301V1_SIG_BYTES];
        unsigned char one_byte = 0x5a;
        const size_t oversized = (size_t)INTPTR_MAX + 1;
        size_t sig_len = sizeof(output);
        int sign_failed = 0;
        int verify_failed = 0;

        ED301V1_CHECK(pkey != NULL, "oversized-message: key");
        memset(output, 0xa5, sizeof(output));
        memcpy(canary, output, sizeof(canary));

        pctx = pkey == NULL ? NULL
            : EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        if (pctx != NULL && ed301v1_sign_message_init(libctx, pctx, NULL))
            sign_failed = EVP_PKEY_sign(pctx, output, &sig_len,
                &one_byte, oversized) != 1
                && memcmp(output, canary, sizeof(output)) == 0;
        ED301V1_CHECK(sign_failed,
            "oversized-message: EVP_PKEY_sign fails closed above isize::MAX");
        EVP_PKEY_CTX_free(pctx);

        pctx = pkey == NULL ? NULL
            : EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        if (pctx != NULL && ed301v1_verify_message_init(libctx, pctx, NULL))
            verify_failed = EVP_PKEY_verify(pctx, tc->signature,
                ED301V1_SIG_BYTES, &one_byte, oversized) < 0;
        ED301V1_CHECK(verify_failed,
            "oversized-message: EVP_PKEY_verify returns an operational error");
        EVP_PKEY_CTX_free(pctx);

        memset(output, 0, sizeof(output));
        ED301V1_CHECK(pkey != NULL
                && ed301v1_digest_sign(libctx, pkey, tc->message,
                    tc->message_len, output)
                && memcmp(output, tc->signature, ED301V1_SIG_BYTES) == 0
                && ed301v1_digest_verify(libctx, pkey, tc->message,
                    tc->message_len, output, ED301V1_SIG_BYTES),
            "oversized-message: normal sign and verify recover");
        EVP_PKEY_free(pkey);
    }

    /* 14 point cases: provider public-key policy surface. */
    for (index = 0; index < 14; index++) {
        const POINT_CASE *tc = &POINT_CASES[index];
        EVP_PKEY *pkey = ed301v1_key_from_public(
            libctx, tc->encoding, tc->encoding_len);

        ED301V1_CHECK((pkey != NULL)
                == (tc->expect_public_key_policy_accept ^ invert),
            "point %s: public-key policy (%s expected)", tc->id,
            tc->expect_public_key_policy_accept ? "accept" : "reject");
        ERR_clear_error();
        EVP_PKEY_free(pkey);

        /*
         * Commitment-policy surface: substituting the encoding as R must
         * never validate against an unrelated valid transcript, whether
         * the encoding itself parses (equation fails) or not (syntax
         * fails).  The discriminating accept cases are exercised by the
         * verification matrix below.
         */
        {
            unsigned char forged[80];
            size_t forged_len = tc->encoding_len + ED301V1_SEED_BYTES;

            memcpy(forged, tc->encoding, tc->encoding_len);
            memcpy(forged + tc->encoding_len,
                POSITIVE_CASES[0].signature + 38, 38);
            ED301V1_CHECK(!ed301v1_triple_accepts(libctx,
                    POSITIVE_CASES[0].public_key, ED301V1_PUB_BYTES,
                    POSITIVE_CASES[0].message,
                    POSITIVE_CASES[0].message_len,
                    forged, forged_len),
                "point %s: R substitution fails closed", tc->id);
        }
    }

    /* 6 scalar cases: provider S-parse surface. */
    for (index = 0; index < 6; index++) {
        const SCALAR_CASE *tc = &SCALAR_CASES[index];
        unsigned char forged[80];
        size_t forged_len = 38 + tc->encoding_len;

        memcpy(forged, POSITIVE_CASES[0].signature, 38);
        memcpy(forged + 38, tc->encoding, tc->encoding_len);
        ED301V1_CHECK(!ed301v1_triple_accepts(libctx,
                POSITIVE_CASES[0].public_key, ED301V1_PUB_BYTES,
                POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
                forged, forged_len),
            "scalar %s (syntax %s): S substitution fails closed",
            tc->id, tc->expect_syntax_accept ? "accept" : "reject");
    }

    /* 22 verification edge cases. */
    for (index = 0; index < 22; index++) {
        const VERIFICATION_CASE *tc = &VERIFICATION_CASES[index];
        int accepted = ed301v1_triple_accepts(libctx,
            tc->public_key, tc->public_key_len,
            tc->message, tc->message_len,
            tc->signature, tc->signature_len);

        ED301V1_CHECK(accepted == (tc->expect_accept ^ invert),
            "verification %s: expected %s", tc->id,
            tc->expect_accept ? "accept" : "reject");
    }

    /*
     * FBL-08: commitment-policy lane.  Every declared point row is
     * decided through the provider's public verify surface: rows whose
     * commitment policy accepts carry an equation-preserving signature
     * built by gen_vectors.py with the bundled reference oracle (chosen
     * nonce or the bundle's own accepting vector), so R-parse acceptance
     * is observable as a full verification success; rejecting rows must
     * fail.  The scalar syntax rows are asserted directly at the core's
     * public parse API by the workspace unit test (policy_tests.rs) and
     * discriminated here by the S + L malleability lane below.
     */
    for (index = 0;
            index < sizeof(POLICY_COMMITMENT_CASES)
                / sizeof(POLICY_COMMITMENT_CASES[0]);
            index++) {
        const POLICY_COMMITMENT_CASE *tc = &POLICY_COMMITMENT_CASES[index];
        int accepted = ed301v1_triple_accepts(libctx,
            tc->public_key, ED301V1_PUB_BYTES,
            tc->message, tc->message_len,
            tc->signature, tc->signature_len);

        ED301V1_CHECK(accepted == (tc->expect_accept ^ invert),
            "commitment policy %s: expected %s", tc->id,
            tc->expect_accept ? "accept" : "reject");
    }

    /* 77 deterministic negative mutations from the reference lane. */
    {
        int rejected_count = 0;

        for (index = 0; index < 77; index++) {
            const NEGATIVE_CASE *tc = &NEGATIVE_CASES[index];
            int accepted;

            if (tc->kind == NEGATIVE_NULL_MESSAGE) {
                accepted = ed301v1_triple_accepts(libctx,
                    tc->public_key, tc->public_key_len,
                    NULL, tc->message_len,
                    tc->signature, tc->signature_len);
            } else if (tc->kind == NEGATIVE_WRONG_PARAM_TYPE) {
                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
                    libctx, ED301V1_ALG, ED301V1_PROP);
                OSSL_PARAM params[2];
                EVP_PKEY *pkey = NULL;

                params[0] = OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_PUB_KEY,
                    (char *)tc->public_key, tc->public_key_len);
                params[1] = OSSL_PARAM_construct_end();
                accepted = ctx != NULL
                    && EVP_PKEY_fromdata_init(ctx) == 1
                    && EVP_PKEY_fromdata(ctx, &pkey,
                        EVP_PKEY_PUBLIC_KEY, params) == 1;
                EVP_PKEY_free(pkey);
                EVP_PKEY_CTX_free(ctx);
                ERR_clear_error();
            } else {
                accepted = ed301v1_triple_accepts(libctx,
                    tc->public_key, tc->public_key_len,
                    tc->message, tc->message_len,
                    tc->signature, tc->signature_len);
            }
            if (!accepted)
                rejected_count++;
            ED301V1_CHECK(!accepted, "negative %zu (%s) must be rejected",
                index, tc->label);
        }
        ED301V1_CHECK(rejected_count == 77,
            "all 77 reference-lane mutations rejected (%d)",
            rejected_count);
    }

    /* S + L malleability. */
    ED301V1_CHECK(!ed301v1_triple_accepts(libctx,
            POSITIVE_CASES[0].public_key, ED301V1_PUB_BYTES,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
            S_PLUS_L_SIGNATURE, sizeof(S_PLUS_L_SIGNATURE)),
        "S + L malleability is rejected");

    /* Historical Ed301-Sig-v1 material does not verify. */
    {
        EVP_PKEY *v1_key = ed301v1_key_from_seed(
            libctx, POSITIVE_CASES[0].seed);

        ED301V1_CHECK(memcmp(HISTORICAL_PUBLIC_KEY,
                POSITIVE_CASES[0].public_key, ED301V1_PUB_BYTES) != 0,
            "same seed yields different Ed301-EdDSA-v1 and Ed301-Sig-v1 "
            "public keys");
        ED301V1_CHECK(!ed301v1_triple_accepts(libctx,
                HISTORICAL_PUBLIC_KEY, ED301V1_PUB_BYTES,
            NULL, 0,
            HISTORICAL_SIGNATURE, sizeof(HISTORICAL_SIGNATURE)),
            "historical signature under historical public key does not "
            "verify as Ed301-EdDSA-v1");
        ED301V1_CHECK(v1_key != NULL
                && !ed301v1_digest_verify(libctx, v1_key, NULL, 0,
                    HISTORICAL_SIGNATURE, sizeof(HISTORICAL_SIGNATURE)),
            "historical signature under the v1 key does not verify");
        ERR_clear_error();
        EVP_PKEY_free(v1_key);
    }

    /* Mode rejections. */
    {
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, POSITIVE_CASES[0].seed);
        EVP_MD_CTX *mctx;
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char sig[76];
        size_t sig_len = sizeof(sig);
        static const unsigned char probe[] = "mode probe";

        /*
         * S5 -- Ed301-v1 pure-EdDSA contract and OpenSSL
         * providers/implementations/signature/eddsa_sig.c
         * ed25519_digest_signverify_init(): non-NULL digest names are invalid.
         * Fetch each
         * digest first, and use no restrictive property query for the init,
         * so that a missing/default-provider digest cannot make this matrix
         * pass before the Ed301 signature implementation is selected.
         */
        {
            static const char *const digest_names[] = {
                "SHA256", "SHA512", "SHAKE256"
            };
            size_t digest_index;

            for (digest_index = 0;
                    digest_index < sizeof(digest_names)
                        / sizeof(digest_names[0]);
                    digest_index++) {
                const char *digest_name = digest_names[digest_index];
                EVP_MD *digest = EVP_MD_fetch(libctx, digest_name, NULL);

                ED301V1_CHECK(digest != NULL,
                    "%s is available for the external-digest rejection gate",
                    digest_name);

                mctx = EVP_MD_CTX_new();
                ED301V1_CHECK(pkey != NULL && digest != NULL && mctx != NULL
                        && EVP_DigestSignInit_ex(mctx, NULL, digest_name,
                            libctx, NULL, pkey, NULL) != 1,
                    "%s rejected at DigestSignInit", digest_name);
                ERR_clear_error();
                EVP_MD_CTX_free(mctx);

                mctx = EVP_MD_CTX_new();
                ED301V1_CHECK(pkey != NULL && digest != NULL && mctx != NULL
                        && EVP_DigestVerifyInit_ex(mctx, NULL, digest_name,
                            libctx, NULL, pkey, NULL) != 1,
                    "%s rejected at DigestVerifyInit", digest_name);
                ERR_clear_error();
                EVP_MD_CTX_free(mctx);
                EVP_MD_free(digest);
            }
        }

        /*
         * S1 -- OpenSSL providers/implementations/signature/eddsa_sig.c
         * exposes one-shot EdDSA semantics; Update must fail on both sides.
         */
        mctx = EVP_MD_CTX_new();
        ED301V1_CHECK(pkey != NULL && mctx != NULL
                && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                    ED301V1_PROP, pkey, NULL) == 1
                && EVP_DigestSignUpdate(mctx, probe,
                    sizeof(probe) - 1) != 1,
            "streaming DigestSignUpdate rejected");
        ERR_clear_error();
        EVP_MD_CTX_free(mctx);

        mctx = EVP_MD_CTX_new();
        ED301V1_CHECK(pkey != NULL && mctx != NULL
                && EVP_DigestVerifyInit_ex(mctx, NULL, NULL, libctx,
                    ED301V1_PROP, pkey, NULL) == 1
                && EVP_DigestVerifyUpdate(mctx, probe,
                    sizeof(probe) - 1) != 1,
            "streaming DigestVerifyUpdate rejected");
        ERR_clear_error();
        EVP_MD_CTX_free(mctx);

        /* S6 -- Ed448-style native contexts are accepted on every one-shot
         * entry point.  Empty context is exactly the default transcript. */
        {
            OSSL_PARAM params[2];
            OSSL_PARAM empty_params[2];
            static const unsigned char context_value[] = "ctx";

            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                (void *)context_value, sizeof(context_value) - 1);
            params[1] = OSSL_PARAM_construct_end();
            empty_params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                (void *)context_value, 0);
            empty_params[1] = OSSL_PARAM_construct_end();

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, NULL)
                    && EVP_PKEY_CTX_set_params(pctx, params) == 1,
                "context string accepted via set_params after message init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, params),
                "context string accepted at message-sign init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_verify_message_init(libctx, pctx, params),
                "context string accepted at message-verify init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            mctx = EVP_MD_CTX_new();
            ED301V1_CHECK(pkey != NULL && mctx != NULL
                    && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                        ED301V1_PROP, pkey, params) == 1,
                "context string accepted at DigestSignInit params");
            ERR_clear_error();
            EVP_MD_CTX_free(mctx);

            /* Explicit empty context is the default Ed301-EdDSA-v1 domain. */
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, NULL)
                    && EVP_PKEY_CTX_set_params(pctx, empty_params) == 1,
                "empty context string accepted via sign set_params");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, empty_params),
                "empty context string accepted at message-sign init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_verify_message_init(libctx, pctx, NULL)
                    && EVP_PKEY_CTX_set_params(pctx, empty_params) == 1,
                "empty context string accepted via verify set_params");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_verify_message_init(libctx, pctx, empty_params),
                "empty context string accepted at message-verify init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            mctx = EVP_MD_CTX_new();
            ED301V1_CHECK(pkey != NULL && mctx != NULL
                    && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                        ED301V1_PROP, pkey, empty_params) == 1,
                "empty context string accepted at DigestSignInit params");
            ERR_clear_error();
            EVP_MD_CTX_free(mctx);

            mctx = EVP_MD_CTX_new();
            ED301V1_CHECK(pkey != NULL && mctx != NULL
                    && EVP_DigestVerifyInit_ex(mctx, NULL, NULL, libctx,
                        ED301V1_PROP, pkey, empty_params) == 1,
                "empty context string accepted at DigestVerifyInit params");
            ERR_clear_error();
            EVP_MD_CTX_free(mctx);
        }

        /* A rejected parameter update or reinitialization invalidates the
         * previous Rust operation; no stale key may sign or verify. */
        {
            OSSL_PARAM bad_params[2];
            static char digest_value[] = "SHA256";
            unsigned char stale_sig[76] = { 0 };
            unsigned char canary[76];
            size_t stale_sig_len;
            EVP_PKEY_CTX *state_ctx;

            bad_params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_DIGEST, digest_value, 0);
            bad_params[1] = OSSL_PARAM_construct_end();

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            memset(stale_sig, 0xa5, sizeof(stale_sig));
            memcpy(canary, stale_sig, sizeof(canary));
            stale_sig_len = sizeof(stale_sig);
            ED301V1_CHECK(state_ctx != NULL
                    && ed301v1_sign_message_init(libctx, state_ctx, NULL)
                    && EVP_PKEY_CTX_set_params(state_ctx, bad_params) != 1
                    && EVP_PKEY_sign(state_ctx, stale_sig, &stale_sig_len,
                        probe, sizeof(probe) - 1) != 1
                    && memcmp(stale_sig, canary, sizeof(stale_sig)) == 0,
                "rejected digest set_params cannot alter signature output");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            memset(stale_sig, 0xa5, sizeof(stale_sig));
            memcpy(canary, stale_sig, sizeof(canary));
            stale_sig_len = sizeof(stale_sig);
            ED301V1_CHECK(state_ctx != NULL
                    && ed301v1_sign_message_init(libctx, state_ctx, NULL)
                    && !ed301v1_sign_message_init(
                        libctx, state_ctx, bad_params)
                    && EVP_PKEY_sign(state_ctx, stale_sig, &stale_sig_len,
                        probe, sizeof(probe) - 1) != 1
                    && memcmp(stale_sig, canary, sizeof(stale_sig)) == 0,
                "rejected digest reinit cannot alter signature output");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(state_ctx != NULL
                    && ed301v1_verify_message_init(libctx, state_ctx, NULL)
                    && EVP_PKEY_CTX_set_params(state_ctx, bad_params) != 1
                    && EVP_PKEY_verify(state_ctx,
                        POSITIVE_CASES[0].signature, ED301V1_SIG_BYTES,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len) != 1,
                "rejected verify set_params invalidates prior operation");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(state_ctx != NULL
                    && ed301v1_verify_message_init(libctx, state_ctx, NULL)
                    && !ed301v1_verify_message_init(
                        libctx, state_ctx, bad_params)
                    && EVP_PKEY_verify(state_ctx,
                        POSITIVE_CASES[0].signature, ED301V1_SIG_BYTES,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len) != 1,
                "rejected verify reinit invalidates prior operation");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            {
                EVP_MD_CTX *digest_ctx = EVP_MD_CTX_new();

                stale_sig_len = sizeof(stale_sig);
                ED301V1_CHECK(digest_ctx != NULL
                        && EVP_DigestSignInit_ex(digest_ctx, NULL, NULL,
                            libctx, ED301V1_PROP, pkey, NULL) == 1
                        && EVP_DigestSignInit_ex(digest_ctx, NULL,
                            "SHA256", libctx, ED301V1_PROP, pkey, NULL) != 1
                        && EVP_DigestSign(digest_ctx, stale_sig,
                            &stale_sig_len, probe,
                            sizeof(probe) - 1) != 1,
                    "rejected digest sign reinit invalidates prior "
                    "operation");
                ERR_clear_error();
                EVP_MD_CTX_free(digest_ctx);
            }

            {
                EVP_MD_CTX *digest_ctx = EVP_MD_CTX_new();

                ED301V1_CHECK(digest_ctx != NULL
                        && EVP_DigestVerifyInit_ex(digest_ctx, NULL, NULL,
                            libctx, ED301V1_PROP, pkey, NULL) == 1
                        && EVP_DigestVerifyInit_ex(digest_ctx, NULL,
                            "SHA256", libctx, ED301V1_PROP, pkey, NULL) != 1
                        && EVP_DigestVerify(digest_ctx,
                            POSITIVE_CASES[0].signature, ED301V1_SIG_BYTES,
                            POSITIVE_CASES[0].message,
                            POSITIVE_CASES[0].message_len) != 1,
                    "rejected digest verify reinit invalidates prior "
                    "operation");
                ERR_clear_error();
                EVP_MD_CTX_free(digest_ctx);
            }
        }

        /* S5 -- The equivalent high-level set_signature_md path rejects too. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL
                && ed301v1_sign_message_init(libctx, pctx, NULL)
                && EVP_PKEY_CTX_set_signature_md(pctx,
                    EVP_sha256()) != 1,
            "set_signature_md rejected");
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);

        /* S5 -- Provider contract: the explicit digest context parameter is
         * rejected symmetrically rather than ignored. */
        {
            OSSL_PARAM params[2];
            char digest_name[] = "SHA256";

            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_DIGEST, digest_name, 0);
            params[1] = OSSL_PARAM_construct_end();

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, NULL)
                    && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                "digest set_params rejected for signing");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_verify_message_init(libctx, pctx, NULL)
                    && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                "digest set_params rejected for verification");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
        }

        /* A successfully loaded provider publishes stable reason strings. */
        {
            OSSL_PARAM params[2];
            static char digest_value[] = "SHA256";
            unsigned long error;
            const char *reason;
            int rejected;

            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_DIGEST, digest_value, 0);
            params[1] = OSSL_PARAM_construct_end();
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            rejected = pctx != NULL
                && ed301v1_sign_message_init(libctx, pctx, NULL)
                && EVP_PKEY_CTX_set_params(pctx, params) != 1;
            error = ERR_peek_last_error();
            reason = error == 0 ? NULL : ERR_reason_error_string(error);
            ED301V1_CHECK(rejected && ERR_GET_REASON(error) == 7
                    && reason != NULL
                    && strcmp(reason, "unsupported mode") == 0,
                "provider reason 7 resolves to unsupported mode");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
        }

        /* The advertised algorithm-id parameter is exact parameterless DER. */
        {
            unsigned char algorithm_id[
                sizeof(ED301V1_EXPECTED_ALGORITHM_ID)] = { 0 };
            char wrong_type[25] = { 0 };
            OSSL_PARAM octets[2];
            OSSL_PARAM utf8[2];
            int octets_ok;
            int utf8_rejected;

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            octets[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                algorithm_id, sizeof(algorithm_id));
            octets[1] = OSSL_PARAM_construct_end();
            utf8[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                wrong_type, sizeof(wrong_type));
            utf8[1] = OSSL_PARAM_construct_end();
            octets_ok = pctx != NULL
                && ed301v1_sign_message_init(libctx, pctx, NULL)
                && EVP_PKEY_CTX_get_params(pctx, octets) == 1
                && octets[0].return_size == sizeof(algorithm_id)
                && memcmp(algorithm_id, ED301V1_EXPECTED_ALGORITHM_ID,
                    sizeof(algorithm_id)) == 0;
            utf8_rejected = pctx != NULL
                && EVP_PKEY_CTX_get_params(pctx, utf8) != 1;
            ED301V1_CHECK(octets_ok,
                "algorithm-id is exact 15-byte parameterless DER");
            ED301V1_CHECK(utf8_rejected,
                "algorithm-id UTF8 query is rejected");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
        }

        /* Randomized-signing options are rejected. */
        {
            OSSL_PARAM params[2];
            unsigned int nonce_type = 1;

            params[0] = OSSL_PARAM_construct_uint(
                OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type);
            params[1] = OSSL_PARAM_construct_end();
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
            ED301V1_CHECK(pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, NULL)
                    && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                "randomized-signing option rejected");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
        }

        /*
         * S7 -- Ed301-v1/provider pure-only contract.  OpenSSL 4.0
         * providers/implementations/signature/eddsa_sig.c
         * eddsa_set_ctx_params_internal() names the ph/ctx instance classes;
         * neither class is an Ed301-EdDSA-v1 mode.
         */
        {
            static const char *const instance_names[] = {
                "Ed25519ph", "Ed25519ctx", "Ed448ph"
            };
            size_t instance_index;

            for (instance_index = 0;
                    instance_index < sizeof(instance_names)
                        / sizeof(instance_names[0]);
                    instance_index++) {
                OSSL_PARAM params[2];

                params[0] = OSSL_PARAM_construct_utf8_string(
                    OSSL_SIGNATURE_PARAM_INSTANCE,
                    (char *)instance_names[instance_index], 0);
                params[1] = OSSL_PARAM_construct_end();
                pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
                ED301V1_CHECK(pctx != NULL
                        && ed301v1_sign_message_init(libctx, pctx, NULL)
                        && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                    "%s instance rejected for signing",
                    instance_names[instance_index]);
                ERR_clear_error();
                EVP_PKEY_CTX_free(pctx);

                pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
                ED301V1_CHECK(pctx != NULL
                        && ed301v1_verify_message_init(libctx, pctx, NULL)
                        && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                    "%s instance rejected for verification",
                    instance_names[instance_index]);
                ERR_clear_error();
                EVP_PKEY_CTX_free(pctx);
            }
        }

        /* Sign with a public-only key fails. */
        {
            EVP_PKEY *public_only = ed301v1_key_from_public(
                libctx, POSITIVE_CASES[0].public_key, ED301V1_PUB_BYTES);

            pctx = public_only == NULL ? NULL
                : EVP_PKEY_CTX_new_from_pkey(libctx, public_only,
                    ED301V1_PROP);
            sig_len = sizeof(sig);
            ED301V1_CHECK(pctx != NULL
                    && (!ed301v1_sign_message_init(libctx, pctx, NULL)
                        || EVP_PKEY_sign(pctx, sig, &sig_len,
                            probe, sizeof(probe) - 1) != 1),
                "signing with a public-only key fails");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(public_only);
        }

        EVP_PKEY_free(pkey);
    }

    /*
     * OpenSSL 4.0 libssl TLS metadata: exactly one signed-int tls-version
     * of value 0x0304 is accepted as transport metadata on the 4.0 lane;
     * every other name, type, size, value, duplicate or trailing unknown
     * parameter stays rejected, and the 3.5 lane advertises and accepts
     * no TLS parameter at all.
     */
    {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[0];
        EVP_PKEY *pkey = ed301v1_key_from_seed(libctx, tc->seed);
        EVP_PKEY_CTX *pctx = NULL;
        OSSL_PARAM params[3];
        int tls13 = 0x0304;
#if OPENSSL_VERSION_MAJOR == 4
        EVP_MD_CTX *mctx = NULL;
        unsigned char sig[76];
        size_t sig_len;
        int tls12 = 0x0303;
        int other = 0x0505;
        unsigned int tls13_unsigned = 0x0304;
        unsigned char tls13_wide[8] = { 0 };
        short tls13_short = 0x0304;

        ED301V1_CHECK(pkey != NULL, "tls-version: key");

        /* The 4.0 list adds signed-int TLS metadata beside native context. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        {
            const OSSL_PARAM *settable = NULL;
            const OSSL_PARAM *tls_entry = NULL;
            const OSSL_PARAM *context_entry = NULL;

            if (pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, NULL))
                settable = EVP_PKEY_CTX_settable_params(pctx);
            if (settable != NULL)
                tls_entry = OSSL_PARAM_locate_const(settable,
                    OSSL_SIGNATURE_PARAM_TLS_VERSION);
            if (settable != NULL)
                context_entry = OSSL_PARAM_locate_const(settable,
                    OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
            ED301V1_CHECK(tls_entry != NULL
                    && tls_entry->data_type == OSSL_PARAM_INTEGER
                    && context_entry != NULL
                    && context_entry->data_type == OSSL_PARAM_OCTET_STRING
                    && settable[0].key != NULL
                    && settable[1].key != NULL
                    && settable[2].key == NULL,
                "tls-version: 4.0 settable list has context and int metadata");
        }
        EVP_PKEY_CTX_free(pctx);

        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[1] = OSSL_PARAM_construct_end();

        /* Message-sign init accepts TLS 1.3 metadata; KAT stays byte-exact. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        sig_len = sizeof(sig);
        ED301V1_CHECK(pctx != NULL
                && ed301v1_sign_message_init(libctx, pctx, params)
                && EVP_PKEY_sign(pctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == ED301V1_SIG_BYTES
                && memcmp(sig, tc->signature, ED301V1_SIG_BYTES) == 0,
            "tls-version: message-sign init accepts, KAT byte-exact");
        EVP_PKEY_CTX_free(pctx);

        /* The libssl-style call order: set_params after message init. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        {
            size_t ed301v1_i;

            for (ed301v1_i = 0; ed301v1_i < sizeof(sig); ed301v1_i++)
                sig[ed301v1_i] = (unsigned char)
                    (tc->signature[ed301v1_i % ED301V1_SIG_BYTES] ^ 0xff);
        }
        sig_len = sizeof(sig);
        ED301V1_CHECK(pctx != NULL
                && ed301v1_sign_message_init(libctx, pctx, NULL)
                && EVP_PKEY_CTX_set_params(pctx, params) == 1
                && EVP_PKEY_sign(pctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == ED301V1_SIG_BYTES
                && memcmp(sig, tc->signature, ED301V1_SIG_BYTES) == 0,
            "tls-version: set_params after message init, KAT byte-exact");
        EVP_PKEY_CTX_free(pctx);

        /* Message-verify init accepts TLS 1.3 metadata. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        ED301V1_CHECK(pctx != NULL
                && ed301v1_verify_message_init(libctx, pctx, params)
                && EVP_PKEY_verify(pctx, tc->signature, ED301V1_SIG_BYTES,
                    tc->message, tc->message_len) == 1,
            "tls-version: message-verify init accepts, vector verifies");
        EVP_PKEY_CTX_free(pctx);

        /* One-shot DigestSign with init params; byte-exact. */
        mctx = EVP_MD_CTX_new();
        sig_len = sizeof(sig);
        ED301V1_CHECK(mctx != NULL
                && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                    ED301V1_PROP, pkey, params) == 1
                && EVP_DigestSign(mctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == ED301V1_SIG_BYTES
                && memcmp(sig, tc->signature, ED301V1_SIG_BYTES) == 0,
            "tls-version: one-shot DigestSign accepts, KAT byte-exact");
        EVP_MD_CTX_free(mctx);

        /* TLS 1.2 is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls12);
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: TLS 1.2 rejected");

        /* Any other value is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &other);
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: value 0x0505 rejected");

        /* The unsigned representation is rejected. */
        params[0] = OSSL_PARAM_construct_uint(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13_unsigned);
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: unsigned representation rejected");

        /* A 64-bit-sized signed representation is rejected. */
        memcpy(tls13_wide, &tls13, sizeof(tls13));
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[0].data = tls13_wide;
        params[0].data_size = sizeof(tls13_wide);
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: 64-bit-sized representation rejected");

        /* Any other size of the signed form is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[0].data = &tls13_short;
        params[0].data_size = sizeof(tls13_short);
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: short-sized representation rejected");

        /* A duplicated valid tls-version is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[1] = params[0];
        params[2] = OSSL_PARAM_construct_end();
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: duplicate rejected");

        /* An unknown parameter after a valid tls-version is rejected. */
        params[1] = OSSL_PARAM_construct_int("unknown-param", &other);
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: trailing unknown parameter rejected");
#else
        ED301V1_CHECK(pkey != NULL, "tls-version: key");

        /* The 3.5 lane advertises native context but no TLS metadata. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ED301V1_PROP);
        {
            const OSSL_PARAM *settable = NULL;

            if (pctx != NULL
                    && ed301v1_sign_message_init(libctx, pctx, NULL))
                settable = EVP_PKEY_CTX_settable_params(pctx);
            ED301V1_CHECK(settable != NULL
                    && settable[0].key != NULL
                    && strcmp(settable[0].key,
                        OSSL_SIGNATURE_PARAM_CONTEXT_STRING) == 0
                    && settable[0].data_type == OSSL_PARAM_OCTET_STRING
                    && settable[1].key == NULL,
                "tls-version: 3.5 settable list has context only");
        }
        EVP_PKEY_CTX_free(pctx);

        /* A fabricated tls-version stays unsupported on 3.5. */
        params[0] = OSSL_PARAM_construct_int("tls-version", &tls13);
        params[1] = OSSL_PARAM_construct_end();
        ED301V1_CHECK(ed301v1_message_sign_init_rejects(libctx, pkey, params),
            "tls-version: fabricated tls-version rejected on 3.5");
#endif
        EVP_PKEY_free(pkey);
    }

    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return ed301v1_summary("provider_signature");
}
