/*
 * Acceptance section 3 (signature contract): four positive draft-00
 * vectors byte-for-byte, 14 point / 6 scalar / 22 verification edge cases,
 * the 77 deterministic negative mutations from the reference lane,
 * determinism, exact size query, undersized buffers without partial
 * signatures, S + L malleability, mode rejections (external digest,
 * prehash, streaming, randomized signing, context) and the demonstration
 * that historical Ed301-Sig-v1 material does not verify.
 */

#include <stdint.h>

#include "harness_common.h"
#include "vectors.h"

static const unsigned char D00_EXPECTED_ALGORITHM_ID[24] = {
    0x30, 0x16, 0x06, 0x14, 0x69, 0x82, 0xa6, 0x8b,
    0xcb, 0x8d, 0xb3, 0x93, 0xe2, 0x9f, 0x8b, 0x8a,
    0x9e, 0xf1, 0xc4, 0xf2, 0xe5, 0xd7, 0xe5, 0x30
};

/*
 * FBL-08 mutation control: with ED301D00_POLICY_MUTATE=1 every expected
 * parser/policy result of the point, scalar, verification and commitment
 * lanes is inverted and this harness MUST fail; the matrix runner asserts
 * that failure.
 */
static int d00_policy_invert(void)
{
    const char *value = getenv("ED301D00_POLICY_MUTATE");

    return value != NULL && strcmp(value, "1") == 0;
}

/*
 * A parameter array that must be refused at sign init; used for every
 * malformed or non-advertised tls-version shape on both lanes.
 */
static int d00_sign_init_rejects(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
    const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
    int rejected = pctx != NULL && EVP_PKEY_sign_init_ex(pctx, params) != 1;

    ERR_clear_error();
    EVP_PKEY_CTX_free(pctx);
    return rejected;
}

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = d00_load(libctx, &deflt);
    size_t index;
    const int invert = d00_policy_invert();

    D00_CHECK(draft != NULL, "provider load");

    /* Positive vectors through EVP_PKEY_sign and one-shot DigestSign. */
    for (index = 0; index < 4; index++) {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[index];
        EVP_PKEY *pkey = d00_key_from_seed(libctx, tc->seed);
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char sig[76] = { 0 };
        unsigned char sig_again[76] = { 0 };
        size_t sig_len = 0;

        D00_CHECK(pkey != NULL, "%s: key", tc->id);
        if (pkey == NULL)
            continue;

        /* Basic EVP path with exact size query. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        D00_CHECK(pctx != NULL && EVP_PKEY_sign_init(pctx) == 1,
            "%s: sign init", tc->id);
        sig_len = 0;
        D00_CHECK(pctx != NULL
                && EVP_PKEY_sign(pctx, NULL, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == D00_SIG_BYTES,
            "%s: size query returns exactly 76", tc->id);

        /* A 75-byte output buffer fails without a partial signature. */
        {
            unsigned char small[75];
            unsigned char canary[75];

            memset(small, 0x5a, sizeof(small));
            memset(canary, 0x5a, sizeof(canary));
            sig_len = sizeof(small);
            D00_CHECK(pctx != NULL
                    && EVP_PKEY_sign(pctx, small, &sig_len, tc->message,
                        tc->message_len) != 1
                    && memcmp(small, canary, sizeof(small)) == 0,
                "%s: 75-byte buffer rejected without partial write",
                tc->id);
            ERR_clear_error();
        }

        sig_len = sizeof(sig);
        D00_CHECK(pctx != NULL
                && EVP_PKEY_sign(pctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == D00_SIG_BYTES
                && memcmp(sig, tc->signature, D00_SIG_BYTES) == 0,
            "%s: EVP_PKEY_sign matches the vector byte-for-byte", tc->id);

        /* Determinism. */
        sig_len = sizeof(sig_again);
        D00_CHECK(pctx != NULL
                && EVP_PKEY_sign(pctx, sig_again, &sig_len, tc->message,
                    tc->message_len) == 1
                && memcmp(sig, sig_again, D00_SIG_BYTES) == 0,
            "%s: deterministic", tc->id);
        EVP_PKEY_CTX_free(pctx);

        /* One-shot DigestSign agrees exactly. */
        memset(sig_again, 0, sizeof(sig_again));
        D00_CHECK(d00_digest_sign(libctx, pkey, tc->message,
                tc->message_len, sig_again)
                && memcmp(sig_again, tc->signature, D00_SIG_BYTES) == 0,
            "%s: one-shot DigestSign matches the vector", tc->id);

        /* EVP_PKEY_verify and DigestVerify accept. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        D00_CHECK(pctx != NULL && EVP_PKEY_verify_init(pctx) == 1
                && EVP_PKEY_verify(pctx, tc->signature, D00_SIG_BYTES,
                    tc->message, tc->message_len) == 1,
            "%s: EVP_PKEY_verify accepts", tc->id);
        EVP_PKEY_CTX_free(pctx);
        D00_CHECK(d00_digest_verify(libctx, pkey, tc->message,
                tc->message_len, tc->signature, D00_SIG_BYTES),
            "%s: DigestVerify accepts", tc->id);

        EVP_PKEY_free(pkey);
    }

    /* R1A: reject an opaque message length above isize::MAX before Rust
     * forms a slice, using a one-byte pointer as the bounded storage. */
    {
        const POSITIVE_CASE *tc = &POSITIVE_CASES[0];
        EVP_PKEY *pkey = d00_key_from_seed(libctx, tc->seed);
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char output[D00_SIG_BYTES];
        unsigned char canary[D00_SIG_BYTES];
        unsigned char one_byte = 0x5a;
        const size_t oversized = (size_t)INTPTR_MAX + 1;
        size_t sig_len = sizeof(output);
        int sign_failed = 0;
        int verify_failed = 0;

        D00_CHECK(pkey != NULL, "oversized-message: key");
        memset(output, 0xa5, sizeof(output));
        memcpy(canary, output, sizeof(canary));

        pctx = pkey == NULL ? NULL
            : EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        if (pctx != NULL && EVP_PKEY_sign_init(pctx) == 1)
            sign_failed = EVP_PKEY_sign(pctx, output, &sig_len,
                &one_byte, oversized) != 1
                && memcmp(output, canary, sizeof(output)) == 0;
        D00_CHECK(sign_failed,
            "oversized-message: EVP_PKEY_sign fails closed above isize::MAX");
        EVP_PKEY_CTX_free(pctx);

        pctx = pkey == NULL ? NULL
            : EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        if (pctx != NULL && EVP_PKEY_verify_init(pctx) == 1)
            verify_failed = EVP_PKEY_verify(pctx, tc->signature,
                D00_SIG_BYTES, &one_byte, oversized) != 1;
        D00_CHECK(verify_failed,
            "oversized-message: EVP_PKEY_verify fails closed above isize::MAX");
        EVP_PKEY_CTX_free(pctx);

        memset(output, 0, sizeof(output));
        D00_CHECK(pkey != NULL
                && d00_digest_sign(libctx, pkey, tc->message,
                    tc->message_len, output)
                && memcmp(output, tc->signature, D00_SIG_BYTES) == 0
                && d00_digest_verify(libctx, pkey, tc->message,
                    tc->message_len, output, D00_SIG_BYTES),
            "oversized-message: normal sign and verify recover");
        EVP_PKEY_free(pkey);
    }

    /* 14 point cases: provider public-key policy surface. */
    for (index = 0; index < 14; index++) {
        const POINT_CASE *tc = &POINT_CASES[index];
        EVP_PKEY *pkey = d00_key_from_public(
            libctx, tc->encoding, tc->encoding_len);

        D00_CHECK((pkey != NULL)
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
            size_t forged_len = tc->encoding_len + D00_SEED_BYTES;

            memcpy(forged, tc->encoding, tc->encoding_len);
            memcpy(forged + tc->encoding_len,
                POSITIVE_CASES[0].signature + 38, 38);
            D00_CHECK(!d00_triple_accepts(libctx,
                    POSITIVE_CASES[0].public_key, D00_PUB_BYTES,
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
        D00_CHECK(!d00_triple_accepts(libctx,
                POSITIVE_CASES[0].public_key, D00_PUB_BYTES,
                POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
                forged, forged_len),
            "scalar %s (syntax %s): S substitution fails closed",
            tc->id, tc->expect_syntax_accept ? "accept" : "reject");
    }

    /* 22 verification edge cases. */
    for (index = 0; index < 22; index++) {
        const VERIFICATION_CASE *tc = &VERIFICATION_CASES[index];
        int accepted = d00_triple_accepts(libctx,
            tc->public_key, tc->public_key_len,
            tc->message, tc->message_len,
            tc->signature, tc->signature_len);

        D00_CHECK(accepted == (tc->expect_accept ^ invert),
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
        int accepted = d00_triple_accepts(libctx,
            tc->public_key, D00_PUB_BYTES,
            tc->message, tc->message_len,
            tc->signature, tc->signature_len);

        D00_CHECK(accepted == (tc->expect_accept ^ invert),
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
                accepted = d00_triple_accepts(libctx,
                    tc->public_key, tc->public_key_len,
                    NULL, tc->message_len,
                    tc->signature, tc->signature_len);
            } else if (tc->kind == NEGATIVE_WRONG_PARAM_TYPE) {
                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
                    libctx, D00_ALG, D00_PROP);
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
                accepted = d00_triple_accepts(libctx,
                    tc->public_key, tc->public_key_len,
                    tc->message, tc->message_len,
                    tc->signature, tc->signature_len);
            }
            if (!accepted)
                rejected_count++;
            D00_CHECK(!accepted, "negative %zu (%s) must be rejected",
                index, tc->label);
        }
        D00_CHECK(rejected_count == 77,
            "all 77 reference-lane mutations rejected (%d)",
            rejected_count);
    }

    /* S + L malleability. */
    D00_CHECK(!d00_triple_accepts(libctx,
            POSITIVE_CASES[0].public_key, D00_PUB_BYTES,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
            S_PLUS_L_SIGNATURE, sizeof(S_PLUS_L_SIGNATURE)),
        "S + L malleability is rejected");

    /* Historical Ed301-Sig-v1 material does not verify. */
    {
        EVP_PKEY *draft_key = d00_key_from_seed(
            libctx, POSITIVE_CASES[0].seed);

        D00_CHECK(memcmp(HISTORICAL_PUBLIC_KEY,
                POSITIVE_CASES[0].public_key, D00_PUB_BYTES) != 0,
            "same seed yields different draft-00 and Ed301-Sig-v1 "
            "public keys");
        D00_CHECK(!d00_triple_accepts(libctx,
                HISTORICAL_PUBLIC_KEY, D00_PUB_BYTES,
                NULL, 0,
                HISTORICAL_SIGNATURE, sizeof(HISTORICAL_SIGNATURE)),
            "historical signature under historical public key does not "
            "verify as draft-00");
        D00_CHECK(draft_key != NULL
                && !d00_digest_verify(libctx, draft_key, NULL, 0,
                    HISTORICAL_SIGNATURE, sizeof(HISTORICAL_SIGNATURE)),
            "historical signature under the draft-00 key does not verify");
        ERR_clear_error();
        EVP_PKEY_free(draft_key);
    }

    /* Mode rejections. */
    {
        EVP_PKEY *pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
        EVP_MD_CTX *mctx;
        EVP_PKEY_CTX *pctx = NULL;
        unsigned char sig[76];
        size_t sig_len = sizeof(sig);
        static const unsigned char probe[] = "mode probe";

        /* External digest names are rejected for sign and verify. */
        mctx = EVP_MD_CTX_new();
        D00_CHECK(pkey != NULL && mctx != NULL
                && EVP_DigestSignInit_ex(mctx, NULL, "SHA2-256", libctx,
                    D00_PROP, pkey, NULL) != 1,
            "external digest rejected at DigestSignInit");
        ERR_clear_error();
        EVP_MD_CTX_free(mctx);

        mctx = EVP_MD_CTX_new();
        D00_CHECK(pkey != NULL && mctx != NULL
                && EVP_DigestVerifyInit_ex(mctx, NULL, "SHAKE-256", libctx,
                    D00_PROP, pkey, NULL) != 1,
            "external XOF digest rejected at DigestVerifyInit");
        ERR_clear_error();
        EVP_MD_CTX_free(mctx);

        /* Streaming update/final is rejected. */
        mctx = EVP_MD_CTX_new();
        D00_CHECK(pkey != NULL && mctx != NULL
                && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                    D00_PROP, pkey, NULL) == 1
                && EVP_DigestSignUpdate(mctx, probe,
                    sizeof(probe) - 1) != 1,
            "streaming DigestSignUpdate rejected");
        ERR_clear_error();
        EVP_MD_CTX_free(mctx);

        mctx = EVP_MD_CTX_new();
        D00_CHECK(pkey != NULL && mctx != NULL
                && EVP_DigestVerifyInit_ex(mctx, NULL, NULL, libctx,
                    D00_PROP, pkey, NULL) == 1
                && EVP_DigestVerifyUpdate(mctx, probe,
                    sizeof(probe) - 1) != 1,
            "streaming DigestVerifyUpdate rejected");
        ERR_clear_error();
        EVP_MD_CTX_free(mctx);

        /* Context strings are rejected, not ignored. */
        {
            OSSL_PARAM params[2];
            static const unsigned char context_value[] = "ctx";

            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                (void *)context_value, sizeof(context_value) - 1);
            params[1] = OSSL_PARAM_construct_end();

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            D00_CHECK(pctx != NULL && EVP_PKEY_sign_init(pctx) == 1
                    && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                "context string rejected via set_params after sign init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            D00_CHECK(pctx != NULL
                    && EVP_PKEY_sign_init_ex(pctx, params) != 1,
                "context string rejected at sign init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            D00_CHECK(pctx != NULL
                    && EVP_PKEY_verify_init_ex(pctx, params) != 1,
                "context string rejected at verify init");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);

            mctx = EVP_MD_CTX_new();
            D00_CHECK(pkey != NULL && mctx != NULL
                    && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                        D00_PROP, pkey, params) != 1,
                "context string rejected at DigestSignInit params");
            ERR_clear_error();
            EVP_MD_CTX_free(mctx);
        }

        /* A rejected parameter update or reinitialization invalidates the
         * previous Rust operation; no stale key may sign or verify. */
        {
            OSSL_PARAM bad_params[2];
            static const unsigned char context_value[] = "ctx";
            unsigned char stale_sig[76] = { 0 };
            size_t stale_sig_len;
            EVP_PKEY_CTX *state_ctx;

            bad_params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                (void *)context_value, sizeof(context_value) - 1);
            bad_params[1] = OSSL_PARAM_construct_end();

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            stale_sig_len = sizeof(stale_sig);
            D00_CHECK(state_ctx != NULL
                    && EVP_PKEY_sign_init(state_ctx) == 1
                    && EVP_PKEY_CTX_set_params(state_ctx, bad_params) != 1
                    && EVP_PKEY_sign(state_ctx, stale_sig, &stale_sig_len,
                        probe, sizeof(probe) - 1) != 1,
                "rejected sign set_params invalidates prior operation");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            stale_sig_len = sizeof(stale_sig);
            D00_CHECK(state_ctx != NULL
                    && EVP_PKEY_sign_init(state_ctx) == 1
                    && EVP_PKEY_sign_init_ex(state_ctx, bad_params) != 1
                    && EVP_PKEY_sign(state_ctx, stale_sig, &stale_sig_len,
                        probe, sizeof(probe) - 1) != 1,
                "rejected sign reinit invalidates prior operation");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            D00_CHECK(state_ctx != NULL
                    && EVP_PKEY_verify_init(state_ctx) == 1
                    && EVP_PKEY_CTX_set_params(state_ctx, bad_params) != 1
                    && EVP_PKEY_verify(state_ctx,
                        POSITIVE_CASES[0].signature, D00_SIG_BYTES,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len) != 1,
                "rejected verify set_params invalidates prior operation");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            state_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            D00_CHECK(state_ctx != NULL
                    && EVP_PKEY_verify_init(state_ctx) == 1
                    && EVP_PKEY_verify_init_ex(state_ctx, bad_params) != 1
                    && EVP_PKEY_verify(state_ctx,
                        POSITIVE_CASES[0].signature, D00_SIG_BYTES,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len) != 1,
                "rejected verify reinit invalidates prior operation");
            ERR_clear_error();
            EVP_PKEY_CTX_free(state_ctx);

            {
                EVP_MD_CTX *digest_ctx = EVP_MD_CTX_new();

                stale_sig_len = sizeof(stale_sig);
                D00_CHECK(digest_ctx != NULL
                        && EVP_DigestSignInit_ex(digest_ctx, NULL, NULL,
                            libctx, D00_PROP, pkey, NULL) == 1
                        && EVP_DigestSignInit_ex(digest_ctx, NULL,
                            "SHA256", libctx, D00_PROP, pkey, NULL) != 1
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

                D00_CHECK(digest_ctx != NULL
                        && EVP_DigestVerifyInit_ex(digest_ctx, NULL, NULL,
                            libctx, D00_PROP, pkey, NULL) == 1
                        && EVP_DigestVerifyInit_ex(digest_ctx, NULL,
                            "SHA256", libctx, D00_PROP, pkey, NULL) != 1
                        && EVP_DigestVerify(digest_ctx,
                            POSITIVE_CASES[0].signature, D00_SIG_BYTES,
                            POSITIVE_CASES[0].message,
                            POSITIVE_CASES[0].message_len) != 1,
                    "rejected digest verify reinit invalidates prior "
                    "operation");
                ERR_clear_error();
                EVP_MD_CTX_free(digest_ctx);
            }
        }

        /* External digest via set_signature_md is rejected. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        D00_CHECK(pctx != NULL && EVP_PKEY_sign_init(pctx) == 1
                && EVP_PKEY_CTX_set_signature_md(pctx,
                    EVP_sha256()) != 1,
            "set_signature_md rejected");
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);

        /* A successfully loaded provider publishes stable reason strings. */
        {
            OSSL_PARAM params[2];
            static const unsigned char context_value[] = "reason-check";
            unsigned long error;
            const char *reason;
            int rejected;

            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                (void *)context_value, sizeof(context_value) - 1);
            params[1] = OSSL_PARAM_construct_end();
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            rejected = pctx != NULL && EVP_PKEY_sign_init(pctx) == 1
                && EVP_PKEY_CTX_set_params(pctx, params) != 1;
            error = ERR_peek_last_error();
            reason = error == 0 ? NULL : ERR_reason_error_string(error);
            D00_CHECK(rejected && ERR_GET_REASON(error) == 7
                    && reason != NULL
                    && strcmp(reason, "unsupported mode") == 0,
                "provider reason 7 resolves to unsupported mode");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
        }

        /* The advertised algorithm-id parameter is exactly OCTET/24-byte DER. */
        {
            unsigned char algorithm_id[24] = { 0 };
            char wrong_type[25] = { 0 };
            OSSL_PARAM octets[2];
            OSSL_PARAM utf8[2];
            int octets_ok;
            int utf8_rejected;

            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            octets[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                algorithm_id, sizeof(algorithm_id));
            octets[1] = OSSL_PARAM_construct_end();
            utf8[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                wrong_type, sizeof(wrong_type));
            utf8[1] = OSSL_PARAM_construct_end();
            octets_ok = pctx != NULL && EVP_PKEY_sign_init(pctx) == 1
                && EVP_PKEY_CTX_get_params(pctx, octets) == 1
                && octets[0].return_size == sizeof(algorithm_id)
                && memcmp(algorithm_id, D00_EXPECTED_ALGORITHM_ID,
                    sizeof(algorithm_id)) == 0;
            utf8_rejected = pctx != NULL
                && EVP_PKEY_CTX_get_params(pctx, utf8) != 1;
            D00_CHECK(octets_ok,
                "algorithm-id is exact 24-byte parameterless DER");
            D00_CHECK(utf8_rejected,
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
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            D00_CHECK(pctx != NULL && EVP_PKEY_sign_init(pctx) == 1
                    && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                "randomized-signing option rejected");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
        }

        /* Prehash instance parameter is rejected. */
        {
            OSSL_PARAM params[2];

            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_INSTANCE, "prehash", 0);
            params[1] = OSSL_PARAM_construct_end();
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
            D00_CHECK(pctx != NULL && EVP_PKEY_sign_init(pctx) == 1
                    && EVP_PKEY_CTX_set_params(pctx, params) != 1,
                "prehash instance rejected");
            ERR_clear_error();
            EVP_PKEY_CTX_free(pctx);
        }

        /* Sign with a public-only key fails. */
        {
            EVP_PKEY *public_only = d00_key_from_public(
                libctx, POSITIVE_CASES[0].public_key, D00_PUB_BYTES);

            pctx = public_only == NULL ? NULL
                : EVP_PKEY_CTX_new_from_pkey(libctx, public_only,
                    D00_PROP);
            sig_len = sizeof(sig);
            D00_CHECK(pctx != NULL
                    && (EVP_PKEY_sign_init(pctx) != 1
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
        EVP_PKEY *pkey = d00_key_from_seed(libctx, tc->seed);
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

        D00_CHECK(pkey != NULL, "tls-version: key");

        /* The 4.0 settable list advertises exactly the signed-int form. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        {
            const OSSL_PARAM *settable = NULL;
            const OSSL_PARAM *entry = NULL;

            if (pctx != NULL && EVP_PKEY_sign_init(pctx) == 1)
                settable = EVP_PKEY_CTX_settable_params(pctx);
            if (settable != NULL)
                entry = OSSL_PARAM_locate_const(settable,
                    OSSL_SIGNATURE_PARAM_TLS_VERSION);
            D00_CHECK(entry != NULL
                    && entry->data_type == OSSL_PARAM_INTEGER
                    && settable[0].key != NULL
                    && settable[1].key == NULL,
                "tls-version: 4.0 settable list is exactly the int form");
        }
        EVP_PKEY_CTX_free(pctx);

        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[1] = OSSL_PARAM_construct_end();

        /* sign-init accepts TLS 1.3 metadata; the KAT stays byte-exact. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        sig_len = sizeof(sig);
        D00_CHECK(pctx != NULL
                && EVP_PKEY_sign_init_ex(pctx, params) == 1
                && EVP_PKEY_sign(pctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == D00_SIG_BYTES
                && memcmp(sig, tc->signature, D00_SIG_BYTES) == 0,
            "tls-version: sign init accepts, KAT byte-exact");
        EVP_PKEY_CTX_free(pctx);

        /* The libssl call order: set_params after plain sign init. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        {
            size_t d00_i;

            for (d00_i = 0; d00_i < sizeof(sig); d00_i++)
                sig[d00_i] = (unsigned char)
                    (tc->signature[d00_i % D00_SIG_BYTES] ^ 0xff);
        }
        sig_len = sizeof(sig);
        D00_CHECK(pctx != NULL && EVP_PKEY_sign_init(pctx) == 1
                && EVP_PKEY_CTX_set_params(pctx, params) == 1
                && EVP_PKEY_sign(pctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == D00_SIG_BYTES
                && memcmp(sig, tc->signature, D00_SIG_BYTES) == 0,
            "tls-version: set_params after sign init, KAT byte-exact");
        EVP_PKEY_CTX_free(pctx);

        /* verify-init accepts TLS 1.3 metadata; the vector verifies. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        D00_CHECK(pctx != NULL
                && EVP_PKEY_verify_init_ex(pctx, params) == 1
                && EVP_PKEY_verify(pctx, tc->signature, D00_SIG_BYTES,
                    tc->message, tc->message_len) == 1,
            "tls-version: verify init accepts, vector verifies");
        EVP_PKEY_CTX_free(pctx);

        /* One-shot DigestSign with init params; byte-exact. */
        mctx = EVP_MD_CTX_new();
        sig_len = sizeof(sig);
        D00_CHECK(mctx != NULL
                && EVP_DigestSignInit_ex(mctx, NULL, NULL, libctx,
                    D00_PROP, pkey, params) == 1
                && EVP_DigestSign(mctx, sig, &sig_len, tc->message,
                    tc->message_len) == 1
                && sig_len == D00_SIG_BYTES
                && memcmp(sig, tc->signature, D00_SIG_BYTES) == 0,
            "tls-version: one-shot DigestSign accepts, KAT byte-exact");
        EVP_MD_CTX_free(mctx);

        /* TLS 1.2 is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls12);
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: TLS 1.2 rejected");

        /* Any other value is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &other);
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: value 0x0505 rejected");

        /* The unsigned representation is rejected. */
        params[0] = OSSL_PARAM_construct_uint(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13_unsigned);
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: unsigned representation rejected");

        /* A 64-bit-sized signed representation is rejected. */
        memcpy(tls13_wide, &tls13, sizeof(tls13));
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[0].data = tls13_wide;
        params[0].data_size = sizeof(tls13_wide);
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: 64-bit-sized representation rejected");

        /* Any other size of the signed form is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[0].data = &tls13_short;
        params[0].data_size = sizeof(tls13_short);
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: short-sized representation rejected");

        /* A duplicated valid tls-version is rejected. */
        params[0] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_TLS_VERSION, &tls13);
        params[1] = params[0];
        params[2] = OSSL_PARAM_construct_end();
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: duplicate rejected");

        /* An unknown parameter after a valid tls-version is rejected. */
        params[1] = OSSL_PARAM_construct_int("unknown-param", &other);
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: trailing unknown parameter rejected");
#else
        D00_CHECK(pkey != NULL, "tls-version: key");

        /* The 3.5 lane advertises no settable TLS parameter at all. */
        pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
        {
            const OSSL_PARAM *settable = NULL;

            if (pctx != NULL && EVP_PKEY_sign_init(pctx) == 1)
                settable = EVP_PKEY_CTX_settable_params(pctx);
            D00_CHECK(settable != NULL && settable[0].key == NULL,
                "tls-version: 3.5 settable list stays empty");
        }
        EVP_PKEY_CTX_free(pctx);

        /* A fabricated tls-version stays unsupported on 3.5. */
        params[0] = OSSL_PARAM_construct_int("tls-version", &tls13);
        params[1] = OSSL_PARAM_construct_end();
        D00_CHECK(d00_sign_init_rejects(libctx, pkey, params),
            "tls-version: fabricated tls-version rejected on 3.5");
#endif
        EVP_PKEY_free(pkey);
    }

    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return d00_summary("provider_signature");
}
