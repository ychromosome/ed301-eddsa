/*
 * Acceptance section 2 (key management): seed, public-key and keypair
 * import/export, key generation, has, validate, match, duplicate, free,
 * exact 38-byte lengths, byte-exact seed/public consistency, and rejection
 * of missing selections, malformed parameters and undersized outputs
 * without partial writes.
 */

#include "harness_common.h"
#include "vectors.h"

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = d00_load(libctx, &deflt);
    const POSITIVE_CASE *base = &POSITIVE_CASES[0];

    D00_CHECK(draft != NULL, "provider load");

    /* Seed import derives the exact vector public key. */
    {
        EVP_PKEY *pkey = d00_key_from_seed(libctx, base->seed);
        unsigned char public_out[38] = { 0 };
        unsigned char seed_out[38] = { 0 };
        size_t out_len = 0;

        D00_CHECK(pkey != NULL, "seed import");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PUB_KEY, public_out,
                    sizeof(public_out), &out_len) == 1
                && out_len == D00_PUB_BYTES
                && memcmp(public_out, base->public_key,
                    D00_PUB_BYTES) == 0,
            "derived public key matches the draft-00 vector");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) == 1
                && out_len == D00_SEED_BYTES
                && memcmp(seed_out, base->seed, D00_SEED_BYTES) == 0,
            "seed export is byte-exact");

        /* Undersized output: no partial write. */
        {
            unsigned char small[37];
            unsigned char canary[37];

            memset(small, 0xa5, sizeof(small));
            memset(canary, 0xa5, sizeof(canary));
            out_len = 0;
            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_octet_string_param(pkey,
                        OSSL_PKEY_PARAM_PUB_KEY, small,
                        sizeof(small), &out_len) != 1
                    && memcmp(small, canary, sizeof(small)) == 0,
                "undersized public output fails without partial write");
            ERR_clear_error();
        }

        /* Raw getters agree. */
        {
            unsigned char raw[38];
            size_t raw_len = sizeof(raw);

            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) == 1
                    && raw_len == D00_PUB_BYTES
                    && memcmp(raw, base->public_key, D00_PUB_BYTES) == 0,
                "raw public getter");
            raw_len = sizeof(raw);
            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_raw_private_key(pkey, raw, &raw_len) == 1
                    && raw_len == D00_SEED_BYTES
                    && memcmp(raw, base->seed, D00_SEED_BYTES) == 0,
                "raw private getter");
        }

        /* Bits / security bits / max size. */
        {
            int bits = 0;
            int security_bits = 0;
            int max_size = 0;

            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_BITS,
                        &bits) == 1
                    && bits == 301
                    && EVP_PKEY_get_int_param(pkey,
                        OSSL_PKEY_PARAM_SECURITY_BITS,
                        &security_bits) == 1
                    && security_bits == 149
                    && EVP_PKEY_get_int_param(pkey,
                        OSSL_PKEY_PARAM_MAX_SIZE, &max_size) == 1
                    && max_size == 76,
                "bits=%d security=%d max=%d", bits, security_bits,
                max_size);
        }

        /* Validation through the public check API. */
        {
            EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new_from_pkey(
                libctx, pkey, D00_PROP);

            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_check(check_ctx) == 1,
                "full key validation");
            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_public_check(check_ctx) == 1,
                "public validation");
            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_private_check(check_ctx) == 1,
                "private validation");
            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_pairwise_check(check_ctx) == 1,
                "pairwise validation");
            EVP_PKEY_CTX_free(check_ctx);
        }

        /* Duplicate and match. */
        {
            EVP_PKEY *copy = EVP_PKEY_dup(pkey);
            EVP_PKEY *public_only = d00_key_from_public(
                libctx, base->public_key, D00_PUB_BYTES);

            D00_CHECK(copy != NULL && EVP_PKEY_eq(pkey, copy) == 1,
                "duplicate matches");
            D00_CHECK(public_only != NULL
                    && EVP_PKEY_eq(pkey, public_only) == 1,
                "public-only key matches the pair on the public component");
            EVP_PKEY_free(copy);
            EVP_PKEY_free(public_only);
        }

        EVP_PKEY_free(pkey);
    }

    /* Public-only import and validation. */
    {
        EVP_PKEY *pkey = d00_key_from_public(
            libctx, base->public_key, D00_PUB_BYTES);
        unsigned char seed_out[38];
        size_t out_len = 0;

        D00_CHECK(pkey != NULL, "public-only import");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) != 1,
            "public-only key has no private component");
        ERR_clear_error();
        EVP_PKEY_free(pkey);
    }

    /* Keypair import with matching public key. */
    {
        EVP_PKEY *pkey = d00_key_from_params(
            libctx, EVP_PKEY_KEYPAIR,
            base->seed, D00_SEED_BYTES,
            base->public_key, D00_PUB_BYTES);

        D00_CHECK(pkey != NULL, "matching keypair import");
        EVP_PKEY_free(pkey);
    }

    /* Rejections. */
    {
        unsigned char wrong_public[38];
        unsigned char short_seed[37];
        unsigned char long_seed[39];
        EVP_PKEY *bad;

        memcpy(wrong_public, base->public_key, sizeof(wrong_public));
        wrong_public[0] ^= 1;
        memcpy(short_seed, base->seed, sizeof(short_seed));
        memcpy(long_seed, base->seed, D00_SEED_BYTES);
        long_seed[38] = 0;

        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            base->seed, D00_SEED_BYTES, wrong_public, D00_PUB_BYTES);
        D00_CHECK(bad == NULL, "mismatched keypair import is rejected");
        ERR_clear_error();

        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            short_seed, sizeof(short_seed), NULL, 0);
        D00_CHECK(bad == NULL, "37-byte seed is rejected");
        ERR_clear_error();

        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            long_seed, sizeof(long_seed), NULL, 0);
        D00_CHECK(bad == NULL, "39-byte seed is rejected");
        ERR_clear_error();

        bad = d00_key_from_public(libctx, base->public_key, 37);
        D00_CHECK(bad == NULL, "37-byte public key is rejected");
        ERR_clear_error();

        bad = d00_key_from_public(libctx, base->public_key, 39);
        D00_CHECK(bad == NULL,
            "39-byte public key length is rejected");
        ERR_clear_error();

        /*
         * OpenSSL's raw-public constructor imports a public-only value under
         * KEYPAIR selection.  Match the built-in Ed25519/Ed448 KEYMGMT
         * contract without inventing a private component.
         */
        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            NULL, 0, base->public_key, D00_PUB_BYTES);
        D00_CHECK(bad != NULL,
            "keypair selection accepts a public-only raw key");
        if (bad != NULL) {
            unsigned char seed_out[38];
            size_t out_len = 0;

            D00_CHECK(EVP_PKEY_get_octet_string_param(bad,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) != 1,
                "public-only raw key does not acquire a private seed");
            ERR_clear_error();
        }
        EVP_PKEY_free(bad);

        bad = EVP_PKEY_new_raw_public_key_ex(libctx, D00_ALG,
            D00_PROP, base->public_key, D00_PUB_BYTES);
        D00_CHECK(bad != NULL,
            "EVP_PKEY_new_raw_public_key_ex imports the public key");
        EVP_PKEY_free(bad);

        bad = EVP_PKEY_new_raw_private_key_ex(libctx, D00_ALG,
            D00_PROP, base->seed, D00_SEED_BYTES);
        D00_CHECK(bad != NULL,
            "EVP_PKEY_new_raw_private_key_ex imports the seed");
        EVP_PKEY_free(bad);

        /* Missing selection material: empty parameter list. */
        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            NULL, 0, NULL, 0);
        D00_CHECK(bad == NULL, "empty import is rejected");
        ERR_clear_error();

        /* Malformed parameter type: UTF8 string instead of octets. */
        {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
                libctx, D00_ALG, D00_PROP);
            OSSL_PARAM params[2];
            EVP_PKEY *pkey = NULL;

            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_PUB_KEY,
                (char *)base->public_key, D00_PUB_BYTES);
            params[1] = OSSL_PARAM_construct_end();
            D00_CHECK(ctx != NULL
                    && EVP_PKEY_fromdata_init(ctx) == 1
                    && EVP_PKEY_fromdata(ctx, &pkey,
                        EVP_PKEY_PUBLIC_KEY, params) != 1
                    && pkey == NULL,
                "wrong parameter type is rejected");
            ERR_clear_error();
            EVP_PKEY_CTX_free(ctx);
        }
    }

    /* Encoded-public setter policy. */
    {
        EVP_PKEY *pkey = d00_key_from_seed(libctx, base->seed);
        unsigned char different[38];

        memcpy(different, base->public_key, sizeof(different));
        different[1] ^= 1;
        D00_CHECK(pkey != NULL
                && EVP_PKEY_set1_encoded_public_key(pkey,
                    base->public_key, D00_PUB_BYTES) == 1,
            "matching encoded public key is accepted");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_set1_encoded_public_key(pkey,
                    different, D00_PUB_BYTES) != 1,
            "different encoded public key cannot replace the pair");
        ERR_clear_error();
        EVP_PKEY_free(pkey);
    }

    /* Key generation produces a valid, self-consistent pair. */
    {
        EVP_PKEY *generated = d00_keygen(libctx);
        EVP_PKEY *reimported = NULL;
        unsigned char seed_out[38];
        unsigned char public_out[38];
        unsigned char sig[76];
        size_t out_len = 0;
        static const unsigned char probe[] = "draft-00 keygen probe";

        D00_CHECK(generated != NULL, "key generation");
        if (generated != NULL) {
            EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new_from_pkey(
                libctx, generated, D00_PROP);

            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_check(check_ctx) == 1,
                "generated pair validates");
            EVP_PKEY_CTX_free(check_ctx);

            D00_CHECK(EVP_PKEY_get_octet_string_param(generated,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) == 1
                    && out_len == D00_SEED_BYTES
                    && EVP_PKEY_get_octet_string_param(generated,
                        OSSL_PKEY_PARAM_PUB_KEY, public_out,
                        sizeof(public_out), &out_len) == 1
                    && out_len == D00_PUB_BYTES,
                "generated components export");

            reimported = d00_key_from_seed(libctx, seed_out);
            D00_CHECK(reimported != NULL
                    && EVP_PKEY_eq(generated, reimported) == 1,
                "generated seed reimports to an equal key");

            D00_CHECK(d00_digest_sign(libctx, generated, probe,
                    sizeof(probe) - 1, sig)
                    && d00_digest_verify(libctx, generated, probe,
                        sizeof(probe) - 1, sig, sizeof(sig)),
                "generated key signs and verifies");

            EVP_PKEY_free(reimported);
            EVP_PKEY_free(generated);
        }
    }

    /* Two generated keys are distinct and do not match. */
    {
        EVP_PKEY *first = d00_keygen(libctx);
        EVP_PKEY *second = d00_keygen(libctx);

        D00_CHECK(first != NULL && second != NULL
                && EVP_PKEY_eq(first, second) != 1,
            "independent generated keys do not match");
        ERR_clear_error();
        EVP_PKEY_free(first);
        EVP_PKEY_free(second);
    }

    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return d00_summary("provider_keymgmt");
}
