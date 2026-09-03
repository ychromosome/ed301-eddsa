/*
 * Acceptance section 4 (serialization): PKCS#8 and SPKI round trips in DER
 * and PEM through provider encoders plus the mandatory project-owned,
 * complete-buffer import boundary, deliberate absence of private text output
 * from the PKI-only artifact, and rejection of the historical and X301
 * OIDs, ASN.1 NULL parameters, wrong OIDs
 * and sizes, truncation, trailing data and malformed public keys.
 * Encrypted PKCS#8 (and its wrong-password rejection) is exercised through
 * the openssl CLI in run_matrix.sh, mirroring the historical route.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* memmem */
#endif

#include <openssl/encoder.h>

#include "harness_common.h"
#include "strict_serialization.h"
#include "vectors.h"

/* Historical Ed301-Sig-v1 PKCS#8/SPKI prefixes (forbidden identity). */
static const unsigned char HISTORICAL_PKCS8_PREFIX[24] = {
    0x30, 0x3c, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06,
    0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x85,
    0x6a, 0x82, 0x2d, 0x01, 0x04, 0x28, 0x04, 0x26
};

static const unsigned char HISTORICAL_SPKI_PREFIX[20] = {
    0x30, 0x38, 0x30, 0x0d, 0x06, 0x0b, 0x2b, 0x06,
    0x01, 0x04, 0x01, 0x84, 0x85, 0x6a, 0x82, 0x2d,
    0x01, 0x03, 0x27, 0x00
};

/* X301 remains assigned to .301.2 and must not alias Ed301-EdDSA. */
static const unsigned char X301_PKCS8_PREFIX[24] = {
    0x30, 0x3c, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06,
    0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x85,
    0x6a, 0x82, 0x2d, 0x02, 0x04, 0x28, 0x04, 0x26
};

static const unsigned char X301_SPKI_PREFIX[20] = {
    0x30, 0x38, 0x30, 0x0d, 0x06, 0x0b, 0x2b, 0x06,
    0x01, 0x04, 0x01, 0x84, 0x85, 0x6a, 0x82, 0x2d,
    0x02, 0x03, 0x27, 0x00
};

static unsigned char *encode(
    EVP_PKEY *pkey,
    int selection,
    const char *format,
    const char *structure,
    size_t *out_len)
{
    OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(
        pkey, selection, format, structure, ED301V1_PKI_PROP);
    unsigned char *data = NULL;

    *out_len = 0;
    if (ctx == NULL)
        return NULL;
    if (OSSL_ENCODER_to_data(ctx, &data, out_len) != 1)
        data = NULL;
    OSSL_ENCODER_CTX_free(ctx);
    return data;
}

static EVP_PKEY *decode(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_len,
    const char *format,
    const char *structure,
    int selection)
{
    const int is_public = strcmp(structure, "SubjectPublicKeyInfo") == 0;

    if ((is_public && selection != OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
            || (!is_public
                && strcmp(structure, "PrivateKeyInfo") != 0)
            || (!is_public
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0))
        return NULL;
    if (strcmp(format, "DER") == 0)
        return ed301v1_strict_der_import(libctx, data, data_len, is_public);
    if (strcmp(format, "PEM") == 0)
        return ed301v1_strict_pem_import(libctx, data, data_len, is_public);
    return NULL;
}

static int der_pem_der_is_identical(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey,
    int selection,
    const char *structure)
{
    unsigned char *first_der = NULL;
    unsigned char *pem = NULL;
    unsigned char *second_der = NULL;
    EVP_PKEY *from_der = NULL;
    EVP_PKEY *from_pem = NULL;
    size_t first_der_length = 0;
    size_t pem_length = 0;
    size_t second_der_length = 0;
    int ok = 0;

    first_der = encode(
        pkey, selection, "DER", structure, &first_der_length);
    from_der = first_der == NULL ? NULL
        : decode(libctx, first_der, first_der_length, "DER", structure,
            selection);
    pem = from_der == NULL ? NULL
        : encode(from_der, selection, "PEM", structure, &pem_length);
    from_pem = pem == NULL ? NULL
        : decode(libctx, pem, pem_length, "PEM", structure, selection);
    second_der = from_pem == NULL ? NULL
        : encode(from_pem, selection, "DER", structure,
            &second_der_length);
    ok = first_der != NULL && from_der != NULL && pem != NULL
        && from_pem != NULL && second_der != NULL
        && second_der_length == first_der_length
        && CRYPTO_memcmp(
            first_der, second_der, first_der_length) == 0;

    OPENSSL_clear_free(first_der, first_der_length);
    OPENSSL_clear_free(pem, pem_length);
    OPENSSL_clear_free(second_der, second_der_length);
    EVP_PKEY_free(from_der);
    EVP_PKEY_free(from_pem);
    ERR_clear_error();
    return ok;
}

static int all_truncations_rejected(
    OSSL_LIB_CTX *libctx,
    const unsigned char *der,
    size_t der_length,
    const char *structure,
    int selection,
    const size_t *lengths,
    size_t lengths_count)
{
    size_t index;

    if (der == NULL || lengths == NULL)
        return 0;
    for (index = 0; index < lengths_count; index++) {
        EVP_PKEY *key;

        if (lengths[index] >= der_length)
            return 0;
        key = decode(libctx, der, lengths[index], "DER", structure,
            selection);
        if (key != NULL) {
            EVP_PKEY_free(key);
            return 0;
        }
        ERR_clear_error();
    }
    return 1;
}

/*
 * Construct the small Ed301-EdDSA-v1 PrivateKeyInfo grammar from semantic fields.
 * Deriving every enclosing length from seed_length ensures D7 exercises a
 * well-formed alternative value, not an accidentally inconsistent object.
 */
static size_t make_pkcs8_with_seed_length(
    unsigned char *output,
    size_t output_capacity,
    const unsigned char *seed,
    size_t seed_length)
{
    size_t index = 0;
    const size_t content_length = 22 + seed_length;
    const size_t encoded_length = 2 + content_length;

    if (output == NULL || seed == NULL || seed_length > 125
            || content_length > 127 || output_capacity < encoded_length)
        return 0;

    output[index++] = 0x30;
    output[index++] = (unsigned char)content_length;
    output[index++] = 0x02;
    output[index++] = 0x01;
    output[index++] = 0x00;
    output[index++] = 0x30;
    output[index++] = 0x0d;
    memcpy(output + index, ED301V1_PKCS8_PREFIX + 7, ED301V1_OID_TLV_BYTES);
    index += ED301V1_OID_TLV_BYTES;
    output[index++] = 0x04;
    output[index++] = (unsigned char)(seed_length + 2);
    output[index++] = 0x04;
    output[index++] = (unsigned char)seed_length;
    memcpy(output + index, seed, seed_length);
    index += seed_length;
    return index;
}

int main(void)
{
    ED301V1_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1;
    const POSITIVE_CASE *base = &POSITIVE_CASES[0];
    EVP_PKEY *pkey;

    ed301v1_property = ED301V1_PKI_PROP;
    v1 = ed301v1_load_named(libctx, &deflt, ED301V1_PKI_PROVIDER);
    pkey = ed301v1_key_from_seed(libctx, base->seed);
    ED301V1_CHECK(v1 != NULL && pkey != NULL, "provider and key");

    /*
     * D1 (provider serialization contract; OpenSSL endecode_test.c pattern):
     * DER -> PEM -> DER is byte-identical for both supported structures.
     */
    ED301V1_CHECK(pkey != NULL && der_pem_der_is_identical(libctx, pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "PrivateKeyInfo"),
        "D1 PKCS#8 DER-to-PEM-to-DER is byte-identical");
    ED301V1_CHECK(pkey != NULL && der_pem_der_is_identical(libctx, pkey,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY, "SubjectPublicKeyInfo"),
        "D1 SPKI DER-to-PEM-to-DER is byte-identical");

    /* PKCS#8 DER is byte-exact and round-trips. */
    {
        size_t der_len = 0;
        unsigned char *der = encode(pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "PrivateKeyInfo", &der_len);
        EVP_PKEY *decoded;

        ED301V1_CHECK(der != NULL && der_len == ED301V1_PKCS8_DER_BYTES
                && memcmp(der, ED301V1_PKCS8_PREFIX,
                    sizeof(ED301V1_PKCS8_PREFIX)) == 0
                && memcmp(der + sizeof(ED301V1_PKCS8_PREFIX), base->seed,
                    38) == 0,
            "PKCS#8 DER is the exact 62-byte profile encoding");

        /*
         * D4/D5 (provider byte contract; OpenSSL ecx encoder pattern):
         * AlgorithmIdentifier parameters are absent and the assigned OID
         * bytes are exact before the private-key OCTET STRING.
         */
        ED301V1_CHECK(der != NULL && der_len == ED301V1_PKCS8_DER_BYTES
                && der[5] == 0x30 && der[6] == 0x0d
                && der[7] == 0x06 && der[20] == 0x04,
            "D4/D5 PKCS#8 has exact OID and absent parameters");

        decoded = der == NULL ? NULL
            : decode(libctx, der, der_len, "DER", "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        ED301V1_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "PKCS#8 DER round trip");
        EVP_PKEY_free(decoded);

        /* Negative shapes derived from the valid DER. */
        if (der != NULL && der_len == ED301V1_PKCS8_DER_BYTES) {
            unsigned char mutated[80];
            unsigned char nonminimal[80];
            unsigned char indefinite[80];
            static const size_t truncation_boundaries[] = {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                20, 21, 22, 23, 24, ED301V1_PKCS8_DER_BYTES - 1
            };

            /*
             * D3 (provider complete-buffer contract; endecode_test.c):
             * every ASN.1 structural boundary and a short value reject.
             */
            ED301V1_CHECK(all_truncations_rejected(libctx, der, der_len,
                    "PrivateKeyInfo", OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                    truncation_boundaries,
                    sizeof(truncation_boundaries)
                        / sizeof(truncation_boundaries[0])),
                "D3 PKCS#8 truncations at all structural boundaries reject");

            /* D2 (provider complete-buffer contract): trailing data rejects. */
            memcpy(mutated, der, der_len);
            mutated[der_len] = 0x00;
            ED301V1_CHECK(decode(libctx, mutated, der_len + 1, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "trailing data after PKCS#8 is rejected");
            ERR_clear_error();

            /* BER/non-canonical length forms are outside the exact profile. */
            nonminimal[0] = 0x30;
            nonminimal[1] = 0x81;
            nonminimal[2] = der[1];
            memcpy(nonminimal + 3, der + 2, der_len - 2);
            ED301V1_CHECK(decode(libctx, nonminimal, der_len + 1, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "PKCS#8 with non-minimal outer length is rejected");
            ERR_clear_error();

            indefinite[0] = 0x30;
            indefinite[1] = 0x80;
            memcpy(indefinite + 2, der + 2, der_len - 2);
            indefinite[der_len] = 0x00;
            indefinite[der_len + 1] = 0x00;
            ED301V1_CHECK(decode(libctx, indefinite, der_len + 2, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "PKCS#8 with indefinite outer length is rejected");
            ERR_clear_error();

            /* D5 (project OID registry): a foreign OID never aliases Ed301. */
            memcpy(mutated, der, der_len);
            mutated[10] ^= 1;
            ED301V1_CHECK(decode(libctx, mutated, der_len, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "wrong OID is rejected");
            ERR_clear_error();

            /*
             * D7 (v1 38-byte seed contract; OpenSSL ECX nested-octet
             * pattern): the inner seed must be exactly 38 bytes.
             */
            memcpy(mutated, der, der_len);
            mutated[22] = 0x03;
            ED301V1_CHECK(decode(libctx, mutated, der_len, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "PKCS#8 with a BIT STRING in place of the nested OCTET "
                "STRING is rejected");
            ERR_clear_error();

            {
                unsigned char seed39[ED301V1_SEED_BYTES + 1];
                unsigned char short_seed_der[80];
                unsigned char long_seed_der[80];
                size_t short_seed_der_length;
                size_t long_seed_der_length;

                memcpy(seed39, base->seed, ED301V1_SEED_BYTES);
                seed39[ED301V1_SEED_BYTES] = 0x00;
                short_seed_der_length = make_pkcs8_with_seed_length(
                    short_seed_der, sizeof(short_seed_der), base->seed,
                    ED301V1_SEED_BYTES - 1);
                long_seed_der_length = make_pkcs8_with_seed_length(
                    long_seed_der, sizeof(long_seed_der), seed39,
                    ED301V1_SEED_BYTES + 1);

                ED301V1_CHECK(short_seed_der_length
                        == ED301V1_PKCS8_DER_BYTES - 1
                        && decode(libctx, short_seed_der,
                            short_seed_der_length, "DER", "PrivateKeyInfo",
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                    "D7 well-formed PKCS#8 with a 37-byte seed is rejected");
                ERR_clear_error();
                ED301V1_CHECK(long_seed_der_length
                        == ED301V1_PKCS8_DER_BYTES + 1
                        && decode(libctx, long_seed_der,
                            long_seed_der_length, "DER", "PrivateKeyInfo",
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                    "D7 well-formed PKCS#8 with a 39-byte seed is rejected");
                ERR_clear_error();
            }
        }
        OPENSSL_free(der);
    }

    /*
     * D4 (provider parameterless AlgorithmIdentifier contract; OpenSSL ECX
     * encoding pattern): decoder rejects NULL and all explicit parameters.
     */
    {
        unsigned char with_null[ED301V1_PKCS8_DER_BYTES + 2];
        size_t index = 0;

        /* SEQ(62+2) { INTEGER 0, SEQ { OID, NULL }, OCTET... } */
        with_null[index++] = 0x30;
        with_null[index++] = 0x3e;
        with_null[index++] = 0x02;
        with_null[index++] = 0x01;
        with_null[index++] = 0x00;
        with_null[index++] = 0x30;
        with_null[index++] = 0x0f;
        memcpy(with_null + index, ED301V1_PKCS8_PREFIX + 7,
            ED301V1_OID_TLV_BYTES);
        index += ED301V1_OID_TLV_BYTES;
        with_null[index++] = 0x05; /* NULL */
        with_null[index++] = 0x00;
        with_null[index++] = 0x04;
        with_null[index++] = 0x28;
        with_null[index++] = 0x04;
        with_null[index++] = 0x26;
        memcpy(with_null + index, base->seed, 38);
        index += 38;
        ED301V1_CHECK(index == sizeof(with_null), "NULL-variant layout");
        ED301V1_CHECK(decode(libctx, with_null, sizeof(with_null), "DER",
                "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "AlgorithmIdentifier with ASN.1 NULL parameters is rejected");
        ERR_clear_error();

        /* No other explicit parameter type is permitted either. */
        with_null[20] = 0x04; /* empty OCTET STRING instead of NULL */
        ED301V1_CHECK(decode(libctx, with_null, sizeof(with_null), "DER",
                "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "AlgorithmIdentifier with explicit non-NULL parameters is "
            "rejected");
        ERR_clear_error();
    }

    /*
     * D6 (provider PKCS#8 policy; OpenSSL ecx OneAsymmetricKey comparison):
     * only PrivateKeyInfo v1 (version INTEGER 0) is part of
     * the test profile.  RFC 5958 OneAsymmetricKey v2 (INTEGER 1 with the
     * optional publicKey field) is deliberately rejected: the 38-byte seed
     * already derives, and KEYMGMT validates, the unique public key.
    */
    {
        unsigned char version_one[ED301V1_PKCS8_DER_BYTES] = {0};
        unsigned char one_asymmetric_key[128] = {0};
        size_t private_key_info_length;
        size_t index = 0;

        private_key_info_length = make_pkcs8_with_seed_length(
            version_one, sizeof(version_one), base->seed, ED301V1_SEED_BYTES);
        ED301V1_CHECK(private_key_info_length == sizeof(version_one),
            "D6 canonical PrivateKeyInfo source layout");
        version_one[4] = 0x01;
        ED301V1_CHECK(private_key_info_length == sizeof(version_one)
                && decode(libctx, version_one, sizeof(version_one), "DER",
                "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "PKCS#8 version INTEGER 1 without publicKey is rejected");
        ERR_clear_error();

        one_asymmetric_key[index++] = 0x30;
        one_asymmetric_key[index++] = 0x65;
        /* Copy from the complete canonical object, never the prefix array. */
        memcpy(one_asymmetric_key + index, version_one + 2,
            ED301V1_PKCS8_DER_BYTES - 2);
        index += ED301V1_PKCS8_DER_BYTES - 2;
        one_asymmetric_key[4] = 0x01;
        one_asymmetric_key[index++] = 0x81; /* [1] IMPLICIT BIT STRING */
        one_asymmetric_key[index++] = 0x27;
        one_asymmetric_key[index++] = 0x00;
        memcpy(one_asymmetric_key + index,
            base->public_key, ED301V1_PUB_BYTES);
        index += ED301V1_PUB_BYTES;
        ED301V1_CHECK(index == 103, "OneAsymmetricKey v2 layout");
        ED301V1_CHECK(decode(libctx, one_asymmetric_key, index, "DER",
                "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "OneAsymmetricKey v2 with embedded publicKey is rejected");
        ERR_clear_error();
    }

    /* Historical OID encodings are rejected. */
    {
        unsigned char historical_p8[ED301V1_PKCS8_DER_BYTES];
        unsigned char historical_spki[ED301V1_SPKI_DER_BYTES];

        memcpy(historical_p8, HISTORICAL_PKCS8_PREFIX,
            sizeof(HISTORICAL_PKCS8_PREFIX));
        memcpy(historical_p8 + sizeof(HISTORICAL_PKCS8_PREFIX),
            base->seed, 38);
        ED301V1_CHECK(decode(libctx, historical_p8, sizeof(historical_p8),
                "DER", "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "historical Ed301-Sig-v1 PKCS#8 OID is rejected");
        ERR_clear_error();

        memcpy(historical_spki, HISTORICAL_SPKI_PREFIX,
            sizeof(HISTORICAL_SPKI_PREFIX));
        memcpy(historical_spki + sizeof(HISTORICAL_SPKI_PREFIX),
            base->public_key, 38);
        ED301V1_CHECK(decode(libctx, historical_spki,
                sizeof(historical_spki), "DER", "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
            "historical Ed301-Sig-v1 SPKI OID is rejected");
        ERR_clear_error();
    }

    /* The adjacent X301 assignment is not accepted as Ed301-EdDSA. */
    {
        unsigned char x301_p8[ED301V1_PKCS8_DER_BYTES];
        unsigned char x301_spki[ED301V1_SPKI_DER_BYTES];

        memcpy(x301_p8, X301_PKCS8_PREFIX, sizeof(X301_PKCS8_PREFIX));
        memcpy(x301_p8 + sizeof(X301_PKCS8_PREFIX), base->seed, 38);
        ED301V1_CHECK(decode(libctx, x301_p8, sizeof(x301_p8), "DER",
                "PrivateKeyInfo", OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "X301 PKCS#8 OID is rejected by Ed301-EdDSA import");
        ERR_clear_error();

        memcpy(x301_spki, X301_SPKI_PREFIX, sizeof(X301_SPKI_PREFIX));
        memcpy(x301_spki + sizeof(X301_SPKI_PREFIX),
            base->public_key, 38);
        ED301V1_CHECK(decode(libctx, x301_spki, sizeof(x301_spki), "DER",
                "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
            "X301 SPKI OID is rejected by Ed301-EdDSA import");
        ERR_clear_error();
    }

    /* SPKI DER is byte-exact and round-trips. */
    {
        size_t der_len = 0;
        unsigned char *der = encode(pkey,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "SubjectPublicKeyInfo", &der_len);
        EVP_PKEY *decoded;

        ED301V1_CHECK(der != NULL && der_len == ED301V1_SPKI_DER_BYTES
                && memcmp(der, ED301V1_SPKI_PREFIX,
                    sizeof(ED301V1_SPKI_PREFIX)) == 0
                && memcmp(der + sizeof(ED301V1_SPKI_PREFIX), base->public_key,
                    38) == 0,
            "SPKI DER is the exact 58-byte profile encoding");

        /* D4/D5: exact project OID, absent parameters, then BIT STRING. */
        ED301V1_CHECK(der != NULL && der_len == ED301V1_SPKI_DER_BYTES
                && der[2] == 0x30 && der[3] == 0x0d
                && der[4] == 0x06 && der[17] == 0x03,
            "D4/D5 SPKI has exact OID and absent parameters");

        decoded = der == NULL ? NULL
            : decode(libctx, der, der_len, "DER", "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        ED301V1_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "SPKI DER round trip (public component)");
        EVP_PKEY_free(decoded);

        /* Malformed embedded public key: identity point. */
        if (der != NULL && der_len == ED301V1_SPKI_DER_BYTES) {
            unsigned char malformed[80];
            unsigned char nonminimal[80];
            unsigned char indefinite[80];
            static const size_t truncation_boundaries[] = {
                0, 1, 2, 3, 4, 5, 6, 17, 18, 19, 20,
                ED301V1_SPKI_DER_BYTES - 1
            };

            memcpy(malformed, der, der_len);
            memcpy(malformed + sizeof(ED301V1_SPKI_PREFIX),
                POINT_CASES[2].encoding, 38); /* identity */
            ED301V1_CHECK(decode(libctx, malformed, der_len, "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "SPKI with an identity public key is rejected");
            ERR_clear_error();

            /* D3 (complete-buffer/endecode pattern): all boundaries reject. */
            ED301V1_CHECK(all_truncations_rejected(libctx, der, der_len,
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                    truncation_boundaries,
                    sizeof(truncation_boundaries)
                        / sizeof(truncation_boundaries[0])),
                "D3 SPKI truncations at all structural boundaries reject");

            /* D2: SPKI also rejects one trailing octet. */
            memcpy(malformed, der, der_len);
            malformed[der_len] = 0x00;
            ED301V1_CHECK(decode(libctx, malformed, der_len + 1, "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "trailing data after SPKI is rejected");
            ERR_clear_error();

            nonminimal[0] = 0x30;
            nonminimal[1] = 0x81;
            nonminimal[2] = der[1];
            memcpy(nonminimal + 3, der + 2, der_len - 2);
            ED301V1_CHECK(decode(libctx, nonminimal, der_len + 1, "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "SPKI with non-minimal outer length is rejected");
            ERR_clear_error();

            indefinite[0] = 0x30;
            indefinite[1] = 0x80;
            memcpy(indefinite + 2, der + 2, der_len - 2);
            indefinite[der_len] = 0x00;
            indefinite[der_len + 1] = 0x00;
            ED301V1_CHECK(decode(libctx, indefinite, der_len + 2, "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "SPKI with indefinite outer length is rejected");
            ERR_clear_error();

            memcpy(malformed, der, der_len);
            malformed[17] = 0x04;
            ED301V1_CHECK(decode(libctx, malformed, der_len, "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "SPKI with an OCTET STRING in place of the BIT STRING is "
                "rejected");
            ERR_clear_error();

            memcpy(malformed, der, der_len);
            malformed[18] = 0x26;
            ED301V1_CHECK(decode(libctx, malformed, der_len, "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "SPKI with a 37-byte public-key BIT STRING is rejected");
            ERR_clear_error();

            memcpy(malformed, der, der_len);
            malformed[19] = 0x01;
            ED301V1_CHECK(decode(libctx, malformed, der_len, "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "SPKI with nonzero unused BIT STRING bits is rejected");
            ERR_clear_error();
        }
        OPENSSL_free(der);
    }

    /* D4: SPKI decoder rejects NULL and all explicit parameters. */
    {
        unsigned char with_null[ED301V1_SPKI_DER_BYTES + 2];
        size_t index = 0;

        with_null[index++] = 0x30;
        with_null[index++] = 0x3a;
        with_null[index++] = 0x30;
        with_null[index++] = 0x0f;
        memcpy(with_null + index, ED301V1_SPKI_PREFIX + 4,
            ED301V1_OID_TLV_BYTES);
        index += ED301V1_OID_TLV_BYTES;
        with_null[index++] = 0x05;
        with_null[index++] = 0x00;
        with_null[index++] = 0x03;
        with_null[index++] = 0x27;
        with_null[index++] = 0x00;
        memcpy(with_null + index, base->public_key, ED301V1_PUB_BYTES);
        index += ED301V1_PUB_BYTES;
        ED301V1_CHECK(index == sizeof(with_null), "SPKI NULL-variant layout");
        ED301V1_CHECK(decode(libctx, with_null, sizeof(with_null), "DER",
                "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
            "SPKI AlgorithmIdentifier with ASN.1 NULL parameters is "
            "rejected");
        ERR_clear_error();

        with_null[17] = 0x04; /* empty OCTET STRING instead of NULL */
        ED301V1_CHECK(decode(libctx, with_null, sizeof(with_null), "DER",
                "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
            "SPKI AlgorithmIdentifier with explicit non-NULL parameters is "
            "rejected");
        ERR_clear_error();
    }

    /* PEM round trips. */
    {
        size_t pem_len = 0;
        unsigned char *pem = encode(pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "PEM", "PrivateKeyInfo", &pem_len);
        EVP_PKEY *decoded;

        ED301V1_CHECK(pem != NULL && pem_len >= 27
                && memcmp(pem, "-----BEGIN PRIVATE KEY-----", 27) == 0,
            "PKCS#8 PEM armor");
        decoded = pem == NULL ? NULL
            : decode(libctx, pem, pem_len, "PEM", "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        ED301V1_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "PKCS#8 PEM round trip");
        EVP_PKEY_free(decoded);
        OPENSSL_free(pem);

        pem = encode(pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "PEM", "SubjectPublicKeyInfo", &pem_len);
        ED301V1_CHECK(pem != NULL && pem_len >= 26
                && memcmp(pem, "-----BEGIN PUBLIC KEY-----", 26) == 0,
            "SPKI PEM armor");
        decoded = pem == NULL ? NULL
            : decode(libctx, pem, pem_len, "PEM", "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        ED301V1_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "SPKI PEM round trip");
        EVP_PKEY_free(decoded);
        OPENSSL_free(pem);
    }

    /* The PKI-only artifact exposes no text/hex encoder (F5). */
    {
        size_t text_len = 0;
        unsigned char *text = encode(pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "TEXT", NULL, &text_len);

        ED301V1_CHECK(text == NULL && text_len == 0,
            "PKI-only provider exposes no private text/hex encoder");
        ERR_clear_error();
        OPENSSL_free(text);
    }

    /* Direct encrypted PKCS#8 through the provider encoder fails closed. */
    {
        OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(
            pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "PrivateKeyInfo", ED301V1_PKI_PROP);
        unsigned char *data = NULL;
        size_t data_len = 0;
        int set_ok = 0;
        int encode_result = 0;

        if (ctx != NULL) {
            set_ok = OSSL_ENCODER_CTX_set_cipher(
                ctx, "AES-256-CBC", NULL) == 1;
            OSSL_ENCODER_CTX_set_passphrase(
                ctx, (const unsigned char *)"secret", 6);
            encode_result = OSSL_ENCODER_to_data(ctx, &data, &data_len);
        }
        ED301V1_CHECK(ctx != NULL && set_ok != 1 && encode_result != 1,
            "direct encrypted PKCS#8 fails closed (set_ok=%d encode=%d)",
            set_ok, encode_result);
        ERR_clear_error();
        OPENSSL_free(data);
        OSSL_ENCODER_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return ed301v1_summary("provider_serialization");
}
