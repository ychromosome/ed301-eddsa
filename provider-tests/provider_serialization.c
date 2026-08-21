/*
 * Acceptance section 4 (serialization): PKCS#8 and SPKI round trips in DER
 * and PEM through public OpenSSL encoder/decoder interfaces, text output,
 * and rejection of the historical OID, ASN.1 NULL parameters, wrong OIDs
 * and sizes, truncation, trailing data and malformed public keys.
 * Encrypted PKCS#8 (and its wrong-password rejection) is exercised through
 * the openssl CLI in run_matrix.sh, mirroring the historical route.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* memmem */
#endif

#include <openssl/decoder.h>
#include <openssl/encoder.h>

#include "harness_common.h"
#include "vectors.h"

/* Exact expected encodings for the 'empty' vector key. */
static const unsigned char PKCS8_PREFIX[33] = {
    0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x16, 0x06,
    0x14, 0x69, 0x82, 0xa6, 0x8b, 0xcb, 0x8d, 0xb3,
    0x93, 0xe2, 0x9f, 0x8b, 0x8a, 0x9e, 0xf1, 0xc4,
    0xf2, 0xe5, 0xd7, 0xe5, 0x30, 0x04, 0x28, 0x04,
    0x26
};

static const unsigned char SPKI_PREFIX[29] = {
    0x30, 0x41, 0x30, 0x16, 0x06, 0x14, 0x69, 0x82,
    0xa6, 0x8b, 0xcb, 0x8d, 0xb3, 0x93, 0xe2, 0x9f,
    0x8b, 0x8a, 0x9e, 0xf1, 0xc4, 0xf2, 0xe5, 0xd7,
    0xe5, 0x30, 0x03, 0x27, 0x00
};

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

static unsigned char *encode(
    EVP_PKEY *pkey,
    int selection,
    const char *format,
    const char *structure,
    size_t *out_len)
{
    OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(
        pkey, selection, format, structure, D00_PROP);
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
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey, format, structure, D00_ALG, selection, libctx, NULL);
    const unsigned char *cursor = data;
    size_t remaining = data_len;

    if (ctx == NULL)
        return NULL;
    /*
     * Caller-side whole-buffer policy (B1-DER): the provider decoder
     * stops after one DER object and leaves trailing bytes unread, so
     * buffer completeness is enforced here, outside that decoder.
     */
    if (OSSL_DECODER_from_data(ctx, &cursor, &remaining) != 1
            || remaining != 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    OSSL_DECODER_CTX_free(ctx);
    return pkey;
}

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = d00_load(libctx, &deflt);
    const POSITIVE_CASE *base = &POSITIVE_CASES[0];
    EVP_PKEY *pkey = d00_key_from_seed(libctx, base->seed);

    D00_CHECK(draft != NULL && pkey != NULL, "provider and key");

    /* PKCS#8 DER is byte-exact and round-trips. */
    {
        size_t der_len = 0;
        unsigned char *der = encode(pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "PrivateKeyInfo", &der_len);
        EVP_PKEY *decoded;

        D00_CHECK(der != NULL && der_len == 71
                && memcmp(der, PKCS8_PREFIX, sizeof(PKCS8_PREFIX)) == 0
                && memcmp(der + sizeof(PKCS8_PREFIX), base->seed,
                    38) == 0,
            "PKCS#8 DER is the exact 71-byte profile encoding");

        decoded = der == NULL ? NULL
            : decode(libctx, der, der_len, "DER", "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        D00_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "PKCS#8 DER round trip");
        EVP_PKEY_free(decoded);

        /* Negative shapes derived from the valid DER. */
        if (der != NULL) {
            unsigned char mutated[80];

            /* Truncation. */
            D00_CHECK(decode(libctx, der, der_len - 1, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "truncated PKCS#8 is rejected");
            ERR_clear_error();

            /* Trailing data. */
            memcpy(mutated, der, der_len);
            mutated[der_len] = 0x00;
            D00_CHECK(decode(libctx, mutated, der_len + 1, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "trailing data after PKCS#8 is rejected");
            ERR_clear_error();

            /* Wrong OID arc byte. */
            memcpy(mutated, der, der_len);
            mutated[10] ^= 1;
            D00_CHECK(decode(libctx, mutated, der_len, "DER",
                    "PrivateKeyInfo",
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
                "wrong OID is rejected");
            ERR_clear_error();

            OPENSSL_free(der);
        }
    }

    /* ASN.1 NULL parameters variant of our AlgorithmIdentifier. */
    {
        unsigned char with_null[73];
        size_t index = 0;

        /* SEQ(71+2) { INTEGER 0, SEQ { OID, NULL }, OCTET... } */
        with_null[index++] = 0x30;
        with_null[index++] = 0x47;
        with_null[index++] = 0x02;
        with_null[index++] = 0x01;
        with_null[index++] = 0x00;
        with_null[index++] = 0x30;
        with_null[index++] = 0x18;
        memcpy(with_null + index, PKCS8_PREFIX + 7, 22); /* OID TLV */
        index += 22;
        with_null[index++] = 0x05; /* NULL */
        with_null[index++] = 0x00;
        with_null[index++] = 0x04;
        with_null[index++] = 0x28;
        with_null[index++] = 0x04;
        with_null[index++] = 0x26;
        memcpy(with_null + index, base->seed, 38);
        index += 38;
        D00_CHECK(index == sizeof(with_null), "NULL-variant layout");
        D00_CHECK(decode(libctx, with_null, sizeof(with_null), "DER",
                "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "AlgorithmIdentifier with ASN.1 NULL parameters is rejected");
        ERR_clear_error();
    }

    /* Historical OID encodings are rejected. */
    {
        unsigned char historical_p8[62];
        unsigned char historical_spki[58];

        memcpy(historical_p8, HISTORICAL_PKCS8_PREFIX,
            sizeof(HISTORICAL_PKCS8_PREFIX));
        memcpy(historical_p8 + sizeof(HISTORICAL_PKCS8_PREFIX),
            base->seed, 38);
        D00_CHECK(decode(libctx, historical_p8, sizeof(historical_p8),
                "DER", "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == NULL,
            "historical Ed301-Sig-v1 PKCS#8 OID is rejected");
        ERR_clear_error();

        memcpy(historical_spki, HISTORICAL_SPKI_PREFIX,
            sizeof(HISTORICAL_SPKI_PREFIX));
        memcpy(historical_spki + sizeof(HISTORICAL_SPKI_PREFIX),
            base->public_key, 38);
        D00_CHECK(decode(libctx, historical_spki,
                sizeof(historical_spki), "DER", "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
            "historical Ed301-Sig-v1 SPKI OID is rejected");
        ERR_clear_error();
    }

    /* SPKI DER is byte-exact and round-trips. */
    {
        size_t der_len = 0;
        unsigned char *der = encode(pkey,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "SubjectPublicKeyInfo", &der_len);
        EVP_PKEY *decoded;

        D00_CHECK(der != NULL && der_len == 67
                && memcmp(der, SPKI_PREFIX, sizeof(SPKI_PREFIX)) == 0
                && memcmp(der + sizeof(SPKI_PREFIX), base->public_key,
                    38) == 0,
            "SPKI DER is the exact 67-byte profile encoding");

        decoded = der == NULL ? NULL
            : decode(libctx, der, der_len, "DER", "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        D00_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "SPKI DER round trip (public component)");
        EVP_PKEY_free(decoded);

        /* Malformed embedded public key: identity point. */
        if (der != NULL) {
            unsigned char malformed[67];

            memcpy(malformed, der, der_len);
            memcpy(malformed + sizeof(SPKI_PREFIX),
                POINT_CASES[2].encoding, 38); /* identity */
            D00_CHECK(decode(libctx, malformed, sizeof(malformed), "DER",
                    "SubjectPublicKeyInfo",
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == NULL,
                "SPKI with an identity public key is rejected");
            ERR_clear_error();
            OPENSSL_free(der);
        }
    }

    /* PEM round trips. */
    {
        size_t pem_len = 0;
        unsigned char *pem = encode(pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "PEM", "PrivateKeyInfo", &pem_len);
        EVP_PKEY *decoded;

        D00_CHECK(pem != NULL
                && memcmp(pem, "-----BEGIN PRIVATE KEY-----", 27) == 0,
            "PKCS#8 PEM armor");
        decoded = pem == NULL ? NULL
            : decode(libctx, pem, pem_len, "PEM", "PrivateKeyInfo",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        D00_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "PKCS#8 PEM round trip");
        EVP_PKEY_free(decoded);
        OPENSSL_free(pem);

        pem = encode(pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "PEM", "SubjectPublicKeyInfo", &pem_len);
        D00_CHECK(pem != NULL
                && memcmp(pem, "-----BEGIN PUBLIC KEY-----", 26) == 0,
            "SPKI PEM armor");
        decoded = pem == NULL ? NULL
            : decode(libctx, pem, pem_len, "PEM", "SubjectPublicKeyInfo",
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        D00_CHECK(decoded != NULL && EVP_PKEY_eq(pkey, decoded) == 1,
            "SPKI PEM round trip");
        EVP_PKEY_free(decoded);
        OPENSSL_free(pem);
    }

    /* Text encoder. */
    {
        size_t text_len = 0;
        unsigned char *text = encode(pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "TEXT", NULL, &text_len);

        D00_CHECK(text != NULL
                && memmem(text, text_len, "Ed301-EdDSA-draft-00", 20)
                    != NULL
                && memmem(text, text_len, "test-only", 9) != NULL,
            "text encoding names the draft and its test-only status");
        OPENSSL_free(text);
    }

    /* Direct encrypted PKCS#8 through the provider encoder fails closed. */
    {
        OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(
            pkey,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "PrivateKeyInfo", D00_PROP);
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
        D00_CHECK(ctx != NULL && set_ok != 1 && encode_result != 1,
            "direct encrypted PKCS#8 fails closed (set_ok=%d encode=%d)",
            set_ok, encode_result);
        ERR_clear_error();
        OPENSSL_free(data);
        OSSL_ENCODER_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return d00_summary("provider_serialization");
}
