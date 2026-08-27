#ifndef ED301D00_STRICT_SERIALIZATION_H
#define ED301D00_STRICT_SERIALIZATION_H

/*
 * Project-owned, complete-buffer import boundary for the test-only PKI
 * profile.  The PKI artifact deliberately exposes encoders but no
 * OSSL_DECODER, so private-key import never joins a generic decoder chain.
 * The separate TLS artifact has only the transactional SPKI decoder needed
 * for peer certificates on the wire.
 */

#include <openssl/pem.h>

#include "harness_common.h"

static const unsigned char D00_PKCS8_PREFIX[24] = {
    0x30, 0x3c, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06,
    0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x85,
    0x6a, 0x82, 0x2d, 0x04, 0x04, 0x28, 0x04, 0x26
};

static const unsigned char D00_SPKI_PREFIX[20] = {
    0x30, 0x38, 0x30, 0x0d, 0x06, 0x0b, 0x2b, 0x06,
    0x01, 0x04, 0x01, 0x84, 0x85, 0x6a, 0x82, 0x2d,
    0x04, 0x03, 0x27, 0x00
};

#define D00_OID_TLV_BYTES ((size_t)13)
#define D00_PKCS8_DER_BYTES \
    (sizeof(D00_PKCS8_PREFIX) + D00_SEED_BYTES)
#define D00_SPKI_DER_BYTES \
    (sizeof(D00_SPKI_PREFIX) + D00_PUB_BYTES)

_Static_assert(D00_PKCS8_DER_BYTES == 62,
    "v1 PKCS#8 must be exactly 62 bytes");
_Static_assert(D00_SPKI_DER_BYTES == 58,
    "v1 SPKI must be exactly 58 bytes");

static inline EVP_PKEY *d00_strict_der_import(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    const unsigned char *prefix = is_public
        ? D00_SPKI_PREFIX : D00_PKCS8_PREFIX;
    const size_t prefix_length = is_public
        ? sizeof(D00_SPKI_PREFIX) : sizeof(D00_PKCS8_PREFIX);
    const size_t expected_length = prefix_length + D00_SEED_BYTES;

    if (data == NULL || data_length != expected_length
            || CRYPTO_memcmp(data, prefix, prefix_length) != 0)
        return NULL;
    if (is_public)
        return d00_key_from_public(
            libctx, data + prefix_length, D00_PUB_BYTES);
    return d00_key_from_seed(libctx, data + prefix_length);
}

static inline EVP_PKEY *d00_strict_pem_import(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    BIO *bio = NULL;
    char *name = NULL;
    char *header = NULL;
    unsigned char *der = NULL;
    long der_length = 0;
    EVP_PKEY *key = NULL;
    unsigned char trailing;
    const char *expected_name = is_public ? PEM_STRING_PUBLIC
        : PEM_STRING_PKCS8INF;

    if (data == NULL || data_length > INT_MAX)
        return NULL;
    bio = BIO_new_mem_buf(data, (int)data_length);
    if (bio == NULL
            || PEM_read_bio(bio, &name, &header, &der, &der_length) != 1
            || name == NULL || strcmp(name, expected_name) != 0
            || header == NULL || header[0] != '\0'
            || der_length < 0
            || BIO_read(bio, &trailing, 1) > 0)
        goto cleanup;
    key = d00_strict_der_import(
        libctx, der, (size_t)der_length, is_public);

cleanup:
    if (der != NULL)
        OPENSSL_clear_free(der, der_length < 0 ? 0 : (size_t)der_length);
    OPENSSL_free(header);
    OPENSSL_free(name);
    BIO_free(bio);
    return key;
}

#endif
