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

static const unsigned char D00_PKCS8_PREFIX[33] = {
    0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x16, 0x06,
    0x14, 0x69, 0x82, 0xa6, 0x8b, 0xcb, 0x8d, 0xb3,
    0x93, 0xe2, 0x9f, 0x8b, 0x8a, 0x9e, 0xf1, 0xc4,
    0xf2, 0xe5, 0xd7, 0xe5, 0x30, 0x04, 0x28, 0x04,
    0x26
};

static const unsigned char D00_SPKI_PREFIX[29] = {
    0x30, 0x41, 0x30, 0x16, 0x06, 0x14, 0x69, 0x82,
    0xa6, 0x8b, 0xcb, 0x8d, 0xb3, 0x93, 0xe2, 0x9f,
    0x8b, 0x8a, 0x9e, 0xf1, 0xc4, 0xf2, 0xe5, 0xd7,
    0xe5, 0x30, 0x03, 0x27, 0x00
};

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
