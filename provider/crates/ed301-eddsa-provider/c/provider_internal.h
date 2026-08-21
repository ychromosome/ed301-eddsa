#ifndef ED301D00_PROVIDER_INTERNAL_H
#define ED301D00_PROVIDER_INTERNAL_H

/*
 * Internal contract between the C provider shim and the Rust callback table
 * for the experimental Ed301-EdDSA-draft-00 signature-only provider.
 *
 * Adapted from the historical provider's provider_internal.h dispatch shape
 * (see the result provenance map).  The X301/KEM surface, the context-string
 * callback and the historical identity are intentionally absent.
 */

#include <stddef.h>
#include <stdint.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

typedef struct ed301d00_signature_rust_api_st {
    uint32_t abi_version;
    size_t struct_size;
    size_t seed_bytes;
    size_t public_key_bytes;
    size_t signature_bytes;
    void *(*key_new)(void);
    void (*key_free)(void *key);
    int (*key_import)(
        void *key,
        const unsigned char *private_key,
        size_t private_length,
        const unsigned char *public_key,
        size_t public_length);
    int (*key_set_encoded_public)(
        void *key,
        const unsigned char *public_key,
        size_t public_length);
    void *(*key_generate)(void);
    void *(*key_duplicate)(
        const void *source,
        int include_private,
        int include_public);
    int (*key_has)(
        const void *key,
        int require_private,
        int require_public);
    int (*key_validate)(
        const void *key,
        int validate_private,
        int validate_public);
    int (*key_match)(
        const void *first,
        const void *second,
        int match_private,
        int match_public);
    int (*key_get_private)(
        const void *key,
        unsigned char *output,
        size_t output_length);
    int (*key_get_public)(
        const void *key,
        unsigned char *output,
        size_t output_length);
    void *(*signature_new)(void);
    void (*signature_free)(void *signature);
    void *(*signature_duplicate)(const void *source);
    void (*signature_reset)(void *signature);
    int (*signature_sign_init)(void *signature, const void *key);
    int (*signature_verify_init)(void *signature, const void *key);
    int (*signature_sign)(
        const void *signature,
        const unsigned char *message,
        size_t message_length,
        unsigned char *output,
        size_t output_length);
    int (*signature_verify)(
        const void *signature,
        const unsigned char *message,
        size_t message_length,
        const unsigned char *signature_value,
        size_t signature_length);
    void (*cleanse)(unsigned char *buffer, size_t length);
} ED301D00_SIGNATURE_RUST_API;

typedef struct ed301d00_provider_context_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_FUNC_CRYPTO_zalloc_fn *zalloc;
    OSSL_FUNC_CRYPTO_clear_free_fn *clear_free;
    OSSL_FUNC_core_new_error_fn *new_error;
    OSSL_FUNC_core_set_error_debug_fn *set_error_debug;
    OSSL_FUNC_core_vset_error_fn *vset_error;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex;
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex;
    OSSL_FUNC_BIO_ctrl_fn *bio_ctrl;
    const ED301D00_SIGNATURE_RUST_API *rust;
} ED301D00_PROVIDER_CONTEXT;

#endif
