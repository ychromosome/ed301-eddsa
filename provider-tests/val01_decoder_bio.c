/*
 * VAL-01: decoder isolation and transactional TLS-test decoding.
 *
 * The ordinary and PKI artifacts expose no OSSL_DECODER.  The private-use
 * TLS artifact exposes strict DER decoders for SPKI and PKCS#8
 * PrivateKeyInfo.  Before reading, each decoder proves that the core BIO is
 * rewindable; short reads and all pre-OID mismatches restore the original
 * position.
 */

#include <openssl/buffer.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/core_object.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>

#include "harness_common.h"
#include "strict_serialization.h"
#include "vectors.h"

#define ED301V1_TLS_PKCS8_DECODER_PROP \
    "provider=ed301_eddsa_v1_tls_test,input=der,structure=PrivateKeyInfo"
#define ED301V1_TLS_SPKI_DECODER_PROP \
    "provider=ed301_eddsa_v1_tls_test,input=der,structure=SubjectPublicKeyInfo"
#define ED301V1_COLLIDER_PKCS8_DECODER_PROP \
    "provider=ed301_eddsa_v1_tls_collider,input=der,structure=PrivateKeyInfo"
#define ED301V1_COLLIDER_SPKI_DECODER_PROP \
    "provider=ed301_eddsa_v1_tls_collider,input=der,structure=SubjectPublicKeyInfo"

static unsigned char *make_der(
    OSSL_LIB_CTX *libctx,
    int is_public,
    size_t *der_length)
{
    EVP_PKEY *key = ed301v1_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    OSSL_ENCODER_CTX *encoder = key == NULL ? NULL
        : OSSL_ENCODER_CTX_new_for_pkey(
            key,
            is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
            "DER",
            is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
            ED301V1_PKI_PROP);
    unsigned char *der = NULL;

    *der_length = 0;
    if (encoder == NULL
            || OSSL_ENCODER_to_data(encoder, &der, der_length) != 1) {
        OPENSSL_free(der);
        der = NULL;
    }
    OSSL_ENCODER_CTX_free(encoder);
    EVP_PKEY_free(key);
    return der;
}

static OSSL_DECODER_CTX *tls_decoder_context(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY **key,
    int is_public)
{
    return OSSL_DECODER_CTX_new_for_pkey(
        key,
        "DER",
        is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
        ED301V1_ALG,
        is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
        libctx,
        ED301V1_TLS_PROP);
}

static EVP_PKEY *tls_decode_data(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *decoder = tls_decoder_context(
        libctx, &key, is_public);
    const unsigned char *cursor = data;
    size_t remaining = data_length;

    if (decoder == NULL
            || OSSL_DECODER_from_data(decoder, &cursor, &remaining) != 1
            || remaining != 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    OSSL_DECODER_CTX_free(decoder);
    ERR_clear_error();
    return key;
}

static unsigned char *pem_from_der(
    const unsigned char *der,
    size_t der_length,
    size_t *pem_length)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BUF_MEM *memory = NULL;
    unsigned char *pem = NULL;
    int write_result;
    long memory_result;

    *pem_length = 0;
    write_result = bio != NULL && der != NULL && der_length <= LONG_MAX
        ? PEM_write_bio(bio, PEM_STRING_PKCS8INF, "", der,
            (long)der_length)
        : 0;
    memory_result = write_result > 0 ? BIO_get_mem_ptr(bio, &memory) : 0;
    if (write_result > 0 && memory_result > 0 && memory != NULL
            && memory->length != 0) {
        pem = OPENSSL_memdup(memory->data, memory->length);
        if (pem != NULL)
            *pem_length = memory->length;
    }
    BIO_free(bio);
    return pem;
}

static int decoder_password(
    char *buffer,
    int buffer_length,
    int reading,
    void *argument)
{
    const char *password = argument;
    size_t password_length;

    (void)reading;
    if (buffer == NULL || buffer_length <= 0 || password == NULL)
        return -1;
    password_length = strlen(password);
    if (password_length > (size_t)buffer_length)
        return -1;
    memcpy(buffer, password, password_length);
    return (int)password_length;
}

static unsigned char *encrypted_pem_from_der(
    OSSL_LIB_CTX *libctx,
    const unsigned char *der,
    size_t der_length,
    const char *password,
    size_t *pem_length)
{
    const unsigned char *cursor = der;
    PKCS8_PRIV_KEY_INFO *private_key_info = NULL;
    EVP_CIPHER *cipher = NULL;
    X509_SIG *encrypted = NULL;
    BIO *bio = NULL;
    BUF_MEM *memory = NULL;
    unsigned char *pem = NULL;

    *pem_length = 0;
    if (der == NULL || der_length > LONG_MAX || password == NULL)
        return NULL;
    private_key_info = d2i_PKCS8_PRIV_KEY_INFO(
        NULL, &cursor, (long)der_length);
    cipher = EVP_CIPHER_fetch(libctx, "AES-256-CBC", "provider=default");
    if (private_key_info != NULL && cursor == der + der_length
            && cipher != NULL)
        encrypted = PKCS8_encrypt_ex(-1, cipher, password,
            (int)strlen(password), NULL, 0, 2048, private_key_info,
            libctx, "provider=default");
    bio = encrypted == NULL ? NULL : BIO_new(BIO_s_mem());
    if (bio != NULL && PEM_write_bio_PKCS8(bio, encrypted) > 0
            && BIO_get_mem_ptr(bio, &memory) > 0 && memory != NULL
            && memory->length != 0) {
        pem = OPENSSL_memdup(memory->data, memory->length);
        if (pem != NULL)
            *pem_length = memory->length;
    }
    BIO_free(bio);
    X509_SIG_free(encrypted);
    EVP_CIPHER_free(cipher);
    PKCS8_PRIV_KEY_INFO_free(private_key_info);
    return pem;
}

static EVP_PKEY *pem_decode_private(
    OSSL_LIB_CTX *libctx,
    const unsigned char *pem,
    size_t pem_length,
    const char *password)
{
    BIO *bio = pem_length > INT_MAX ? NULL
        : BIO_new_mem_buf(pem, (int)pem_length);
    EVP_PKEY *key = bio == NULL ? NULL
        : PEM_read_bio_PrivateKey_ex(bio, NULL,
            password == NULL ? NULL : decoder_password,
            (void *)password, libctx, NULL);

    BIO_free(bio);
    return key;
}

static int private_key_matches_vector(EVP_PKEY *key)
{
    const OSSL_PROVIDER *provider = key == NULL ? NULL
        : EVP_PKEY_get0_provider(key);
    unsigned char seed[ED301V1_SEED_BYTES] = { 0 };
    unsigned char public_key[ED301V1_PUB_BYTES] = { 0 };
    size_t seed_length = sizeof(seed);
    size_t public_length = sizeof(public_key);

    return key != NULL && provider != NULL
        && strcmp(OSSL_PROVIDER_get0_name(provider), ED301V1_TLS_PROVIDER) == 0
        && EVP_PKEY_is_a(key, ED301V1_ALG) == 1
        && EVP_PKEY_get_raw_private_key(key, seed, &seed_length) == 1
        && seed_length == sizeof(seed)
        && CRYPTO_memcmp(seed, POSITIVE_CASES[0].seed, sizeof(seed)) == 0
        && EVP_PKEY_get_raw_public_key(
            key, public_key, &public_length) == 1
        && public_length == sizeof(public_key)
        && CRYPTO_memcmp(public_key, POSITIVE_CASES[0].public_key,
            sizeof(public_key)) == 0;
}

static int private_key_signs_for_public(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *public_key)
{
    unsigned char signature[ED301V1_SIG_BYTES];

    return ed301v1_digest_sign(libctx, private_key,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
            signature)
        && CRYPTO_memcmp(signature, POSITIVE_CASES[0].signature,
            sizeof(signature)) == 0
        && ed301v1_digest_verify(libctx, public_key,
            POSITIVE_CASES[0].message, POSITIVE_CASES[0].message_len,
            signature, sizeof(signature));
}

static int record_construct(
    OSSL_DECODER_INSTANCE *decoder_instance,
    const OSSL_PARAM *parameters,
    void *construct_argument)
{
    int *constructed = construct_argument;
    const OSSL_PARAM *data_type = OSSL_PARAM_locate_const(
        parameters, OSSL_OBJECT_PARAM_DATA_TYPE);

    (void)decoder_instance;
    if (constructed == NULL || data_type == NULL || data_type->data == NULL
            || strcmp(data_type->data, ED301V1_ALG) != 0)
        return 0;
    *constructed = 1;
    return 1;
}

static int reject_construct(
    OSSL_DECODER_INSTANCE *decoder_instance,
    const OSSL_PARAM *parameters,
    void *construct_argument)
{
    int *called = construct_argument;
    const OSSL_PARAM *data_type = OSSL_PARAM_locate_const(
        parameters, OSSL_OBJECT_PARAM_DATA_TYPE);

    (void)decoder_instance;
    if (called == NULL || data_type == NULL || data_type->data == NULL
            || strcmp(data_type->data, ED301V1_ALG) != 0)
        return 0;
    *called = 1;
    return 0;
}

static OSSL_DECODER_CTX *single_tls_decoder_context_with_construct(
    OSSL_LIB_CTX *libctx,
    int is_public,
    OSSL_DECODER_CONSTRUCT *construct,
    void *construct_data,
    OSSL_DECODER **decoder_out)
{
    OSSL_DECODER_CTX *context = OSSL_DECODER_CTX_new();
    OSSL_DECODER *decoder = OSSL_DECODER_fetch(
        libctx,
        ED301V1_ALG,
        is_public ? ED301V1_TLS_SPKI_DECODER_PROP
                  : ED301V1_TLS_PKCS8_DECODER_PROP);

    *decoder_out = decoder;
    if (context == NULL || decoder == NULL || construct == NULL
            || OSSL_DECODER_CTX_add_decoder(context, decoder) != 1
            || OSSL_DECODER_CTX_set_selection(
                context,
                is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR) != 1
            || OSSL_DECODER_CTX_set_input_type(context, "DER") != 1
            || OSSL_DECODER_CTX_set_input_structure(
                context,
                is_public ? "SubjectPublicKeyInfo"
                          : "PrivateKeyInfo") != 1
            || OSSL_DECODER_CTX_set_construct(context, construct) != 1
            || OSSL_DECODER_CTX_set_construct_data(
                context, construct_data) != 1) {
        OSSL_DECODER_CTX_free(context);
        context = NULL;
    }
    return context;
}

static OSSL_DECODER_CTX *single_tls_decoder_context(
    OSSL_LIB_CTX *libctx,
    int is_public,
    int *constructed,
    OSSL_DECODER **decoder_out)
{
    *constructed = 0;
    return single_tls_decoder_context_with_construct(
        libctx, is_public, record_construct, constructed, decoder_out);
}

static int rejected_input_is_unconsumed(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    OSSL_DECODER *implementation = NULL;
    int constructed = 0;
    OSSL_DECODER_CTX *decoder = single_tls_decoder_context(
        libctx, is_public, &constructed, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;
    int no_provider_error;
    unsigned long errors[ED301V1_ERROR_QUEUE_CAPACITY];
    size_t error_count;

    if (decoder == NULL || input == NULL) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ed301v1_seed_error_sentinel();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    error_count = ed301v1_drain_error_queue(
        errors, ED301V1_ERROR_QUEUE_CAPACITY);
    no_provider_error = error_count == 3
        && ERR_GET_LIB(errors[0]) == ERR_LIB_USER
        && ERR_GET_REASON(errors[0]) == ED301V1_CALLER_SENTINEL_A
        && ERR_GET_LIB(errors[1]) == ERR_LIB_USER
        && ERR_GET_REASON(errors[1]) == ED301V1_CALLER_SENTINEL_B
        && ERR_GET_LIB(errors[2]) == ERR_LIB_OSSL_DECODER;
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    return result != 1 && !constructed
        && remaining == (long)data_length && no_provider_error;
}

static int hard_failure_is_consumed_and_reported(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public,
    size_t expected_remaining)
{
    OSSL_DECODER *implementation = NULL;
    int constructed = 0;
    OSSL_DECODER_CTX *decoder = single_tls_decoder_context(
        libctx, is_public, &constructed, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;
    unsigned long error;

    if (decoder == NULL || input == NULL) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ERR_clear_error();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    error = ERR_peek_error();
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    ERR_clear_error();
    return result != 1 && !constructed
        && remaining == (long)expected_remaining && error != 0;
}

static int callback_rejection_consumes_reference(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    OSSL_DECODER *implementation = NULL;
    int called = 0;
    OSSL_DECODER_CTX *decoder =
        single_tls_decoder_context_with_construct(
            libctx, is_public, reject_construct, &called, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;

    if (decoder == NULL || input == NULL) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ERR_clear_error();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    ERR_clear_error();

    /* The existing focused Valgrind lane checks the rejected reference. */
    return result != 1 && called == 1 && remaining == 0;
}

static int retry_every_split(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public)
{
    size_t split;

    for (split = 1; split < data_length; split++) {
        OSSL_DECODER *implementation = NULL;
        int constructed = 0;
        OSSL_DECODER_CTX *decoder = single_tls_decoder_context(
            libctx, is_public, &constructed, &implementation);
        BIO *reader = NULL;
        BIO *writer = NULL;
        int ok = decoder != NULL
            && BIO_new_bio_pair(&reader, 0, &writer, 0) == 1
            && BIO_write(writer, data, (int)split) == (int)split;

        if (ok) {
            ok = BIO_ctrl_pending(reader) == split
                && OSSL_DECODER_from_bio(decoder, reader) != 1
                && !constructed
                && BIO_ctrl_pending(reader) == split;
            if (!ok)
                fprintf(stderr,
                    "retry split %zu/%zu consumed an incomplete prefix\n",
                    split, data_length);
            ERR_clear_error();
        }
        if (ok) {
            ok = BIO_write(
                    writer,
                    data + split,
                    (int)(data_length - split))
                    == (int)(data_length - split)
                && OSSL_DECODER_from_bio(decoder, reader) == 1
                && constructed;
            if (!ok)
                fprintf(stderr,
                    "retry split %zu/%zu did not resume exact decoding\n",
                    split, data_length);
        }
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(reader);
        BIO_free(writer);
        ERR_clear_error();
        if (!ok)
            return 0;
    }
    return 1;
}

static int wrong_selection_is_unconsumed(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length)
{
    OSSL_DECODER *implementation = NULL;
    int constructed = 0;
    OSSL_DECODER_CTX *decoder = single_tls_decoder_context_with_construct(
        libctx, 0, record_construct, &constructed, &implementation);
    BIO *input = BIO_new_mem_buf(data, (int)data_length);
    int result;
    long remaining;

    if (decoder == NULL || input == NULL
            || OSSL_DECODER_CTX_set_selection(
                decoder, EVP_PKEY_PUBLIC_KEY) != 1) {
        OSSL_DECODER_CTX_free(decoder);
        OSSL_DECODER_free(implementation);
        BIO_free(input);
        return 0;
    }
    ERR_clear_error();
    result = OSSL_DECODER_from_bio(decoder, input);
    remaining = BIO_ctrl_pending(input);
    OSSL_DECODER_CTX_free(decoder);
    OSSL_DECODER_free(implementation);
    BIO_free(input);
    ERR_clear_error();
    return result != 1 && !constructed
        && remaining == (long)data_length;
}

static int fresh_context_private_load(
    const unsigned char *pem,
    size_t pem_length,
    int rounds)
{
    int round;

    for (round = 0; round < rounds; round++) {
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = NULL;
        OSSL_PROVIDER *tls = libctx == NULL ? NULL
            : ed301v1_load_named(
                libctx, &deflt, ED301V1_TLS_PROVIDER);
        EVP_PKEY *key = tls == NULL ? NULL
            : pem_decode_private(libctx, pem, pem_length, NULL);
        unsigned char signature[ED301V1_SIG_BYTES];
        int ok = private_key_matches_vector(key)
            && ed301v1_digest_sign(libctx, key,
                POSITIVE_CASES[0].message,
                POSITIVE_CASES[0].message_len, signature)
            && CRYPTO_memcmp(signature, POSITIVE_CASES[0].signature,
                sizeof(signature)) == 0;

        EVP_PKEY_free(key);
        OSSL_PROVIDER_unload(tls);
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
        ERR_clear_error();
        if (!ok)
            return 0;
    }
    return 1;
}

static EVP_PKEY *make_foreign_key(OSSL_LIB_CTX *libctx, const char *name)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, name, "provider=default");
    EVP_PKEY *key = NULL;
    int ok = context != NULL && EVP_PKEY_keygen_init(context) == 1;

    if (ok && strcmp(name, "RSA") == 0)
        ok = EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) == 1;
    if (ok && strcmp(name, "EC") == 0)
        ok = EVP_PKEY_CTX_set_group_name(context, "prime256v1") == 1;
    if (!ok || EVP_PKEY_generate(context, &key) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static unsigned char *encode_foreign_key(
    EVP_PKEY *key,
    int is_public,
    size_t *encoded_length)
{
    OSSL_ENCODER_CTX *encoder = key == NULL ? NULL
        : OSSL_ENCODER_CTX_new_for_pkey(
            key,
            is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
            "DER",
            is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
            "provider=default");
    unsigned char *encoded = NULL;

    *encoded_length = 0;
    if (encoder == NULL
            || OSSL_ENCODER_to_data(
                encoder, &encoded, encoded_length) != 1) {
        OPENSSL_free(encoded);
        encoded = NULL;
    }
    OSSL_ENCODER_CTX_free(encoder);
    return encoded;
}

static int generic_decode_is(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length,
    int is_public,
    const char *expected_type)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *decoder = OSSL_DECODER_CTX_new_for_pkey(
        &key,
        "DER",
        is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
        NULL,
        is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
        libctx,
        NULL);
    const unsigned char *cursor = data;
    size_t remaining = data_length;
    int ok;
    int queue_unchanged;

    ed301v1_seed_error_sentinel();
    ok = decoder != NULL
        && OSSL_DECODER_from_data(decoder, &cursor, &remaining) == 1
        && remaining == 0 && key != NULL
        && EVP_PKEY_is_a(key, expected_type) == 1;
    queue_unchanged = ed301v1_queue_is_sentinel_only();

    OSSL_DECODER_CTX_free(decoder);
    EVP_PKEY_free(key);
    return ok && queue_unchanged;
}

int main(void)
{
    ED301V1_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *reverse_libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = NULL;
    OSSL_PROVIDER *tls = NULL;
    OSSL_PROVIDER *collider = NULL;
    OSSL_PROVIDER *reverse_tls = NULL;
    OSSL_PROVIDER *reverse_default = NULL;
    OSSL_DECODER *decoder;
    unsigned char *pkcs8 = NULL;
    unsigned char *spki = NULL;
    unsigned char *rsa_pkcs8 = NULL;
    unsigned char *rsa_spki = NULL;
    unsigned char *ec_pkcs8 = NULL;
    unsigned char *ec_spki = NULL;
    unsigned char *ed25519_pkcs8 = NULL;
    unsigned char *ed448_pkcs8 = NULL;
    unsigned char *pkcs8_pem = NULL;
    unsigned char *encrypted_pkcs8_pem = NULL;
    size_t pkcs8_length = 0;
    size_t spki_length = 0;
    size_t rsa_pkcs8_length = 0;
    size_t rsa_spki_length = 0;
    size_t ec_pkcs8_length = 0;
    size_t ec_spki_length = 0;
    size_t ed25519_pkcs8_length = 0;
    size_t ed448_pkcs8_length = 0;
    size_t pkcs8_pem_length = 0;
    size_t encrypted_pkcs8_pem_length = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY *rsa = NULL;
    EVP_PKEY *ec = NULL;
    EVP_PKEY *ed25519 = NULL;
    EVP_PKEY *ed448 = NULL;
    unsigned char foreign[ED301V1_PKCS8_DER_BYTES + 1] = { 0 };
    unsigned char malformed[160] = { 0 };

    ed301v1_property = ED301V1_PKI_PROP;
    v1 = ed301v1_load_named(libctx, &deflt, ED301V1_PKI_PROVIDER);
    ED301V1_CHECK(libctx != NULL && v1 != NULL,
        "test-only PKI provider loads through the host integration gate");

    decoder = OSSL_DECODER_fetch(libctx, ED301V1_ALG, ED301V1_PKI_PROP);
    ED301V1_CHECK(decoder == NULL,
        "PKI artifact exposes no provider decoder operation");
    OSSL_DECODER_free(decoder);
    ERR_clear_error();

    pkcs8 = make_der(libctx, 0, &pkcs8_length);
    spki = make_der(libctx, 1, &spki_length);
    ED301V1_CHECK(pkcs8 != NULL && pkcs8_length == ED301V1_PKCS8_DER_BYTES,
        "exact PKCS#8 test object produced");
    ED301V1_CHECK(spki != NULL && spki_length == ED301V1_SPKI_DER_BYTES,
        "exact SPKI test object produced");

    key = ed301v1_strict_der_import(libctx, pkcs8, pkcs8_length, 0);
    ED301V1_CHECK(key != NULL,
        "complete-buffer PKCS#8 import succeeds after explicit selection");
    EVP_PKEY_free(key);
    key = NULL;

    key = ed301v1_strict_der_import(libctx, spki, spki_length, 1);
    ED301V1_CHECK(key != NULL,
        "complete-buffer SPKI import succeeds after explicit selection");
    EVP_PKEY_free(key);
    key = NULL;

    if (pkcs8 != NULL) {
        memcpy(foreign, pkcs8, pkcs8_length);
        foreign[10] ^= 1;
        ED301V1_CHECK(ed301v1_strict_der_import(
                libctx, foreign, pkcs8_length, 0) == NULL,
            "foreign OID is rejected before any key import");
        ED301V1_CHECK(ed301v1_strict_der_import(
                libctx, pkcs8, pkcs8_length - 1, 0) == NULL,
            "partial input is rejected without a streaming state");
        foreign[10] ^= 1;
        foreign[pkcs8_length] = 0;
        ED301V1_CHECK(ed301v1_strict_der_import(
                libctx, foreign, pkcs8_length + 1, 0) == NULL,
            "trailing bytes are rejected at the complete-buffer boundary");
    }

    tls = ed301v1_load_named(libctx, NULL, ED301V1_TLS_PROVIDER);
    ED301V1_CHECK(tls != NULL,
        "TLS artifact loads after the exact host registry preflight");
    ed301v1_property = ED301V1_TLS_PROP;
    decoder = OSSL_DECODER_fetch(
        libctx, ED301V1_ALG, ED301V1_TLS_SPKI_DECODER_PROP);
    ED301V1_CHECK(decoder != NULL,
        "TLS artifact exposes the transactional SPKI DER decoder");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(
        libctx, ED301V1_ALG, ED301V1_TLS_PKCS8_DECODER_PROP);
    ED301V1_CHECK(decoder != NULL,
        "TLS artifact exposes the strict PKCS#8 DER decoder");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(
        libctx, ED301V1_OID_TEXT, ED301V1_TLS_PKCS8_DECODER_PROP);
    ED301V1_CHECK(decoder != NULL,
        "canonical v1 OID resolves to the TLS PKCS#8 decoder");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(libctx,
        "1.3.6.1.4.1.66282.301.3", ED301V1_TLS_PKCS8_DECODER_PROP);
    ED301V1_CHECK(decoder == NULL,
        "historical Ed301 OID is not a decoder alias");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(libctx,
        "1.3.6.1.4.1.66282.301.2", ED301V1_TLS_PKCS8_DECODER_PROP);
    ED301V1_CHECK(decoder == NULL,
        "X301 OID is not an Ed301 decoder alias");
    OSSL_DECODER_free(decoder);
    ERR_clear_error();

    collider = ed301v1_load_named(
        libctx, NULL, ED301V1_TLS_COLLIDER_PROVIDER);
    decoder = collider == NULL ? NULL : OSSL_DECODER_fetch(
        libctx, ED301V1_ALG, ED301V1_COLLIDER_PKCS8_DECODER_PROP);
    ED301V1_CHECK(collider != NULL && decoder == NULL,
        "TLS collider remains without a private-key decoder");
    OSSL_DECODER_free(decoder);
    decoder = collider == NULL ? NULL : OSSL_DECODER_fetch(
        libctx, ED301V1_ALG, ED301V1_COLLIDER_SPKI_DECODER_PROP);
    ED301V1_CHECK(decoder != NULL,
        "TLS collider retains its SPKI-only decoder surface");
    OSSL_DECODER_free(decoder);
    OSSL_PROVIDER_unload(collider);
    collider = NULL;
    ERR_clear_error();

    if (tls != NULL && pkcs8 != NULL && spki != NULL) {
        key = tls_decode_data(libctx, pkcs8, pkcs8_length, 0);
        public_key = tls_decode_data(libctx, spki, spki_length, 1);
        ED301V1_CHECK(private_key_matches_vector(key),
            "TLS decoder imports the exact PKCS#8 seed and public key");
        ED301V1_CHECK(public_key != NULL
                && private_key_signs_for_public(libctx, key, public_key),
            "PKCS#8-loaded private key signs for the decoded public key");
        EVP_PKEY_free(key);
        key = NULL;
        EVP_PKEY_free(public_key);
        public_key = NULL;

        pkcs8_pem = pem_from_der(
            pkcs8, pkcs8_length, &pkcs8_pem_length);
        key = pkcs8_pem == NULL ? NULL : pem_decode_private(
            libctx, pkcs8_pem, pkcs8_pem_length, NULL);
        ED301V1_CHECK(private_key_matches_vector(key),
            "generic OpenSSL PEM chain reaches the TLS PKCS#8 decoder");
        EVP_PKEY_free(key);
        key = NULL;

        encrypted_pkcs8_pem = encrypted_pem_from_der(libctx,
            pkcs8, pkcs8_length, "ed301-decoder-test",
            &encrypted_pkcs8_pem_length);
        key = encrypted_pkcs8_pem == NULL ? NULL : pem_decode_private(
            libctx, encrypted_pkcs8_pem, encrypted_pkcs8_pem_length,
            "ed301-decoder-test");
        ED301V1_CHECK(private_key_matches_vector(key),
            "generic EncryptedPrivateKeyInfo chain reaches the TLS decoder");
        EVP_PKEY_free(key);
        key = NULL;
        key = encrypted_pkcs8_pem == NULL ? NULL : pem_decode_private(
            libctx, encrypted_pkcs8_pem, encrypted_pkcs8_pem_length,
            "wrong-password");
        ED301V1_CHECK(key == NULL,
            "encrypted PKCS#8 rejects the wrong password");
        EVP_PKEY_free(key);
        key = NULL;

        key = tls_decode_data(libctx, spki, spki_length, 1);
        ED301V1_CHECK(key != NULL,
            "TLS decoder imports one exact SPKI object");
        EVP_PKEY_free(key);
        key = NULL;

        ED301V1_CHECK(retry_every_split(
                libctx, spki, spki_length, 1),
            "SPKI retry source remains untouched at every split");
        ED301V1_CHECK(retry_every_split(
                libctx, pkcs8, pkcs8_length, 0),
            "PKCS#8 retry source remains untouched at every split");

        memcpy(foreign, spki, spki_length);
        foreign[8] ^= 1;
        ED301V1_CHECK(rejected_input_is_unconsumed(
                libctx, foreign, spki_length, 1),
            "foreign SPKI OID is a soft non-match without consumption");
        ED301V1_CHECK(rejected_input_is_unconsumed(
                libctx, spki, spki_length - 1, 1),
            "partial SPKI is a soft non-match before consuming its prefix");

        memcpy(foreign, pkcs8, pkcs8_length);
        foreign[19] = 0x01;
        ED301V1_CHECK(rejected_input_is_unconsumed(
                libctx, foreign, pkcs8_length, 0),
            "historical Ed301 PKCS#8 OID is a soft non-match");
        foreign[19] = 0x02;
        ED301V1_CHECK(rejected_input_is_unconsumed(
                libctx, foreign, pkcs8_length, 0),
            "X301 PKCS#8 OID is a soft non-match");
        ED301V1_CHECK(rejected_input_is_unconsumed(
                libctx, pkcs8, pkcs8_length - 1, 0),
            "partial PKCS#8 is retryable without input or error damage");
        ED301V1_CHECK(wrong_selection_is_unconsumed(
                libctx, pkcs8, pkcs8_length),
            "PKCS#8 decoder rejects a public-only selection unconsumed");

        memcpy(foreign, spki, spki_length);
        foreign[2] ^= 1;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, foreign, spki_length, 1, 0),
            "malformed confirmed-OID SPKI is a consuming hard failure");

        memcpy(foreign, spki, spki_length);
        memcpy(foreign + sizeof(ED301V1_SPKI_PREFIX),
            POINT_CASES[2].encoding, ED301V1_PUB_BYTES); /* identity */
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, foreign, spki_length, 1, 0),
            "confirmed-OID SPKI with invalid key material is a consuming "
            "hard failure");

        ED301V1_CHECK(callback_rejection_consumes_reference(
                libctx, spki, spki_length, 1),
            "construct-callback rejection consumes the matched object; "
            "Valgrind checks reference release");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[2] ^= 1;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "malformed confirmed-OID PKCS#8 is a consuming hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[4] = 0x01;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "OneAsymmetricKey version is a consuming hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[21] = 0x27;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "wrong outer private OCTET STRING length is a hard failure");
        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[22] = 0x03;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "wrong private-key nesting is a consuming hard failure");
        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[23] = 0x25;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length, 0, 0),
            "wrong seed length is a consuming hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[1] = 0x3d;
        malformed[pkcs8_length] = 0x00;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 1, 0,
                1),
            "additional PKCS#8 content is a hard failure");

        memset(malformed, 0, sizeof(malformed));
        malformed[0] = 0x30;
        malformed[1] = 0x3e;
        malformed[2] = 0x02;
        malformed[3] = 0x01;
        malformed[4] = 0x00;
        malformed[5] = 0x30;
        malformed[6] = 0x0f;
        memcpy(malformed + 7, pkcs8 + 7, ED301V1_OID_TLV_BYTES);
        malformed[20] = 0x05;
        malformed[21] = 0x00;
        memcpy(malformed + 22, pkcs8 + 20, pkcs8_length - 20);
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 2, 0,
                2),
            "PKCS#8 NULL parameters are a hard failure");
        malformed[20] = 0x04;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 2, 0,
                2),
            "PKCS#8 explicit parameters are a hard failure");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[1] = 0x3b;
        malformed[21] = 0x27;
        malformed[23] = 0x25;
        ED301V1_CHECK(rejected_input_is_unconsumed(
                libctx, malformed, pkcs8_length - 1, 0),
            "37-byte seed form remains retryable and is not imported");

        memcpy(malformed, pkcs8, pkcs8_length);
        malformed[1] = 0x3d;
        malformed[21] = 0x29;
        malformed[23] = 0x27;
        malformed[pkcs8_length] = 0x00;
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 1, 0,
                1),
            "39-byte seed form is not partially imported");

        memcpy(malformed, pkcs8, 20);
        malformed[0] = 0x30;
        malformed[1] = 0x3d;
        malformed[20] = 0x04;
        malformed[21] = 0x81;
        malformed[22] = 0x28;
        memcpy(malformed + 23, pkcs8 + 22, pkcs8_length - 22);
        ED301V1_CHECK(hard_failure_is_consumed_and_reported(
                libctx, malformed, pkcs8_length + 1, 0,
                1),
            "non-minimal inner DER length is a hard failure");

        malformed[0] = 0x30;
        malformed[1] = 0x81;
        malformed[2] = pkcs8[1];
        memcpy(malformed + 3, pkcs8 + 2, pkcs8_length - 2);
        ED301V1_CHECK(rejected_input_is_unconsumed(
                libctx, malformed, pkcs8_length + 1, 0),
            "non-minimal outer DER length is rejected without chain damage");

        ED301V1_CHECK(callback_rejection_consumes_reference(
                libctx, pkcs8, pkcs8_length, 0),
            "private construct rejection releases the matched reference");
    }

    rsa = make_foreign_key(libctx, "RSA");
    ec = make_foreign_key(libctx, "EC");
    ed25519 = make_foreign_key(libctx, "ED25519");
    ed448 = make_foreign_key(libctx, "ED448");
    rsa_pkcs8 = encode_foreign_key(rsa, 0, &rsa_pkcs8_length);
    rsa_spki = encode_foreign_key(rsa, 1, &rsa_spki_length);
    ec_pkcs8 = encode_foreign_key(ec, 0, &ec_pkcs8_length);
    ec_spki = encode_foreign_key(ec, 1, &ec_spki_length);
    ed25519_pkcs8 = encode_foreign_key(
        ed25519, 0, &ed25519_pkcs8_length);
    ed448_pkcs8 = encode_foreign_key(ed448, 0, &ed448_pkcs8_length);
    ED301V1_CHECK(rsa_pkcs8 != NULL && rsa_spki != NULL
            && ec_pkcs8 != NULL && ec_spki != NULL
            && ed25519_pkcs8 != NULL && ed448_pkcs8 != NULL,
        "foreign RSA, EC, Ed25519 and Ed448 controls are available");

    if (rsa_pkcs8 != NULL && rsa_spki != NULL
            && ec_pkcs8 != NULL && ec_spki != NULL
            && ed25519_pkcs8 != NULL && ed448_pkcs8 != NULL) {
        ED301V1_CHECK(generic_decode_is(libctx, rsa_pkcs8,
                rsa_pkcs8_length, 0, "RSA")
                && generic_decode_is(libctx, rsa_spki,
                    rsa_spki_length, 1, "RSA")
                && generic_decode_is(libctx, ec_pkcs8,
                    ec_pkcs8_length, 0, "EC")
                && generic_decode_is(libctx, ec_spki,
                    ec_spki_length, 1, "EC")
                && generic_decode_is(libctx, ed25519_pkcs8,
                    ed25519_pkcs8_length, 0, "ED25519")
                && generic_decode_is(libctx, ed448_pkcs8,
                    ed448_pkcs8_length, 0, "ED448"),
            "generic foreign-key decoding survives default-first order");

        reverse_libctx = OSSL_LIB_CTX_new();
        reverse_tls = reverse_libctx == NULL ? NULL
            : OSSL_PROVIDER_load(reverse_libctx, ED301V1_TLS_PROVIDER);
        reverse_default = reverse_libctx == NULL ? NULL
            : OSSL_PROVIDER_load(reverse_libctx, "default");
        ED301V1_CHECK(reverse_tls != NULL && reverse_default != NULL,
            "reverse-order TLS/default providers load");
        ED301V1_CHECK(reverse_tls != NULL && reverse_default != NULL
                && generic_decode_is(reverse_libctx, rsa_pkcs8,
                    rsa_pkcs8_length, 0, "RSA")
                && generic_decode_is(reverse_libctx, rsa_spki,
                    rsa_spki_length, 1, "RSA")
                && generic_decode_is(reverse_libctx, ec_pkcs8,
                    ec_pkcs8_length, 0, "EC")
                && generic_decode_is(reverse_libctx, ec_spki,
                    ec_spki_length, 1, "EC")
                && generic_decode_is(reverse_libctx, ed25519_pkcs8,
                    ed25519_pkcs8_length, 0, "ED25519")
                && generic_decode_is(reverse_libctx, ed448_pkcs8,
                    ed448_pkcs8_length, 0, "ED448"),
            "generic foreign-key decoding survives TLS-first order");
    }

    ED301V1_CHECK(pkcs8_pem != NULL
            && fresh_context_private_load(pkcs8_pem, pkcs8_pem_length, 8),
        "PKCS#8 PEM reloads in fresh library contexts");

    OSSL_PROVIDER_unload(tls);
    tls = OSSL_PROVIDER_load(libctx, ED301V1_TLS_PROVIDER);
    key = tls == NULL || pkcs8_pem == NULL ? NULL
        : pem_decode_private(libctx, pkcs8_pem, pkcs8_pem_length, NULL);
    ED301V1_CHECK(tls != NULL && private_key_matches_vector(key),
        "PKCS#8 decoder reloads without retaining an old key reference");
    EVP_PKEY_free(key);
    key = NULL;

    OPENSSL_clear_free(pkcs8, pkcs8_length);
    OPENSSL_free(spki);
    OPENSSL_clear_free(rsa_pkcs8, rsa_pkcs8_length);
    OPENSSL_free(rsa_spki);
    OPENSSL_clear_free(ec_pkcs8, ec_pkcs8_length);
    OPENSSL_free(ec_spki);
    OPENSSL_clear_free(ed25519_pkcs8, ed25519_pkcs8_length);
    OPENSSL_clear_free(ed448_pkcs8, ed448_pkcs8_length);
    OPENSSL_clear_free(pkcs8_pem, pkcs8_pem_length);
    OPENSSL_clear_free(
        encrypted_pkcs8_pem, encrypted_pkcs8_pem_length);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(ed25519);
    EVP_PKEY_free(ed448);
    OSSL_PROVIDER_unload(reverse_default);
    OSSL_PROVIDER_unload(reverse_tls);
    OSSL_LIB_CTX_free(reverse_libctx);
    OSSL_PROVIDER_unload(collider);
    OSSL_PROVIDER_unload(tls);
    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return ed301v1_summary("val01_transactional_tls_decoder");
}
