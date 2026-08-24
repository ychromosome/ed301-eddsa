/*
 * VAL-01: decoder isolation and transactional TLS-test decoding.
 *
 * The ordinary and PKI artifacts expose no OSSL_DECODER.  The private-use
 * TLS artifact needs an SPKI decoder for certificates received on the wire,
 * so it exposes a deliberately narrow DER decoder which accepts only a fully
 * buffered fixed-size candidate.  Before reading it proves that the core BIO
 * is rewindable; all pre-OID mismatches restore the original position.  A
 * retryable short source is declined before its first byte is consumed.
 */

#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/core_object.h>
#include <openssl/rsa.h>

#include "harness_common.h"
#include "strict_serialization.h"
#include "vectors.h"

#define D00_TLS_PKCS8_DECODER_PROP \
    "provider=ed301_eddsa_draft00_tls_test,input=der,structure=PrivateKeyInfo"
#define D00_TLS_SPKI_DECODER_PROP \
    "provider=ed301_eddsa_draft00_tls_test,input=der,structure=SubjectPublicKeyInfo"

static unsigned char *make_der(
    OSSL_LIB_CTX *libctx,
    int is_public,
    size_t *der_length)
{
    EVP_PKEY *key = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    OSSL_ENCODER_CTX *encoder = key == NULL ? NULL
        : OSSL_ENCODER_CTX_new_for_pkey(
            key,
            is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
            "DER",
            is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
            D00_PKI_PROP);
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
        D00_ALG,
        is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
        libctx,
        D00_TLS_PROP);
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
            || strcmp(data_type->data, D00_ALG) != 0)
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
            || strcmp(data_type->data, D00_ALG) != 0)
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
        D00_ALG,
        is_public ? D00_TLS_SPKI_DECODER_PROP
                  : D00_TLS_PKCS8_DECODER_PROP);

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
    return result != 1 && !constructed
        && remaining == (long)data_length;
}

static int hard_failure_is_consumed_and_reported(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length)
{
    OSSL_DECODER *implementation = NULL;
    int constructed = 0;
    OSSL_DECODER_CTX *decoder = single_tls_decoder_context(
        libctx, 1, &constructed, &implementation);
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
    return result != 1 && !constructed && remaining == 0 && error != 0;
}

static int callback_rejection_consumes_reference(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_length)
{
    OSSL_DECODER *implementation = NULL;
    int called = 0;
    OSSL_DECODER_CTX *decoder =
        single_tls_decoder_context_with_construct(
            libctx, 1, reject_construct, &called, &implementation);
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
    int ok = decoder != NULL
        && OSSL_DECODER_from_data(decoder, &cursor, &remaining) == 1
        && remaining == 0 && key != NULL
        && EVP_PKEY_is_a(key, expected_type) == 1;

    OSSL_DECODER_CTX_free(decoder);
    EVP_PKEY_free(key);
    ERR_clear_error();
    return ok;
}

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *reverse_libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    OSSL_PROVIDER *tls = NULL;
    OSSL_PROVIDER *reverse_tls = NULL;
    OSSL_PROVIDER *reverse_default = NULL;
    OSSL_DECODER *decoder;
    unsigned char *pkcs8 = NULL;
    unsigned char *spki = NULL;
    unsigned char *rsa_pkcs8 = NULL;
    unsigned char *rsa_spki = NULL;
    unsigned char *ec_pkcs8 = NULL;
    unsigned char *ec_spki = NULL;
    size_t pkcs8_length = 0;
    size_t spki_length = 0;
    size_t rsa_pkcs8_length = 0;
    size_t rsa_spki_length = 0;
    size_t ec_pkcs8_length = 0;
    size_t ec_spki_length = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY *rsa = NULL;
    EVP_PKEY *ec = NULL;
    unsigned char foreign[D00_PKCS8_DER_BYTES + 1] = { 0 };

    d00_property = D00_PKI_PROP;
    draft = d00_load_named(libctx, &deflt, D00_PKI_PROVIDER);
    D00_CHECK(libctx != NULL && draft != NULL,
        "test-only PKI provider loads through the host integration gate");

    decoder = OSSL_DECODER_fetch(libctx, D00_ALG, D00_PKI_PROP);
    D00_CHECK(decoder == NULL,
        "PKI artifact exposes no provider decoder operation");
    OSSL_DECODER_free(decoder);
    ERR_clear_error();

    pkcs8 = make_der(libctx, 0, &pkcs8_length);
    spki = make_der(libctx, 1, &spki_length);
    D00_CHECK(pkcs8 != NULL && pkcs8_length == D00_PKCS8_DER_BYTES,
        "exact PKCS#8 test object produced");
    D00_CHECK(spki != NULL && spki_length == D00_SPKI_DER_BYTES,
        "exact SPKI test object produced");

    key = d00_strict_der_import(libctx, pkcs8, pkcs8_length, 0);
    D00_CHECK(key != NULL,
        "complete-buffer PKCS#8 import succeeds after explicit selection");
    EVP_PKEY_free(key);
    key = NULL;

    key = d00_strict_der_import(libctx, spki, spki_length, 1);
    D00_CHECK(key != NULL,
        "complete-buffer SPKI import succeeds after explicit selection");
    EVP_PKEY_free(key);
    key = NULL;

    if (pkcs8 != NULL) {
        memcpy(foreign, pkcs8, pkcs8_length);
        foreign[10] ^= 1;
        D00_CHECK(d00_strict_der_import(
                libctx, foreign, pkcs8_length, 0) == NULL,
            "foreign OID is rejected before any key import");
        D00_CHECK(d00_strict_der_import(
                libctx, pkcs8, pkcs8_length - 1, 0) == NULL,
            "partial input is rejected without a streaming state");
        foreign[10] ^= 1;
        foreign[pkcs8_length] = 0;
        D00_CHECK(d00_strict_der_import(
                libctx, foreign, pkcs8_length + 1, 0) == NULL,
            "trailing bytes are rejected at the complete-buffer boundary");
    }

    tls = d00_load_named(libctx, NULL, D00_TLS_PROVIDER);
    D00_CHECK(tls != NULL,
        "TLS artifact loads after the exact host registry preflight");
    decoder = OSSL_DECODER_fetch(libctx, D00_ALG, D00_TLS_PROP);
    D00_CHECK(decoder != NULL,
        "only the TLS artifact exposes its transactional DER decoder");
    OSSL_DECODER_free(decoder);
    decoder = OSSL_DECODER_fetch(
        libctx, D00_ALG, D00_TLS_PKCS8_DECODER_PROP);
    D00_CHECK(decoder == NULL,
        "TLS artifact exposes no private-key decoder");
    OSSL_DECODER_free(decoder);
    ERR_clear_error();

    if (tls != NULL && pkcs8 != NULL && spki != NULL) {
        key = tls_decode_data(libctx, spki, spki_length, 1);
        D00_CHECK(key != NULL,
            "TLS decoder imports one exact SPKI object");
        EVP_PKEY_free(key);
        key = NULL;

        D00_CHECK(retry_every_split(
                libctx, spki, spki_length, 1),
            "SPKI retry source remains untouched at every split");

        memcpy(foreign, spki, spki_length);
        foreign[8] ^= 1;
        D00_CHECK(rejected_input_is_unconsumed(
                libctx, foreign, spki_length, 1),
            "foreign SPKI OID is a soft non-match without consumption");
        D00_CHECK(rejected_input_is_unconsumed(
                libctx, spki, spki_length - 1, 1),
            "partial SPKI is a soft non-match before consuming its prefix");

        memcpy(foreign, spki, spki_length);
        foreign[2] ^= 1;
        D00_CHECK(hard_failure_is_consumed_and_reported(
                libctx, foreign, spki_length),
            "malformed confirmed-OID SPKI is a consuming hard failure");

        memcpy(foreign, spki, spki_length);
        memcpy(foreign + sizeof(D00_SPKI_PREFIX),
            POINT_CASES[2].encoding, D00_PUB_BYTES); /* identity */
        D00_CHECK(hard_failure_is_consumed_and_reported(
                libctx, foreign, spki_length),
            "confirmed-OID SPKI with invalid key material is a consuming "
            "hard failure");

        D00_CHECK(callback_rejection_consumes_reference(
                libctx, spki, spki_length),
            "construct-callback rejection consumes the matched object; "
            "Valgrind checks reference release");
    }

    rsa = make_foreign_key(libctx, "RSA");
    ec = make_foreign_key(libctx, "EC");
    rsa_pkcs8 = encode_foreign_key(rsa, 0, &rsa_pkcs8_length);
    rsa_spki = encode_foreign_key(rsa, 1, &rsa_spki_length);
    ec_pkcs8 = encode_foreign_key(ec, 0, &ec_pkcs8_length);
    ec_spki = encode_foreign_key(ec, 1, &ec_spki_length);
    D00_CHECK(rsa_pkcs8 != NULL && rsa_spki != NULL
            && ec_pkcs8 != NULL && ec_spki != NULL,
        "foreign RSA and EC PKCS#8/SPKI controls are available");

    if (rsa_pkcs8 != NULL && rsa_spki != NULL
            && ec_pkcs8 != NULL && ec_spki != NULL) {
        D00_CHECK(generic_decode_is(libctx, rsa_pkcs8,
                rsa_pkcs8_length, 0, "RSA")
                && generic_decode_is(libctx, rsa_spki,
                    rsa_spki_length, 1, "RSA")
                && generic_decode_is(libctx, ec_pkcs8,
                    ec_pkcs8_length, 0, "EC")
                && generic_decode_is(libctx, ec_spki,
                    ec_spki_length, 1, "EC"),
            "generic foreign-key decoding survives default-first order");

        reverse_libctx = OSSL_LIB_CTX_new();
        reverse_tls = reverse_libctx == NULL ? NULL
            : OSSL_PROVIDER_load(reverse_libctx, D00_TLS_PROVIDER);
        reverse_default = reverse_libctx == NULL ? NULL
            : OSSL_PROVIDER_load(reverse_libctx, "default");
        D00_CHECK(reverse_tls != NULL && reverse_default != NULL,
            "reverse-order TLS/default providers load");
        D00_CHECK(reverse_tls != NULL && reverse_default != NULL
                && generic_decode_is(reverse_libctx, rsa_pkcs8,
                    rsa_pkcs8_length, 0, "RSA")
                && generic_decode_is(reverse_libctx, rsa_spki,
                    rsa_spki_length, 1, "RSA")
                && generic_decode_is(reverse_libctx, ec_pkcs8,
                    ec_pkcs8_length, 0, "EC")
                && generic_decode_is(reverse_libctx, ec_spki,
                    ec_spki_length, 1, "EC"),
            "generic foreign-key decoding survives TLS-first order");
    }

    OPENSSL_clear_free(pkcs8, pkcs8_length);
    OPENSSL_free(spki);
    OPENSSL_clear_free(rsa_pkcs8, rsa_pkcs8_length);
    OPENSSL_free(rsa_spki);
    OPENSSL_clear_free(ec_pkcs8, ec_pkcs8_length);
    OPENSSL_free(ec_spki);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    OSSL_PROVIDER_unload(reverse_default);
    OSSL_PROVIDER_unload(reverse_tls);
    OSSL_LIB_CTX_free(reverse_libctx);
    OSSL_PROVIDER_unload(tls);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return d00_summary("val01_transactional_tls_decoder");
}
