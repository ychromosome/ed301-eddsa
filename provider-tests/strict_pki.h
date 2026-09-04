#ifndef ED301V1_STRICT_PKI_H
#define ED301V1_STRICT_PKI_H

#include <limits.h>

/*
 * Mandatory verification boundary for the test-only Ed301 PKI profile.
 * OpenSSL's generic X.509 verification accepts some AlgorithmIdentifier
 * parameter variants before dispatching the signature.  Every supported
 * Ed301 CSR/certificate path therefore checks the exact numeric OID,
 * absent parameters, fixed signature size, matching TBS/outer identifiers,
 * and exact SPKI before ordinary cryptographic verification.
 */

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "harness_common.h"

static inline size_t ed301v1_bit_string_length(const ASN1_BIT_STRING *value)
{
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    size_t length = 0;
    int unused_bits = 0;

    if (ASN1_BIT_STRING_get_length(value, &length, &unused_bits) != 1
            || unused_bits != 0)
        return SIZE_MAX;
    return length;
#else
    return (size_t)ASN1_STRING_length((const ASN1_STRING *)value);
#endif
}

static inline int ed301v1_bit_string_set(
    ASN1_BIT_STRING *value,
    const unsigned char *data,
    size_t length)
{
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    return ASN1_BIT_STRING_set1(value, data, length, 0);
#else
    if (length > INT_MAX)
        return 0;
    return ASN1_BIT_STRING_set(value, (unsigned char *)data, (int)length);
#endif
}

static inline int ed301v1_pki_algorithm_is_exact(const X509_ALGOR *algorithm)
{
    const ASN1_OBJECT *object = NULL;
    const void *parameter = NULL;
    int parameter_type = V_ASN1_UNDEF;
    char text[96] = { 0 };

    if (algorithm == NULL)
        return 0;
    X509_ALGOR_get0(&object, &parameter_type, &parameter, algorithm);
    return object != NULL
        && OBJ_obj2txt(text, sizeof(text), object, 1) > 0
        && strcmp(text, ED301V1_OID_TEXT) == 0
        && parameter_type == V_ASN1_UNDEF
        && parameter == NULL;
}

static inline int ed301v1_pki_public_key_is_exact(const X509_PUBKEY *public_key)
{
    ASN1_OBJECT *object = NULL;
    const unsigned char *key_bytes = NULL;
    int key_length = 0;
    X509_ALGOR *algorithm = NULL;

    return public_key != NULL
        && X509_PUBKEY_get0_param(&object, &key_bytes, &key_length,
            &algorithm, public_key) == 1
        && object != NULL && key_bytes != NULL
        && key_length == (int)ED301V1_PUB_BYTES
        && ed301v1_pki_algorithm_is_exact(algorithm);
}

static inline int ed301v1_pki_request_is_exact(const X509_REQ *request)
{
    const ASN1_BIT_STRING *signature = NULL;
    const X509_ALGOR *outer = NULL;

    if (request == NULL)
        return 0;
    X509_REQ_get0_signature(request, &signature, &outer);
    return signature != NULL
        && ed301v1_bit_string_length(signature) == ED301V1_SIG_BYTES
        && ed301v1_pki_algorithm_is_exact(outer)
        && ed301v1_pki_public_key_is_exact(
            X509_REQ_get_X509_PUBKEY((X509_REQ *)request));
}

static inline int ed301v1_pki_certificate_is_exact(const X509 *certificate)
{
    const ASN1_BIT_STRING *signature = NULL;
    const X509_ALGOR *outer = NULL;
    const X509_ALGOR *tbs;

    if (certificate == NULL)
        return 0;
    X509_get0_signature(&signature, &outer, certificate);
    tbs = X509_get0_tbs_sigalg(certificate);
    return signature != NULL
        && ed301v1_bit_string_length(signature) == ED301V1_SIG_BYTES
        && ed301v1_pki_algorithm_is_exact(outer)
        && ed301v1_pki_algorithm_is_exact(tbs)
        && X509_ALGOR_cmp(outer, tbs) == 0
        && ed301v1_pki_public_key_is_exact(
            X509_get_X509_PUBKEY((X509 *)certificate));
}

static inline int ed301v1_pki_verify_request(
    X509_REQ *request,
    EVP_PKEY *public_key)
{
    return ed301v1_pki_request_is_exact(request)
        && X509_REQ_verify(request, public_key) == 1;
}

static inline int ed301v1_pki_verify_certificate(
    X509 *certificate,
    EVP_PKEY *issuer_key)
{
    return ed301v1_pki_certificate_is_exact(certificate)
        && X509_verify(certificate, issuer_key) == 1;
}

static inline int ed301v1_pki_verify_two_certificate_chain(
    X509_STORE_CTX *store_context,
    X509 *leaf,
    X509 *trust_anchor)
{
    return store_context != NULL
        && ed301v1_pki_certificate_is_exact(leaf)
        && ed301v1_pki_certificate_is_exact(trust_anchor)
        && X509_verify_cert(store_context) == 1;
}

#endif
