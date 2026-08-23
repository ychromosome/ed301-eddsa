/*
 * Acceptance section 4 (PKI): CSR generation and verification, self-signed
 * certificate, CA-signed leaf chain, corrupted-signature rejection, all
 * through public OpenSSL interfaces with the explicitly ephemeral,
 * parameterless test AlgorithmIdentifier.  The providers are loaded into
 * the default library context because the X509 convenience signers fetch
 * from it.
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "harness_common.h"
#include "strict_pki.h"
#include "vectors.h"

static X509_NAME *make_name(const char *common_name)
{
    X509_NAME *name = X509_NAME_new();

    if (name == NULL
            || X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                (const unsigned char *)"Ed301 draft-00 experiment "
                    "(test-only)", -1, -1, 0) != 1
            || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char *)common_name, -1, -1, 0) != 1) {
        X509_NAME_free(name);
        return NULL;
    }
    return name;
}

static int add_extension(X509 *cert, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *extension;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (extension == NULL)
        return 0;
    if (X509_add_ext(cert, extension, -1) != 1) {
        X509_EXTENSION_free(extension);
        return 0;
    }
    X509_EXTENSION_free(extension);
    return 1;
}

static X509 *make_cert(
    const char *subject_cn,
    const X509_NAME *issuer_name,
    EVP_PKEY *subject_key,
    EVP_PKEY *issuer_key,
    int is_ca,
    long serial)
{
    X509 *cert = X509_new();
    X509_NAME *subject = make_name(subject_cn);
    int ok = 0;

    if (cert == NULL || subject == NULL)
        goto done;
    if (X509_set_version(cert, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) != 1
            || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 3600) == NULL
            || X509_set_subject_name(cert, subject) != 1
            || X509_set_issuer_name(cert,
                issuer_name != NULL ? issuer_name : subject) != 1
            || X509_set_pubkey(cert, subject_key) != 1)
        goto done;
    if (is_ca) {
        if (!add_extension(cert, NID_basic_constraints,
                "critical,CA:TRUE")
                || !add_extension(cert, NID_key_usage,
                    "critical,keyCertSign,cRLSign"))
            goto done;
    } else {
        if (!add_extension(cert, NID_basic_constraints,
                "critical,CA:FALSE")
                || !add_extension(cert, NID_key_usage,
                    "critical,digitalSignature"))
            goto done;
    }
    if (X509_sign(cert, issuer_key, NULL) <= 0)
        goto done;
    ok = 1;

done:
    X509_NAME_free(subject);
    if (!ok) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

static int algor_negative_controls(void)
{
    X509_ALGOR *wrong = X509_ALGOR_new();
    X509_ALGOR *with_null = X509_ALGOR_new();
    X509_ALGOR *missing = X509_ALGOR_new();
    ASN1_OBJECT *target = OBJ_txt2obj(D00_OID_TEXT, 1);
    ASN1_OBJECT *foreign = OBJ_txt2obj("1.3.101.112", 1);
    int ok = wrong != NULL && with_null != NULL && missing != NULL
        && target != NULL && foreign != NULL;

    if (ok) {
        X509_ALGOR_set0(wrong, foreign, V_ASN1_UNDEF, NULL);
        foreign = NULL;
        X509_ALGOR_set0(with_null, target, V_ASN1_NULL, NULL);
        target = NULL;
        ok = !d00_pki_algorithm_is_exact(wrong)
            && !d00_pki_algorithm_is_exact(with_null)
            && !d00_pki_algorithm_is_exact(missing);
    }
    ASN1_OBJECT_free(target);
    ASN1_OBJECT_free(foreign);
    X509_ALGOR_free(wrong);
    X509_ALGOR_free(with_null);
    X509_ALGOR_free(missing);
    return ok;
}

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft;
    d00_property = D00_PKI_PROP;
    draft = d00_load_named(NULL, &deflt, D00_PKI_PROVIDER);
    EVP_PKEY *ca_key = d00_keygen(NULL);
    EVP_PKEY *leaf_key = d00_keygen(NULL);

    D00_CHECK(deflt != NULL && draft != NULL,
        "providers in the default context");
    D00_CHECK(ca_key != NULL && leaf_key != NULL, "test keys");
    if (ca_key == NULL || leaf_key == NULL)
        return d00_summary("provider_pki");

    /* The ephemeral test OID resolves to a usable NID with a sigid. */
    {
        int nid = OBJ_txt2nid(D00_OID_TEXT);
        int signature_nid = NID_undef;

        D00_CHECK(nid != NID_undef, "ephemeral OID registered");
        D00_CHECK(OBJ_find_sigid_by_algs(&signature_nid, NID_undef,
                nid) == 1 && signature_nid == nid,
            "sigid maps the algorithm to itself with no digest");
        D00_CHECK(algor_negative_controls(),
            "wrong, NULL-parameter and missing AlgorithmIdentifiers fail "
            "the application precheck");
    }

    /* CSR: sign, verify, corrupt, reject. */
    {
        X509_REQ *req = X509_REQ_new();
        X509_NAME *subject = make_name("draft-00 CSR (test-only)");

        D00_CHECK(req != NULL && subject != NULL
                && X509_REQ_set_version(req, 0) == 1
                && X509_REQ_set_subject_name(req, subject) == 1
                && X509_REQ_set_pubkey(req, leaf_key) == 1
                && X509_REQ_sign(req, leaf_key, NULL) > 0,
            "CSR creation and signing");
        D00_CHECK(req != NULL && d00_pki_verify_request(req, leaf_key),
            "strict CSR wrapper enforces identifiers and verifies");

        if (req != NULL) {
            const ASN1_BIT_STRING *signature = NULL;
            const X509_ALGOR *algorithm = NULL;

            X509_REQ_get0_signature(req, &signature, &algorithm);
            D00_CHECK(signature != NULL
                    && ASN1_STRING_length(signature) == 76,
                "CSR carries a 76-byte draft-00 signature");
            if (algorithm != NULL) {
                char oid_text[96] = { 0 };

                OBJ_obj2txt(oid_text, sizeof(oid_text),
                    algorithm->algorithm, 1);
                D00_CHECK(strcmp(oid_text, D00_OID_TEXT) == 0,
                    "CSR AlgorithmIdentifier is the ephemeral test OID "
                    "(%s)", oid_text);
                D00_CHECK(algorithm->parameter == NULL,
                    "CSR AlgorithmIdentifier is parameterless");
            }
            if (signature != NULL && ASN1_STRING_length(signature) > 0) {
                /* Corrupt one signature byte in place. */
                unsigned char *bytes =
                    (unsigned char *)ASN1_STRING_get0_data(signature);

                bytes[0] ^= 1;
                D00_CHECK(!d00_pki_verify_request(req, leaf_key),
                    "strict CSR wrapper rejects a corrupted signature");
                ERR_clear_error();
                bytes[0] ^= 1;
            }

            /*
             * X.509 AlgorithmIdentifier parameters are parsed by libcrypto
             * and are not passed to the signature provider.  A strict
             * application therefore checks them before ordinary verify.
             */
            {
                X509_REQ *mutated = X509_REQ_dup(req);
                const ASN1_BIT_STRING *mutated_signature = NULL;
                const X509_ALGOR *mutated_outer = NULL;
                int ordinary_verify = -1;

                if (mutated != NULL) {
                    X509_REQ_get0_signature(mutated, &mutated_signature,
                        &mutated_outer);
                    if (mutated_outer != NULL)
                        X509_ALGOR_set0((X509_ALGOR *)mutated_outer,
                            OBJ_txt2obj(D00_OID_TEXT, 1),
                            V_ASN1_NULL, NULL);
                    ordinary_verify = X509_REQ_verify(mutated, leaf_key);
                }
                D00_CHECK(mutated != NULL
                        && !d00_pki_verify_request(mutated, leaf_key),
                    "strict CSR wrapper rejects NULL parameters");
                printf("ordinary CSR verify without precheck: %d "
                    "(outside provider enforcement)\n", ordinary_verify);
                ERR_clear_error();
                X509_REQ_free(mutated);
            }
        }
        X509_NAME_free(subject);
        X509_REQ_free(req);
    }

    /* Self-signed certificate and CA-signed leaf chain. */
    {
        X509 *ca_cert = make_cert("draft-00 test CA", NULL, ca_key,
            ca_key, 1, 1);
        X509 *leaf_cert = NULL;

        D00_CHECK(ca_cert != NULL, "self-signed CA certificate");
        D00_CHECK(ca_cert != NULL
                && d00_pki_verify_certificate(ca_cert, ca_key),
            "strict certificate wrapper verifies the self-signed CA");

        if (ca_cert != NULL) {
            leaf_cert = make_cert("draft-00 test leaf",
                X509_get_subject_name(ca_cert), leaf_key, ca_key, 0, 2);
            D00_CHECK(leaf_cert != NULL, "CA-signed leaf certificate");
            D00_CHECK(d00_pki_certificate_is_exact(leaf_cert),
                "leaf identifiers are exact before chain validation");
        }

        if (ca_cert != NULL && leaf_cert != NULL) {
            X509_STORE *store = X509_STORE_new();
            X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();

            D00_CHECK(store != NULL && store_ctx != NULL
                    && X509_STORE_add_cert(store, ca_cert) == 1
                    && X509_STORE_CTX_init(store_ctx, store, leaf_cert,
                        NULL) == 1
                    && d00_pki_verify_two_certificate_chain(
                        store_ctx, leaf_cert, ca_cert),
                "strict chain wrapper verifies the leaf and CA profile");
            X509_STORE_CTX_free(store_ctx);

            /* Corrupt the leaf signature: chain must fail. */
            {
                const ASN1_BIT_STRING *signature = NULL;
                const X509_ALGOR *algorithm = NULL;
                X509_STORE_CTX *bad_ctx = X509_STORE_CTX_new();

                X509_get0_signature(&signature, &algorithm, leaf_cert);
                if (signature != NULL
                        && ASN1_STRING_length(signature) > 0) {
                    unsigned char *bytes = (unsigned char *)
                        ASN1_STRING_get0_data(signature);

                    bytes[10] ^= 1;
                    D00_CHECK(bad_ctx != NULL
                            && X509_STORE_CTX_init(bad_ctx, store,
                                leaf_cert, NULL) == 1
                            && !d00_pki_verify_two_certificate_chain(
                                bad_ctx, leaf_cert, ca_cert),
                        "strict chain wrapper rejects a corrupted leaf");
                    ERR_clear_error();
                    bytes[10] ^= 1;
                }
                X509_STORE_CTX_free(bad_ctx);
            }

            /* Wrong-key verification fails. */
            D00_CHECK(!d00_pki_verify_certificate(leaf_cert, leaf_key),
                "strict certificate wrapper rejects the wrong key");
            ERR_clear_error();

            {
                X509 *mutated = X509_dup(leaf_cert);
                const ASN1_BIT_STRING *mutated_signature = NULL;
                const X509_ALGOR *mutated_outer = NULL;
                int ordinary_verify = -1;

                if (mutated != NULL) {
                    X509_get0_signature(&mutated_signature,
                        &mutated_outer, mutated);
                    if (mutated_outer != NULL)
                        X509_ALGOR_set0((X509_ALGOR *)mutated_outer,
                            OBJ_txt2obj(D00_OID_TEXT, 1),
                            V_ASN1_NULL, NULL);
                    ordinary_verify = X509_verify(mutated, ca_key);
                }
                D00_CHECK(mutated != NULL
                        && !d00_pki_verify_certificate(mutated, ca_key),
                    "strict certificate wrapper rejects NULL parameters");
                printf("ordinary X509 verify without precheck: %d "
                    "(outside provider enforcement)\n", ordinary_verify);
                ERR_clear_error();
                X509_free(mutated);
            }

            X509_STORE_free(store);
        }
        X509_free(leaf_cert);
        X509_free(ca_cert);
    }

    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(leaf_key);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    return d00_summary("provider_pki");
}
