/*
 * Acceptance section 4 (PKI): CSR generation and verification, self-signed
 * certificate, CA-signed leaf chain, corrupted-signature rejection, all
 * through public OpenSSL interfaces with the project-assigned,
 * parameterless AlgorithmIdentifier.  The providers are loaded into
 * the default library context because the X509 convenience signers fetch
 * from it.
 */

#include <openssl/pem.h>
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

static X509 *make_cert_with_digest(
    const char *subject_cn,
    const X509_NAME *issuer_name,
    EVP_PKEY *subject_key,
    EVP_PKEY *issuer_key,
    int is_ca,
    long serial,
    const EVP_MD *digest)
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
    if (X509_sign(cert, issuer_key, digest) <= 0)
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

static X509 *make_cert(
    const char *subject_cn,
    const X509_NAME *issuer_name,
    EVP_PKEY *subject_key,
    EVP_PKEY *issuer_key,
    int is_ca,
    long serial)
{
    return make_cert_with_digest(subject_cn, issuer_name, subject_key,
        issuer_key, is_ca, serial, NULL);
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

static X509_REQ *reparse_request_der(const X509_REQ *request)
{
    unsigned char *der = NULL;
    const unsigned char *cursor;
    X509_REQ *parsed = NULL;
    int length = request == NULL ? -1 : i2d_X509_REQ(request, &der);

    if (length > 0 && der != NULL) {
        cursor = der;
        parsed = d2i_X509_REQ(NULL, &cursor, length);
        if (parsed == NULL || cursor != der + length) {
            X509_REQ_free(parsed);
            parsed = NULL;
        }
    }
    OPENSSL_free(der);
    return parsed;
}

static X509_REQ *reparse_request_pem(const X509_REQ *request)
{
    BIO *bio = BIO_new(BIO_s_mem());
    X509_REQ *parsed = NULL;

    if (bio != NULL && request != NULL
            && PEM_write_bio_X509_REQ(bio, request) == 1)
        parsed = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return parsed;
}

static X509 *reparse_certificate_der(const X509 *certificate)
{
    unsigned char *der = NULL;
    const unsigned char *cursor;
    X509 *parsed = NULL;
    int length = certificate == NULL ? -1 : i2d_X509(certificate, &der);

    if (length > 0 && der != NULL) {
        cursor = der;
        parsed = d2i_X509(NULL, &cursor, length);
        if (parsed == NULL || cursor != der + length) {
            X509_free(parsed);
            parsed = NULL;
        }
    }
    OPENSSL_free(der);
    return parsed;
}

static X509 *reparse_certificate_pem(const X509 *certificate)
{
    BIO *bio = BIO_new(BIO_s_mem());
    X509 *parsed = NULL;

    if (bio != NULL && certificate != NULL
            && PEM_write_bio_X509(bio, certificate) == 1)
        parsed = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return parsed;
}

static EVP_PKEY *make_ec_key(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        NULL, "EC", "provider=default");
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) != 1
            || EVP_PKEY_CTX_set_group_name(context, "prime256v1") != 1
            || EVP_PKEY_generate(context, &key) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int verify_direct_chain(X509 *trust_anchor, X509 *leaf)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    int ok = store != NULL && context != NULL
        && X509_STORE_add_cert(store, trust_anchor) == 1
        && X509_STORE_CTX_init(context, store, leaf, NULL) == 1
        && X509_verify_cert(context) == 1;

    X509_STORE_CTX_free(context);
    X509_STORE_free(store);
    ERR_clear_error();
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

    /*
     * D5 (project OID registry and provider PKI contract): the numeric OID
     * resolves byte-exactly to its no-digest signature identifier.
     */
    {
        int nid = OBJ_txt2nid(D00_OID_TEXT);
        int signature_nid = NID_undef;
        char oid_text[96] = { 0 };

        D00_CHECK(nid != NID_undef
                && OBJ_obj2txt(oid_text, sizeof(oid_text),
                    OBJ_nid2obj(nid), 1) == (int)strlen(D00_OID_TEXT)
                && strcmp(oid_text, D00_OID_TEXT) == 0,
            "D5 project OID is registered byte-exactly");
        D00_CHECK(OBJ_find_sigid_by_algs(&signature_nid, NID_undef,
                nid) == 1 && signature_nid == nid,
            "sigid maps the algorithm to itself with no digest");
        D00_CHECK(algor_negative_controls(),
            "wrong, NULL-parameter and missing AlgorithmIdentifiers fail "
            "the application precheck");
    }

    /*
     * P5 (provider PKI contract; OpenSSL test/x509_req_test.c pattern):
     * create, verify, DER/PEM reparse and negatively mutate an Ed301 CSR.
     */
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
            X509_REQ *der_copy = reparse_request_der(req);
            X509_REQ *pem_copy = reparse_request_pem(req);

            D00_CHECK(der_copy != NULL
                    && d00_pki_verify_request(der_copy, leaf_key),
                "CSR DER reparse round trip preserves the exact profile");
            D00_CHECK(pem_copy != NULL
                    && d00_pki_verify_request(pem_copy, leaf_key),
                "CSR PEM reparse round trip preserves the exact profile");
            X509_REQ_free(der_copy);
            X509_REQ_free(pem_copy);
        }

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

            /* Public API mutations of the signature and embedded SPKI. */
            {
                X509_REQ *mutated = X509_REQ_dup(req);
                const ASN1_BIT_STRING *mutated_signature = NULL;
                unsigned char shortened[D00_SIG_BYTES - 1];
                int set_ok = 0;

                if (mutated != NULL) {
                    X509_REQ_get0_signature(
                        mutated, &mutated_signature, NULL);
                    if (mutated_signature != NULL
                            && ASN1_STRING_length(mutated_signature)
                                == (int)D00_SIG_BYTES) {
                        memcpy(shortened,
                            ASN1_STRING_get0_data(mutated_signature),
                            sizeof(shortened));
                        set_ok = ASN1_STRING_set(
                            (ASN1_STRING *)mutated_signature,
                            shortened, sizeof(shortened));
                    }
                }
                D00_CHECK(mutated != NULL && set_ok == 1
                        && !d00_pki_verify_request(mutated, leaf_key),
                    "strict CSR wrapper rejects a 75-byte signature BIT "
                    "STRING");
                ERR_clear_error();
                X509_REQ_free(mutated);
            }

            {
                X509_REQ *mutated = X509_REQ_dup(req);
                X509_PUBKEY *public_key = mutated == NULL ? NULL
                    : X509_REQ_get_X509_PUBKEY(mutated);
                ASN1_OBJECT *object = NULL;
                const unsigned char *key_bytes = NULL;
                int key_length = 0;
                X509_ALGOR *algorithm = NULL;
                int set_ok = public_key != NULL
                    && X509_PUBKEY_get0_param(&object, &key_bytes,
                        &key_length, &algorithm, public_key) == 1
                    && algorithm != NULL
                    && X509_ALGOR_set0(algorithm,
                        OBJ_txt2obj("1.3.101.112", 1),
                        V_ASN1_UNDEF, NULL) == 1;

                D00_CHECK(mutated != NULL && set_ok
                        && !d00_pki_verify_request(mutated, leaf_key),
                    "strict CSR wrapper rejects a foreign embedded SPKI "
                    "algorithm");
                ERR_clear_error();
                X509_REQ_free(mutated);
            }

            {
                X509_REQ *mutated = X509_REQ_dup(req);
                X509_PUBKEY *public_key = mutated == NULL ? NULL
                    : X509_REQ_get_X509_PUBKEY(mutated);
                ASN1_OBJECT *object = NULL;
                const unsigned char *key_bytes = NULL;
                int key_length = 0;
                X509_ALGOR *algorithm = NULL;
                unsigned char *short_key = NULL;
                ASN1_OBJECT *target = NULL;
                int set_ok = 0;

                if (public_key != NULL
                        && X509_PUBKEY_get0_param(&object, &key_bytes,
                            &key_length, &algorithm, public_key) == 1
                        && key_bytes != NULL
                        && key_length == (int)D00_PUB_BYTES) {
                    short_key = OPENSSL_memdup(
                        key_bytes, D00_PUB_BYTES - 1);
                    target = OBJ_txt2obj(D00_OID_TEXT, 1);
                    if (short_key != NULL && target != NULL
                            && X509_PUBKEY_set0_param(public_key, target,
                                V_ASN1_UNDEF, NULL, short_key,
                                (int)D00_PUB_BYTES - 1) == 1) {
                        target = NULL;
                        short_key = NULL;
                        set_ok = 1;
                    }
                }
                D00_CHECK(mutated != NULL && set_ok
                        && !d00_pki_verify_request(mutated, leaf_key),
                    "strict CSR wrapper rejects a 37-byte SPKI key");
                ASN1_OBJECT_free(target);
                OPENSSL_free(short_key);
                ERR_clear_error();
                X509_REQ_free(mutated);
            }
        }
        X509_NAME_free(subject);
        X509_REQ_free(req);
    }

    /*
     * P1/P2 (provider PKI contract; OpenSSL test/x509_test.c and
     * test/verify_extra_test.c patterns):
     * self-signed DER round trip and direct Ed301 CA -> Ed301 leaf chain.
     */
    {
        X509 *ca_cert = make_cert("draft-00 test CA", NULL, ca_key,
            ca_key, 1, 1);
        X509 *leaf_cert = NULL;

        D00_CHECK(ca_cert != NULL, "self-signed CA certificate");
        D00_CHECK(ca_cert != NULL
                && d00_pki_verify_certificate(ca_cert, ca_key),
            "strict certificate wrapper verifies the self-signed CA");
        if (ca_cert != NULL) {
            X509 *der_copy = reparse_certificate_der(ca_cert);

            D00_CHECK(der_copy != NULL
                    && d00_pki_verify_certificate(der_copy, ca_key),
                "P1 self-signed Ed301 certificate DER round trip verifies");
            X509_free(der_copy);
        }

        if (ca_cert != NULL) {
            leaf_cert = make_cert("draft-00 test leaf",
                X509_get_subject_name(ca_cert), leaf_key, ca_key, 0, 2);
            D00_CHECK(leaf_cert != NULL, "CA-signed leaf certificate");
            D00_CHECK(d00_pki_certificate_is_exact(leaf_cert),
                "leaf identifiers are exact before chain validation");
            if (leaf_cert != NULL) {
                X509 *der_copy = reparse_certificate_der(leaf_cert);
                X509 *pem_copy = reparse_certificate_pem(leaf_cert);

                D00_CHECK(der_copy != NULL
                        && d00_pki_verify_certificate(der_copy, ca_key),
                    "certificate DER reparse round trip preserves the "
                    "exact profile");
                D00_CHECK(pem_copy != NULL
                        && d00_pki_verify_certificate(pem_copy, ca_key),
                    "certificate PEM reparse round trip preserves the "
                    "exact profile");
                X509_free(der_copy);
                X509_free(pem_copy);
            }
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
                "P2 strict Ed301 CA-to-Ed301 leaf store verification");
            X509_STORE_CTX_free(store_ctx);

            /* Corrupt the leaf signature: chain must fail. */
            {
                const ASN1_BIT_STRING *signature = NULL;
                const X509_ALGOR *algorithm = NULL;
                X509_STORE_CTX *bad_ctx = X509_STORE_CTX_new();

                X509_get0_signature(&signature, &algorithm, leaf_cert);
                if (signature != NULL
                        && ASN1_STRING_length(signature) > 10) {
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

            /*
             * P4 (X.509 signed-TBS contract; OpenSSL test/x509_test.c
             * verification pattern):
             * mutate a semantic TBS field through its public setter while
             * leaving the signature untouched.
             */
            {
                X509 *mutated = X509_dup(leaf_cert);
                ASN1_INTEGER *serial = ASN1_INTEGER_new();
                unsigned char *tbs = NULL;
                int set_ok = serial != NULL
                    && ASN1_INTEGER_set(serial, 999) == 1
                    && mutated != NULL
                    && X509_set_serialNumber(mutated, serial) == 1
                    && i2d_re_X509_tbs(mutated, &tbs) > 0;

                D00_CHECK(set_ok
                        && !d00_pki_verify_certificate(mutated, ca_key),
                    "P4 TBS serial mutation invalidates certificate "
                    "verification");
                ASN1_INTEGER_free(serial);
                OPENSSL_free(tbs);
                ERR_clear_error();
                X509_free(mutated);
            }

            {
                X509 *mutated = X509_dup(leaf_cert);
                const X509_ALGOR *inner = mutated == NULL ? NULL
                    : X509_get0_tbs_sigalg(mutated);
                int set_ok = inner != NULL
                    && X509_ALGOR_set0((X509_ALGOR *)inner,
                        OBJ_txt2obj("1.3.101.112", 1),
                        V_ASN1_UNDEF, NULL) == 1;

                D00_CHECK(mutated != NULL && set_ok
                        && !d00_pki_verify_certificate(mutated, ca_key),
                    "strict certificate wrapper rejects an inner/outer "
                    "signature-algorithm mismatch");
                ERR_clear_error();
                X509_free(mutated);
            }

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

        /*
         * P3 (provider interoperability contract; OpenSSL
         * test/verify_extra_test.c store pattern): both direct
         * cross-algorithm chains use generic X509 validation.  They are
         * intentionally outside the all-Ed301 strict profile predicate.
         */
        if (ca_cert != NULL) {
            EVP_PKEY *ec_ca_key = make_ec_key();
            EVP_PKEY *ec_leaf_key = make_ec_key();
            X509 *ec_ca_cert = ec_ca_key == NULL ? NULL
                : make_cert_with_digest("classic ECDSA test CA", NULL,
                    ec_ca_key, ec_ca_key, 1, 101, EVP_sha256());
            X509 *ecdsa_to_ed_leaf = ec_ca_cert == NULL ? NULL
                : make_cert_with_digest("Ed301 under ECDSA",
                    X509_get_subject_name(ec_ca_cert), leaf_key,
                    ec_ca_key, 0, 102, EVP_sha256());
            X509 *ed_to_ecdsa_leaf = ec_leaf_key == NULL ? NULL
                : make_cert("ECDSA under Ed301",
                    X509_get_subject_name(ca_cert), ec_leaf_key,
                    ca_key, 0, 103);

            D00_CHECK(ec_ca_cert != NULL && ecdsa_to_ed_leaf != NULL
                    && d00_pki_public_key_is_exact(
                        X509_get_X509_PUBKEY(ecdsa_to_ed_leaf))
                    && !d00_pki_certificate_is_exact(ecdsa_to_ed_leaf)
                    && verify_direct_chain(ec_ca_cert, ecdsa_to_ed_leaf),
                "P3 classic ECDSA CA-to-Ed301 leaf verifies generically");
            D00_CHECK(ed_to_ecdsa_leaf != NULL
                    && !d00_pki_public_key_is_exact(
                        X509_get_X509_PUBKEY(ed_to_ecdsa_leaf))
                    && !d00_pki_certificate_is_exact(ed_to_ecdsa_leaf)
                    && verify_direct_chain(ca_cert, ed_to_ecdsa_leaf),
                "P3 Ed301 CA-to-classic ECDSA leaf verifies generically");

            X509_free(ed_to_ecdsa_leaf);
            X509_free(ecdsa_to_ed_leaf);
            X509_free(ec_ca_cert);
            EVP_PKEY_free(ec_leaf_key);
            EVP_PKEY_free(ec_ca_key);
        }
        X509_free(leaf_cert);
        X509_free(ca_cert);
    }

    /*
     * P6 (draft/provider scope): CRL and OCSP profiles are deliberately not
     * synthesized here; the dated decision and revisit gate are recorded in
     * docs/OPENSSL_PATTERN_DEVIATIONS.md.
     */

    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(leaf_key);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    return d00_summary("provider_pki");
}
