/*
 * Acceptance section 4 (collision handling): a host-side integration
 * preflight owns the registry transition in the loading libcrypto before
 * loading the separate PKI test artifact.  The ordinary signature provider
 * has no OID alias, encoder/decoder or registry side effect and remains
 * usable through its explicit EVP name even when the global registry is
 * conflicting.
 * Each mode runs in a fresh process (the object database is process-global).
 *
 * Modes:
 *   occupied-oid    OID bound to a foreign name           -> load fails
 *   occupied-name   name bound to a foreign OID           -> load fails
 *   sigid-conflict  correct object, wrong digest sigid    -> load fails
 *   digest-slot     foreign sigid uses the target NID only
 *                   as its digest_nid (VAL-02 fixture)    -> load fails
 *   public-slot     foreign sigid uses target as key NID  -> load fails
 *   free            no pre-registration                    -> load succeeds
 *   object-only     exact object without sigid             -> preflight fails
 *   exact           exact object and sigid pre-registered -> load succeeds
 */

#include <openssl/objects.h>

#include "harness_common.h"

int main(int argc, char **argv)
{
    ED301V1_REQUIRE_RUNTIME_BINDING();
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *ordinary;
    OSSL_PROVIDER *v1;
    const char *mode = argc > 1 ? argv[1] : "";
    int expect_load_success = 0;
    int prepared = 0;
    int queue_ok;

    if (deflt == NULL) {
        fprintf(stderr, "default provider load failed\n");
        return 2;
    }

    if (strcmp(mode, "occupied-oid") == 0) {
        prepared = OBJ_create(ED301V1_OID_TEXT, "ED301V1-COLLIDER",
            "ED301V1 collision test object") != NID_undef;
    } else if (strcmp(mode, "occupied-name") == 0) {
        prepared = OBJ_create("2.25.4242424242424242424242", ED301V1_ALG,
            ED301V1_ALG) != NID_undef;
    } else if (strcmp(mode, "sigid-conflict") == 0) {
        int nid = OBJ_create(ED301V1_OID_TEXT, ED301V1_ALG, ED301V1_ALG);

        prepared = nid != NID_undef
            && OBJ_add_sigid(nid, NID_sha256, nid) == 1;
    } else if (strcmp(mode, "digest-slot") == 0) {
        /*
         * VAL-02 fixture: the target NID appears in the process-global
         * signature-id registry ONLY as the digest_nid of a foreign
         * mapping.  This is a foreign use of the identifier and the
         * provider must fail closed on it.
         */
        int nid = OBJ_create(ED301V1_OID_TEXT, ED301V1_ALG, ED301V1_ALG);
        int foreign = OBJ_create("2.25.171717171717171717171717",
            "ED301V1-DIGEST-SLOT-COLLIDER",
            "ED301V1 digest-slot collision object");

        prepared = nid != NID_undef && foreign != NID_undef
            && OBJ_add_sigid(foreign, nid, foreign) == 1;
    } else if (strcmp(mode, "public-slot") == 0) {
        int nid = OBJ_create(ED301V1_OID_TEXT, ED301V1_ALG, ED301V1_ALG);
        int foreign = OBJ_create("2.25.181818181818181818181818",
            "ED301V1-PUBLIC-SLOT-COLLIDER",
            "ED301V1 public-slot collision object");

        prepared = nid != NID_undef && foreign != NID_undef
            && OBJ_add_sigid(foreign, NID_sha256, nid) == 1;
    } else if (strcmp(mode, "free") == 0) {
        prepared = 1;
        expect_load_success = 1;
    } else if (strcmp(mode, "object-only") == 0) {
        prepared = OBJ_create(ED301V1_OID_TEXT, ED301V1_ALG, ED301V1_ALG)
            != NID_undef;
    } else if (strcmp(mode, "exact") == 0) {
        int nid = OBJ_create(ED301V1_OID_TEXT, ED301V1_ALG, ED301V1_ALG);

        prepared = nid != NID_undef
            && OBJ_add_sigid(nid, NID_undef, nid) == 1;
        expect_load_success = 1;
    } else {
        fprintf(stderr, "usage: provider_oid_collision "
            "occupied-oid|occupied-name|sigid-conflict|digest-slot|"
            "public-slot|free|object-only|exact\n");
        OSSL_PROVIDER_unload(deflt);
        return 2;
    }

    if (!prepared) {
        fprintf(stderr, "%s: registry preparation failed\n", mode);
        ERR_print_errors_fp(stderr);
        OSSL_PROVIDER_unload(deflt);
        return 2;
    }

    ED301V1_CHECK(ed301v1_registry_preflight_ok() == expect_load_success,
        "%s: host preflight classifies the registry", mode);

    ed301v1_seed_error_sentinel();
    ordinary = ed301v1_load_named(NULL, NULL, ED301V1_PROVIDER);
    queue_ok = ed301v1_queue_is_sentinel_only();
    ED301V1_CHECK(ordinary != NULL,
        "%s: ordinary signature-only provider ignores global OID state",
        mode);
    if (ordinary != NULL) {
        EVP_SIGNATURE *algorithm =
            EVP_SIGNATURE_fetch(NULL, ED301V1_ALG, ED301V1_PROP);

        ED301V1_CHECK(algorithm != NULL,
            "%s: explicit-name signature fetch remains usable", mode);
        ED301V1_CHECK(queue_ok,
            "%s: ordinary load preserves the caller error queue", mode);
        EVP_SIGNATURE_free(algorithm);
        OSSL_PROVIDER_unload(ordinary);
    }

    ed301v1_seed_error_sentinel();
    v1 = ed301v1_load_named(NULL, NULL, ED301V1_PKI_PROVIDER);
    queue_ok = ed301v1_queue_is_sentinel_only();
    if (expect_load_success) {
        ED301V1_CHECK(v1 != NULL,
            "%s: provider load succeeds after a clean host preflight",
            mode);
        if (v1 != NULL) {
            EVP_SIGNATURE *alg =
                EVP_SIGNATURE_fetch(NULL, ED301V1_ALG, ED301V1_PKI_PROP);

            ED301V1_CHECK(alg != NULL, "%s: algorithm fetch", mode);
            ED301V1_CHECK(queue_ok,
                "%s: caller queue preserved on successful load", mode);
            ED301V1_CHECK(ed301v1_registry_is_exact(),
                "%s: object and forward/reverse sigid are exact", mode);
            ED301V1_CHECK(ed301v1_provider_has_reason_dispatch(v1),
                "%s: provider exports reason-string dispatch", mode);
            EVP_SIGNATURE_free(alg);
            OSSL_PROVIDER_unload(v1);
        }
    } else {
        ED301V1_CHECK(v1 == NULL,
            "%s: host preflight blocks the optional PKI test artifact",
            mode);
        ED301V1_CHECK(queue_ok,
            "%s: host preflight preserves the caller error queue", mode);
        if (v1 != NULL)
            OSSL_PROVIDER_unload(v1);
    }

    OSSL_PROVIDER_unload(deflt);
    return ed301v1_summary(mode);
}
