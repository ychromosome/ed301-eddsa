/*
 * Acceptance section 2 (loading): isolated library contexts, fetch by new
 * name and explicit property, unload independence, repeated and parallel
 * cold load, clean unload.  Start-gate pattern adapted from the disclosed
 * post-commit parallel-load harness (see the result provenance map).
 */

#include <pthread.h>

#include <openssl/decoder.h>
#include <openssl/encoder.h>

#include "harness_common.h"
#include "vectors.h"

#define PARALLEL_THREADS 8
#define PARALLEL_ROUNDS 5
#define REPEAT_ROUNDS 50

typedef struct start_gate_st {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int target;
    int arrived;
    int start;
    int abort;
} START_GATE;

typedef struct worker_st {
    START_GATE *gate;
    int rounds;
    int failed;
} WORKER;

static int gate_wait(START_GATE *gate)
{
    int proceed;

    pthread_mutex_lock(&gate->mutex);
    gate->arrived++;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->start && !gate->abort)
        pthread_cond_wait(&gate->condition, &gate->mutex);
    proceed = !gate->abort;
    pthread_mutex_unlock(&gate->mutex);
    return proceed;
}

static int one_cold_load_cycle(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = NULL;
    EVP_SIGNATURE *fetched = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char sig[76];
    int ok = 0;

    if (libctx == NULL)
        return 0;
    v1 = ed301v1_load(libctx, &deflt);
    if (v1 == NULL)
        goto done;
    fetched = EVP_SIGNATURE_fetch(libctx, ED301V1_ALG, ED301V1_PROP);
    if (fetched == NULL)
        goto done;
    pkey = ed301v1_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    if (pkey == NULL)
        goto done;
    if (!ed301v1_digest_sign(libctx, pkey, POSITIVE_CASES[0].message,
            POSITIVE_CASES[0].message_len, sig))
        goto done;
    if (memcmp(sig, POSITIVE_CASES[0].signature, sizeof(sig)) != 0)
        goto done;
    ok = 1;

done:
    EVP_PKEY_free(pkey);
    EVP_SIGNATURE_free(fetched);
    if (v1 != NULL)
        OSSL_PROVIDER_unload(v1);
    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return ok;
}

static int provider_lifetime_cycle(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *first = NULL;
    OSSL_PROVIDER *second = NULL;
    EVP_SIGNATURE *signature = NULL;
    EVP_KEYMGMT *keymgmt = NULL;
    EVP_PKEY *pkey = NULL;
    const OSSL_PROVIDER *signature_provider;
    const OSSL_PROVIDER *keymgmt_provider;
    unsigned char value[ED301V1_SIG_BYTES];
    int ok = 0;

    if (libctx == NULL)
        goto done;
    first = ed301v1_load(libctx, &deflt);
    second = OSSL_PROVIDER_load(libctx, ED301V1_PROVIDER);
    signature = EVP_SIGNATURE_fetch(libctx, ED301V1_ALG, ED301V1_PROP);
    keymgmt = EVP_KEYMGMT_fetch(libctx, ED301V1_ALG, ED301V1_PROP);
    pkey = ed301v1_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    if (first == NULL || second == NULL || signature == NULL
            || keymgmt == NULL || pkey == NULL)
        goto done;
    signature_provider = EVP_SIGNATURE_get0_provider(signature);
    keymgmt_provider = EVP_KEYMGMT_get0_provider(keymgmt);
    if (signature_provider == NULL
            || signature_provider != keymgmt_provider)
        goto done;

    OSSL_PROVIDER_unload(second);
    second = NULL;
    OSSL_PROVIDER_unload(first);
    first = NULL;
    OSSL_PROVIDER_unload(deflt);
    deflt = NULL;

    if (strcmp(OSSL_PROVIDER_get0_name(signature_provider), ED301V1_PROVIDER) != 0
            || !ed301v1_digest_sign(libctx, pkey,
                POSITIVE_CASES[0].message,
                POSITIVE_CASES[0].message_len, value)
            || memcmp(value, POSITIVE_CASES[0].signature,
                ED301V1_SIG_BYTES) != 0
            || !ed301v1_digest_verify(libctx, pkey,
                POSITIVE_CASES[0].message,
                POSITIVE_CASES[0].message_len,
                value, sizeof(value)))
        goto done;
    ok = 1;

done:
    EVP_PKEY_free(pkey);
    EVP_KEYMGMT_free(keymgmt);
    EVP_SIGNATURE_free(signature);
    if (second != NULL)
        OSSL_PROVIDER_unload(second);
    if (first != NULL)
        OSSL_PROVIDER_unload(first);
    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    return ok;
}

static void *worker_main(void *argument)
{
    WORKER *worker = argument;
    int round;

    if (!gate_wait(worker->gate))
        return NULL;
    for (round = 0; round < worker->rounds; round++) {
        if (!one_cold_load_cycle()) {
            worker->failed = 1;
            return NULL;
        }
    }
    return NULL;
}

int main(void)
{
    ED301V1_REQUIRE_RUNTIME_BINDING();
    /* Fetch by name and property in an isolated context. */
    {
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = NULL;
        OSSL_PROVIDER *v1;
        EVP_SIGNATURE *sig_alg;
        EVP_SIGNATURE *by_oid;
        EVP_KEYMGMT *keymgmt;
        OSSL_ENCODER *encoder;
        OSSL_DECODER *decoder;
        int registry_nid = NID_undef;

        ED301V1_CHECK(libctx != NULL, "library context");
        v1 = ed301v1_load(libctx, &deflt);
        ED301V1_CHECK(v1 != NULL, "provider load in isolated context");
        ED301V1_CHECK(!ed301v1_provider_has_dispatch(
                v1, OSSL_FUNC_PROVIDER_GET_CAPABILITIES),
            "ordinary provider has no TLS capability dispatch");
        ED301V1_CHECK(OSSL_PROVIDER_available(libctx, ED301V1_PROVIDER) == 1,
            "provider availability");

        sig_alg = EVP_SIGNATURE_fetch(libctx, ED301V1_ALG, ED301V1_PROP);
        ED301V1_CHECK(sig_alg != NULL, "signature fetch by name and property");
        keymgmt = EVP_KEYMGMT_fetch(libctx, ED301V1_ALG, ED301V1_PROP);
        ED301V1_CHECK(keymgmt != NULL, "keymgmt fetch by name and property");
        by_oid = EVP_SIGNATURE_fetch(libctx, ED301V1_OID_TEXT, ED301V1_PROP);
        ED301V1_CHECK(by_oid == NULL,
            "ordinary provider exposes no OID alias");
        ERR_clear_error();
        encoder = OSSL_ENCODER_fetch(libctx, ED301V1_ALG, ED301V1_PROP);
        decoder = OSSL_DECODER_fetch(libctx, ED301V1_ALG, ED301V1_PROP);
        ED301V1_CHECK(encoder == NULL && decoder == NULL,
            "ordinary provider exposes no PKI codec operations");
        ED301V1_CHECK(ed301v1_registry_identity_state(&registry_nid)
                == ED301V1_REGISTRY_FREE
                && ed301v1_registry_sigid_state(registry_nid)
                    == ED301V1_REGISTRY_FREE,
            "ordinary provider leaves the global OID/SIGID registry free");

        EVP_SIGNATURE_free(sig_alg);
        EVP_SIGNATURE_free(by_oid);
        EVP_KEYMGMT_free(keymgmt);
        OSSL_ENCODER_free(encoder);
        OSSL_DECODER_free(decoder);

        /*
         * Unload independence: correctly owned key and signature results
         * stay usable after both provider handles are released.
         */
        {
            EVP_PKEY *pkey = ed301v1_key_from_seed(
                libctx, POSITIVE_CASES[0].seed);
            unsigned char sig[76];

            ED301V1_CHECK(pkey != NULL, "key before unload");
            OSSL_PROVIDER_unload(v1);
            OSSL_PROVIDER_unload(deflt);
            ED301V1_CHECK(pkey != NULL
                    && ed301v1_digest_sign(libctx, pkey,
                        POSITIVE_CASES[0].message,
                        POSITIVE_CASES[0].message_len, sig)
                    && memcmp(sig, POSITIVE_CASES[0].signature,
                        sizeof(sig)) == 0,
                "owned key still signs after provider handles unloaded");
            EVP_PKEY_free(pkey);
        }
        OSSL_LIB_CTX_free(libctx);
    }

    /* Without the provider, fetch must fail. */
    {
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(libctx, "default");
        EVP_SIGNATURE *missing =
            EVP_SIGNATURE_fetch(libctx, ED301V1_ALG, NULL);

        ED301V1_CHECK(deflt != NULL, "default provider");
        ED301V1_CHECK(missing == NULL,
            "algorithm invisible while the provider is not loaded");
        ERR_clear_error();
        EVP_SIGNATURE_free(missing);
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
    }

    /* Independent library contexts do not interfere. */
    {
        OSSL_LIB_CTX *first = OSSL_LIB_CTX_new();
        OSSL_LIB_CTX *second = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *first_def = NULL;
        OSSL_PROVIDER *second_def = NULL;
        OSSL_PROVIDER *first_v1 = ed301v1_load(first, &first_def);
        OSSL_PROVIDER *second_v1 = ed301v1_load(second, &second_def);
        EVP_SIGNATURE *first_alg =
            EVP_SIGNATURE_fetch(first, ED301V1_ALG, ED301V1_PROP);
        EVP_SIGNATURE *second_alg =
            EVP_SIGNATURE_fetch(second, ED301V1_ALG, ED301V1_PROP);

        ED301V1_CHECK(first_v1 != NULL && second_v1 != NULL
                && first_alg != NULL && second_alg != NULL,
            "independent library contexts");
        {
            int registry_nid = NID_undef;

            ED301V1_CHECK(ed301v1_registry_identity_state(&registry_nid)
                    == ED301V1_REGISTRY_FREE,
                "ordinary providers do not populate the global registry");
        }
        EVP_SIGNATURE_free(first_alg);
        EVP_SIGNATURE_free(second_alg);
        OSSL_PROVIDER_unload(first_v1);
        OSSL_PROVIDER_unload(first_def);
        OSSL_LIB_CTX_free(first);
        /* second context torn down after first is already gone */
        EVP_SIGNATURE *again =
            EVP_SIGNATURE_fetch(second, ED301V1_ALG, ED301V1_PROP);
        ED301V1_CHECK(again != NULL,
            "second context unaffected by first teardown");
        {
            int registry_nid = NID_undef;

            ED301V1_CHECK(ed301v1_registry_identity_state(&registry_nid)
                    == ED301V1_REGISTRY_FREE,
                "global registry remains untouched after teardown");
        }
        EVP_SIGNATURE_free(again);
        OSSL_PROVIDER_unload(second_v1);
        OSSL_PROVIDER_unload(second_def);
        OSSL_LIB_CTX_free(second);
    }

    /* Fetched algorithms and keys keep the provider alive after handles. */
    {
        int round;
        int ok = 1;

        for (round = 0; round < REPEAT_ROUNDS; round++) {
            if (!provider_lifetime_cycle()) {
                ok = 0;
                break;
            }
        }
        ED301V1_CHECK(ok,
            "provider/fetched-object/key lifetime stress x%d (round %d)",
            REPEAT_ROUNDS, round);
    }

    /* Repeated cold load. */
    {
        int round;
        int ok = 1;

        for (round = 0; round < REPEAT_ROUNDS; round++) {
            if (!one_cold_load_cycle()) {
                ok = 0;
                break;
            }
        }
        ED301V1_CHECK(ok, "repeated cold load x%d (failed round %d)",
            REPEAT_ROUNDS, round);
    }

    /* Parallel cold load through a start gate. */
    {
        pthread_t threads[PARALLEL_THREADS];
        WORKER workers[PARALLEL_THREADS];
        START_GATE gate = {
            PTHREAD_MUTEX_INITIALIZER,
            PTHREAD_COND_INITIALIZER,
            PARALLEL_THREADS,
            0,
            0,
            0
        };
        int index;
        int created = 0;
        int ok = 1;

        for (index = 0; index < PARALLEL_THREADS; index++) {
            workers[index].gate = &gate;
            workers[index].rounds = PARALLEL_ROUNDS;
            workers[index].failed = 0;
            if (pthread_create(
                    &threads[index], NULL, worker_main,
                    &workers[index]) != 0) {
                ok = 0;
                break;
            }
            created++;
        }
        pthread_mutex_lock(&gate.mutex);
        if (ok) {
            while (gate.arrived < created)
                pthread_cond_wait(&gate.condition, &gate.mutex);
            gate.start = 1;
        } else {
            gate.abort = 1;
        }
        pthread_cond_broadcast(&gate.condition);
        pthread_mutex_unlock(&gate.mutex);

        for (index = 0; index < created; index++) {
            pthread_join(threads[index], NULL);
            if (workers[index].failed)
                ok = 0;
        }
        if (created != PARALLEL_THREADS)
            ok = 0;
        pthread_cond_destroy(&gate.condition);
        pthread_mutex_destroy(&gate.mutex);
        ED301V1_CHECK(ok, "parallel cold load (%d threads x %d rounds)",
            PARALLEL_THREADS, PARALLEL_ROUNDS);
    }

    return ed301v1_summary("provider_load");
}
