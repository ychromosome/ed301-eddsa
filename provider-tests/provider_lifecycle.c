/*
 * OpenSSL-style lifecycle and concurrency contracts for the ordinary
 * Ed301-EdDSA provider.  The cited OpenSSL test files exist in both normative
 * source lanes (3.5.7 and 4.0.1); this harness translates their contracts to
 * Ed301's 38-byte keys, 76-byte signatures and pure one-shot message API.
 */

#include <pthread.h>

#include "harness_common.h"
#include "vectors.h"

#define LIFECYCLE_LOAD_ROUNDS 100
#define LIFECYCLE_THREADS 4
#define LIFECYCLE_THREAD_ROUNDS 16

typedef struct lifecycle_gate_st {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int arrived;
    int start;
    int abort;
} LIFECYCLE_GATE;

typedef struct lifecycle_worker_st {
    LIFECYCLE_GATE *gate;
    OSSL_LIB_CTX *libctx;
    EVP_PKEY *shared_key;
    int failed;
} LIFECYCLE_WORKER;

static int lifecycle_sign_verify(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey,
    const POSITIVE_CASE *test_case)
{
    unsigned char signature[D00_SIG_BYTES];

    return libctx != NULL && pkey != NULL && test_case != NULL
        && d00_digest_sign(libctx, pkey,
            test_case->message, test_case->message_len, signature)
        && memcmp(signature, test_case->signature, sizeof(signature)) == 0
        && d00_digest_verify(libctx, pkey,
            test_case->message, test_case->message_len,
            signature, sizeof(signature));
}

static int lifecycle_cold_cycle(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    if (libctx == NULL)
        goto done;
    draft = d00_load(libctx, &deflt);
    if (draft == NULL)
        goto done;
    pkey = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    ok = lifecycle_sign_verify(libctx, pkey, &POSITIVE_CASES[0]);

done:
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    return ok;
}

static int lifecycle_key_after_handle_release(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    EVP_PKEY *pkey = NULL;
    int handles_released = 0;
    int ok = 0;

    if (libctx == NULL)
        goto done;
    draft = d00_load(libctx, &deflt);
    if (draft == NULL)
        goto done;
    pkey = d00_key_from_seed(libctx, POSITIVE_CASES[1].seed);
    if (pkey == NULL)
        goto done;

    /*
     * Drop only the caller's provider handles.  We deliberately do not claim
     * that the DSO is fully unloaded: EVP_PKEY and fetched operations retain
     * the provider references required by the OpenSSL ownership contract.
     */
    handles_released = OSSL_PROVIDER_unload(draft) == 1;
    draft = NULL;
    handles_released = handles_released
        && OSSL_PROVIDER_unload(deflt) == 1;
    deflt = NULL;
    ok = handles_released
        && lifecycle_sign_verify(libctx, pkey, &POSITIVE_CASES[1]);

done:
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    return ok;
}

static int lifecycle_two_libctx(void)
{
    OSSL_LIB_CTX *first = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *second = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *first_deflt = NULL;
    OSSL_PROVIDER *second_deflt = NULL;
    OSSL_PROVIDER *first_draft = NULL;
    OSSL_PROVIDER *second_draft = NULL;
    EVP_PKEY *first_key = NULL;
    EVP_PKEY *second_key = NULL;
    int ok = 0;

    if (first == NULL || second == NULL)
        goto done;
    first_draft = d00_load(first, &first_deflt);
    second_draft = d00_load(second, &second_deflt);
    if (first_draft == NULL || second_draft == NULL)
        goto done;
    first_key = d00_key_from_seed(first, POSITIVE_CASES[0].seed);
    second_key = d00_key_from_seed(second, POSITIVE_CASES[1].seed);
    if (!lifecycle_sign_verify(first, first_key, &POSITIVE_CASES[0])
            || !lifecycle_sign_verify(
                second, second_key, &POSITIVE_CASES[1]))
        goto done;

    /* Reverse the load order and prove the surviving context is isolated. */
    EVP_PKEY_free(second_key);
    second_key = NULL;
    OSSL_PROVIDER_unload(second_draft);
    second_draft = NULL;
    OSSL_PROVIDER_unload(second_deflt);
    second_deflt = NULL;
    OSSL_LIB_CTX_free(second);
    second = NULL;
    ok = lifecycle_sign_verify(first, first_key, &POSITIVE_CASES[0]);

done:
    EVP_PKEY_free(second_key);
    EVP_PKEY_free(first_key);
    OSSL_PROVIDER_unload(second_draft);
    OSSL_PROVIDER_unload(second_deflt);
    OSSL_PROVIDER_unload(first_draft);
    OSSL_PROVIDER_unload(first_deflt);
    OSSL_LIB_CTX_free(second);
    OSSL_LIB_CTX_free(first);
    ERR_clear_error();
    return ok;
}

static int lifecycle_sign_once(
    EVP_PKEY_CTX *context,
    const POSITIVE_CASE *test_case,
    unsigned char signature[D00_SIG_BYTES])
{
    size_t signature_length = D00_SIG_BYTES;

    return context != NULL && test_case != NULL
        && EVP_PKEY_sign(context, signature, &signature_length,
            test_case->message, test_case->message_len) == 1
        && signature_length == D00_SIG_BYTES
        && memcmp(signature, test_case->signature, D00_SIG_BYTES) == 0;
}

static int lifecycle_verify_once(
    EVP_PKEY_CTX *context,
    const POSITIVE_CASE *test_case)
{
    return context != NULL && test_case != NULL
        && EVP_PKEY_verify(context,
            test_case->signature, D00_SIG_BYTES,
            test_case->message, test_case->message_len) == 1;
}

static int lifecycle_duplicate_contexts(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey,
    int free_original_first)
{
    const POSITIVE_CASE *test_case = &POSITIVE_CASES[3];
    EVP_PKEY_CTX *sign_original = NULL;
    EVP_PKEY_CTX *sign_duplicate = NULL;
    EVP_PKEY_CTX *verify_original = NULL;
    EVP_PKEY_CTX *verify_duplicate = NULL;
    unsigned char original_signature[D00_SIG_BYTES];
    unsigned char duplicate_signature[D00_SIG_BYTES];
    int first_ok;
    int second_ok;
    int ok = 0;
    const char *failure_stage = "sign context creation";

    sign_original = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
    if (sign_original == NULL
            || !d00_sign_message_init(libctx, sign_original, NULL))
        goto done;
    failure_stage = "sign context duplication";
    sign_duplicate = EVP_PKEY_CTX_dup(sign_original);
    if (sign_duplicate == NULL)
        goto done;

    failure_stage = "independent duplicated signing";
    if (free_original_first) {
        first_ok = lifecycle_sign_once(
            sign_original, test_case, original_signature);
        EVP_PKEY_CTX_free(sign_original);
        sign_original = NULL;
        second_ok = lifecycle_sign_once(
            sign_duplicate, test_case, duplicate_signature);
    } else {
        first_ok = lifecycle_sign_once(
            sign_duplicate, test_case, duplicate_signature);
        EVP_PKEY_CTX_free(sign_duplicate);
        sign_duplicate = NULL;
        second_ok = lifecycle_sign_once(
            sign_original, test_case, original_signature);
    }
    if (!first_ok || !second_ok
            || memcmp(original_signature, duplicate_signature,
                D00_SIG_BYTES) != 0)
        goto done;

    failure_stage = "verify context creation";
    verify_original = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, D00_PROP);
    if (verify_original == NULL
            || !d00_verify_message_init(libctx, verify_original, NULL))
        goto done;
    failure_stage = "verify context duplication";
    verify_duplicate = EVP_PKEY_CTX_dup(verify_original);
    if (verify_duplicate == NULL)
        goto done;

    failure_stage = "independent duplicated verification";
    if (free_original_first) {
        first_ok = lifecycle_verify_once(verify_original, test_case);
        EVP_PKEY_CTX_free(verify_original);
        verify_original = NULL;
        second_ok = lifecycle_verify_once(verify_duplicate, test_case);
    } else {
        first_ok = lifecycle_verify_once(verify_duplicate, test_case);
        EVP_PKEY_CTX_free(verify_duplicate);
        verify_duplicate = NULL;
        second_ok = lifecycle_verify_once(verify_original, test_case);
    }
    ok = first_ok && second_ok;

done:
    if (!ok)
        fprintf(stderr, "L4 failure stage: %s\n", failure_stage);
    EVP_PKEY_CTX_free(verify_duplicate);
    EVP_PKEY_CTX_free(verify_original);
    EVP_PKEY_CTX_free(sign_duplicate);
    EVP_PKEY_CTX_free(sign_original);
    OPENSSL_cleanse(original_signature, sizeof(original_signature));
    OPENSSL_cleanse(duplicate_signature, sizeof(duplicate_signature));
    ERR_clear_error();
    return ok;
}

static int lifecycle_gate_wait(LIFECYCLE_GATE *gate)
{
    int proceed;

    if (pthread_mutex_lock(&gate->mutex) != 0)
        return 0;
    gate->arrived++;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->start && !gate->abort)
        pthread_cond_wait(&gate->condition, &gate->mutex);
    proceed = !gate->abort;
    pthread_mutex_unlock(&gate->mutex);
    return proceed;
}

static void *lifecycle_shared_key_worker(void *argument)
{
    LIFECYCLE_WORKER *worker = argument;
    int round;

    if (!lifecycle_gate_wait(worker->gate)) {
        worker->failed = 1;
        return NULL;
    }
    for (round = 0; round < LIFECYCLE_THREAD_ROUNDS; round++) {
        if (!lifecycle_sign_verify(worker->libctx, worker->shared_key,
                &POSITIVE_CASES[3])) {
            worker->failed = 1;
            break;
        }
    }
    return NULL;
}

static int lifecycle_parallel_shared_key(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *shared_key)
{
    pthread_t threads[LIFECYCLE_THREADS];
    LIFECYCLE_WORKER workers[LIFECYCLE_THREADS];
    LIFECYCLE_GATE gate = {
        PTHREAD_MUTEX_INITIALIZER,
        PTHREAD_COND_INITIALIZER,
        0,
        0,
        0
    };
    int created = 0;
    int ok = 1;
    int index;

    memset(workers, 0, sizeof(workers));
    for (index = 0; index < LIFECYCLE_THREADS; index++) {
        workers[index].gate = &gate;
        workers[index].libctx = libctx;
        workers[index].shared_key = shared_key;
        if (pthread_create(&threads[index], NULL,
                lifecycle_shared_key_worker, &workers[index]) != 0) {
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
        if (pthread_join(threads[index], NULL) != 0
                || workers[index].failed)
            ok = 0;
    }
    if (created != LIFECYCLE_THREADS)
        ok = 0;
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    return ok;
}

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    EVP_PKEY *shared_key = NULL;
    int round;
    int load_ok = 1;

    D00_REQUIRE_RUNTIME_BINDING();

    /*
     * L1 -- repeated load/unload.
     * Source: test/threadstest.c:thread_provider_load_unload and
     * test/recipes/90-test_threads.t.  Whole-process Valgrind runs this
     * exact >=100-cycle harness in scripts/test-provider.sh.
     */
    for (round = 0; round < LIFECYCLE_LOAD_ROUNDS; round++) {
        if (!lifecycle_cold_cycle()) {
            load_ok = 0;
            break;
        }
    }
    D00_CHECK(load_ok,
        "L1 repeated provider load/use/unload x%d (failed round %d)",
        LIFECYCLE_LOAD_ROUNDS, round);

    /*
     * L2 -- retained EVP object ownership.
     * Source: OpenSSL's provider-object ownership contract and
     * test/threadstest.c:test_multi_shared_pkey_release.  The assertion is
     * intentionally about released caller handles, not forced DSO unload.
     */
    D00_CHECK(lifecycle_key_after_handle_release(),
        "L2 key remains usable after caller provider handles are released");

    /*
     * L3 -- independent library contexts.
     * Source: test/threadstest.c:thread_setup_libctx/thread_run_test.
     * Both contexts execute Ed301 operations and are torn down in reverse
     * load order; the survivor is exercised again after the first teardown.
     */
    D00_CHECK(lifecycle_two_libctx(),
        "L3 two libctx operate independently under reverse teardown");

    libctx = OSSL_LIB_CTX_new();
    if (libctx != NULL)
        draft = d00_load(libctx, &deflt);
    if (draft != NULL)
        shared_key = d00_key_from_seed(libctx, POSITIVE_CASES[3].seed);
    D00_CHECK(libctx != NULL && draft != NULL && shared_key != NULL,
        "lifecycle shared-key fixture");

    /*
     * L4 -- initialized signature-context duplication.
     * Source: test/slh_dsa_test.c's EVP_PKEY_CTX_dup sign/verify pattern and
     * test/evp_test.c's provider dupctx checks.  Ed301 exposes
     * OSSL_FUNC_SIGNATURE_DUPCTX, so both original and duplicate must remain
     * independently usable under both free orders.  There is no streaming
     * state to clone because Ed301-EdDSA-v1 is pure one-shot EdDSA.
     */
    D00_CHECK(shared_key != NULL
            && lifecycle_duplicate_contexts(libctx, shared_key, 1),
        "L4 initialized sign/verify contexts survive original-first free");
    D00_CHECK(shared_key != NULL
            && lifecycle_duplicate_contexts(libctx, shared_key, 0),
        "L4 initialized sign/verify contexts survive duplicate-first free");

    /*
     * L5 -- shared EVP_PKEY concurrency.
     * Source: test/threadstest.c:test_multi_shared_pkey.  Four threads share
     * the immutable key while each creates its own EVP context, then perform
     * deterministic sign and verify operations in parallel.
     */
    D00_CHECK(shared_key != NULL
            && lifecycle_parallel_shared_key(libctx, shared_key),
        "L5 same EVP_PKEY signs/verifies in %d threads x %d rounds",
        LIFECYCLE_THREADS, LIFECYCLE_THREAD_ROUNDS);

    /*
     * L6 -- failure-path coverage is deliberately split rather than faked:
     * provider_hardening exercises the real signature_duplicate allocation
     * failpoint and recovery, while provider_rand exercises generate failure
     * and recovery.  RAND installation and pthread setup are host test
     * infrastructure, not provider-owned product allocation sites, so no
     * product failpoint is added for them.
     */

    EVP_PKEY_free(shared_key);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return d00_summary("provider_lifecycle");
}
