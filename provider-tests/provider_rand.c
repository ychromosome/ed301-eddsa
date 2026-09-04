/*
 * F1 regression: Ed301 key generation must consume the application's
 * OpenSSL RAND policy through the provider child OSSL_LIB_CTX.
 *
 * A deterministic, host-owned RAND provider is loaded in the parent context
 * and selected with parent default properties. Child-context mirroring makes
 * it visible to the provider-owned, primary-parented CTR-DRBG. The generated
 * seed must be byte-exact, and an injected failure must make key generation
 * fail closed and subsequently recover.
 */

#include <stdlib.h>
#include <pthread.h>

#include <openssl/rand.h>

#include "harness_common.h"
#include "vectors.h"

#define TEST_RAND_PROVIDER "ed301_test_rand"
#define TEST_RAND_PROPERTY "provider=ed301_test_rand"
#define CONCURRENT_KEYGEN_THREADS 4

typedef struct test_rand_context_st {
    int state;
} TEST_RAND_CONTEXT;

static int test_rand_fail;
static unsigned int test_rand_advertised_strength = 256U;
static unsigned int test_rand_instantiate_strength;
static unsigned int test_rand_generate_strength;
static unsigned int test_rand_generate_calls;

typedef struct lifecycle_worker_st {
    OSSL_LIB_CTX *libctx;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int ready;
    int release;
    int keygen_ok;
} LIFECYCLE_WORKER;

typedef struct concurrent_gate_st {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned int ready;
    int start;
} CONCURRENT_GATE;

typedef struct concurrent_keygen_worker_st {
    OSSL_LIB_CTX *libctx;
    CONCURRENT_GATE *gate;
    unsigned char public_key[ED301V1_PUB_BYTES];
    int ok;
} CONCURRENT_KEYGEN_WORKER;

static void *concurrent_keygen_worker(void *argument)
{
    CONCURRENT_KEYGEN_WORKER *worker = argument;
    EVP_PKEY *key;
    size_t length = sizeof(worker->public_key);

    pthread_mutex_lock(&worker->gate->mutex);
    worker->gate->ready++;
    pthread_cond_broadcast(&worker->gate->condition);
    while (!worker->gate->start)
        pthread_cond_wait(&worker->gate->condition, &worker->gate->mutex);
    pthread_mutex_unlock(&worker->gate->mutex);

    key = ed301v1_keygen(worker->libctx);
    worker->ok = key != NULL
        && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
            worker->public_key, sizeof(worker->public_key), &length) == 1
        && length == sizeof(worker->public_key);
    EVP_PKEY_free(key);
    OPENSSL_thread_stop_ex(worker->libctx);
    return NULL;
}

static int concurrent_default_keygen_is_distinct(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = NULL;
    CONCURRENT_GATE gate;
    CONCURRENT_KEYGEN_WORKER workers[CONCURRENT_KEYGEN_THREADS];
    pthread_t threads[CONCURRENT_KEYGEN_THREADS];
    unsigned char zero[ED301V1_PUB_BYTES] = { 0 };
    size_t created = 0;
    size_t index;
    size_t other;
    int mutex_ready = 0;
    int condition_ready = 0;
    int result = 0;

    memset(&gate, 0, sizeof(gate));
    memset(workers, 0, sizeof(workers));
    if (libctx == NULL
            || (deflt = OSSL_PROVIDER_load(libctx, "default")) == NULL
            || (v1 = OSSL_PROVIDER_load(libctx, ED301V1_PROVIDER)) == NULL)
        goto done;
    mutex_ready = pthread_mutex_init(&gate.mutex, NULL) == 0;
    condition_ready = mutex_ready
        && pthread_cond_init(&gate.condition, NULL) == 0;
    if (!condition_ready)
        goto done;
    for (index = 0; index < CONCURRENT_KEYGEN_THREADS; index++) {
        workers[index].libctx = libctx;
        workers[index].gate = &gate;
        if (pthread_create(&threads[index], NULL,
                concurrent_keygen_worker, &workers[index]) != 0)
            break;
        created++;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready < created)
        pthread_cond_wait(&gate.condition, &gate.mutex);
    gate.start = 1;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    for (index = 0; index < created; index++)
        pthread_join(threads[index], NULL);
    if (created != CONCURRENT_KEYGEN_THREADS)
        goto done;
    result = 1;
    for (index = 0; index < created; index++) {
        if (!workers[index].ok
                || CRYPTO_memcmp(workers[index].public_key,
                    zero, sizeof(zero)) == 0)
            result = 0;
        for (other = 0; other < index; other++) {
            if (CRYPTO_memcmp(workers[index].public_key,
                    workers[other].public_key,
                    sizeof(workers[index].public_key)) == 0)
                result = 0;
        }
    }

done:
    if (condition_ready)
        pthread_cond_destroy(&gate.condition);
    if (mutex_ready)
        pthread_mutex_destroy(&gate.mutex);
    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    return result;
}

static void *lifecycle_keygen_worker(void *argument)
{
    LIFECYCLE_WORKER *worker = argument;
    EVP_PKEY *key = ed301v1_keygen(worker->libctx);

    worker->keygen_ok = key != NULL;
    EVP_PKEY_free(key);
    /* Release application-context thread state, if any. */
    OPENSSL_thread_stop_ex(worker->libctx);
    if (pthread_mutex_lock(&worker->mutex) != 0)
        return NULL;
    worker->ready = 1;
    pthread_cond_signal(&worker->condition);
    while (!worker->release)
        pthread_cond_wait(&worker->condition, &worker->mutex);
    pthread_mutex_unlock(&worker->mutex);
    return NULL;
}

static void *test_rand_new_context(
    void *provider_context,
    void *parent,
    const OSSL_DISPATCH *parent_dispatch)
{
    TEST_RAND_CONTEXT *context = calloc(1, sizeof(*context));

    (void)provider_context;
    (void)parent;
    (void)parent_dispatch;
    if (context != NULL)
        context->state = EVP_RAND_STATE_UNINITIALISED;
    return context;
}

static void test_rand_free_context(void *rand_context)
{
    free(rand_context);
}

static int test_rand_instantiate(
    void *rand_context,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *personalization,
    size_t personalization_length,
    const OSSL_PARAM params[])
{
    TEST_RAND_CONTEXT *context = rand_context;

    test_rand_instantiate_strength = strength;
    (void)prediction_resistance;
    (void)personalization;
    (void)personalization_length;
    (void)params;
    if (context == NULL)
        return 0;
    context->state = EVP_RAND_STATE_READY;
    return 1;
}

static int test_rand_uninstantiate(void *rand_context)
{
    TEST_RAND_CONTEXT *context = rand_context;

    if (context == NULL)
        return 0;
    context->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int test_rand_generate(
    void *rand_context,
    unsigned char *output,
    size_t output_length,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *additional_input,
    size_t additional_input_length)
{
    TEST_RAND_CONTEXT *context = rand_context;
    size_t index;

    test_rand_generate_strength = strength;
    (void)prediction_resistance;
    (void)additional_input;
    (void)additional_input_length;
    test_rand_generate_calls++;
    if (context == NULL || context->state != EVP_RAND_STATE_READY
            || output == NULL || test_rand_fail
            || strength > test_rand_advertised_strength)
        return 0;
    for (index = 0; index < output_length; index++)
        output[index] = (unsigned char)(0xa0U + (index % 0x40U));
    return 1;
}

static int test_rand_enable_locking(void *rand_context)
{
    return rand_context != NULL;
}

static int test_rand_lock(void *rand_context)
{
    return rand_context != NULL;
}

static void test_rand_unlock(void *rand_context)
{
    (void)rand_context;
}

static const OSSL_PARAM *test_rand_gettable_context_params(
    void *rand_context,
    void *provider_context)
{
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    (void)rand_context;
    (void)provider_context;
    return parameters;
}

static int test_rand_get_context_params(
    void *rand_context,
    OSSL_PARAM params[])
{
    TEST_RAND_CONTEXT *context = rand_context;
    OSSL_PARAM *parameter;

    if (context == NULL)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (parameter != NULL
            && OSSL_PARAM_set_int(parameter, context->state) != 1)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (parameter != NULL
            && OSSL_PARAM_set_uint(
                parameter, test_rand_advertised_strength) != 1)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (parameter != NULL
            && OSSL_PARAM_set_size_t(parameter, INT_MAX) != 1)
        return 0;
    return 1;
}

static const OSSL_DISPATCH TEST_RAND_FUNCTIONS[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))test_rand_new_context },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))test_rand_free_context },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))test_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,
        (void (*)(void))test_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))test_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,
        (void (*)(void))test_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))test_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))test_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))test_rand_gettable_context_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,
        (void (*)(void))test_rand_get_context_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM TEST_RAND_ALGORITHMS[] = {
    { "CTR-DRBG", TEST_RAND_PROPERTY, TEST_RAND_FUNCTIONS,
        "deterministic Ed301 child-libctx test RAND" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *test_rand_query(
    void *provider_context,
    int operation_id,
    int *no_cache)
{
    (void)provider_context;
    if (no_cache != NULL)
        *no_cache = 0;
    return operation_id == OSSL_OP_RAND ? TEST_RAND_ALGORITHMS : NULL;
}

static const OSSL_DISPATCH TEST_RAND_PROVIDER_DISPATCH[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))test_rand_query },
    { 0, NULL }
};

static int test_rand_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context)
{
    (void)handle;
    (void)input_dispatch;
    if (output_dispatch == NULL || provider_context == NULL)
        return 0;
    *provider_context = NULL;
    *output_dispatch = TEST_RAND_PROVIDER_DISPATCH;
    return 1;
}

static int ed301_first_load_has_no_child_fallback(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = NULL;
    EVP_PKEY *before = NULL;
    EVP_PKEY *after = NULL;
    int result = 0;

    if (libctx == NULL
            || (v1 = OSSL_PROVIDER_load(libctx, ED301V1_PROVIDER)) == NULL)
        goto done;
    ERR_clear_error();
    before = ed301v1_keygen(libctx);
    if (before != NULL || OSSL_PROVIDER_available(libctx, "default") != 0)
        goto done;
    ERR_clear_error();
    deflt = OSSL_PROVIDER_load(libctx, "default");
    after = deflt == NULL ? NULL : ed301v1_keygen(libctx);
    result = after != NULL;

done:
    ERR_clear_error();
    EVP_PKEY_free(after);
    EVP_PKEY_free(before);
    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return result;
}

int main(void)
{
    ED301V1_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *rand_provider = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *kat_key = NULL;
    EVP_PKEY *weak_key = NULL;
    EVP_PKEY *failed_key = NULL;
    EVP_PKEY *recovered_key = NULL;
    EVP_PKEY *warm_policy_key = NULL;
    unsigned char expected[ED301V1_SEED_BYTES];
    static const unsigned char expected_public[ED301V1_PUB_BYTES] = {
        0xca, 0x69, 0x43, 0x21, 0xce, 0x6f, 0xce, 0x86,
        0xde, 0xfe, 0x10, 0x84, 0xfb, 0x49, 0xb8, 0xb7,
        0x0f, 0xbf, 0xd5, 0xd2, 0x8c, 0xa2, 0x16, 0x80,
        0x32, 0x88, 0x08, 0x08, 0xf6, 0xa5, 0xfc, 0x68,
        0xba, 0x53, 0x10, 0xae, 0x0a, 0x90
    };
    unsigned char actual[ED301V1_SEED_BYTES];
    unsigned char actual_public[ED301V1_PUB_BYTES];
    unsigned char deterministic_signature[ED301V1_SIG_BYTES];
    size_t actual_length = 0;
    size_t actual_public_length = 0;
    size_t index;
    unsigned int calls_before_failure;
    LIFECYCLE_WORKER worker;
    pthread_t worker_thread;
    int worker_started = 0;
    int worker_joined = 0;
    int mutex_ready = 0;
    int condition_ready = 0;
    int synchronization_ready = 0;

    ED301V1_CHECK(ed301_first_load_has_no_child_fallback(),
        "Ed301-first load remains keygen-disabled until application RAND "
        "becomes available");
    ED301V1_CHECK(concurrent_default_keygen_is_distinct(),
        "concurrent keygen uses the locked private DRBG and distinct keys");

    for (index = 0; index < sizeof(expected); index++)
        expected[index] = (unsigned char)(0xa0U + (index % 0x40U));

    ED301V1_CHECK(libctx != NULL, "parent library context");
    ED301V1_CHECK(libctx != NULL
            && OSSL_PROVIDER_add_builtin(
                libctx, TEST_RAND_PROVIDER, test_rand_provider_init) == 1,
        "application installs its test RAND provider");
    if (libctx != NULL)
        rand_provider = OSSL_PROVIDER_load(libctx, TEST_RAND_PROVIDER);
    ED301V1_CHECK(rand_provider != NULL, "application test RAND provider loads");
    ED301V1_CHECK(libctx != NULL
            && EVP_set_default_properties(libctx, TEST_RAND_PROPERTY) == 1,
        "application RAND property policy configured");

    if (libctx != NULL)
        v1 = ed301v1_load(libctx, &deflt);
    ED301V1_CHECK(v1 != NULL,
        "Ed301 provider loads with a mirrored child library context");
    if (v1 != NULL)
        key = ed301v1_keygen(libctx);
    /*
     * R2 -- OpenSSL ECX keygen contract.
     * Source: providers/implementations/keymgmt/ecx_kmgmt.c, whose Ed25519
     * and Ed448 keygen paths consume the parent libctx's private RAND.  The
     * expected public key below was calculated offline from the a0..c5 seed
     * by both provider-tests/oracle/ed301_eddsa/reference.py and the frozen
     * blind-0c482948 oracle; it is not read back from provider behaviour.
     */
    ED301V1_CHECK(key != NULL && test_rand_generate_calls > 0,
        "keygen reaches the application-selected OpenSSL RAND provider");
    ED301V1_CHECK(key != NULL && test_rand_generate_strength >= 149U,
        "keygen generate request carries at least 149-bit strength "
        "(instantiate=%u, generate=%u)",
        test_rand_instantiate_strength, test_rand_generate_strength);
    ED301V1_CHECK(key != NULL
            && EVP_PKEY_get_octet_string_param(
                key, OSSL_PKEY_PARAM_PRIV_KEY, actual, sizeof(actual),
                &actual_length) == 1
            && actual_length == sizeof(actual)
            && memcmp(actual, expected, sizeof(actual)) == 0,
        "generated Ed301 seed is byte-exact from application RAND");
    ED301V1_CHECK(key != NULL
            && EVP_PKEY_get_octet_string_param(
                key, OSSL_PKEY_PARAM_PUB_KEY,
                actual_public, sizeof(actual_public),
                &actual_public_length) == 1
            && actual_public_length == sizeof(actual_public)
            && memcmp(actual_public, expected_public,
                sizeof(actual_public)) == 0,
        "deterministic RAND seed derives the independently fixed public key");

    ED301V1_CHECK(EVP_set_default_properties(libctx, ED301V1_PROP) == 1,
        "application policy can tighten after DRBG creation");
    warm_policy_key = ed301v1_keygen(libctx);
    ED301V1_CHECK(warm_policy_key != NULL,
        "warm provider DRBG remains usable after a policy change");
    ED301V1_CHECK(EVP_set_default_properties(
            libctx, TEST_RAND_PROPERTY) == 1,
        "application RAND policy restored");

    /*
     * R1 -- PureEdDSA determinism and RAND separation.
     * Source: providers/implementations/signature/eddsa_sig.c and the
     * Ed25519/Ed448 one-shot cases in test/recipes/30-test_evp_data/
     * evppkey_ecx_sigalg.txt.  Once the key exists, signing and verification
     * are deterministic and must not call RAND.  The poisoned generator
     * makes any accidental call fail while the exact counter proves zero
     * generate() invocations.
     */
    kat_key = ed301v1_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    calls_before_failure = test_rand_generate_calls;
    test_rand_fail = 1;
    ED301V1_CHECK(kat_key != NULL
            && ed301v1_digest_sign(libctx, kat_key,
                POSITIVE_CASES[0].message,
                POSITIVE_CASES[0].message_len,
                deterministic_signature)
            && memcmp(deterministic_signature,
                POSITIVE_CASES[0].signature,
                sizeof(deterministic_signature)) == 0
            && ed301v1_digest_verify(libctx, kat_key,
                POSITIVE_CASES[0].message,
                POSITIVE_CASES[0].message_len,
                deterministic_signature,
                sizeof(deterministic_signature))
            && test_rand_generate_calls == calls_before_failure,
        "poisoned application RAND is never called by sign or verify");
    test_rand_fail = 0;

    test_rand_advertised_strength = 128U;
    calls_before_failure = test_rand_generate_calls;
    weak_key = ed301v1_keygen(libctx);
    ED301V1_CHECK(weak_key == NULL
            && test_rand_generate_calls >= calls_before_failure,
        "sub-149-bit application RAND makes Ed301 keygen fail closed");
    ERR_clear_error();
    test_rand_advertised_strength = 256U;

    /*
     * R3 -- Keygen fails closed on application-RAND failure.
     * Source: providers/implementations/keymgmt/ecx_kmgmt.c and
     * test/testutil/fake_random.c.  A failed generate produces no EVP_PKEY;
     * recovery must return the same independently specified keypair.
     */
    calls_before_failure = test_rand_generate_calls;
    test_rand_fail = 1;
    failed_key = ed301v1_keygen(libctx);
    ED301V1_CHECK(failed_key == NULL
            && test_rand_generate_calls > calls_before_failure,
        "application RAND failure makes Ed301 keygen fail closed");
    ERR_clear_error();

    test_rand_fail = 0;
    recovered_key = ed301v1_keygen(libctx);
    actual_length = 0;
    actual_public_length = 0;
    ED301V1_CHECK(recovered_key != NULL
            && EVP_PKEY_get_octet_string_param(
                recovered_key, OSSL_PKEY_PARAM_PRIV_KEY,
                actual, sizeof(actual), &actual_length) == 1
            && actual_length == sizeof(actual)
            && memcmp(actual, expected, sizeof(actual)) == 0
            && EVP_PKEY_get_octet_string_param(
                recovered_key, OSSL_PKEY_PARAM_PUB_KEY,
                actual_public, sizeof(actual_public),
                &actual_public_length) == 1
            && actual_public_length == sizeof(actual_public)
            && memcmp(actual_public, expected_public,
                sizeof(actual_public)) == 0,
        "Ed301 keygen recovers with the exact deterministic keypair");

    memset(&worker, 0, sizeof(worker));
    worker.libctx = libctx;
    mutex_ready = pthread_mutex_init(&worker.mutex, NULL) == 0;
    condition_ready = mutex_ready
        && pthread_cond_init(&worker.condition, NULL) == 0;
    synchronization_ready = mutex_ready && condition_ready;
    ED301V1_CHECK(synchronization_ready,
        "cross-thread child-LIBCTX lifecycle synchronization setup");
    if (synchronization_ready)
        worker_started = pthread_create(
            &worker_thread, NULL, lifecycle_keygen_worker, &worker) == 0;
    ED301V1_CHECK(worker_started,
        "worker thread performs provider key generation");
    if (worker_started) {
        pthread_mutex_lock(&worker.mutex);
        while (!worker.ready)
            pthread_cond_wait(&worker.condition, &worker.mutex);
        pthread_mutex_unlock(&worker.mutex);
        ED301V1_CHECK(worker.keygen_ok,
            "worker keygen completes before final provider unload");

        EVP_PKEY_free(recovered_key);
        recovered_key = NULL;
        EVP_PKEY_free(warm_policy_key);
        warm_policy_key = NULL;
        EVP_PKEY_free(failed_key);
        failed_key = NULL;
        EVP_PKEY_free(weak_key);
        weak_key = NULL;
        EVP_PKEY_free(kat_key);
        kat_key = NULL;
        EVP_PKEY_free(key);
        key = NULL;
        ED301V1_CHECK(OSSL_PROVIDER_unload(v1) == 1,
            "provider unload succeeds while the worker thread remains alive");
        v1 = NULL;
        OSSL_PROVIDER_unload(deflt);
        deflt = NULL;
        OSSL_PROVIDER_unload(rand_provider);
        rand_provider = NULL;
        OSSL_LIB_CTX_free(libctx);
        libctx = NULL;

        pthread_mutex_lock(&worker.mutex);
        worker.release = 1;
        pthread_cond_signal(&worker.condition);
        pthread_mutex_unlock(&worker.mutex);
        worker_joined = pthread_join(worker_thread, NULL) == 0;
        ED301V1_CHECK(worker_joined,
            "worker exits after child context teardown without stale TLS state");
    }

    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(actual_public, sizeof(actual_public));
    OPENSSL_cleanse(deterministic_signature,
        sizeof(deterministic_signature));
    OPENSSL_cleanse(expected, sizeof(expected));
    EVP_PKEY_free(weak_key);
    EVP_PKEY_free(recovered_key);
    EVP_PKEY_free(warm_policy_key);
    EVP_PKEY_free(failed_key);
    EVP_PKEY_free(kat_key);
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(deflt);
    OSSL_PROVIDER_unload(rand_provider);
    OSSL_LIB_CTX_free(libctx);
    if (condition_ready)
        pthread_cond_destroy(&worker.condition);
    if (mutex_ready)
        pthread_mutex_destroy(&worker.mutex);
    return ed301v1_summary("provider_rand");
}
