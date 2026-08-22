/*
 * F1 regression: Ed301 key generation must consume the application's
 * OpenSSL RAND policy through the provider child OSSL_LIB_CTX.
 *
 * A deterministic, host-owned RAND provider is loaded in the parent context
 * and selected with parent default properties.  Child-context mirroring must
 * make its CTR-DRBG implementation visible to RAND_priv_bytes_ex().  The
 * generated Ed301 private seed must be byte-exact, and an injected RAND
 * failure must make key generation fail closed and subsequently recover.
 */

#include <stdlib.h>

#include <openssl/rand.h>

#include "harness_common.h"

#define TEST_RAND_PROVIDER "ed301_test_rand"
#define TEST_RAND_PROPERTY "provider=ed301_test_rand"

typedef struct test_rand_context_st {
    int state;
} TEST_RAND_CONTEXT;

static int test_rand_fail;
static unsigned int test_rand_generate_calls;

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

    (void)strength;
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

    (void)strength;
    (void)prediction_resistance;
    (void)additional_input;
    (void)additional_input_length;
    test_rand_generate_calls++;
    if (context == NULL || context->state != EVP_RAND_STATE_READY
            || output == NULL || test_rand_fail)
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
    if (parameter != NULL && OSSL_PARAM_set_uint(parameter, 256U) != 1)
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

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *rand_provider = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *failed_key = NULL;
    EVP_PKEY *recovered_key = NULL;
    unsigned char expected[D00_SEED_BYTES];
    unsigned char actual[D00_SEED_BYTES];
    size_t actual_length = 0;
    size_t index;
    unsigned int calls_before_failure;

    for (index = 0; index < sizeof(expected); index++)
        expected[index] = (unsigned char)(0xa0U + (index % 0x40U));

    D00_CHECK(libctx != NULL, "parent library context");
    D00_CHECK(libctx != NULL
            && OSSL_PROVIDER_add_builtin(
                libctx, TEST_RAND_PROVIDER, test_rand_provider_init) == 1,
        "application installs its test RAND provider");
    if (libctx != NULL)
        rand_provider = OSSL_PROVIDER_load(libctx, TEST_RAND_PROVIDER);
    D00_CHECK(rand_provider != NULL, "application test RAND provider loads");
    D00_CHECK(libctx != NULL
            && EVP_set_default_properties(libctx, TEST_RAND_PROPERTY) == 1,
        "application RAND property policy configured");

    if (libctx != NULL)
        draft = d00_load(libctx, &deflt);
    D00_CHECK(draft != NULL,
        "Ed301 provider loads with a mirrored child library context");
    if (draft != NULL)
        key = d00_keygen(libctx);
    D00_CHECK(key != NULL && test_rand_generate_calls > 0,
        "keygen reaches the application-selected OpenSSL RAND provider");
    D00_CHECK(key != NULL
            && EVP_PKEY_get_octet_string_param(
                key, OSSL_PKEY_PARAM_PRIV_KEY, actual, sizeof(actual),
                &actual_length) == 1
            && actual_length == sizeof(actual)
            && memcmp(actual, expected, sizeof(actual)) == 0,
        "generated Ed301 seed is byte-exact from application RAND");

    calls_before_failure = test_rand_generate_calls;
    test_rand_fail = 1;
    failed_key = d00_keygen(libctx);
    D00_CHECK(failed_key == NULL
            && test_rand_generate_calls > calls_before_failure,
        "application RAND failure makes Ed301 keygen fail closed");
    ERR_clear_error();

    test_rand_fail = 0;
    recovered_key = d00_keygen(libctx);
    D00_CHECK(recovered_key != NULL,
        "Ed301 keygen recovers after application RAND recovers");

    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(expected, sizeof(expected));
    EVP_PKEY_free(recovered_key);
    EVP_PKEY_free(failed_key);
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_PROVIDER_unload(rand_provider);
    OSSL_LIB_CTX_free(libctx);
    return d00_summary("provider_rand");
}
