/* Focused C-side contract tests for ABI, version and encoder policy. */

#include "harness_common.h"
#include "../provider/crates/ed301-eddsa-provider/c/provider_shim.c"

static void unit_dummy(void)
{
}

static int unit_verify_result;
static unsigned int unit_verify_calls;
static unsigned int unit_error_calls;
static uint32_t unit_error_reason;
static const char *unit_error_function;
static unsigned int unit_signature_reset_calls;
static unsigned int unit_sign_init_calls;
static unsigned int unit_verify_init_calls;
static int unit_sign_key_bound;
static int unit_verify_key_bound;
static int unit_sign_init_result = 1;
static int unit_verify_init_result = 1;
static unsigned char unit_context[ED301V1_MAX_CONTEXT_BYTES];
static size_t unit_context_length;

static int unit_signature_verify(
    const void *signature,
    const unsigned char *message,
    size_t message_length,
    const unsigned char *signature_value,
    size_t signature_length)
{
    (void)signature;
    (void)message;
    (void)message_length;
    (void)signature_value;
    (void)signature_length;
    unit_verify_calls++;
    return unit_verify_result;
}

static void unit_signature_reset(void *signature)
{
    (void)signature;
    unit_signature_reset_calls++;
    unit_sign_key_bound = 0;
    unit_verify_key_bound = 0;
}

static int unit_signature_set_context(
    void *signature,
    const unsigned char *context_string,
    size_t context_length)
{
    (void)signature;
    if (context_length > sizeof(unit_context)
            || (context_length != 0 && context_string == NULL))
        return 0;
    memset(unit_context, 0, sizeof(unit_context));
    if (context_length != 0)
        memcpy(unit_context, context_string, context_length);
    unit_context_length = context_length;
    return 1;
}

static int unit_signature_get_context(
    const void *signature,
    unsigned char *context_string,
    size_t context_capacity,
    size_t *context_length)
{
    (void)signature;
    if (context_length == NULL || context_capacity < unit_context_length
            || (unit_context_length != 0 && context_string == NULL))
        return 0;
    if (unit_context_length != 0)
        memcpy(context_string, unit_context, unit_context_length);
    *context_length = unit_context_length;
    return 1;
}

static int unit_signature_sign_init(void *signature, const void *key)
{
    (void)signature;
    unit_sign_init_calls++;
    if (unit_sign_init_result != 1)
        return unit_sign_init_result;
    if (key == NULL)
        return unit_sign_key_bound;
    unit_sign_key_bound = 1;
    unit_verify_key_bound = 0;
    return 1;
}

static int unit_signature_verify_init(void *signature, const void *key)
{
    (void)signature;
    unit_verify_init_calls++;
    if (unit_verify_init_result != 1)
        return unit_verify_init_result;
    if (key == NULL)
        return unit_verify_key_bound;
    unit_sign_key_bound = 0;
    unit_verify_key_bound = 1;
    return 1;
}

static void unit_core_new_error(const OSSL_CORE_HANDLE *handle)
{
    (void)handle;
    unit_error_calls++;
}

static void unit_core_set_error_debug(
    const OSSL_CORE_HANDLE *handle,
    const char *file,
    int line,
    const char *function)
{
    (void)handle;
    (void)file;
    (void)line;
    unit_error_function = function;
}

static void unit_core_vset_error(
    const OSSL_CORE_HANDLE *handle,
    uint32_t reason,
    const char *format,
    va_list arguments)
{
    (void)handle;
    (void)format;
    (void)arguments;
    unit_error_reason = reason;
}

static OSSL_FUNC_signature_verify_fn *unit_verify_dispatch(void)
{
    const OSSL_DISPATCH *dispatch = ED301V1_SIGNATURE_DISPATCH;

    for (; dispatch->function_id != 0; dispatch++) {
        if (dispatch->function_id == OSSL_FUNC_SIGNATURE_VERIFY)
            return OSSL_FUNC_signature_verify(dispatch);
    }
    return NULL;
}

static void unit_reset_verify_observation(int result)
{
    unit_verify_result = result;
    unit_verify_calls = 0;
    unit_error_calls = 0;
    unit_error_reason = 0;
}

typedef int (*unit_digest_init_fn)(
    void *, const char *, void *, const OSSL_PARAM []);

static void unit_test_digest_reinit_contract(
    ED301V1_SIGNATURE_RUST_API *api,
    int verification)
{
    ED301V1_PROVIDER_CONTEXT provider = { 0 };
    ED301V1_SIGNATURE_CONTEXT signature = { 0 };
    ED301V1_KEY key = { 0 };
    OSSL_PARAM bad_params[2];
    static char digest_value[] = "SHA256";
    int signature_inner = 1;
    int key_inner = 2;
    unit_digest_init_fn init = verification
        ? ed301v1_signature_digest_verify_init
        : ed301v1_signature_digest_sign_init;
    const char *operation = verification ? "verify" : "sign";

    api->signature_reset = unit_signature_reset;
    api->signature_set_context = unit_signature_set_context;
    api->signature_get_context = unit_signature_get_context;
    api->signature_sign_init = unit_signature_sign_init;
    api->signature_verify_init = unit_signature_verify_init;
    provider.handle = (const OSSL_CORE_HANDLE *)&provider;
    provider.new_error = unit_core_new_error;
    provider.set_error_debug = unit_core_set_error_debug;
    provider.vset_error = unit_core_vset_error;
    provider.rust = api;
    signature.provider = &provider;
    signature.inner = &signature_inner;
    key.provider = &provider;
    key.inner = &key_inner;

    bad_params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_SIGNATURE_PARAM_DIGEST, digest_value, 0);
    bad_params[1] = OSSL_PARAM_construct_end();

    unit_signature_reset_calls = 0;
    unit_sign_init_calls = 0;
    unit_verify_init_calls = 0;
    unit_sign_init_result = 1;
    unit_verify_init_result = 1;
    unit_sign_key_bound = !verification;
    unit_verify_key_bound = verification;
    unit_error_reason = 0;
    unit_error_function = NULL;
    ED301V1_CHECK(init(&signature, NULL, NULL, NULL) == 1
            && unit_signature_reset_calls == 0
            && (verification ? unit_verify_init_calls
                             : unit_sign_init_calls) == 1
            && (verification ? unit_verify_key_bound
                             : unit_sign_key_bound) == 1
            && unit_error_reason == 0,
        "NULL-key %s reinit retains the matching operation",
        operation);

    unit_signature_reset_calls = 0;
    unit_sign_init_calls = 0;
    unit_verify_init_calls = 0;
    unit_error_reason = 0;
    ED301V1_CHECK(init(&signature, "SHA256", NULL, NULL) == 0
            && unit_signature_reset_calls == 0
            && (verification ? unit_verify_init_calls
                             : unit_sign_init_calls) == 0
            && (verification ? unit_verify_key_bound
                             : unit_sign_key_bound) == 1
            && unit_error_reason == ED301V1_R_UNSUPPORTED_MODE,
        "rejected digest preserves a bound NULL-key %s operation",
        operation);

    unit_signature_reset_calls = 0;
    unit_sign_init_calls = 0;
    unit_verify_init_calls = 0;
    unit_sign_key_bound = !verification;
    unit_verify_key_bound = verification;
    unit_error_reason = 0;
    ED301V1_CHECK(init(&signature, NULL, NULL, bad_params) == 0
            && unit_signature_reset_calls == 0
            && (verification ? unit_verify_init_calls
                             : unit_sign_init_calls) == 1
            && (verification ? unit_verify_key_bound
                             : unit_sign_key_bound) == 1
            && unit_error_reason == ED301V1_R_UNSUPPORTED_MODE,
        "rejected params preserve a bound NULL-key %s operation",
        operation);

    unit_signature_reset_calls = 0;
    unit_sign_init_calls = 0;
    unit_verify_init_calls = 0;
    unit_sign_key_bound = !verification;
    unit_verify_key_bound = verification;
    unit_error_reason = 0;
    ED301V1_CHECK(init(&signature, "SHA256", &key, NULL) == 0
            && unit_signature_reset_calls == 0
            && (verification ? unit_verify_init_calls
                             : unit_sign_init_calls) == 0
            && (verification ? unit_verify_key_bound
                             : unit_sign_key_bound) == 1
            && unit_error_reason == ED301V1_R_UNSUPPORTED_MODE,
        "rejected digest with a new key preserves the old %s operation",
        operation);

    unit_signature_reset_calls = 0;
    unit_sign_init_calls = 0;
    unit_verify_init_calls = 0;
    unit_sign_key_bound = !verification;
    unit_verify_key_bound = verification;
    ED301V1_CHECK(init(&signature, NULL, &key, bad_params) == 0
            && unit_signature_reset_calls == 1
            && (verification ? unit_verify_init_calls
                             : unit_sign_init_calls) == 0
            && unit_sign_key_bound == 0
            && unit_verify_key_bound == 0,
        "rejected params with a new key reset the old %s operation",
        operation);

    unit_signature_reset_calls = 0;
    unit_sign_init_calls = 0;
    unit_verify_init_calls = 0;
    unit_sign_key_bound = !verification;
    unit_verify_key_bound = verification;
    if (verification)
        unit_verify_init_result = 0;
    else
        unit_sign_init_result = 0;
    ED301V1_CHECK(init(&signature, NULL, NULL, NULL) == 0
            && unit_signature_reset_calls == 0
            && (verification ? unit_verify_init_calls
                             : unit_sign_init_calls) == 1
            && (verification ? unit_verify_key_bound
                             : unit_sign_key_bound) == 1,
        "failed NULL-key %s callback preserves the bound operation",
        operation);
    unit_sign_init_result = 1;
    unit_verify_init_result = 1;

    unit_signature_reset_calls = 0;
    unit_sign_init_calls = 0;
    unit_verify_init_calls = 0;
    unit_sign_key_bound = !verification;
    unit_verify_key_bound = verification;
    ED301V1_CHECK(init(&signature, NULL, &key, NULL) == 1
            && unit_signature_reset_calls == 1
            && (verification ? unit_verify_init_calls
                             : unit_sign_init_calls) == 1
            && (verification ? unit_verify_key_bound
                             : unit_sign_key_bound) == 1,
        "valid new-key %s reinit remains supported", operation);
}

static void unit_fill_api(ED301V1_SIGNATURE_RUST_API *api)
{
    memset(api, 0, sizeof(*api));
    api->abi_version = 3;
    api->struct_size = sizeof(*api);
    api->seed_bytes = ED301V1_SEED_BYTES;
    api->public_key_bytes = ED301V1_PUBLIC_KEY_BYTES;
    api->signature_bytes = ED301V1_SIGNATURE_BYTES;
#define ASSIGN_CALLBACK(field) \
    api->field = (__typeof__(api->field))unit_dummy
    ASSIGN_CALLBACK(key_new);
    ASSIGN_CALLBACK(key_free);
    ASSIGN_CALLBACK(key_import);
    ASSIGN_CALLBACK(key_set_encoded_public);
    ASSIGN_CALLBACK(key_from_seed);
    ASSIGN_CALLBACK(key_duplicate);
    ASSIGN_CALLBACK(key_has);
    ASSIGN_CALLBACK(key_validate);
    ASSIGN_CALLBACK(key_match);
    ASSIGN_CALLBACK(key_get_private);
    ASSIGN_CALLBACK(key_get_public);
    ASSIGN_CALLBACK(signature_new);
    ASSIGN_CALLBACK(signature_free);
    ASSIGN_CALLBACK(signature_duplicate);
    ASSIGN_CALLBACK(signature_reset);
    api->signature_set_context = unit_signature_set_context;
    api->signature_get_context = unit_signature_get_context;
    ASSIGN_CALLBACK(signature_sign_init);
    ASSIGN_CALLBACK(signature_verify_init);
    ASSIGN_CALLBACK(signature_sign);
    ASSIGN_CALLBACK(signature_verify);
    ASSIGN_CALLBACK(cleanse);
#undef ASSIGN_CALLBACK
}

#define EXPECT_MISSING_CALLBACK(api, field) \
    do { \
        ED301V1_SIGNATURE_RUST_API candidate = *(api); \
        candidate.field = NULL; \
        ED301V1_CHECK(!ed301v1_rust_api_valid(&candidate), \
            "missing ABI callback rejected: %s", #field); \
    } while (0)

int main(void)
{
    ED301V1_SIGNATURE_RUST_API api;
    const OSSL_PARAM *settable;
    ED301V1_CODEC_CONTEXT codec = { 0 };
    OSSL_PARAM cipher[2];
    OSSL_PARAM properties[2];

    ED301V1_REQUIRE_RUNTIME_BINDING();
    unit_fill_api(&api);
    ED301V1_CHECK(ed301v1_rust_api_valid(&api), "complete ABI table accepted");
    EXPECT_MISSING_CALLBACK(&api, key_new);
    EXPECT_MISSING_CALLBACK(&api, key_free);
    EXPECT_MISSING_CALLBACK(&api, key_import);
    EXPECT_MISSING_CALLBACK(&api, key_set_encoded_public);
    EXPECT_MISSING_CALLBACK(&api, key_from_seed);
    EXPECT_MISSING_CALLBACK(&api, key_duplicate);
    EXPECT_MISSING_CALLBACK(&api, key_has);
    EXPECT_MISSING_CALLBACK(&api, key_validate);
    EXPECT_MISSING_CALLBACK(&api, key_match);
    EXPECT_MISSING_CALLBACK(&api, key_get_private);
    EXPECT_MISSING_CALLBACK(&api, key_get_public);
    EXPECT_MISSING_CALLBACK(&api, signature_new);
    EXPECT_MISSING_CALLBACK(&api, signature_free);
    EXPECT_MISSING_CALLBACK(&api, signature_duplicate);
    EXPECT_MISSING_CALLBACK(&api, signature_reset);
    EXPECT_MISSING_CALLBACK(&api, signature_set_context);
    EXPECT_MISSING_CALLBACK(&api, signature_get_context);
    EXPECT_MISSING_CALLBACK(&api, signature_sign_init);
    EXPECT_MISSING_CALLBACK(&api, signature_verify_init);
    EXPECT_MISSING_CALLBACK(&api, signature_sign);
    EXPECT_MISSING_CALLBACK(&api, signature_verify);
    EXPECT_MISSING_CALLBACK(&api, cleanse);

    /*
     * Exercise the function registered in the SIGNATURE dispatch table, not
     * a test-only copy, and preserve OpenSSL's 1 / 0 / negative verification
     * result contract across the C/Rust boundary.
     */
    {
        ED301V1_PROVIDER_CONTEXT provider = { 0 };
        ED301V1_SIGNATURE_CONTEXT signature = { 0 };
        OSSL_FUNC_signature_verify_fn *verify = unit_verify_dispatch();
        unsigned char message = 0x42;
        unsigned char signature_value[ED301V1_SIGNATURE_BYTES] = { 0 };
        int inner = 1;

        api.signature_verify = unit_signature_verify;
        provider.handle = (const OSSL_CORE_HANDLE *)&provider;
        provider.new_error = unit_core_new_error;
        provider.set_error_debug = unit_core_set_error_debug;
        provider.vset_error = unit_core_vset_error;
        provider.rust = &api;
        signature.provider = &provider;
        signature.inner = &inner;

        ED301V1_CHECK(verify != NULL,
            "SIGNATURE verify dispatch is present");

        unit_reset_verify_observation(1);
        ED301V1_CHECK(verify != NULL
                && verify(&signature, signature_value,
                    sizeof(signature_value), &message, sizeof(message)) == 1
                && unit_verify_calls == 1 && unit_error_calls == 0,
            "verify dispatch preserves acceptance result");

        unit_reset_verify_observation(0);
        ED301V1_CHECK(verify != NULL
                && verify(&signature, signature_value,
                    sizeof(signature_value), &message, sizeof(message)) == 0
                && unit_verify_calls == 1 && unit_error_calls == 0,
            "verify dispatch preserves cryptographic non-match");

        unit_reset_verify_observation(-1);
        ED301V1_CHECK(verify != NULL
                && verify(&signature, signature_value,
                    sizeof(signature_value), &message, sizeof(message)) < 0
                && unit_verify_calls == 1 && unit_error_calls == 1
                && unit_error_reason == ED301V1_R_INVALID_STATE,
            "verify dispatch preserves operational failure and raises error");

        unit_reset_verify_observation(1);
        ED301V1_CHECK(verify != NULL
                && verify(&signature, signature_value,
                    sizeof(signature_value) - 1,
                    &message, sizeof(message)) == 0
                && unit_verify_calls == 0 && unit_error_calls == 0,
            "wrong signature length is a normal non-match");

        unit_reset_verify_observation(1);
        ED301V1_CHECK(verify != NULL
                && verify(&signature, NULL, sizeof(signature_value),
                    &message, sizeof(message)) < 0
                && unit_verify_calls == 0 && unit_error_calls == 1
                && unit_error_reason == ED301V1_R_INVALID_PARAMETER,
            "NULL signature buffer is an operational error");

        unit_reset_verify_observation(1);
        ED301V1_CHECK(verify != NULL
                && verify(&signature, signature_value,
                    sizeof(signature_value), NULL, 1) < 0
                && unit_verify_calls == 0 && unit_error_calls == 1
                && unit_error_reason == ED301V1_R_INVALID_PARAMETER,
            "NULL message with nonzero length is an operational error");

        unit_reset_verify_observation(1);
        ED301V1_CHECK(verify != NULL
                && verify(&signature, signature_value,
                    sizeof(signature_value) - 1, NULL, 1) < 0
                && unit_verify_calls == 0 && unit_error_calls == 1
                && unit_error_reason == ED301V1_R_INVALID_PARAMETER,
            "invalid message takes precedence over malformed signature");

        unit_reset_verify_observation(1);
        ED301V1_CHECK(verify != NULL
                && verify(NULL, signature_value, sizeof(signature_value),
                    &message, sizeof(message)) < 0
                && unit_verify_calls == 0,
            "invalid signature context is an operational error");
    }

    unit_test_digest_reinit_contract(&api, 0);
    unit_test_digest_reinit_contract(&api, 1);

#if OPENSSL_VERSION_MAJOR == 3
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("3.0.0"),
        "OpenSSL 3.0 predates the source/API minimum");
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("3.4.999"),
        "OpenSSL 3.4 predates the tested source/API minimum");
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("3.5.6"),
        "OpenSSL 3.5 patch below the tested minimum rejected");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("3.5.7"),
        "OpenSSL 3.5.7 source/API minimum accepted");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("3.5.999"),
        "OpenSSL 3.5 patch update accepted");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("3.6.0"),
        "later OpenSSL 3 minor accepted");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("3.99.1"),
        "later OpenSSL 3 minor accepted");
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("4.0.1"),
        "different OpenSSL major rejected");
#else
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("4.0.0"),
        "OpenSSL 4 patch below the source/API minimum rejected");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("4.0.1"),
        "OpenSSL 4.0.1 source/API minimum accepted");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("4.0.999"),
        "OpenSSL 4 patch update accepted");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("4.1.0"),
        "later OpenSSL 4 minor accepted");
    ED301V1_CHECK(ed301v1_core_version_text_is_supported("4.99.1"),
        "later OpenSSL 4 minor accepted");
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("3.99.99"),
        "different OpenSSL major rejected");
#endif
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("invalid"),
        "malformed core version rejected");
    ED301V1_CHECK(!ed301v1_core_version_text_is_supported("3.5"),
        "incomplete core version rejected");

    settable = ed301v1_private_codec_settable_ctx_params(NULL);
    ED301V1_CHECK(settable != NULL && settable[0].key == NULL,
        "private encoder advertises an empty settable list");

    codec.structure = ED301V1_CODEC_PRIVATE_KEY_INFO;
    cipher[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_ENCODER_PARAM_CIPHER, "AES-256-CBC", 0);
    cipher[1] = OSSL_PARAM_construct_end();
    ED301V1_CHECK(ed301v1_private_codec_set_ctx_params(&codec, cipher) == 0,
        "encoder cipher remains rejected");
    ED301V1_CHECK(codec.invalid == 1,
        "rejected encoder cipher poisons the context");
    ERR_clear_error();

    codec.invalid = 0;
    properties[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_ENCODER_PARAM_PROPERTIES, "provider=default", 0);
    properties[1] = OSSL_PARAM_construct_end();
    ED301V1_CHECK(ed301v1_private_codec_set_ctx_params(&codec, properties) == 0,
        "encoder properties remain rejected");
    ED301V1_CHECK(codec.invalid == 1,
        "rejected encoder properties poison the context");
    ERR_clear_error();

    return ed301v1_summary("provider_shim_unit");
}
