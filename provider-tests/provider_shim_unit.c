/* Focused C-side contract tests for the Rust ABI table and encoder policy. */

#include "harness_common.h"
#include "../provider/crates/ed301-eddsa-provider/c/provider_shim.c"

static void unit_dummy(void)
{
}

static void unit_fill_api(ED301D00_SIGNATURE_RUST_API *api)
{
    memset(api, 0, sizeof(*api));
    api->abi_version = 1;
    api->struct_size = sizeof(*api);
    api->seed_bytes = ED301D00_SEED_BYTES;
    api->public_key_bytes = ED301D00_PUBLIC_KEY_BYTES;
    api->signature_bytes = ED301D00_SIGNATURE_BYTES;
#define ASSIGN_CALLBACK(field) \
    api->field = (__typeof__(api->field))unit_dummy
    ASSIGN_CALLBACK(key_new);
    ASSIGN_CALLBACK(key_free);
    ASSIGN_CALLBACK(key_import);
    ASSIGN_CALLBACK(key_set_encoded_public);
    ASSIGN_CALLBACK(key_generate);
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
    ASSIGN_CALLBACK(signature_sign_init);
    ASSIGN_CALLBACK(signature_verify_init);
    ASSIGN_CALLBACK(signature_sign);
    ASSIGN_CALLBACK(signature_verify);
    ASSIGN_CALLBACK(cleanse);
#undef ASSIGN_CALLBACK
}

#define EXPECT_MISSING_CALLBACK(api, field) \
    do { \
        ED301D00_SIGNATURE_RUST_API candidate = *(api); \
        candidate.field = NULL; \
        D00_CHECK(!ed301d00_rust_api_valid(&candidate), \
            "missing ABI callback rejected: %s", #field); \
    } while (0)

int main(void)
{
    ED301D00_SIGNATURE_RUST_API api;
    const OSSL_PARAM *settable;
    ED301D00_CODEC_CONTEXT codec = { 0 };
    OSSL_PARAM cipher[2];
    OSSL_PARAM properties[2];

    D00_REQUIRE_RUNTIME_BINDING();
    unit_fill_api(&api);
    D00_CHECK(ed301d00_rust_api_valid(&api), "complete ABI table accepted");
    EXPECT_MISSING_CALLBACK(&api, key_new);
    EXPECT_MISSING_CALLBACK(&api, key_free);
    EXPECT_MISSING_CALLBACK(&api, key_import);
    EXPECT_MISSING_CALLBACK(&api, key_set_encoded_public);
    EXPECT_MISSING_CALLBACK(&api, key_generate);
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
    EXPECT_MISSING_CALLBACK(&api, signature_sign_init);
    EXPECT_MISSING_CALLBACK(&api, signature_verify_init);
    EXPECT_MISSING_CALLBACK(&api, signature_sign);
    EXPECT_MISSING_CALLBACK(&api, signature_verify);
    EXPECT_MISSING_CALLBACK(&api, cleanse);

    settable = ed301d00_private_codec_settable_ctx_params(NULL);
    D00_CHECK(settable != NULL && settable[0].key == NULL,
        "private encoder advertises an empty settable list");

    codec.structure = ED301D00_CODEC_PRIVATE_KEY_INFO;
    cipher[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_ENCODER_PARAM_CIPHER, "AES-256-CBC", 0);
    cipher[1] = OSSL_PARAM_construct_end();
    D00_CHECK(ed301d00_private_codec_set_ctx_params(&codec, cipher) == 0,
        "encoder cipher remains rejected");
    D00_CHECK(codec.invalid == 1,
        "rejected encoder cipher poisons the context");
    ERR_clear_error();

    codec.invalid = 0;
    properties[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_ENCODER_PARAM_PROPERTIES, "provider=default", 0);
    properties[1] = OSSL_PARAM_construct_end();
    D00_CHECK(ed301d00_private_codec_set_ctx_params(&codec, properties) == 0,
        "encoder properties remain rejected");
    D00_CHECK(codec.invalid == 1,
        "rejected encoder properties poison the context");
    ERR_clear_error();

    return d00_summary("provider_shim_unit");
}
