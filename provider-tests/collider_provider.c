/*
 * VAL-05 fixture: a minimal test-only provider whose ONLY function is to
 * advertise a TLS-SIGALG capability with the SAME private-use code point
 * 0xFE84 as the draft-00 test scheme, but bound to a different algorithm
 * (Ed25519 from the default provider).  It offers no algorithms of its
 * own.  Built as collider_fe84.so and loaded next to the draft-00 module
 * to observe libssl's duplicate-code-point behaviour.
 */

#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

static int collider_get_capabilities(
    void *provider_context,
    const char *capability,
    OSSL_CALLBACK *callback,
    void *callback_argument)
{
    unsigned int code_point = 0xfe84;
    unsigned int security_bits = 128;
    int minimum_tls = TLS1_3_VERSION;
    int maximum_tls = TLS1_3_VERSION;
    int minimum_dtls = -1;
    int maximum_dtls = -1;
    OSSL_PARAM sigalg_parameters[] = {
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,
            "collider_fe84", sizeof("collider_fe84")),
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,
            "ED25519", sizeof("ED25519")),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,
            &code_point),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,
            &security_bits),
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE,
            "ED25519", sizeof("ED25519")),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, &minimum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, &maximum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS, &minimum_dtls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS, &maximum_dtls),
        OSSL_PARAM_END
    };

    (void)provider_context;
    if (capability == NULL || callback == NULL)
        return 0;
    if (strcmp(capability, "TLS-SIGALG") == 0)
        return callback(sigalg_parameters, callback_argument);
    return 1;
}

static const OSSL_ALGORITHM *collider_query_operation(
    void *provider_context,
    int operation_id,
    int *no_cache)
{
    (void)provider_context;
    (void)operation_id;
    if (no_cache != NULL)
        *no_cache = 0;
    return NULL;
}

static void collider_teardown(void *provider_context)
{
    (void)provider_context;
}

static const OSSL_DISPATCH collider_dispatch[] = {
    {
        OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))collider_query_operation
    },
    {
        OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))collider_get_capabilities
    },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))collider_teardown },
    { 0, NULL }
};

int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context);

int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context)
{
    (void)input_dispatch;
    if (handle == NULL || output_dispatch == NULL
            || provider_context == NULL)
        return 0;
    *output_dispatch = collider_dispatch;
    *provider_context = (void *)1;
    return 1;
}
