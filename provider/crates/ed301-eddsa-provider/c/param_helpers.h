#ifndef ED301V1_PARAM_HELPERS_H
#define ED301V1_PARAM_HELPERS_H

/*
 * OSSL_PARAM helpers, adapted unchanged in shape from the historical
 * provider's param_helpers.h (see the result provenance map).
 */

#include <stddef.h>

#include <openssl/params.h>

/*
 * Optional output parameters are absent when the caller did not request
 * them.  Present parameters, including size queries with data == NULL, are
 * handled by OpenSSL's public parameter API.
 */
static inline int ed301v1_param_set_optional_int(
    OSSL_PARAM *parameter,
    int value)
{
    return parameter == NULL || OSSL_PARAM_set_int(parameter, value) == 1;
}

static inline int ed301v1_param_set_optional_utf8_ptr(
    OSSL_PARAM *parameter,
    const char *value)
{
    return parameter == NULL
        || OSSL_PARAM_set_utf8_ptr(parameter, value) == 1;
}

static inline int ed301v1_param_set_optional_utf8_string(
    OSSL_PARAM *parameter,
    const char *value)
{
    return parameter == NULL
        || OSSL_PARAM_set_utf8_string(parameter, value) == 1;
}

static inline int ed301v1_param_set_optional_octet_string(
    OSSL_PARAM *parameter,
    const unsigned char *value,
    size_t value_length)
{
    return parameter == NULL
        || OSSL_PARAM_set_octet_string(
            parameter,
            value,
            value_length) == 1;
}

/*
 * OpenSSL's pointer getter intentionally accepts both OCTET_STRING and
 * OCTET_PTR.  The Ed301-EdDSA-v1 key encodings require the former, a non-NULL
 * value and an exact profile length, so validate those public representation
 * properties before delegating pointer extraction to OpenSSL.
 */
static inline int ed301v1_param_get_strict_octet_string(
    const OSSL_PARAM parameters[],
    const char *name,
    const unsigned char **value,
    size_t *value_length,
    size_t expected_length,
    int required)
{
    const OSSL_PARAM *parameter;
    const void *octets = NULL;
    size_t octet_length = 0;

    if (name == NULL || value == NULL || value_length == NULL)
        return 0;
    *value = NULL;
    *value_length = 0;
    parameter = parameters == NULL
        ? NULL
        : OSSL_PARAM_locate_const(parameters, name);
    if (parameter == NULL)
        return required == 0;
    if (parameter->data_type != OSSL_PARAM_OCTET_STRING
            || parameter->data == NULL
            || parameter->data_size != expected_length
            || OSSL_PARAM_get_octet_string_ptr(
                parameter,
                &octets,
                &octet_length) != 1
            || octets == NULL
            || octet_length != expected_length)
        return 0;

    *value = octets;
    *value_length = octet_length;
    return 1;
}

#endif
