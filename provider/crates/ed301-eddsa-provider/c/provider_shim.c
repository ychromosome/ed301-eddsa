/*
 * Experimental signature-only OpenSSL provider for Ed301-EdDSA-draft-00.
 *
 * Adapted from the historical ed301-openssl-provider shim (dispatch shapes,
 * selection logic, buffer contracts, serialization structure, collision
 * handling) and from the post-commit hardening patch (process-global object
 * registry transaction).  See the result provenance map.  The historical
 * Ed301-Sig-v1 identity, context support, transcript, OID 1.3.6.1.4.1.66282.*
 * and TLS codepoint 0xFE2D are intentionally not reused.
 *
 * Identifier boundary: every identifier below marked TEST-ONLY is an
 * explicitly ephemeral, collision-checked, NONREGISTRABLE working identifier
 * for this isolated experiment.  Nothing here is a permanent OID or IANA
 * assignment, a production claim, a constant-time claim or a release claim.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#include "param_helpers.h"
#include "provider_internal.h"

/*
 * One artifact per ABI lane (FBL-01): the module binds at compile time to
 * the major.minor of the OpenSSL headers it was built against and refuses
 * at runtime to initialise against a core of any other major.minor.  A
 * deliberately crossed header/library combination therefore fails before
 * any algorithm is offered.  Each supported lane is built, tested and
 * shipped separately; one DSO never covers incompatible ABIs.
 */
#if OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 5
# define ED301D00_SUPPORTED_CORE_VERSION_PREFIX "3.5."
#elif OPENSSL_VERSION_MAJOR == 4 && OPENSSL_VERSION_MINOR == 0
# define ED301D00_SUPPORTED_CORE_VERSION_PREFIX "4.0."
#else
# error "This Ed301-EdDSA-draft-00 experiment supports only OpenSSL 3.5.x or 4.0.x headers"
#endif

#define ED301D00_SEED_BYTES ((size_t)38)
#define ED301D00_PUBLIC_KEY_BYTES ((size_t)38)
#define ED301D00_SIGNATURE_BYTES ((size_t)76)
#define ED301D00_BITS 301
#define ED301D00_SECURITY_BITS 149
#define ED301D00_TLS_VERSION_1_3 0x0304

/*
 * TEST-ONLY, NONREGISTRABLE ephemeral identifier profile for this isolated
 * experiment.  The OID is UUID-derived under the 2.25 arc and was collision
 * checked at generation and is collision checked again fail-closed at every
 * provider load.  The TLS SignatureScheme codepoint is from the private-use
 * range and deliberately differs from the historical 0xFE2D.
 */
#define ED301D00_OID_TEXT \
    "2.25.195456677253783758411179833219689607856"
#define ED301D00_TLS_SIGALG_CODE_POINT ((unsigned int)0xfe84)

/*
 * The separately named, test-only failpoint artifact renames both the
 * module and its "provider=" property so it can never be mistaken for or
 * fetched as the ordinary module (FBL-02).
 */
#ifdef ED301D00_TEST_FAILPOINT_ARTIFACT
# define ED301D00_PROVIDER_BASENAME "ed301_eddsa_draft00_failpoint"
#else
# define ED301D00_PROVIDER_BASENAME "ed301_eddsa_draft00"
#endif

static const char ED301D00_PROVIDER_NAME[] =
    "Ed301-EdDSA-draft-00 Experimental Provider (test-only)";
static const char ED301D00_PROVIDER_VERSION[] = "0.0.1";
static const char ED301D00_PROVIDER_BUILDINFO[] =
    "ed301_eddsa_draft00 provider-experiment-1 (test-only, nonregistrable "
    "identifiers); headers: " OPENSSL_VERSION_TEXT;
static const char ED301D00_ALGORITHM_NAME[] = "Ed301-EdDSA-draft-00";
static const char ED301D00_OID[] = ED301D00_OID_TEXT;
static const char ED301D00_ALGORITHM_NAMES[] =
    "Ed301-EdDSA-draft-00:" ED301D00_OID_TEXT;
static const char ED301D00_PROPERTY[] =
    "provider=" ED301D00_PROVIDER_BASENAME;
#ifndef ED301D00_TEST_FAILPOINT_ARTIFACT
static const char ED301D00_TLS_SIGALG_CAPABILITY[] = "TLS-SIGALG";
static const char ED301D00_TLS_SIGALG_IANA_NAME[] =
    "ed301_eddsa_draft00_test";
#endif

/*
 * DER SEQUENCE { OBJECT IDENTIFIER 2.25.195456677253783758411179833219689607856 };
 * parameterless by profile.  TEST-ONLY, NONREGISTRABLE.
 */
static const unsigned char ED301D00_ALGORITHM_ID_DER[] = {
    0x30, 0x16, 0x06, 0x14, 0x69, 0x82, 0xa6, 0x8b,
    0xcb, 0x8d, 0xb3, 0x93, 0xe2, 0x9f, 0x8b, 0x8a,
    0x9e, 0xf1, 0xc4, 0xf2, 0xe5, 0xd7, 0xe5, 0x30
};

static const unsigned char ED301D00_SPKI_PREFIX[] = {
    0x30, 0x41, 0x30, 0x16, 0x06, 0x14, 0x69, 0x82,
    0xa6, 0x8b, 0xcb, 0x8d, 0xb3, 0x93, 0xe2, 0x9f,
    0x8b, 0x8a, 0x9e, 0xf1, 0xc4, 0xf2, 0xe5, 0xd7,
    0xe5, 0x30, 0x03, 0x27, 0x00
};

static const unsigned char ED301D00_PKCS8_PREFIX[] = {
    0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x16, 0x06,
    0x14, 0x69, 0x82, 0xa6, 0x8b, 0xcb, 0x8d, 0xb3,
    0x93, 0xe2, 0x9f, 0x8b, 0x8a, 0x9e, 0xf1, 0xc4,
    0xf2, 0xe5, 0xd7, 0xe5, 0x30, 0x04, 0x28, 0x04,
    0x26
};

#define ED301D00_OID_TLV_BYTES ((size_t)22)

_Static_assert(
    sizeof(ED301D00_ALGORITHM_ID_DER) == 24,
    "draft-00 AlgorithmIdentifier must be exactly 24 bytes");
_Static_assert(
    sizeof(ED301D00_SPKI_PREFIX) + ED301D00_PUBLIC_KEY_BYTES == 67,
    "draft-00 SPKI must be exactly 67 bytes");
_Static_assert(
    sizeof(ED301D00_PKCS8_PREFIX) + ED301D00_SEED_BYTES == 71,
    "draft-00 PKCS#8 must be exactly 71 bytes");

typedef struct ed301d00_key_st {
    ED301D00_PROVIDER_CONTEXT *provider;
    void *inner;
} ED301D00_KEY;

typedef struct ed301d00_gen_context_st {
    ED301D00_PROVIDER_CONTEXT *provider;
} ED301D00_GEN_CONTEXT;

typedef struct ed301d00_signature_context_st {
    ED301D00_PROVIDER_CONTEXT *provider;
    void *inner;
} ED301D00_SIGNATURE_CONTEXT;

typedef enum ed301d00_codec_structure_st {
    ED301D00_CODEC_PRIVATE_KEY_INFO = 1,
    ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO = 2,
    ED301D00_CODEC_TEXT_KEY = 3
} ED301D00_CODEC_STRUCTURE;

typedef enum ed301d00_codec_format_st {
    ED301D00_CODEC_FORMAT_DER = 1,
    ED301D00_CODEC_FORMAT_PEM = 2,
    ED301D00_CODEC_FORMAT_TEXT = 3
} ED301D00_CODEC_FORMAT;

typedef struct ed301d00_codec_context_st {
    ED301D00_PROVIDER_CONTEXT *provider;
    ED301D00_CODEC_STRUCTURE structure;
    ED301D00_CODEC_FORMAT format;
    int selection;
    int invalid;
} ED301D00_CODEC_CONTEXT;

enum {
    ED301D00_R_INVALID_KEY = 1,
    ED301D00_R_INVALID_STATE = 2,
    ED301D00_R_INVALID_PARAMETER = 3,
    ED301D00_R_ALLOCATION_FAILURE = 4,
    ED301D00_R_OBJECT_REGISTRATION_FAILURE = 5,
    ED301D00_R_SERIALIZATION_FAILURE = 6,
    ED301D00_R_UNSUPPORTED_MODE = 7
};

/* Static reason descriptions copied by a successfully initialized core. */
static const OSSL_ITEM ED301D00_REASON_STRINGS[] = {
    { ED301D00_R_INVALID_KEY, "invalid key" },
    { ED301D00_R_INVALID_STATE, "invalid state" },
    { ED301D00_R_INVALID_PARAMETER, "invalid parameter" },
    { ED301D00_R_ALLOCATION_FAILURE, "allocation failure" },
    { ED301D00_R_OBJECT_REGISTRATION_FAILURE,
        "object registration failure" },
    { ED301D00_R_SERIALIZATION_FAILURE, "serialization failure" },
    { ED301D00_R_UNSUPPORTED_MODE, "unsupported mode" },
    { 0, NULL }
};

static const OSSL_PARAM ED301D00_PROVIDER_GETTABLE_PARAMS[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301D00_KEY_GETTABLE_PARAMS[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301D00_PRIVATE_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301D00_PUBLIC_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301D00_KEYPAIR_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301D00_SETTABLE_KEY_PARAMS[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

/*
 * The draft defines no context, digest, prehash, streaming or randomized
 * signing mode, so every such parameter is rejected rather than
 * accepted-and-ignored.  The single exception is transport metadata on the
 * OpenSSL 4.0 lane: its libssl announces the negotiated protocol version to
 * the signature provider as a signed int constructed with
 * OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_TLS_VERSION, &s->version),
 * and only that exact form carrying TLS 1.3 is tolerated.  The 3.5 lane
 * sends no such parameter, advertises nothing and keeps rejecting it.
 */
#if OPENSSL_VERSION_MAJOR == 4
# define ED301D00_ACCEPT_TLS_VERSION_PARAM 1
#else
# define ED301D00_ACCEPT_TLS_VERSION_PARAM 0
#endif

static const OSSL_PARAM ED301D00_SETTABLE_CTX_PARAMS[] = {
#if ED301D00_ACCEPT_TLS_VERSION_PARAM
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_TLS_VERSION, NULL),
#endif
    OSSL_PARAM_END
};

static const OSSL_PARAM ED301D00_GETTABLE_CTX_PARAMS[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static int ed301d00_selection_supported(int selection)
{
    return (selection & ~OSSL_KEYMGMT_SELECT_ALL) == 0;
}

static int ed301d00_wants_private(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int ed301d00_wants_public(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static void ed301d00_raise(
    ED301D00_PROVIDER_CONTEXT *provider,
    uint32_t reason,
    const char *format,
    ...)
{
    va_list arguments;

    if (provider == NULL || provider->new_error == NULL
            || provider->set_error_debug == NULL
            || provider->vset_error == NULL)
        return;

    provider->new_error(provider->handle);
    provider->set_error_debug(provider->handle, __FILE__, __LINE__, __func__);
    va_start(arguments, format);
    provider->vset_error(provider->handle, reason, format, arguments);
    va_end(arguments);
}

static void *ed301d00_allocate(
    ED301D00_PROVIDER_CONTEXT *provider,
    size_t size)
{
    if (provider == NULL || provider->zalloc == NULL)
        return NULL;
    return provider->zalloc(size, __FILE__, __LINE__);
}

static void ed301d00_clear_free(
    ED301D00_PROVIDER_CONTEXT *provider,
    void *pointer,
    size_t size)
{
    if (provider != NULL && provider->clear_free != NULL && pointer != NULL)
        provider->clear_free(pointer, size, __FILE__, __LINE__);
}

static void *ed301d00_key_load(const void *reference, size_t reference_size)
{
    void **mutable_reference;
    void *key;

    if (reference == NULL || reference_size != sizeof(key))
        return NULL;

    mutable_reference = (void **)reference;
    key = *mutable_reference;
    *mutable_reference = NULL;
    return key;
}

/* ------------------------------------------------------------------ */
/* Key management                                                     */
/* ------------------------------------------------------------------ */

static ED301D00_KEY *ed301d00_wrap_key(
    ED301D00_PROVIDER_CONTEXT *provider,
    void *inner)
{
    ED301D00_KEY *key;

    if (provider == NULL || inner == NULL)
        return NULL;
    key = ed301d00_allocate(provider, sizeof(*key));
    if (key == NULL) {
        provider->rust->key_free(inner);
        ed301d00_raise(provider, ED301D00_R_ALLOCATION_FAILURE,
            "draft-00 key allocation failed");
        return NULL;
    }

    key->provider = provider;
    key->inner = inner;
    return key;
}

static void *ed301d00_key_new(void *provider_context)
{
    ED301D00_PROVIDER_CONTEXT *provider = provider_context;
    void *inner;

    if (provider == NULL || provider->rust == NULL)
        return NULL;
    inner = provider->rust->key_new();
    if (inner == NULL) {
        ed301d00_raise(provider, ED301D00_R_ALLOCATION_FAILURE,
            "draft-00 key allocation failed");
        return NULL;
    }
    return ed301d00_wrap_key(provider, inner);
}

static void ed301d00_key_free(void *key_data)
{
    ED301D00_KEY *key = key_data;
    ED301D00_PROVIDER_CONTEXT *provider;

    if (key == NULL)
        return;
    provider = key->provider;
    if (provider != NULL && provider->rust != NULL && key->inner != NULL)
        provider->rust->key_free(key->inner);
    ed301d00_clear_free(provider, key, sizeof(*key));
}

static int ed301d00_key_import(
    void *key_data,
    int selection,
    const OSSL_PARAM params[])
{
    ED301D00_KEY *key = key_data;
    const unsigned char *private_key = NULL;
    const unsigned char *public_key = NULL;
    size_t private_length = 0;
    size_t public_length = 0;
    const int wants_private = ed301d00_wants_private(selection);
    const int wants_public = ed301d00_wants_public(selection);

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || params == NULL || !ed301d00_selection_supported(selection)
            || (!wants_private && !wants_public))
        return 0;

    if (wants_private && !ed301d00_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_PRIV_KEY,
            &private_key,
            &private_length,
            ED301D00_SEED_BYTES,
            wants_private && !wants_public))
        goto invalid;

    if (wants_public && !ed301d00_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_PUB_KEY,
            &public_key,
            &public_length,
            ED301D00_PUBLIC_KEY_BYTES,
            wants_public && !wants_private))
        goto invalid;

    /*
     * Selection contract (see the disclosed historical import-selection
     * correction, independently re-reviewed for this experiment): a
     * private-only selection requires a seed, a public-only selection
     * requires a public key, and a keypair selection requires at least the
     * seed, whose derived public key must match any supplied encoding.
     */
    if ((private_key == NULL && public_key == NULL)
            || (wants_private && !wants_public && private_key == NULL)
            || (wants_public && !wants_private && public_key == NULL)
            || (wants_private && wants_public && private_key == NULL))
        goto invalid;

    if (key->provider->rust->key_import(
            key->inner,
            wants_private ? private_key : NULL,
            wants_private ? private_length : 0,
            wants_public ? public_key : NULL,
            wants_public ? public_length : 0) != 1)
        goto invalid;

    return 1;

invalid:
    ed301d00_raise(key->provider, ED301D00_R_INVALID_KEY,
        "invalid draft-00 key material");
    return 0;
}

static const OSSL_PARAM *ed301d00_key_import_types(int selection)
{
    const int wants_private = ed301d00_wants_private(selection);
    const int wants_public = ed301d00_wants_public(selection);

    if (!ed301d00_selection_supported(selection))
        return NULL;
    if (wants_private && wants_public)
        return ED301D00_KEYPAIR_TYPES;
    if (wants_private)
        return ED301D00_PRIVATE_TYPES;
    if (wants_public)
        return ED301D00_PUBLIC_TYPES;
    return NULL;
}

static int ed301d00_key_export(
    void *key_data,
    int selection,
    OSSL_CALLBACK *parameter_callback,
    void *callback_argument)
{
    ED301D00_KEY *key = key_data;
    unsigned char private_key[ED301D00_SEED_BYTES] = { 0 };
    unsigned char public_key[ED301D00_PUBLIC_KEY_BYTES] = { 0 };
    OSSL_PARAM export_params[3];
    size_t parameter_count = 0;
    int result = 0;
    const int wants_private = ed301d00_wants_private(selection);
    const int wants_public = ed301d00_wants_public(selection);

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || parameter_callback == NULL
            || !ed301d00_selection_supported(selection)
            || (!wants_private && !wants_public))
        goto cleanup;

    if (key->provider->rust->key_has(
            key->inner,
            wants_private,
            wants_public) != 1)
        goto cleanup;

    if (wants_private) {
        if (key->provider->rust->key_get_private(
                key->inner,
                private_key,
                sizeof(private_key)) != 1)
            goto cleanup;
        export_params[parameter_count++] = (OSSL_PARAM)
            OSSL_PARAM_octet_string(
                OSSL_PKEY_PARAM_PRIV_KEY,
                private_key,
                sizeof(private_key));
    }
    if (wants_public) {
        if (key->provider->rust->key_get_public(
                key->inner,
                public_key,
                sizeof(public_key)) != 1)
            goto cleanup;
        export_params[parameter_count++] = (OSSL_PARAM)
            OSSL_PARAM_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY,
                public_key,
                sizeof(public_key));
    }
    export_params[parameter_count] = (OSSL_PARAM)OSSL_PARAM_END;
    result = parameter_callback(export_params, callback_argument);

cleanup:
    if (key != NULL && key->provider != NULL && key->provider->rust != NULL)
        key->provider->rust->cleanse(private_key, sizeof(private_key));
    if (result != 1 && key != NULL)
        ed301d00_raise(key->provider, ED301D00_R_INVALID_KEY,
            "draft-00 key export failed");
    return result == 1 ? 1 : 0;
}

static const OSSL_PARAM *ed301d00_key_export_types(int selection)
{
    return ed301d00_key_import_types(selection);
}

static const OSSL_PARAM *ed301d00_key_gettable_params(void *provider_context)
{
    (void)provider_context;
    return ED301D00_KEY_GETTABLE_PARAMS;
}

static int ed301d00_key_get_params(void *key_data, OSSL_PARAM params[])
{
    ED301D00_KEY *key = key_data;
    OSSL_PARAM *public_param;
    OSSL_PARAM *encoded_public_param;
    OSSL_PARAM *private_param;
    unsigned char private_key[ED301D00_SEED_BYTES] = { 0 };
    unsigned char public_key[ED301D00_PUBLIC_KEY_BYTES] = { 0 };
    int result = 0;

    if (key == NULL || key->provider == NULL || key->provider->rust == NULL
            || key->inner == NULL || params == NULL)
        goto cleanup;

    if (!ed301d00_param_set_optional_int(
            OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS),
            ED301D00_BITS)
            || !ed301d00_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS),
                ED301D00_SECURITY_BITS)
            || !ed301d00_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE),
                (int)ED301D00_SIGNATURE_BYTES)
            || !ed301d00_param_set_optional_utf8_string(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST),
                ""))
        goto cleanup;

    public_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    encoded_public_param =
        OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (public_param != NULL || encoded_public_param != NULL) {
        if (key->provider->rust->key_get_public(
                key->inner,
                public_key,
                sizeof(public_key)) != 1
                || !ed301d00_param_set_optional_octet_string(
                    public_param,
                    public_key,
                    sizeof(public_key))
                || !ed301d00_param_set_optional_octet_string(
                    encoded_public_param,
                    public_key,
                    sizeof(public_key)))
            goto cleanup;
    }

    private_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (private_param != NULL) {
        if (key->provider->rust->key_get_private(
                key->inner,
                private_key,
                sizeof(private_key)) != 1
                || !ed301d00_param_set_optional_octet_string(
                    private_param,
                    private_key,
                    sizeof(private_key)))
            goto cleanup;
    }

    result = 1;

cleanup:
    if (key != NULL && key->provider != NULL && key->provider->rust != NULL)
        key->provider->rust->cleanse(private_key, sizeof(private_key));
    if (result != 1 && key != NULL)
        ed301d00_raise(key->provider, ED301D00_R_INVALID_PARAMETER,
            "draft-00 key parameter query failed");
    return result;
}

static const OSSL_PARAM *ed301d00_key_settable_params(void *provider_context)
{
    (void)provider_context;
    return ED301D00_SETTABLE_KEY_PARAMS;
}

static int ed301d00_key_set_params(void *key_data, const OSSL_PARAM params[])
{
    ED301D00_KEY *key = key_data;
    const unsigned char *public_key = NULL;
    size_t public_length = 0;

    if (key == NULL || key->provider == NULL || key->inner == NULL)
        return 0;
    if (params == NULL
            || OSSL_PARAM_locate_const(
                params,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) == NULL)
        return 1;
    if (!ed301d00_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            &public_key,
            &public_length,
            ED301D00_PUBLIC_KEY_BYTES,
            1)
            || key->provider->rust->key_set_encoded_public(
                key->inner,
                public_key,
                public_length) != 1) {
        ed301d00_raise(key->provider, ED301D00_R_INVALID_KEY,
            "invalid draft-00 encoded public key");
        return 0;
    }
    return 1;
}

static int ed301d00_key_has(const void *key_data, int selection)
{
    const ED301D00_KEY *key = key_data;

    if (key == NULL || key->provider == NULL
            || key->provider->rust == NULL || key->inner == NULL
            || !ed301d00_selection_supported(selection))
        return 0;
    return key->provider->rust->key_has(
        key->inner,
        ed301d00_wants_private(selection),
        ed301d00_wants_public(selection));
}

static int ed301d00_key_validate(
    const void *key_data,
    int selection,
    int check_type)
{
    const ED301D00_KEY *key = key_data;
    int result;

    if (key == NULL || key->provider == NULL
            || key->provider->rust == NULL || key->inner == NULL
            || !ed301d00_selection_supported(selection)
            || (check_type != OSSL_KEYMGMT_VALIDATE_FULL_CHECK
                && check_type != OSSL_KEYMGMT_VALIDATE_QUICK_CHECK))
        return 0;

    result = key->provider->rust->key_validate(
        key->inner,
        ed301d00_wants_private(selection),
        ed301d00_wants_public(selection));
    if (result != 1)
        ed301d00_raise(key->provider, ED301D00_R_INVALID_KEY,
            "draft-00 key validation failed");
    return result;
}

static int ed301d00_key_match(
    const void *first_data,
    const void *second_data,
    int selection)
{
    const ED301D00_KEY *first = first_data;
    const ED301D00_KEY *second = second_data;

    if (first == NULL || second == NULL || first->provider == NULL
            || first->provider != second->provider
            || first->provider->rust == NULL
            || first->inner == NULL || second->inner == NULL
            || !ed301d00_selection_supported(selection))
        return 0;

    return first->provider->rust->key_match(
        first->inner,
        second->inner,
        ed301d00_wants_private(selection),
        ed301d00_wants_public(selection));
}

static void *ed301d00_key_duplicate(const void *source_data, int selection)
{
    const ED301D00_KEY *source = source_data;
    void *inner;

    if (source == NULL || source->provider == NULL
            || source->provider->rust == NULL
            || source->inner == NULL
            || !ed301d00_selection_supported(selection))
        return NULL;
    inner = source->provider->rust->key_duplicate(
        source->inner,
        ed301d00_wants_private(selection),
        ed301d00_wants_public(selection));
    if (inner == NULL)
        return NULL;
    return ed301d00_wrap_key(source->provider, inner);
}

static const char *ed301d00_key_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
        return ED301D00_ALGORITHM_NAME;
    return NULL;
}

static void *ed301d00_key_gen_init(
    void *provider_context,
    int selection,
    const OSSL_PARAM params[])
{
    ED301D00_PROVIDER_CONTEXT *provider = provider_context;
    ED301D00_GEN_CONTEXT *generation;
    const int generates_keypair =
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
            == OSSL_KEYMGMT_SELECT_KEYPAIR;

    if (provider == NULL || provider->rust == NULL
            || !generates_keypair || !ed301d00_selection_supported(selection)
            || (params != NULL && params[0].key != NULL)) {
        ed301d00_raise(provider, ED301D00_R_INVALID_PARAMETER,
            "invalid draft-00 key generation parameters");
        return NULL;
    }

    generation = ed301d00_allocate(provider, sizeof(*generation));
    if (generation == NULL) {
        ed301d00_raise(provider, ED301D00_R_ALLOCATION_FAILURE,
            "draft-00 generation context allocation failed");
        return NULL;
    }
    generation->provider = provider;
    return generation;
}

static void *ed301d00_key_gen(
    void *generation_context,
    OSSL_CALLBACK *progress_callback,
    void *callback_argument)
{
    ED301D00_GEN_CONTEXT *generation = generation_context;
    void *inner;

    (void)progress_callback;
    (void)callback_argument;
    if (generation == NULL || generation->provider == NULL
            || generation->provider->rust == NULL)
        return NULL;

    inner = generation->provider->rust->key_generate();
    if (inner == NULL) {
        ed301d00_raise(generation->provider, ED301D00_R_INVALID_KEY,
            "draft-00 key generation failed");
        return NULL;
    }
    return ed301d00_wrap_key(generation->provider, inner);
}

static void ed301d00_key_gen_cleanup(void *generation_context)
{
    ED301D00_GEN_CONTEXT *generation = generation_context;
    ED301D00_PROVIDER_CONTEXT *provider;

    if (generation == NULL)
        return;
    provider = generation->provider;
    ed301d00_clear_free(provider, generation, sizeof(*generation));
}

/* ------------------------------------------------------------------ */
/* Signature operation                                                */
/* ------------------------------------------------------------------ */

static ED301D00_SIGNATURE_CONTEXT *ed301d00_signature_wrap_context(
    ED301D00_PROVIDER_CONTEXT *provider,
    void *inner)
{
    ED301D00_SIGNATURE_CONTEXT *signature;

    if (provider == NULL || provider->rust == NULL || inner == NULL)
        return NULL;
    signature = ed301d00_allocate(provider, sizeof(*signature));
    if (signature == NULL) {
        provider->rust->signature_free(inner);
        ed301d00_raise(provider, ED301D00_R_ALLOCATION_FAILURE,
            "draft-00 signature context allocation failed");
        return NULL;
    }

    signature->provider = provider;
    signature->inner = inner;
    return signature;
}

static void *ed301d00_signature_new_context(
    void *provider_context,
    const char *property_query)
{
    ED301D00_PROVIDER_CONTEXT *provider = provider_context;
    void *inner;

    (void)property_query;
    if (provider == NULL || provider->rust == NULL)
        return NULL;
    inner = provider->rust->signature_new();
    if (inner == NULL)
        return NULL;
    return ed301d00_signature_wrap_context(provider, inner);
}

static void ed301d00_signature_free_context(void *signature_context)
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;
    ED301D00_PROVIDER_CONTEXT *provider;

    if (signature == NULL)
        return;
    provider = signature->provider;
    if (provider != NULL && provider->rust != NULL
            && signature->inner != NULL)
        provider->rust->signature_free(signature->inner);
    ed301d00_clear_free(provider, signature, sizeof(*signature));
}

static void *ed301d00_signature_duplicate_context(void *signature_context)
{
    ED301D00_SIGNATURE_CONTEXT *source = signature_context;
    void *inner;

    if (source == NULL || source->provider == NULL
            || source->provider->rust == NULL || source->inner == NULL)
        return NULL;
    inner = source->provider->rust->signature_duplicate(source->inner);
    if (inner == NULL)
        return NULL;
    return ed301d00_signature_wrap_context(source->provider, inner);
}

static void ed301d00_signature_reset(
    ED301D00_SIGNATURE_CONTEXT *signature)
{
    if (signature != NULL && signature->provider != NULL
            && signature->provider->rust != NULL
            && signature->inner != NULL)
        signature->provider->rust->signature_reset(signature->inner);
}

static int ed301d00_signature_get_context_params(
    void *signature_context,
    OSSL_PARAM params[])
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;
    if (params == NULL)
        return 1;

    return ed301d00_param_set_optional_octet_string(
        OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID),
        ED301D00_ALGORITHM_ID_DER,
        sizeof(ED301D00_ALGORITHM_ID_DER));
}

static const OSSL_PARAM *ed301d00_signature_gettable_context_params(
    void *signature_context,
    void *provider_context)
{
    (void)signature_context;
    (void)provider_context;
    return ED301D00_GETTABLE_CTX_PARAMS;
}

/*
 * Fail closed on every present signature-context parameter.  The draft
 * defines no context string, digest selection, prehash mode, streaming
 * update or randomized-signing option; a caller supplying any of these must
 * observe an error rather than silent acceptance.
 */
static int ed301d00_signature_reject_params(
    ED301D00_SIGNATURE_CONTEXT *signature,
    const OSSL_PARAM params[])
{
    size_t index;
    int tls_version_seen = 0;

    if (params == NULL)
        return 1;
    for (index = 0; params[index].key != NULL; index++) {
#if ED301D00_ACCEPT_TLS_VERSION_PARAM
        /*
         * OpenSSL 4.0 transport metadata only: at most one
         * OSSL_PARAM_INTEGER of exactly sizeof(int) whose value is
         * exactly TLS 1.3.  It is neither stored nor hashed nor added
         * to the draft-00 transcript and enables no mode; the whole
         * array is still walked so a valid tls-version cannot shadow
         * a later unsupported parameter.
         */
        const OSSL_PARAM *parameter = &params[index];

        if (strcmp(parameter->key, OSSL_SIGNATURE_PARAM_TLS_VERSION) == 0
                && !tls_version_seen
                && parameter->data_type == OSSL_PARAM_INTEGER
                && parameter->data != NULL
                && parameter->data_size == sizeof(int)) {
            int tls_version = 0;

            memcpy(&tls_version, parameter->data, sizeof(tls_version));
            if (tls_version == ED301D00_TLS_VERSION_1_3) {
                tls_version_seen = 1;
                continue;
            }
        }
#endif
        if (signature != NULL)
            ed301d00_raise(signature->provider, ED301D00_R_UNSUPPORTED_MODE,
                "Ed301-EdDSA-draft-00 rejects parameter '%s': no context, "
                "digest, prehash, streaming or randomized mode is defined",
                params[index].key);
        return 0;
    }
    (void)tls_version_seen;
    return 1;
}

static int ed301d00_signature_set_context_params(
    void *signature_context,
    const OSSL_PARAM params[])
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;
    if (!ed301d00_signature_reject_params(signature, params)) {
        ed301d00_signature_reset(signature);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *ed301d00_signature_settable_context_params(
    void *signature_context,
    void *provider_context)
{
    (void)signature_context;
    (void)provider_context;
    return ED301D00_SETTABLE_CTX_PARAMS;
}

static int ed301d00_signature_sign_init(
    void *signature_context,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;
    ED301D00_KEY *key = key_data;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;
    ed301d00_signature_reset(signature);
    if (key == NULL || signature->provider != key->provider
            || key->inner == NULL)
        return 0;
    if (!ed301d00_signature_reject_params(signature, params))
        return 0;
    if (signature->provider->rust->signature_sign_init(
            signature->inner,
            key->inner) != 1) {
        ed301d00_raise(signature->provider, ED301D00_R_INVALID_KEY,
            "draft-00 signing requires a consistent private key");
        return 0;
    }
    return 1;
}

static int ed301d00_signature_verify_init(
    void *signature_context,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;
    ED301D00_KEY *key = key_data;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL)
        return 0;
    ed301d00_signature_reset(signature);
    if (key == NULL || signature->provider != key->provider
            || key->inner == NULL)
        return 0;
    if (!ed301d00_signature_reject_params(signature, params))
        return 0;
    if (signature->provider->rust->signature_verify_init(
            signature->inner,
            key->inner) != 1) {
        ed301d00_raise(signature->provider, ED301D00_R_INVALID_KEY,
            "draft-00 verification requires a valid public key");
        return 0;
    }
    return 1;
}

static int ed301d00_signature_sign(
    void *signature_context,
    unsigned char *signature_value,
    size_t *signature_length,
    size_t signature_size,
    const unsigned char *message,
    size_t message_length)
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL || signature_length == NULL)
        return 0;
    if (signature_value == NULL) {
        *signature_length = ED301D00_SIGNATURE_BYTES;
        return 1;
    }
    if (signature_size < ED301D00_SIGNATURE_BYTES) {
        *signature_length = ED301D00_SIGNATURE_BYTES;
        ed301d00_raise(signature->provider, ED301D00_R_INVALID_PARAMETER,
            "draft-00 output buffer is too small");
        return 0;
    }

    *signature_length = 0;
    if (signature->provider->rust->signature_sign(
            signature->inner,
            message,
            message_length,
            signature_value,
            signature_size) != 1) {
        ed301d00_raise(signature->provider, ED301D00_R_INVALID_STATE,
            "draft-00 signing failed");
        return 0;
    }
    *signature_length = ED301D00_SIGNATURE_BYTES;
    return 1;
}

static int ed301d00_signature_verify(
    void *signature_context,
    const unsigned char *signature_value,
    size_t signature_length,
    const unsigned char *message,
    size_t message_length)
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;

    if (signature == NULL || signature->provider == NULL
            || signature->provider->rust == NULL
            || signature->inner == NULL || signature_value == NULL
            || signature_length != ED301D00_SIGNATURE_BYTES)
        return 0;
    return signature->provider->rust->signature_verify(
        signature->inner,
        message,
        message_length,
        signature_value,
        signature_length);
}

static int ed301d00_digest_name_is_pure(const char *digest_name)
{
    return digest_name == NULL || digest_name[0] == '\0';
}

static int ed301d00_signature_digest_sign_init(
    void *signature_context,
    const char *digest_name,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;

    ed301d00_signature_reset(signature);
    if (!ed301d00_digest_name_is_pure(digest_name)) {
        if (signature != NULL)
            ed301d00_raise(signature->provider, ED301D00_R_UNSUPPORTED_MODE,
                "Ed301-EdDSA-draft-00 does not accept an external digest");
        return 0;
    }
    return ed301d00_signature_sign_init(signature_context, key_data, params);
}

static int ed301d00_signature_digest_verify_init(
    void *signature_context,
    const char *digest_name,
    void *key_data,
    const OSSL_PARAM params[])
{
    ED301D00_SIGNATURE_CONTEXT *signature = signature_context;

    ed301d00_signature_reset(signature);
    if (!ed301d00_digest_name_is_pure(digest_name)) {
        if (signature != NULL)
            ed301d00_raise(signature->provider, ED301D00_R_UNSUPPORTED_MODE,
                "Ed301-EdDSA-draft-00 does not accept an external digest");
        return 0;
    }
    return ed301d00_signature_verify_init(signature_context, key_data, params);
}

static int ed301d00_signature_digest_sign(
    void *signature_context,
    unsigned char *signature_value,
    size_t *signature_length,
    size_t signature_size,
    const unsigned char *message,
    size_t message_length)
{
    return ed301d00_signature_sign(
        signature_context,
        signature_value,
        signature_length,
        signature_size,
        message,
        message_length);
}

static int ed301d00_signature_digest_verify(
    void *signature_context,
    const unsigned char *signature_value,
    size_t signature_length,
    const unsigned char *message,
    size_t message_length)
{
    return ed301d00_signature_verify(
        signature_context,
        signature_value,
        signature_length,
        message,
        message_length);
}

/* ------------------------------------------------------------------ */
/* Encoders and decoders                                              */
/* ------------------------------------------------------------------ */

static ED301D00_CODEC_CONTEXT *ed301d00_codec_new_context(
    void *provider_context,
    ED301D00_CODEC_STRUCTURE structure,
    ED301D00_CODEC_FORMAT format)
{
    ED301D00_PROVIDER_CONTEXT *provider = provider_context;
    ED301D00_CODEC_CONTEXT *codec;

    if (provider == NULL || provider->bio_read_ex == NULL
            || provider->bio_write_ex == NULL || provider->bio_ctrl == NULL)
        return NULL;
    codec = ed301d00_allocate(provider, sizeof(*codec));
    if (codec == NULL) {
        ed301d00_raise(provider, ED301D00_R_ALLOCATION_FAILURE,
            "draft-00 codec context allocation failed");
        return NULL;
    }
    codec->provider = provider;
    codec->structure = structure;
    codec->format = format;
    codec->selection = 0;
    codec->invalid = 0;
    return codec;
}

static void *ed301d00_pkcs8_der_codec_new_context(void *provider_context)
{
    return ed301d00_codec_new_context(
        provider_context,
        ED301D00_CODEC_PRIVATE_KEY_INFO,
        ED301D00_CODEC_FORMAT_DER);
}

static void *ed301d00_pkcs8_pem_codec_new_context(void *provider_context)
{
    return ed301d00_codec_new_context(
        provider_context,
        ED301D00_CODEC_PRIVATE_KEY_INFO,
        ED301D00_CODEC_FORMAT_PEM);
}

static void *ed301d00_spki_der_codec_new_context(void *provider_context)
{
    return ed301d00_codec_new_context(
        provider_context,
        ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO,
        ED301D00_CODEC_FORMAT_DER);
}

static void *ed301d00_spki_pem_codec_new_context(void *provider_context)
{
    return ed301d00_codec_new_context(
        provider_context,
        ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO,
        ED301D00_CODEC_FORMAT_PEM);
}

static void *ed301d00_text_codec_new_context(void *provider_context)
{
    return ed301d00_codec_new_context(
        provider_context,
        ED301D00_CODEC_TEXT_KEY,
        ED301D00_CODEC_FORMAT_TEXT);
}

static void ed301d00_codec_free_context(void *codec_context)
{
    ED301D00_CODEC_CONTEXT *codec = codec_context;
    ED301D00_PROVIDER_CONTEXT *provider;

    if (codec == NULL)
        return;
    provider = codec->provider;
    ed301d00_clear_free(provider, codec, sizeof(*codec));
}

static int ed301d00_codec_required_selection(
    const ED301D00_CODEC_CONTEXT *codec)
{
    if (codec == NULL)
        return 0;
    if (codec->structure == ED301D00_CODEC_PRIVATE_KEY_INFO)
        return OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    if (codec->structure == ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO)
        return OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    if (codec->structure == ED301D00_CODEC_TEXT_KEY)
        return OSSL_KEYMGMT_SELECT_KEYPAIR;
    return 0;
}

static int ed301d00_codec_does_selection(void *codec_context, int selection)
{
    const ED301D00_CODEC_CONTEXT *codec = codec_context;

    if (codec == NULL)
        return 0;
    if (codec->structure == ED301D00_CODEC_PRIVATE_KEY_INFO)
        return selection == 0
            || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    if (codec->structure == ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO)
        return selection == 0
            || ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0);
    if (codec->structure == ED301D00_CODEC_TEXT_KEY)
        return selection == 0
            || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
    return 0;
}

static int ed301d00_private_codec_does_selection(
    void *provider_context,
    int selection)
{
    (void)provider_context;
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int ed301d00_public_codec_does_selection(
    void *provider_context,
    int selection)
{
    (void)provider_context;
    return selection == 0
        || ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0);
}

static int ed301d00_text_codec_does_selection(
    void *provider_context,
    int selection)
{
    (void)provider_context;
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
}

static const OSSL_PARAM *ed301d00_private_codec_settable_ctx_params(
    void *provider_context)
{
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_END
    };

    (void)provider_context;
    return parameters;
}

static int ed301d00_private_codec_set_ctx_params(
    void *codec_context,
    const OSSL_PARAM parameters[])
{
    ED301D00_CODEC_CONTEXT *codec = codec_context;

    if (codec == NULL
            || codec->structure != ED301D00_CODEC_PRIVATE_KEY_INFO)
        return 0;
    if (parameters == NULL)
        return 1;
    if (OSSL_PARAM_locate_const(
            parameters, OSSL_ENCODER_PARAM_CIPHER) != NULL
            || OSSL_PARAM_locate_const(
                parameters, OSSL_ENCODER_PARAM_PROPERTIES) != NULL) {
        codec->invalid = 1;
        ed301d00_raise(codec->provider, ED301D00_R_SERIALIZATION_FAILURE,
            "direct encrypted PKCS#8 is not supported by this encoder");
        return 0;
    }
    return 1;
}

static const unsigned char *ed301d00_codec_prefix(
    const ED301D00_CODEC_CONTEXT *codec,
    size_t *prefix_length,
    size_t *encoded_length)
{
    if (prefix_length == NULL || encoded_length == NULL || codec == NULL)
        return NULL;

    if (codec->structure == ED301D00_CODEC_PRIVATE_KEY_INFO) {
        *prefix_length = sizeof(ED301D00_PKCS8_PREFIX);
        *encoded_length = sizeof(ED301D00_PKCS8_PREFIX)
            + ED301D00_SEED_BYTES;
        return ED301D00_PKCS8_PREFIX;
    }
    if (codec->structure == ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO) {
        *prefix_length = sizeof(ED301D00_SPKI_PREFIX);
        *encoded_length = sizeof(ED301D00_SPKI_PREFIX)
            + ED301D00_PUBLIC_KEY_BYTES;
        return ED301D00_SPKI_PREFIX;
    }
    return NULL;
}

static void ed301d00_codec_cleanse(
    const ED301D00_CODEC_CONTEXT *codec,
    unsigned char *buffer,
    size_t buffer_length)
{
    if (codec == NULL || codec->provider == NULL || buffer == NULL
            || codec->provider->rust == NULL)
        return;
    codec->provider->rust->cleanse(buffer, buffer_length);
}

static int ed301d00_codec_write_all(
    const ED301D00_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *output,
    const unsigned char *data,
    size_t data_length)
{
    size_t offset = 0;

    if (codec == NULL || codec->provider == NULL
            || codec->provider->bio_write_ex == NULL || output == NULL
            || (data == NULL && data_length != 0))
        return 0;
    while (offset < data_length) {
        size_t written = 0;

        if (codec->provider->bio_write_ex(
                output,
                data + offset,
                data_length - offset,
                &written) != 1
                || written == 0 || written > data_length - offset)
            return 0;
        offset += written;
    }
    return 1;
}

static int ed301d00_codec_read_exact(
    const ED301D00_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *input,
    unsigned char *data,
    size_t data_length,
    size_t *consumed)
{
    size_t offset = 0;

    if (consumed != NULL)
        *consumed = 0;
    if (codec == NULL || codec->provider == NULL
            || codec->provider->bio_read_ex == NULL || input == NULL
            || (data == NULL && data_length != 0))
        return 0;
    while (offset < data_length) {
        size_t read_length = 0;

        if (codec->provider->bio_read_ex(
                input,
                data + offset,
                data_length - offset,
                &read_length) != 1
                || read_length == 0 || read_length > data_length - offset)
            break;
        offset += read_length;
    }
    if (consumed != NULL)
        *consumed = offset;
    return offset == data_length;
}

static int ed301d00_codec_has_target_oid(
    const ED301D00_CODEC_CONTEXT *codec,
    const unsigned char *encoded,
    size_t encoded_length)
{
    const unsigned char *prefix;
    size_t prefix_length = 0;
    size_t expected_length = 0;
    size_t oid_offset;

    prefix = ed301d00_codec_prefix(codec, &prefix_length, &expected_length);
    if (prefix == NULL)
        return 0;
    oid_offset =
        codec->structure == ED301D00_CODEC_PRIVATE_KEY_INFO ? 7 : 4;
    return prefix_length >= oid_offset + ED301D00_OID_TLV_BYTES
        && encoded_length >= oid_offset + ED301D00_OID_TLV_BYTES
        && memcmp(
            encoded + oid_offset,
            prefix + oid_offset,
            ED301D00_OID_TLV_BYTES) == 0;
}

/*
 * The inputs to these helpers are bounded to six and four bits respectively.
 * Derive the ASCII code arithmetically so private serialization never uses a
 * secret nibble or sextet as a table address.
 */
static uint32_t ed301d00_small_ge(uint32_t value, uint32_t threshold)
{
    return 1U ^ ((value - threshold) >> 31);
}

static unsigned char ed301d00_base64_character(uint32_t index)
{
    uint32_t character = index + (uint32_t)'A';

    character += 6U * ed301d00_small_ge(index, 26U);
    character -= 75U * ed301d00_small_ge(index, 52U);
    character -= 15U * ed301d00_small_ge(index, 62U);
    character += 3U * ed301d00_small_ge(index, 63U);
    return (unsigned char)character;
}

static unsigned char ed301d00_hex_character(uint32_t nibble)
{
    return (unsigned char)(
        nibble + (uint32_t)'0' + 39U * ed301d00_small_ge(nibble, 10U));
}

static size_t ed301d00_base64_encode(
    const unsigned char *input,
    size_t input_length,
    unsigned char *output,
    size_t output_capacity)
{
    const size_t required = 4 * ((input_length + 2) / 3);
    size_t input_offset = 0;
    size_t output_offset = 0;

    if (input == NULL || output == NULL || output_capacity < required)
        return 0;
    while (input_offset + 3 <= input_length) {
        const uint32_t value = ((uint32_t)input[input_offset] << 16)
            | ((uint32_t)input[input_offset + 1] << 8)
            | (uint32_t)input[input_offset + 2];

        output[output_offset++] =
            ed301d00_base64_character((value >> 18) & 0x3f);
        output[output_offset++] =
            ed301d00_base64_character((value >> 12) & 0x3f);
        output[output_offset++] =
            ed301d00_base64_character((value >> 6) & 0x3f);
        output[output_offset++] = ed301d00_base64_character(value & 0x3f);
        input_offset += 3;
    }
    if (input_offset < input_length) {
        uint32_t value = (uint32_t)input[input_offset] << 16;

        output[output_offset++] =
            ed301d00_base64_character((value >> 18) & 0x3f);
        if (input_offset + 1 < input_length) {
            value |= (uint32_t)input[input_offset + 1] << 8;
            output[output_offset++] =
                ed301d00_base64_character((value >> 12) & 0x3f);
            output[output_offset++] =
                ed301d00_base64_character((value >> 6) & 0x3f);
            output[output_offset++] = '=';
        } else {
            output[output_offset++] =
                ed301d00_base64_character((value >> 12) & 0x3f);
            output[output_offset++] = '=';
            output[output_offset++] = '=';
        }
    }
    return output_offset == required ? output_offset : 0;
}

static int ed301d00_codec_write_pem(
    const ED301D00_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *output,
    const unsigned char *der,
    size_t der_length)
{
    static const unsigned char private_begin[] =
        "-----BEGIN PRIVATE KEY-----\n";
    static const unsigned char private_end[] =
        "-----END PRIVATE KEY-----\n";
    static const unsigned char public_begin[] =
        "-----BEGIN PUBLIC KEY-----\n";
    static const unsigned char public_end[] =
        "-----END PUBLIC KEY-----\n";
    static const unsigned char newline[] = "\n";
    const unsigned char *begin;
    const unsigned char *end;
    size_t begin_length;
    size_t end_length;
    unsigned char base64[128] = { 0 };
    size_t base64_length;
    size_t offset = 0;
    int result = 0;

    if (codec == NULL || output == NULL || der == NULL)
        goto cleanup;
    if (codec->structure == ED301D00_CODEC_PRIVATE_KEY_INFO) {
        begin = private_begin;
        begin_length = sizeof(private_begin) - 1;
        end = private_end;
        end_length = sizeof(private_end) - 1;
    } else if (codec->structure == ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO) {
        begin = public_begin;
        begin_length = sizeof(public_begin) - 1;
        end = public_end;
        end_length = sizeof(public_end) - 1;
    } else {
        goto cleanup;
    }

    base64_length = ed301d00_base64_encode(
        der, der_length, base64, sizeof(base64));
    if (base64_length == 0
            || !ed301d00_codec_write_all(
                codec, output, begin, begin_length))
        goto cleanup;
    while (offset < base64_length) {
        size_t line_length = base64_length - offset;

        if (line_length > 64)
            line_length = 64;
        if (!ed301d00_codec_write_all(
                codec, output, base64 + offset, line_length)
                || !ed301d00_codec_write_all(
                    codec, output, newline, sizeof(newline) - 1))
            goto cleanup;
        offset += line_length;
    }
    result = ed301d00_codec_write_all(codec, output, end, end_length);

cleanup:
    ed301d00_codec_cleanse(codec, base64, sizeof(base64));
    return result;
}

static int ed301d00_codec_get_key_bytes(
    const ED301D00_CODEC_CONTEXT *codec,
    const void *key_data,
    ED301D00_CODEC_STRUCTURE component,
    unsigned char output[ED301D00_SEED_BYTES])
{
    const ED301D00_KEY *key = key_data;

    if (codec == NULL || codec->provider == NULL || key == NULL
            || output == NULL || key->provider != codec->provider
            || key->inner == NULL || codec->provider->rust == NULL)
        return 0;
    if (component == ED301D00_CODEC_PRIVATE_KEY_INFO)
        return codec->provider->rust->key_get_private(
            key->inner, output, ED301D00_SEED_BYTES);
    if (component == ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO)
        return codec->provider->rust->key_get_public(
            key->inner, output, ED301D00_PUBLIC_KEY_BYTES);
    return 0;
}

static void *ed301d00_codec_import_key(
    ED301D00_CODEC_CONTEXT *codec,
    const unsigned char key_bytes[ED301D00_SEED_BYTES])
{
    OSSL_PARAM parameters[2];
    void *key = NULL;
    const int selection = ed301d00_codec_required_selection(codec);
    const char *parameter_name;

    if (codec == NULL || key_bytes == NULL || selection == 0)
        return NULL;
    parameter_name = codec->structure == ED301D00_CODEC_PRIVATE_KEY_INFO
        ? OSSL_PKEY_PARAM_PRIV_KEY
        : OSSL_PKEY_PARAM_PUB_KEY;
    parameters[0] = OSSL_PARAM_construct_octet_string(
        parameter_name,
        (void *)key_bytes,
        ED301D00_SEED_BYTES);
    parameters[1] = OSSL_PARAM_construct_end();

    key = ed301d00_key_new(codec->provider);
    if (key == NULL || !ed301d00_key_import(key, selection, parameters)) {
        ed301d00_key_free(key);
        return NULL;
    }
    return key;
}

static void *ed301d00_codec_import_object(
    void *codec_context,
    int selection,
    const OSSL_PARAM parameters[])
{
    ED301D00_CODEC_CONTEXT *codec = codec_context;
    void *key = NULL;
    int effective_selection;

    if (codec == NULL || parameters == NULL
            || !ed301d00_codec_does_selection(codec, selection))
        return NULL;
    effective_selection = selection == 0
        ? ed301d00_codec_required_selection(codec)
        : selection;
    key = ed301d00_key_new(codec->provider);
    if (key == NULL
            || !ed301d00_key_import(key, effective_selection, parameters)) {
        ed301d00_key_free(key);
        return NULL;
    }
    return key;
}

static void ed301d00_codec_free_object(void *key_data)
{
    ed301d00_key_free(key_data);
}

static int ed301d00_codec_write_hex_key(
    const ED301D00_CODEC_CONTEXT *codec,
    OSSL_CORE_BIO *output,
    const unsigned char key_bytes[ED301D00_SEED_BYTES])
{
    unsigned char line[4 + (ED301D00_SEED_BYTES * 3)] = { 0 };
    size_t offset = 0;
    size_t index;
    int result;

    if (codec == NULL || output == NULL || key_bytes == NULL)
        return 0;
    memcpy(line, "    ", 4);
    offset = 4;
    for (index = 0; index < ED301D00_SEED_BYTES; index++) {
        line[offset++] = ed301d00_hex_character(key_bytes[index] >> 4);
        line[offset++] = ed301d00_hex_character(key_bytes[index] & 0x0f);
        line[offset++] = index + 1 == ED301D00_SEED_BYTES ? '\n' : ':';
    }
    result = ed301d00_codec_write_all(codec, output, line, offset);
    ed301d00_codec_cleanse(codec, line, sizeof(line));
    return result;
}

static int ed301d00_codec_encode_text(
    void *codec_context,
    OSSL_CORE_BIO *output,
    const void *key_data,
    const OSSL_PARAM key_parameters[],
    int selection,
    OSSL_PASSPHRASE_CALLBACK *passphrase_callback,
    void *passphrase_argument)
{
    static const unsigned char private_header[] =
        " Private-Key: (301 bit, test-only draft-00 experiment)\n";
    static const unsigned char public_header[] =
        " Public-Key: (301 bit, test-only draft-00 experiment)\n";
    static const unsigned char private_label[] = "priv:\n";
    static const unsigned char public_label[] = "pub:\n";
    ED301D00_CODEC_CONTEXT *codec = codec_context;
    unsigned char private_key[ED301D00_SEED_BYTES] = { 0 };
    unsigned char public_key[ED301D00_PUBLIC_KEY_BYTES] = { 0 };
    const int wants_private =
        (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    const int wants_public = selection == 0 || wants_private
        || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    int result = 0;

    (void)passphrase_callback;
    (void)passphrase_argument;
    if (codec == NULL || codec->format != ED301D00_CODEC_FORMAT_TEXT
            || output == NULL || key_data == NULL || key_parameters != NULL
            || !ed301d00_codec_does_selection(codec, selection))
        goto cleanup;

    if (!ed301d00_codec_write_all(
            codec,
            output,
            (const unsigned char *)ED301D00_ALGORITHM_NAME,
            sizeof(ED301D00_ALGORITHM_NAME) - 1)
            || !ed301d00_codec_write_all(
                codec,
                output,
                wants_private ? private_header : public_header,
                wants_private ? sizeof(private_header) - 1
                    : sizeof(public_header) - 1))
        goto cleanup;
    if (wants_private) {
        if (!ed301d00_codec_get_key_bytes(
                codec,
                key_data,
                ED301D00_CODEC_PRIVATE_KEY_INFO,
                private_key)
                || !ed301d00_codec_write_all(
                    codec,
                    output,
                    private_label,
                    sizeof(private_label) - 1)
                || !ed301d00_codec_write_hex_key(
                    codec, output, private_key))
            goto cleanup;
    }
    if (wants_public) {
        if (!ed301d00_codec_get_key_bytes(
                codec,
                key_data,
                ED301D00_CODEC_SUBJECT_PUBLIC_KEY_INFO,
                public_key)
                || !ed301d00_codec_write_all(
                    codec,
                    output,
                    public_label,
                    sizeof(public_label) - 1)
                || !ed301d00_codec_write_hex_key(codec, output, public_key))
            goto cleanup;
    }
    result = 1;

cleanup:
    ed301d00_codec_cleanse(codec, private_key, sizeof(private_key));
    ed301d00_codec_cleanse(codec, public_key, sizeof(public_key));
    if (result != 1 && codec != NULL)
        ed301d00_raise(codec->provider, ED301D00_R_SERIALIZATION_FAILURE,
            "draft-00 key text encoding failed");
    return result;
}

static int ed301d00_codec_encode(
    void *codec_context,
    OSSL_CORE_BIO *output,
    const void *key_data,
    const OSSL_PARAM key_parameters[],
    int selection,
    OSSL_PASSPHRASE_CALLBACK *passphrase_callback,
    void *passphrase_argument)
{
    ED301D00_CODEC_CONTEXT *codec = codec_context;
    unsigned char encoded[71] = { 0 };
    unsigned char key_bytes[ED301D00_SEED_BYTES] = { 0 };
    const unsigned char *prefix;
    size_t prefix_length = 0;
    size_t encoded_length = 0;
    int result = 0;

    (void)passphrase_callback;
    (void)passphrase_argument;
    if (codec == NULL || codec->invalid || output == NULL || key_data == NULL
            || key_parameters != NULL
            || !ed301d00_codec_does_selection(codec, selection))
        goto cleanup;
    prefix = ed301d00_codec_prefix(codec, &prefix_length, &encoded_length);
    if (prefix == NULL || encoded_length > sizeof(encoded)
            || !ed301d00_codec_get_key_bytes(
                codec, key_data, codec->structure, key_bytes))
        goto cleanup;

    memcpy(encoded, prefix, prefix_length);
    memcpy(encoded + prefix_length, key_bytes, ED301D00_SEED_BYTES);
    if (codec->format == ED301D00_CODEC_FORMAT_DER)
        result = ed301d00_codec_write_all(
            codec, output, encoded, encoded_length);
    else if (codec->format == ED301D00_CODEC_FORMAT_PEM)
        result = ed301d00_codec_write_pem(
            codec, output, encoded, encoded_length);

cleanup:
    ed301d00_codec_cleanse(codec, key_bytes, sizeof(key_bytes));
    ed301d00_codec_cleanse(codec, encoded, sizeof(encoded));
    if (result != 1 && codec != NULL)
        ed301d00_raise(codec->provider, ED301D00_R_SERIALIZATION_FAILURE,
            "draft-00 key encoding failed");
    return result;
}

static int ed301d00_codec_decode(
    void *codec_context,
    OSSL_CORE_BIO *input,
    int selection,
    OSSL_CALLBACK *data_callback,
    void *callback_argument,
    OSSL_PASSPHRASE_CALLBACK *passphrase_callback,
    void *passphrase_argument)
{
    ED301D00_CODEC_CONTEXT *codec = codec_context;
    unsigned char encoded[71] = { 0 };
    const unsigned char *prefix;
    void *key = NULL;
    void *reference;
    size_t prefix_length = 0;
    size_t encoded_length = 0;
    size_t consumed = 0;
    int object_type = OSSL_OBJECT_PKEY;
    char *data_type;
    OSSL_PARAM object_parameters[4];
    int result = 1;

    (void)passphrase_callback;
    (void)passphrase_argument;
    if (codec == NULL || codec->format != ED301D00_CODEC_FORMAT_DER
            || input == NULL || data_callback == NULL
            || !ed301d00_codec_does_selection(codec, selection))
        return 0;
    codec->selection = selection == 0
        ? ed301d00_codec_required_selection(codec)
        : selection;
    prefix = ed301d00_codec_prefix(codec, &prefix_length, &encoded_length);
    if (prefix == NULL || encoded_length > sizeof(encoded))
        return 0;

    /*
     * One-object stream boundary (B1-DER): this decoder owns exactly one
     * canonical DER object per call.  Read only the two-byte outer header
     * first; the expected body length (0x45 or 0x41) is a canonical
     * short-form length byte, so a plain equality test also rejects
     * long-form and indefinite lengths.  The body is read only after the
     * header is valid, and nothing is read past the declared body: no
     * pending probe, no extra byte, no stream-EOF requirement.  Bytes or
     * objects after this one stay in the BIO for the caller; a
     * whole-buffer no-trailing-data policy belongs to the caller,
     * outside this one-object decoder.
     */
    if (!ed301d00_codec_read_exact(codec, input, encoded, 2, &consumed))
        goto cleanup;   /* no complete header: empty source, retry or EOF */
    if (encoded[0] != 0x30
            || encoded[1] != (unsigned char)(encoded_length - 2)) {
        ed301d00_raise(codec->provider, ED301D00_R_SERIALIZATION_FAILURE,
            "draft-00 key decoding rejected outer DER header");
        result = 0;
        goto cleanup;
    }
    if (!ed301d00_codec_read_exact(
            codec, input, encoded + 2, encoded_length - 2, &consumed)) {
        ed301d00_raise(codec->provider, ED301D00_R_SERIALIZATION_FAILURE,
            "truncated draft-00 key encoding");
        result = 0;
        goto cleanup;
    }
    if (!ed301d00_codec_has_target_oid(codec, encoded, encoded_length))
        goto cleanup;
    if (memcmp(encoded, prefix, prefix_length) != 0) {
        ed301d00_raise(codec->provider, ED301D00_R_SERIALIZATION_FAILURE,
            "non-canonical draft-00 key encoding");
        result = 0;
        goto cleanup;
    }

    key = ed301d00_codec_import_key(codec, encoded + prefix_length);
    if (key == NULL) {
        ed301d00_raise(codec->provider, ED301D00_R_SERIALIZATION_FAILURE,
            "draft-00 key decoding rejected key material");
        result = 0;
        goto cleanup;
    }

    data_type = (char *)ED301D00_ALGORITHM_NAME;
    reference = key;
    object_parameters[0] = OSSL_PARAM_construct_int(
        OSSL_OBJECT_PARAM_TYPE,
        &object_type);
    object_parameters[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_OBJECT_PARAM_DATA_TYPE,
        data_type,
        0);
    object_parameters[2] = OSSL_PARAM_construct_octet_string(
        OSSL_OBJECT_PARAM_REFERENCE,
        &reference,
        sizeof(reference));
    object_parameters[3] = OSSL_PARAM_construct_end();
    result = data_callback(object_parameters, callback_argument);
    key = reference;

cleanup:
    ed301d00_key_free(key);
    ed301d00_codec_cleanse(codec, encoded, sizeof(encoded));
    return result;
}

static int ed301d00_codec_export_object(
    void *codec_context,
    const void *reference,
    size_t reference_size,
    OSSL_CALLBACK *export_callback,
    void *callback_argument)
{
    ED301D00_CODEC_CONTEXT *codec = codec_context;
    void *key;
    int selection;

    if (codec == NULL || reference == NULL
            || reference_size != sizeof(key) || export_callback == NULL)
        return 0;
    key = *(void *const *)reference;
    if (key == NULL)
        return 0;
    selection = codec->selection == 0
        ? ed301d00_codec_required_selection(codec)
        : codec->selection;
    return ed301d00_key_export(
        key, selection, export_callback, callback_argument);
}

#define ED301D00_DEFINE_ENCODER_DISPATCH(name, new_context, does_selection) \
    static const OSSL_DISPATCH name[] = {                                   \
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))new_context },          \
        { OSSL_FUNC_ENCODER_FREECTX,                                        \
            (void (*)(void))ed301d00_codec_free_context },                  \
        { OSSL_FUNC_ENCODER_DOES_SELECTION,                                 \
            (void (*)(void))does_selection },                               \
        { OSSL_FUNC_ENCODER_ENCODE,                                         \
            (void (*)(void))ed301d00_codec_encode },                        \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
            (void (*)(void))ed301d00_codec_import_object },                 \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
            (void (*)(void))ed301d00_codec_free_object },                   \
        { 0, NULL }                                                         \
    }

#define ED301D00_DEFINE_PRIVATE_ENCODER_DISPATCH(                           \
    name, new_context, does_selection)                                      \
    static const OSSL_DISPATCH name[] = {                                   \
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))new_context },          \
        { OSSL_FUNC_ENCODER_FREECTX,                                        \
            (void (*)(void))ed301d00_codec_free_context },                  \
        { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                            \
            (void (*)(void))ed301d00_private_codec_settable_ctx_params },   \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                 \
            (void (*)(void))ed301d00_private_codec_set_ctx_params },        \
        { OSSL_FUNC_ENCODER_DOES_SELECTION,                                 \
            (void (*)(void))does_selection },                               \
        { OSSL_FUNC_ENCODER_ENCODE,                                         \
            (void (*)(void))ed301d00_codec_encode },                        \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
            (void (*)(void))ed301d00_codec_import_object },                 \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
            (void (*)(void))ed301d00_codec_free_object },                   \
        { 0, NULL }                                                         \
    }

#define ED301D00_DEFINE_DECODER_DISPATCH(name, new_context, does_selection) \
    static const OSSL_DISPATCH name[] = {                                   \
        { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))new_context },          \
        { OSSL_FUNC_DECODER_FREECTX,                                        \
            (void (*)(void))ed301d00_codec_free_context },                  \
        { OSSL_FUNC_DECODER_DOES_SELECTION,                                 \
            (void (*)(void))does_selection },                               \
        { OSSL_FUNC_DECODER_DECODE,                                         \
            (void (*)(void))ed301d00_codec_decode },                        \
        { OSSL_FUNC_DECODER_EXPORT_OBJECT,                                  \
            (void (*)(void))ed301d00_codec_export_object },                 \
        { 0, NULL }                                                         \
    }

ED301D00_DEFINE_PRIVATE_ENCODER_DISPATCH(
    ED301D00_PKCS8_DER_ENCODER_DISPATCH,
    ed301d00_pkcs8_der_codec_new_context,
    ed301d00_private_codec_does_selection);
ED301D00_DEFINE_PRIVATE_ENCODER_DISPATCH(
    ED301D00_PKCS8_PEM_ENCODER_DISPATCH,
    ed301d00_pkcs8_pem_codec_new_context,
    ed301d00_private_codec_does_selection);
ED301D00_DEFINE_ENCODER_DISPATCH(
    ED301D00_SPKI_DER_ENCODER_DISPATCH,
    ed301d00_spki_der_codec_new_context,
    ed301d00_public_codec_does_selection);
ED301D00_DEFINE_ENCODER_DISPATCH(
    ED301D00_SPKI_PEM_ENCODER_DISPATCH,
    ed301d00_spki_pem_codec_new_context,
    ed301d00_public_codec_does_selection);

static const OSSL_DISPATCH ED301D00_TEXT_ENCODER_DISPATCH[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,
        (void (*)(void))ed301d00_text_codec_new_context },
    { OSSL_FUNC_ENCODER_FREECTX,
        (void (*)(void))ed301d00_codec_free_context },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
        (void (*)(void))ed301d00_text_codec_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,
        (void (*)(void))ed301d00_codec_encode_text },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,
        (void (*)(void))ed301d00_codec_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,
        (void (*)(void))ed301d00_codec_free_object },
    { 0, NULL }
};

ED301D00_DEFINE_DECODER_DISPATCH(
    ED301D00_PKCS8_DER_DECODER_DISPATCH,
    ed301d00_pkcs8_der_codec_new_context,
    ed301d00_private_codec_does_selection);
ED301D00_DEFINE_DECODER_DISPATCH(
    ED301D00_SPKI_DER_DECODER_DISPATCH,
    ed301d00_spki_der_codec_new_context,
    ed301d00_public_codec_does_selection);

/* ------------------------------------------------------------------ */
/* Dispatch and algorithm tables                                      */
/* ------------------------------------------------------------------ */

static const OSSL_DISPATCH ED301D00_KEYMGMT_DISPATCH[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ed301d00_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ed301d00_key_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ed301d00_key_load },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ed301d00_key_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ed301d00_key_gen },
    {
        OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        (void (*)(void))ed301d00_key_gen_cleanup
    },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))ed301d00_key_get_params },
    {
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        (void (*)(void))ed301d00_key_gettable_params
    },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))ed301d00_key_set_params },
    {
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        (void (*)(void))ed301d00_key_settable_params
    },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ed301d00_key_has },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ed301d00_key_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ed301d00_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ed301d00_key_import },
    {
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        (void (*)(void))ed301d00_key_import_types
    },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ed301d00_key_export },
    {
        OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        (void (*)(void))ed301d00_key_export_types
    },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ed301d00_key_duplicate },
    {
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void (*)(void))ed301d00_key_query_operation_name
    },
    { 0, NULL }
};

static const OSSL_DISPATCH ED301D00_SIGNATURE_DISPATCH[] = {
    {
        OSSL_FUNC_SIGNATURE_NEWCTX,
        (void (*)(void))ed301d00_signature_new_context
    },
    {
        OSSL_FUNC_SIGNATURE_SIGN_INIT,
        (void (*)(void))ed301d00_signature_sign_init
    },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ed301d00_signature_sign },
    {
        OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        (void (*)(void))ed301d00_signature_verify_init
    },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ed301d00_signature_verify },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        (void (*)(void))ed301d00_signature_digest_sign_init
    },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
        (void (*)(void))ed301d00_signature_digest_sign
    },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        (void (*)(void))ed301d00_signature_digest_verify_init
    },
    {
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
        (void (*)(void))ed301d00_signature_digest_verify
    },
    {
        OSSL_FUNC_SIGNATURE_FREECTX,
        (void (*)(void))ed301d00_signature_free_context
    },
    {
        OSSL_FUNC_SIGNATURE_DUPCTX,
        (void (*)(void))ed301d00_signature_duplicate_context
    },
    {
        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        (void (*)(void))ed301d00_signature_get_context_params
    },
    {
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        (void (*)(void))ed301d00_signature_gettable_context_params
    },
    {
        OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        (void (*)(void))ed301d00_signature_set_context_params
    },
    {
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (void (*)(void))ed301d00_signature_settable_context_params
    },
    { 0, NULL }
};

static const OSSL_ALGORITHM ED301D00_KEYMGMT_ALGORITHMS[] = {
    {
        ED301D00_ALGORITHM_NAMES,
        ED301D00_PROPERTY,
        ED301D00_KEYMGMT_DISPATCH,
        "Experimental Ed301-EdDSA-draft-00 raw key management (test-only)"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ED301D00_SIGNATURE_ALGORITHMS[] = {
    {
        ED301D00_ALGORITHM_NAMES,
        ED301D00_PROPERTY,
        ED301D00_SIGNATURE_DISPATCH,
        "Experimental pure Ed301-EdDSA-draft-00 signatures (test-only)"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ED301D00_ENCODER_ALGORITHMS[] = {
    {
        ED301D00_ALGORITHM_NAMES,
        "provider=" ED301D00_PROVIDER_BASENAME ",output=text",
        ED301D00_TEXT_ENCODER_DISPATCH,
        "draft-00 human-readable key encoder (test-only)"
    },
    {
        ED301D00_ALGORITHM_NAMES,
        "provider=" ED301D00_PROVIDER_BASENAME ",output=der,structure=PrivateKeyInfo",
        ED301D00_PKCS8_DER_ENCODER_DISPATCH,
        "draft-00 PKCS#8 DER encoder (test-only)"
    },
    {
        ED301D00_ALGORITHM_NAMES,
        "provider=" ED301D00_PROVIDER_BASENAME ",output=pem,structure=PrivateKeyInfo",
        ED301D00_PKCS8_PEM_ENCODER_DISPATCH,
        "draft-00 PKCS#8 PEM encoder (test-only)"
    },
    {
        ED301D00_ALGORITHM_NAMES,
        "provider=" ED301D00_PROVIDER_BASENAME ",output=der,structure=SubjectPublicKeyInfo",
        ED301D00_SPKI_DER_ENCODER_DISPATCH,
        "draft-00 SPKI DER encoder (test-only)"
    },
    {
        ED301D00_ALGORITHM_NAMES,
        "provider=" ED301D00_PROVIDER_BASENAME ",output=pem,structure=SubjectPublicKeyInfo",
        ED301D00_SPKI_PEM_ENCODER_DISPATCH,
        "draft-00 SPKI PEM encoder (test-only)"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ED301D00_DECODER_ALGORITHMS[] = {
    {
        ED301D00_ALGORITHM_NAMES,
        "provider=" ED301D00_PROVIDER_BASENAME ",input=der,structure=PrivateKeyInfo",
        ED301D00_PKCS8_DER_DECODER_DISPATCH,
        "draft-00 PKCS#8 DER decoder (test-only)"
    },
    {
        ED301D00_ALGORITHM_NAMES,
        "provider=" ED301D00_PROVIDER_BASENAME ",input=der,structure=SubjectPublicKeyInfo",
        ED301D00_SPKI_DER_DECODER_DISPATCH,
        "draft-00 SPKI DER decoder (test-only)"
    },
    { NULL, NULL, NULL, NULL }
};

/* ------------------------------------------------------------------ */
/* Capabilities                                                       */
/* ------------------------------------------------------------------ */

static int ed301d00_provider_get_capabilities(
    void *provider_context,
    const char *capability,
    OSSL_CALLBACK *callback,
    void *callback_argument)
{
#ifdef ED301D00_TEST_FAILPOINT_ARTIFACT
    /* The allocation-failpoint DSO is never a TLS capability provider. */
    (void)provider_context;
    (void)capability;
    (void)callback;
    (void)callback_argument;
    return 1;
#else
    unsigned int code_point = ED301D00_TLS_SIGALG_CODE_POINT;
    unsigned int security_bits = ED301D00_SECURITY_BITS;
    int minimum_tls = ED301D00_TLS_VERSION_1_3;
    int maximum_tls = ED301D00_TLS_VERSION_1_3;
    int minimum_dtls = -1;
    int maximum_dtls = -1;
    OSSL_PARAM sigalg_parameters[] = {
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,
            (char *)ED301D00_TLS_SIGALG_IANA_NAME,
            sizeof(ED301D00_TLS_SIGALG_IANA_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_NAME,
            (char *)ED301D00_ALGORITHM_NAME,
            sizeof(ED301D00_ALGORITHM_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_OID,
            (char *)ED301D00_OID,
            sizeof(ED301D00_OID)),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, &code_point),
        OSSL_PARAM_uint(
            OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,
            &security_bits),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE,
            (char *)ED301D00_ALGORITHM_NAME,
            sizeof(ED301D00_ALGORITHM_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID,
            (char *)ED301D00_OID,
            sizeof(ED301D00_OID)),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, &minimum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, &maximum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS, &minimum_dtls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS, &maximum_dtls),
        OSSL_PARAM_END
    };

    (void)provider_context;
    if (capability == NULL || callback == NULL)
        return 0;
    if (strcmp(capability, ED301D00_TLS_SIGALG_CAPABILITY) == 0)
        return callback(sigalg_parameters, callback_argument);
    /*
     * Unknown capabilities succeed with zero entries; returning failure
     * would abort the caller's provider iteration (libssl treats a zero
     * return from the capability query as a hard error).
     */
    return 1;
#endif
}

/* ------------------------------------------------------------------ */
/* Provider plumbing                                                  */
/* ------------------------------------------------------------------ */

static void ed301d00_provider_teardown(void *provider_context)
{
    ED301D00_PROVIDER_CONTEXT *provider = provider_context;

    if (provider != NULL && provider->clear_free != NULL)
        provider->clear_free(
            provider,
            sizeof(*provider),
            __FILE__,
            __LINE__);
}

static const OSSL_ITEM *ed301d00_provider_get_reason_strings(
    void *provider_context)
{
    (void)provider_context;
    return ED301D00_REASON_STRINGS;
}

static const OSSL_PARAM *ed301d00_provider_gettable_params(
    void *provider_context)
{
    (void)provider_context;
    return ED301D00_PROVIDER_GETTABLE_PARAMS;
}

static int ed301d00_provider_get_params(
    void *provider_context,
    OSSL_PARAM params[])
{
    ED301D00_PROVIDER_CONTEXT *provider = provider_context;

    if (provider == NULL)
        return 0;

    if (!ed301d00_param_set_optional_utf8_ptr(
            OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME),
            ED301D00_PROVIDER_NAME)
            || !ed301d00_param_set_optional_utf8_ptr(
                OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION),
                ED301D00_PROVIDER_VERSION)
            || !ed301d00_param_set_optional_utf8_ptr(
                OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO),
                ED301D00_PROVIDER_BUILDINFO)
            || !ed301d00_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS),
                1))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *ed301d00_provider_query_operation(
    void *provider_context,
    int operation_id,
    int *no_cache)
{
    (void)provider_context;

    if (no_cache != NULL)
        *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return ED301D00_KEYMGMT_ALGORITHMS;
    if (operation_id == OSSL_OP_SIGNATURE)
        return ED301D00_SIGNATURE_ALGORITHMS;
    if (operation_id == OSSL_OP_ENCODER)
        return ED301D00_ENCODER_ALGORITHMS;
    if (operation_id == OSSL_OP_DECODER)
        return ED301D00_DECODER_ALGORITHMS;
    return NULL;
}

static const OSSL_DISPATCH ED301D00_PROVIDER_DISPATCH[] = {
    {
        OSSL_FUNC_PROVIDER_TEARDOWN,
        (void (*)(void))ed301d00_provider_teardown
    },
    {
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        (void (*)(void))ed301d00_provider_gettable_params
    },
    {
        OSSL_FUNC_PROVIDER_GET_PARAMS,
        (void (*)(void))ed301d00_provider_get_params
    },
    {
        OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
        (void (*)(void))ed301d00_provider_get_reason_strings
    },
    {
        OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))ed301d00_provider_query_operation
    },
    {
        OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))ed301d00_provider_get_capabilities
    },
    { 0, NULL }
};

static int ed301d00_core_version_is_supported(
    const OSSL_CORE_HANDLE *handle,
    OSSL_FUNC_core_get_params_fn *get_params)
{
    char *core_version = NULL;
    const char *patch;
    const size_t prefix_length =
        sizeof(ED301D00_SUPPORTED_CORE_VERSION_PREFIX) - 1;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_utf8_ptr(
            OSSL_PROV_PARAM_CORE_VERSION,
            &core_version,
            0),
        OSSL_PARAM_END
    };

    if (handle == NULL || get_params == NULL
            || get_params(handle, parameters) != 1
            || core_version == NULL
            || strncmp(
                core_version,
                ED301D00_SUPPORTED_CORE_VERSION_PREFIX,
                prefix_length) != 0)
        return 0;

    patch = core_version + prefix_length;
    if (*patch < '0' || *patch > '9')
        return 0;
    do {
        patch++;
    } while (*patch >= '0' && *patch <= '9');
    return *patch == '\0';
}

/* ------------------------------------------------------------------ */
/* Concurrency-safe ephemeral object registration                     */
/*                                                                    */
/* The object registry is process-global while provider               */
/* initialisation can run concurrently in independent library         */
/* contexts.  The entire preflight/mutation/postflight transaction is */
/* kept serial within this module; the owner slot stores the PID so a */
/* child forked while the parent owns the lock can replace the        */
/* inherited, unreachable owner.  Adapted from the disclosed          */
/* post-commit hardening reference.                                   */
/* ------------------------------------------------------------------ */

enum ed301d00_object_state {
    ED301D00_OBJECT_CONFLICT = -1,
    ED301D00_OBJECT_FREE = 0,
    ED301D00_OBJECT_EXACT = 1
};

static _Atomic unsigned long ed301d00_object_registry_lock_owner;

_Static_assert(
    ATOMIC_LONG_LOCK_FREE == 2,
    "a lock-free atomic PID owner is required for fork recovery");

static void ed301d00_object_registry_lock_acquire(void)
{
    const unsigned long process_id = (unsigned long)getpid();

    for (;;) {
        unsigned long expected = 0;

        if (atomic_compare_exchange_weak_explicit(
                &ed301d00_object_registry_lock_owner,
                &expected,
                process_id,
                memory_order_acquire,
                memory_order_relaxed))
            return;
        if (expected != process_id
                && atomic_compare_exchange_weak_explicit(
                    &ed301d00_object_registry_lock_owner,
                    &expected,
                    process_id,
                    memory_order_acquire,
                    memory_order_relaxed))
            return;
    }
}

static void ed301d00_object_registry_lock_release(void)
{
    atomic_store_explicit(
        &ed301d00_object_registry_lock_owner,
        0,
        memory_order_release);
}

#ifndef ED301D00_OBJECT_REGISTRY_RETRY_LIMIT
# define ED301D00_OBJECT_REGISTRY_RETRY_LIMIT 1024U
#endif

typedef struct ed301d00_error_mark_st {
    int had_errors;
    int marked;
} ED301D00_ERROR_MARK;

static int ed301d00_error_mark_begin(ED301D00_ERROR_MARK *error_mark)
{
    if (error_mark == NULL)
        return 0;
    error_mark->had_errors = ERR_peek_error() != 0;
    error_mark->marked = error_mark->had_errors && ERR_set_mark() == 1;
    return !error_mark->had_errors || error_mark->marked;
}

static int ed301d00_error_mark_success(ED301D00_ERROR_MARK *error_mark)
{
    if (error_mark == NULL)
        return 0;
    if (!error_mark->had_errors) {
        ERR_clear_error();
        return 1;
    }
    if (!error_mark->marked || ERR_pop_to_mark() != 1)
        return 0;
    error_mark->marked = 0;
    return 1;
}

static void ed301d00_error_mark_failure(ED301D00_ERROR_MARK *error_mark)
{
    if (error_mark != NULL && error_mark->marked) {
        (void)ERR_clear_last_mark();
        error_mark->marked = 0;
    }
}

static enum ed301d00_object_state ed301d00_object_identity_state(
    const char *oid,
    const char *name,
    int *nid_out)
{
    char numeric_oid[96];
    ASN1_OBJECT *object;
    const char *short_name;
    const char *long_name;
    int oid_nid;
    int short_name_nid;
    int long_name_nid;
    int text_length;

    if (oid == NULL || name == NULL || nid_out == NULL)
        return ED301D00_OBJECT_CONFLICT;

    *nid_out = NID_undef;
    oid_nid = OBJ_txt2nid(oid);
    short_name_nid = OBJ_sn2nid(name);
    long_name_nid = OBJ_ln2nid(name);
    if (oid_nid == NID_undef && short_name_nid == NID_undef
            && long_name_nid == NID_undef)
        return ED301D00_OBJECT_FREE;
    if (oid_nid == NID_undef || short_name_nid != oid_nid
            || long_name_nid != oid_nid)
        return ED301D00_OBJECT_CONFLICT;

    short_name = OBJ_nid2sn(oid_nid);
    long_name = OBJ_nid2ln(oid_nid);
    object = OBJ_nid2obj(oid_nid);
    if (short_name == NULL || long_name == NULL || object == NULL
            || strcmp(short_name, name) != 0 || strcmp(long_name, name) != 0)
        return ED301D00_OBJECT_CONFLICT;
    text_length = OBJ_obj2txt(
        numeric_oid,
        (int)sizeof(numeric_oid),
        object,
        1);
    if (text_length != (int)strlen(oid) || strcmp(numeric_oid, oid) != 0)
        return ED301D00_OBJECT_CONFLICT;

    *nid_out = oid_nid;
    return ED301D00_OBJECT_EXACT;
}

static enum ed301d00_object_state ed301d00_signature_identifier_state(
    int algorithm_nid)
{
    int digest_nid = -1;
    int public_key_nid = -1;
    int reverse_signature_nid = NID_undef;
    int next_nid;
    int signature_nid;
    int found = 0;

    /*
     * The scan must consider every slot of each signature-id triple,
     * including the digest slot (VAL-02 repair): a foreign mapping that
     * uses the target NID only as its digest is a foreign use of the
     * identifier and must fail closed like any other conflict.  With
     * algorithm_nid == NID_undef the digest/public-key comparisons below
     * would alias the many legitimate digestless mappings, so an
     * unregistered identity is reported as FREE before scanning.
     */
    if (algorithm_nid == NID_undef)
        return ED301D00_OBJECT_FREE;

    next_nid = OBJ_new_nid(0);
    if (next_nid == NID_undef)
        return ED301D00_OBJECT_CONFLICT;

    for (signature_nid = 1; signature_nid < next_nid; signature_nid++) {
        if (OBJ_find_sigid_algs(
                signature_nid,
                &digest_nid,
                &public_key_nid) != 1)
            continue;
        if (signature_nid != algorithm_nid
                && public_key_nid != algorithm_nid
                && digest_nid != algorithm_nid)
            continue;
        if (signature_nid != algorithm_nid || digest_nid != NID_undef
                || public_key_nid != algorithm_nid || found)
            return ED301D00_OBJECT_CONFLICT;
        found = 1;
    }

    if (!found)
        return ED301D00_OBJECT_FREE;
    if (OBJ_find_sigid_by_algs(
            &reverse_signature_nid,
            NID_undef,
            algorithm_nid) != 1
            || reverse_signature_nid != algorithm_nid)
        return ED301D00_OBJECT_CONFLICT;
    return ED301D00_OBJECT_EXACT;
}

static int ed301d00_object_registry_preflight(void)
{
    int algorithm_nid = NID_undef;
    enum ed301d00_object_state identity_state =
        ed301d00_object_identity_state(
            ED301D00_OID,
            ED301D00_ALGORITHM_NAME,
            &algorithm_nid);
    enum ed301d00_object_state signature_state;

    if (identity_state == ED301D00_OBJECT_CONFLICT)
        return 0;
    signature_state = ed301d00_signature_identifier_state(algorithm_nid);
    if (signature_state == ED301D00_OBJECT_CONFLICT)
        return 0;
    if (identity_state == ED301D00_OBJECT_FREE
            && signature_state != ED301D00_OBJECT_FREE)
        return 0;
    return 1;
}

static int ed301d00_object_registry_postflight(void)
{
    int algorithm_nid = NID_undef;

    return ed301d00_object_identity_state(
               ED301D00_OID,
               ED301D00_ALGORITHM_NAME,
               &algorithm_nid) == ED301D00_OBJECT_EXACT
        && ed301d00_signature_identifier_state(algorithm_nid)
               == ED301D00_OBJECT_EXACT;
}

/*
 * Bounded wait for a competing registration to reach the exact expected
 * state (VAL-03 repair): the earlier loop performed only 1024 bare
 * sched_yield() calls (well under a millisecond), so a competing
 * registrant that was merely descheduled between its OBJ_create and
 * OBJ_add_sigid could exhaust the ceiling and fail a load that would have
 * succeeded.  The wait now backs off to short sleeps after an initial
 * yield burst, giving a total bound of roughly half a second.  Exhaustion
 * remains fail-closed by design: an incomplete foreign registration that
 * persists beyond the bound is indistinguishable from a conflict.
 */
static int ed301d00_object_registry_wait_for_exact(void)
{
    unsigned int attempt;

    for (attempt = 0; attempt < ED301D00_OBJECT_REGISTRY_RETRY_LIMIT;
            attempt++) {
        if (ed301d00_object_registry_postflight())
            return 1;
        if (attempt < 64U) {
            (void)sched_yield();
        } else {
            struct timespec delay = { 0, 500000L }; /* 0.5 ms */

            (void)nanosleep(&delay, NULL);
        }
    }
    return ed301d00_object_registry_postflight();
}

static int ed301d00_object_registry_register(
    const OSSL_CORE_HANDLE *handle,
    OSSL_FUNC_core_obj_create_fn *obj_create,
    OSSL_FUNC_core_obj_add_sigid_fn *obj_add_sigid)
{
    ED301D00_ERROR_MARK error_mark = { 0 };
    int callbacks_ok = 0;
    int ok = 0;

    ed301d00_object_registry_lock_acquire();
    if (!ed301d00_error_mark_begin(&error_mark))
        goto done;

    if (!ed301d00_object_registry_preflight()) {
        ok = ed301d00_object_registry_wait_for_exact();
        goto done;
    }

    callbacks_ok = obj_create(
                       handle,
                       ED301D00_OID,
                       ED301D00_ALGORITHM_NAME,
                       ED301D00_ALGORITHM_NAME) == 1
        && obj_add_sigid(
               handle,
               ED301D00_OID,
               "",
               ED301D00_OID) == 1;
    ok = callbacks_ok && ed301d00_object_registry_postflight();
    if (!ok)
        ok = ed301d00_object_registry_wait_for_exact();

done:
    if (ok) {
        if (!ed301d00_error_mark_success(&error_mark))
            ok = 0;
    } else {
        ed301d00_error_mark_failure(&error_mark);
    }
    ed301d00_object_registry_lock_release();
    return ok;
}

/* ------------------------------------------------------------------ */
/* Entry point called by the Rust cdylib wrapper                      */
/* ------------------------------------------------------------------ */

/* Every function pointer is part of the Rust/C ABI contract. */
static int ed301d00_rust_api_valid(
    const ED301D00_SIGNATURE_RUST_API *rust_api)
{
    return rust_api != NULL
        && rust_api->abi_version == 1
        && rust_api->struct_size == sizeof(*rust_api)
        && rust_api->seed_bytes == ED301D00_SEED_BYTES
        && rust_api->public_key_bytes == ED301D00_PUBLIC_KEY_BYTES
        && rust_api->signature_bytes == ED301D00_SIGNATURE_BYTES
        && rust_api->key_new != NULL
        && rust_api->key_free != NULL
        && rust_api->key_import != NULL
        && rust_api->key_set_encoded_public != NULL
        && rust_api->key_generate != NULL
        && rust_api->key_duplicate != NULL
        && rust_api->key_has != NULL
        && rust_api->key_validate != NULL
        && rust_api->key_match != NULL
        && rust_api->key_get_private != NULL
        && rust_api->key_get_public != NULL
        && rust_api->signature_new != NULL
        && rust_api->signature_free != NULL
        && rust_api->signature_duplicate != NULL
        && rust_api->signature_reset != NULL
        && rust_api->signature_sign_init != NULL
        && rust_api->signature_verify_init != NULL
        && rust_api->signature_sign != NULL
        && rust_api->signature_verify != NULL
        && rust_api->cleanse != NULL;
}

int ed301_eddsa_draft00_shim_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context,
    const ED301D00_SIGNATURE_RUST_API *rust_api);

int ed301_eddsa_draft00_shim_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context,
    const ED301D00_SIGNATURE_RUST_API *rust_api)
{
    const OSSL_DISPATCH *dispatch;
    OSSL_FUNC_CRYPTO_zalloc_fn *zalloc = NULL;
    OSSL_FUNC_CRYPTO_clear_free_fn *clear_free = NULL;
    OSSL_FUNC_core_new_error_fn *new_error = NULL;
    OSSL_FUNC_core_set_error_debug_fn *set_error_debug = NULL;
    OSSL_FUNC_core_vset_error_fn *vset_error = NULL;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex = NULL;
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex = NULL;
    OSSL_FUNC_BIO_ctrl_fn *bio_ctrl = NULL;
    OSSL_FUNC_core_obj_create_fn *obj_create = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn *obj_add_sigid = NULL;
    OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
    ED301D00_PROVIDER_CONTEXT *provider;

    if (handle == NULL || input_dispatch == NULL || output_dispatch == NULL
            || provider_context == NULL)
        return 0;

    *output_dispatch = NULL;
    *provider_context = NULL;

    if (!ed301d00_rust_api_valid(rust_api))
        return 0;

    for (dispatch = input_dispatch; dispatch->function_id != 0; dispatch++) {
        switch (dispatch->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            core_get_params = OSSL_FUNC_core_get_params(dispatch);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            zalloc = OSSL_FUNC_CRYPTO_zalloc(dispatch);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            clear_free = OSSL_FUNC_CRYPTO_clear_free(dispatch);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            new_error = OSSL_FUNC_core_new_error(dispatch);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            set_error_debug = OSSL_FUNC_core_set_error_debug(dispatch);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            vset_error = OSSL_FUNC_core_vset_error(dispatch);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            bio_read_ex = OSSL_FUNC_BIO_read_ex(dispatch);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            bio_write_ex = OSSL_FUNC_BIO_write_ex(dispatch);
            break;
        case OSSL_FUNC_BIO_CTRL:
            bio_ctrl = OSSL_FUNC_BIO_ctrl(dispatch);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            obj_create = OSSL_FUNC_core_obj_create(dispatch);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(dispatch);
            break;
        default:
            break;
        }
    }

    if (zalloc == NULL || clear_free == NULL || bio_read_ex == NULL
            || bio_write_ex == NULL || bio_ctrl == NULL || obj_create == NULL
            || obj_add_sigid == NULL || core_get_params == NULL)
        return 0;
    if (!ed301d00_core_version_is_supported(handle, core_get_params))
        return 0;
    provider = zalloc(sizeof(*provider), __FILE__, __LINE__);
    if (provider == NULL)
        return 0;

    provider->handle = handle;
    provider->zalloc = zalloc;
    provider->clear_free = clear_free;
    provider->new_error = new_error;
    provider->set_error_debug = set_error_debug;
    provider->vset_error = vset_error;
    provider->bio_read_ex = bio_read_ex;
    provider->bio_write_ex = bio_write_ex;
    provider->bio_ctrl = bio_ctrl;
    provider->rust = rust_api;

    if (!ed301d00_object_registry_register(
            handle,
            obj_create,
            obj_add_sigid)) {
        ed301d00_raise(provider, ED301D00_R_OBJECT_REGISTRATION_FAILURE,
            "ephemeral draft-00 test OID registration failed "
            "(collision or registry conflict)");
        clear_free(provider, sizeof(*provider), __FILE__, __LINE__);
        return 0;
    }

    *provider_context = provider;
    *output_dispatch = ED301D00_PROVIDER_DISPATCH;
    return 1;
}
