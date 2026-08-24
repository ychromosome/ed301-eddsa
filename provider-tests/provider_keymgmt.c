/*
 * Acceptance section 2 (key management): seed, public-key and keypair
 * import/export, key generation, has, validate, match, duplicate, free,
 * exact 38-byte lengths, byte-exact seed/public consistency, and rejection
 * of missing selections, malformed parameters and undersized outputs
 * without partial writes.
 */

#include <openssl/bio.h>

#include "harness_common.h"
#include "vectors.h"

static unsigned char ascii_lower(unsigned char value)
{
    return value >= 'A' && value <= 'Z'
        ? (unsigned char)(value + ('a' - 'A')) : value;
}

static int contains_ascii_case_insensitive(
    const char *haystack,
    size_t haystack_length,
    const char *needle,
    size_t needle_length)
{
    size_t offset;

    if (haystack == NULL || needle == NULL || needle_length > haystack_length)
        return 0;
    for (offset = 0; offset <= haystack_length - needle_length; offset++) {
        size_t index;

        for (index = 0; index < needle_length; index++) {
            if (ascii_lower((unsigned char)haystack[offset + index])
                    != ascii_lower((unsigned char)needle[index]))
                break;
        }
        if (index == needle_length)
            return 1;
    }
    return 0;
}

static int printed_text_contains_seed_hex(
    const char *text,
    size_t text_length,
    const unsigned char seed[D00_SEED_BYTES])
{
    static const char hex[] = "0123456789abcdef";
    char compact[D00_SEED_BYTES * 2];
    char colon_separated[D00_SEED_BYTES * 3 - 1];
    size_t index;

    for (index = 0; index < D00_SEED_BYTES; index++) {
        compact[index * 2] = hex[seed[index] >> 4];
        compact[index * 2 + 1] = hex[seed[index] & 0x0f];
        colon_separated[index * 3] = compact[index * 2];
        colon_separated[index * 3 + 1] = compact[index * 2 + 1];
        if (index + 1 < D00_SEED_BYTES)
            colon_separated[index * 3 + 2] = ':';
    }
    return contains_ascii_case_insensitive(
            text, text_length, compact, sizeof(compact))
        || contains_ascii_case_insensitive(
            text, text_length, colon_separated, sizeof(colon_separated));
}

static int descriptor_matches(
    const OSSL_PARAM *descriptor,
    int wants_private,
    int wants_public)
{
    const OSSL_PARAM *parameter;
    const OSSL_PARAM *private_parameter;
    const OSSL_PARAM *public_parameter;
    size_t count = 0;

    if (descriptor == NULL)
        return 0;
    for (parameter = descriptor; parameter->key != NULL; parameter++) {
        if (strcmp(parameter->key, OSSL_PKEY_PARAM_PRIV_KEY) != 0
                && strcmp(parameter->key, OSSL_PKEY_PARAM_PUB_KEY) != 0)
            return 0;
        count++;
    }
    private_parameter = OSSL_PARAM_locate_const(
        descriptor, OSSL_PKEY_PARAM_PRIV_KEY);
    public_parameter = OSSL_PARAM_locate_const(
        descriptor, OSSL_PKEY_PARAM_PUB_KEY);
    return count == (size_t)(wants_private + wants_public)
        && (private_parameter != NULL) == wants_private
        && (public_parameter != NULL) == wants_public
        && (!wants_private
            || private_parameter->data_type == OSSL_PARAM_OCTET_STRING)
        && (!wants_public
            || public_parameter->data_type == OSSL_PARAM_OCTET_STRING);
}

static int exported_material_matches(
    const OSSL_PARAM *parameters,
    int wants_private,
    int wants_public,
    const unsigned char expected_private[D00_SEED_BYTES],
    const unsigned char expected_public[D00_PUB_BYTES])
{
    const OSSL_PARAM *parameter;
    const OSSL_PARAM *private_parameter;
    const OSSL_PARAM *public_parameter;
    size_t count = 0;

    if (parameters == NULL)
        return 0;
    for (parameter = parameters; parameter->key != NULL; parameter++) {
        if (strcmp(parameter->key, OSSL_PKEY_PARAM_PRIV_KEY) != 0
                && strcmp(parameter->key, OSSL_PKEY_PARAM_PUB_KEY) != 0)
            return 0;
        count++;
    }
    private_parameter = OSSL_PARAM_locate_const(
        parameters, OSSL_PKEY_PARAM_PRIV_KEY);
    public_parameter = OSSL_PARAM_locate_const(
        parameters, OSSL_PKEY_PARAM_PUB_KEY);
    if (count != (size_t)(wants_private + wants_public)
            || (private_parameter != NULL) != wants_private
            || (public_parameter != NULL) != wants_public)
        return 0;
    if (wants_private
            && (private_parameter->data_type != OSSL_PARAM_OCTET_STRING
                || private_parameter->data == NULL
                || private_parameter->data_size != D00_SEED_BYTES
                || memcmp(private_parameter->data, expected_private,
                    D00_SEED_BYTES) != 0))
        return 0;
    if (wants_public
            && (public_parameter->data_type != OSSL_PARAM_OCTET_STRING
                || public_parameter->data == NULL
                || public_parameter->data_size != D00_PUB_BYTES
                || memcmp(public_parameter->data, expected_public,
                    D00_PUB_BYTES) != 0))
        return 0;
    return 1;
}

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = d00_load(libctx, &deflt);
    const POSITIVE_CASE *base = &POSITIVE_CASES[0];

    D00_CHECK(draft != NULL, "provider load");

    /* Seed import derives the exact vector public key. */
    {
        EVP_PKEY *pkey = d00_key_from_seed(libctx, base->seed);
        unsigned char public_out[38] = { 0 };
        unsigned char seed_out[38] = { 0 };
        size_t out_len = 0;

        D00_CHECK(pkey != NULL, "seed import");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PUB_KEY, public_out,
                    sizeof(public_out), &out_len) == 1
                && out_len == D00_PUB_BYTES
                && memcmp(public_out, base->public_key,
                    D00_PUB_BYTES) == 0,
            "derived public key matches the draft-00 vector");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) == 1
                && out_len == D00_SEED_BYTES
                && memcmp(seed_out, base->seed, D00_SEED_BYTES) == 0,
            "seed export is byte-exact");

        /* Undersized output: no partial write. */
        {
            unsigned char small[37];
            unsigned char canary[37];

            memset(small, 0xa5, sizeof(small));
            memset(canary, 0xa5, sizeof(canary));
            out_len = 0;
            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_octet_string_param(pkey,
                        OSSL_PKEY_PARAM_PUB_KEY, small,
                        sizeof(small), &out_len) != 1
                    && memcmp(small, canary, sizeof(small)) == 0,
                "undersized public output fails without partial write");
            ERR_clear_error();
        }

        /* Raw getters agree. */
        {
            unsigned char raw[38];
            size_t raw_len = sizeof(raw);

            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) == 1
                    && raw_len == D00_PUB_BYTES
                    && memcmp(raw, base->public_key, D00_PUB_BYTES) == 0,
                "raw public getter");
            raw_len = sizeof(raw);
            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_raw_private_key(pkey, raw, &raw_len) == 1
                    && raw_len == D00_SEED_BYTES
                    && memcmp(raw, base->seed, D00_SEED_BYTES) == 0,
                "raw private getter");
        }

        /* Bits / security bits / max size. */
        {
            int bits = 0;
            int security_bits = 0;
            int max_size = 0;

            D00_CHECK(pkey != NULL
                    && EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_BITS,
                        &bits) == 1
                    && bits == 301
                    && EVP_PKEY_get_int_param(pkey,
                        OSSL_PKEY_PARAM_SECURITY_BITS,
                        &security_bits) == 1
                    && security_bits == 149
                    && EVP_PKEY_get_int_param(pkey,
                        OSSL_PKEY_PARAM_MAX_SIZE, &max_size) == 1
                    && max_size == 76,
                "bits=%d security=%d max=%d", bits, security_bits,
                max_size);
        }

        /*
         * K6 -- Draft public-key policy and OpenSSL
         * test/evp_extra_test.c test_EVP_PKEY_check() pattern: valid keypair
         * validation succeeds through check and public_check.
         */
        {
            EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new_from_pkey(
                libctx, pkey, D00_PROP);

            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_check(check_ctx) == 1,
                "full key validation");
            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_public_check(check_ctx) == 1,
                "public validation");
            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_public_check_quick(check_ctx) == 1,
                "quick public validation");
            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_private_check(check_ctx) == 1,
                "private validation");
            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_pairwise_check(check_ctx) == 1,
                "pairwise validation");
            EVP_PKEY_CTX_free(check_ctx);
        }

        /*
         * K3 -- Provider match contract, following OpenSSL
         * test/evp_extra_test.c EVP_PKEY_eq() comparison patterns.
         */
        {
            EVP_PKEY *copy = EVP_PKEY_dup(pkey);
            EVP_PKEY *public_only = d00_key_from_public(
                libctx, base->public_key, D00_PUB_BYTES);
            EVP_PKEY *same_public = d00_key_from_public(
                libctx, base->public_key, D00_PUB_BYTES);
            EVP_PKEY *other_public = d00_key_from_public(
                libctx, POSITIVE_CASES[1].public_key, D00_PUB_BYTES);
            EVP_PKEY *other_pair = d00_key_from_seed(
                libctx, POSITIVE_CASES[1].seed);

            D00_CHECK(copy != NULL && EVP_PKEY_eq(pkey, copy) == 1,
                "duplicate matches");
            D00_CHECK(public_only != NULL
                    && EVP_PKEY_eq(pkey, public_only) == 1,
                "public-only key matches the pair on the public component");
            D00_CHECK(public_only != NULL && same_public != NULL
                    && EVP_PKEY_eq(public_only, same_public) == 1,
                "equal public-only keys match");
            D00_CHECK(public_only != NULL && other_public != NULL
                    && EVP_PKEY_eq(public_only, other_public) == 0,
                "different public-only keys do not match");
            D00_CHECK(other_pair != NULL
                    && EVP_PKEY_eq(pkey, other_pair) == 0,
                "deterministic different keypairs do not match");
            EVP_PKEY_free(copy);
            EVP_PKEY_free(public_only);
            EVP_PKEY_free(same_public);
            EVP_PKEY_free(other_public);
            EVP_PKEY_free(other_pair);
        }

        /*
         * K4 -- OpenSSL test/evp_extra_test2.c
         * do_pkey_tofrom_data_select() pattern: the public fromdata descriptor
         * and actual todata result must agree
         * for every meaningful component selection.  In particular, a
         * public-only export must never carry the private seed.
         */
        {
            EVP_PKEY_CTX *from_ctx = EVP_PKEY_CTX_new_from_name(
                libctx, D00_ALG, D00_PROP);
            const OSSL_PARAM *private_types = from_ctx == NULL ? NULL
                : EVP_PKEY_fromdata_settable(
                    from_ctx, EVP_PKEY_PRIVATE_KEY);
            const OSSL_PARAM *public_types = from_ctx == NULL ? NULL
                : EVP_PKEY_fromdata_settable(
                    from_ctx, EVP_PKEY_PUBLIC_KEY);
            const OSSL_PARAM *keypair_types = from_ctx == NULL ? NULL
                : EVP_PKEY_fromdata_settable(from_ctx, EVP_PKEY_KEYPAIR);
            OSSL_PARAM *private_export = NULL;
            OSSL_PARAM *public_export = NULL;
            OSSL_PARAM *keypair_export = NULL;

            D00_CHECK(descriptor_matches(private_types, 1, 0),
                "private import descriptor is exactly one octet-string seed");
            D00_CHECK(descriptor_matches(public_types, 0, 1),
                "public import descriptor is exactly one octet-string key");
            D00_CHECK(descriptor_matches(keypair_types, 1, 1),
                "keypair import descriptor declares both octet strings");
            D00_CHECK(from_ctx != NULL
                    && EVP_PKEY_fromdata_settable(from_ctx, 0) == NULL,
                "empty selection has no import descriptor");

            D00_CHECK(pkey != NULL
                    && EVP_PKEY_todata(pkey, EVP_PKEY_PRIVATE_KEY,
                        &private_export) == 1
                    && exported_material_matches(private_export, 1, 0,
                        base->seed, base->public_key),
                "private export contains exactly the byte-exact seed");
            D00_CHECK(pkey != NULL
                    && EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY,
                        &public_export) == 1
                    && exported_material_matches(public_export, 0, 1,
                        base->seed, base->public_key),
                "public export contains exactly the byte-exact public key");
            D00_CHECK(pkey != NULL
                    && EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR,
                        &keypair_export) == 1
                    && exported_material_matches(keypair_export, 1, 1,
                        base->seed, base->public_key),
                "keypair export contains exactly both key components");

            OSSL_PARAM_free(keypair_export);
            OSSL_PARAM_free(public_export);
            OSSL_PARAM_free(private_export);
            EVP_PKEY_CTX_free(from_ctx);
        }

        EVP_PKEY_free(pkey);
    }

    /* Public-only import and validation. */
    {
        EVP_PKEY *pkey = d00_key_from_public(
            libctx, base->public_key, D00_PUB_BYTES);
        unsigned char seed_out[38];
        size_t out_len = 0;

        D00_CHECK(pkey != NULL, "public-only import");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) != 1,
            "public-only key has no private component");
        ERR_clear_error();

        /*
         * K5 -- Provider contract: the ordinary artifact has no text encoder,
         * and a public-only key has no private component.  OpenSSL 3.5/4.0
         * crypto/evp/p_lib.c print_pkey() may therefore emit its unsupported
         * diagnostic or fail closed.  Neither result may contain compact or
         * colon-separated seed hex.
         */
        {
            BIO *text = BIO_new(BIO_s_mem());
            char *printed = NULL;
            int print_result = text == NULL ? 0
                : EVP_PKEY_print_private(text, pkey, 0, NULL);
            long printed_length = text == NULL
                ? -1 : BIO_get_mem_data(text, &printed);

            D00_CHECK(text != NULL
                    && (print_result == 0 || print_result == 1)
                    && printed_length >= 0
                    && (printed_length == 0
                        || (printed != NULL
                            && !printed_text_contains_seed_hex(printed,
                                (size_t)printed_length, base->seed))),
                "print_private(public-only) emits no seed hex");
            ERR_clear_error();
            BIO_free(text);
        }
        EVP_PKEY_free(pkey);
    }

    /* A private-only selection requires only the seed and derives public. */
    {
        EVP_PKEY *pkey = d00_key_from_params(
            libctx, EVP_PKEY_PRIVATE_KEY,
            base->seed, D00_SEED_BYTES, NULL, 0);
        unsigned char public_out[D00_PUB_BYTES] = { 0 };
        size_t public_length = 0;

        D00_CHECK(pkey != NULL,
            "private-only import derives a complete internal key");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PUB_KEY, public_out,
                    sizeof(public_out), &public_length) == 1
                && public_length == D00_PUB_BYTES
                && memcmp(public_out, base->public_key,
                    D00_PUB_BYTES) == 0,
            "private-only import derives the byte-exact public key");
        EVP_PKEY_free(pkey);
    }

    /*
     * K6 -- Draft canonical-prime-subgroup policy.  Unlike generic OpenSSL
     * test/evp_extra_test.c test_EVP_PKEY_check() fixtures, this provider
     * validates public material atomically during import.  Torsion and mixed-
     * order encodings therefore fail before an EVP_PKEY exists to check.
     */
    {
        static const size_t invalid_point_indices[] = { 2, 3, 4, 5, 6, 7 };
        size_t point_index;

        for (point_index = 0;
                point_index < sizeof(invalid_point_indices)
                    / sizeof(invalid_point_indices[0]);
                point_index++) {
            const POINT_CASE *point =
                &POINT_CASES[invalid_point_indices[point_index]];
            EVP_PKEY *invalid = d00_key_from_public(
                libctx, point->encoding, point->encoding_len);

            D00_CHECK(invalid == NULL,
                "K6 %s rejected before public_check", point->id);
            ERR_clear_error();
            EVP_PKEY_free(invalid);
        }
    }

    /* Keypair import with matching public key. */
    {
        EVP_PKEY *pkey = d00_key_from_params(
            libctx, EVP_PKEY_KEYPAIR,
            base->seed, D00_SEED_BYTES,
            base->public_key, D00_PUB_BYTES);

        D00_CHECK(pkey != NULL, "matching keypair import");
        EVP_PKEY_free(pkey);
    }

    /*
     * K1/K2 -- OpenSSL test/evp_extra_test.c
     * test_set_get_raw_keys_int() pattern plus the draft's exact 38-byte raw
     * key contract: _ex constructors round-trip exactly and all adjacent
     * lengths, including zero, are rejected.
     */
    {
        EVP_PKEY *raw_private = EVP_PKEY_new_raw_private_key_ex(
            libctx, D00_ALG, D00_PROP, base->seed, D00_SEED_BYTES);
        EVP_PKEY *raw_public = EVP_PKEY_new_raw_public_key_ex(
            libctx, D00_ALG, D00_PROP,
            base->public_key, D00_PUB_BYTES);
        unsigned char private_input[D00_SEED_BYTES + 1];
        unsigned char public_input[D00_PUB_BYTES + 1];
        unsigned char output[D00_SEED_BYTES];
        static const size_t invalid_lengths[] = { 0, 37, 39 };
        size_t output_length = 0;
        size_t length_index;

        memcpy(private_input, base->seed, D00_SEED_BYTES);
        memcpy(public_input, base->public_key, D00_PUB_BYTES);
        private_input[D00_SEED_BYTES] = 0;
        public_input[D00_PUB_BYTES] = 0;

        D00_CHECK(raw_private != NULL
                && EVP_PKEY_get_raw_private_key(
                    raw_private, NULL, &output_length) == 1
                && output_length == D00_SEED_BYTES,
            "raw-private length query returns exactly 38");
        output_length = sizeof(output);
        D00_CHECK(raw_private != NULL
                && EVP_PKEY_get_raw_private_key(
                    raw_private, output, &output_length) == 1
                && output_length == D00_SEED_BYTES
                && memcmp(output, base->seed, D00_SEED_BYTES) == 0,
            "raw-private bytes round-trip exactly");

        output_length = 0;
        D00_CHECK(raw_private != NULL
                && EVP_PKEY_get_raw_public_key(
                    raw_private, NULL, &output_length) == 1
                && output_length == D00_PUB_BYTES,
            "raw-private key derives a 38-byte public length");
        output_length = sizeof(output);
        D00_CHECK(raw_private != NULL
                && EVP_PKEY_get_raw_public_key(
                    raw_private, output, &output_length) == 1
                && output_length == D00_PUB_BYTES
                && memcmp(output, base->public_key, D00_PUB_BYTES) == 0,
            "raw-private key derives the byte-exact public key");

        output_length = 0;
        D00_CHECK(raw_public != NULL
                && EVP_PKEY_get_raw_public_key(
                    raw_public, NULL, &output_length) == 1
                && output_length == D00_PUB_BYTES,
            "raw-public length query returns exactly 38");
        output_length = sizeof(output);
        D00_CHECK(raw_public != NULL
                && EVP_PKEY_get_raw_public_key(
                    raw_public, output, &output_length) == 1
                && output_length == D00_PUB_BYTES
                && memcmp(output, base->public_key, D00_PUB_BYTES) == 0,
            "raw-public bytes round-trip exactly");
        output_length = 0;
        D00_CHECK(raw_public != NULL
                && EVP_PKEY_get_raw_private_key(
                    raw_public, NULL, &output_length) != 1,
            "raw-public key exposes no private length or seed");
        ERR_clear_error();

        for (length_index = 0;
                length_index < sizeof(invalid_lengths)
                    / sizeof(invalid_lengths[0]);
                length_index++) {
            const size_t length = invalid_lengths[length_index];
            EVP_PKEY *bad_private = EVP_PKEY_new_raw_private_key_ex(
                libctx, D00_ALG, D00_PROP, private_input, length);
            EVP_PKEY *bad_public = EVP_PKEY_new_raw_public_key_ex(
                libctx, D00_ALG, D00_PROP, public_input, length);

            D00_CHECK(bad_private == NULL,
                "raw-private length %zu is rejected", length);
            D00_CHECK(bad_public == NULL,
                "raw-public length %zu is rejected", length);
            ERR_clear_error();
            EVP_PKEY_free(bad_private);
            EVP_PKEY_free(bad_public);
        }
        OPENSSL_cleanse(output, sizeof(output));
        OPENSSL_cleanse(private_input, sizeof(private_input));
        EVP_PKEY_free(raw_private);
        EVP_PKEY_free(raw_public);
    }

    /* Rejections. */
    {
        unsigned char wrong_public[38];
        unsigned char short_seed[37];
        unsigned char long_seed[39];
        EVP_PKEY *bad;

        memcpy(wrong_public, POSITIVE_CASES[1].public_key,
            sizeof(wrong_public));
        memcpy(short_seed, base->seed, sizeof(short_seed));
        memcpy(long_seed, base->seed, D00_SEED_BYTES);
        long_seed[38] = 0;

        /*
         * K7 -- Provider atomic-keypair contract: a seed plus a different,
         * individually valid draft public key is rejected during import, so
         * no inconsistent EVP_PKEY can reach EVP_PKEY_check().
         */
        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            base->seed, D00_SEED_BYTES, wrong_public, D00_PUB_BYTES);
        D00_CHECK(bad == NULL, "mismatched keypair import is rejected");
        ERR_clear_error();

        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            short_seed, sizeof(short_seed), NULL, 0);
        D00_CHECK(bad == NULL, "37-byte seed is rejected");
        ERR_clear_error();

        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            long_seed, sizeof(long_seed), NULL, 0);
        D00_CHECK(bad == NULL, "39-byte seed is rejected");
        ERR_clear_error();

        bad = d00_key_from_public(libctx, base->public_key, 37);
        D00_CHECK(bad == NULL, "37-byte public key is rejected");
        ERR_clear_error();

        bad = d00_key_from_public(libctx, base->public_key, 39);
        D00_CHECK(bad == NULL,
            "39-byte public key length is rejected");
        ERR_clear_error();

        /*
         * OpenSSL's raw-public constructor imports a public-only value under
         * KEYPAIR selection.  Match the built-in Ed25519/Ed448 KEYMGMT
         * contract without inventing a private component.
         */
        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            NULL, 0, base->public_key, D00_PUB_BYTES);
        D00_CHECK(bad != NULL,
            "keypair selection accepts a public-only raw key");
        if (bad != NULL) {
            unsigned char seed_out[38];
            size_t out_len = 0;

            D00_CHECK(EVP_PKEY_get_octet_string_param(bad,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) != 1,
                "public-only raw key does not acquire a private seed");
            ERR_clear_error();
        }
        EVP_PKEY_free(bad);

        /* Missing selection material: empty parameter list. */
        bad = d00_key_from_params(libctx, EVP_PKEY_KEYPAIR,
            NULL, 0, NULL, 0);
        D00_CHECK(bad == NULL, "empty import is rejected");
        ERR_clear_error();

        /* Malformed parameter type: UTF8 string instead of octets. */
        {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
                libctx, D00_ALG, D00_PROP);
            OSSL_PARAM params[2];
            EVP_PKEY *pkey = NULL;

            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_PUB_KEY,
                (char *)base->public_key, D00_PUB_BYTES);
            params[1] = OSSL_PARAM_construct_end();
            D00_CHECK(ctx != NULL
                    && EVP_PKEY_fromdata_init(ctx) == 1
                    && EVP_PKEY_fromdata(ctx, &pkey,
                        EVP_PKEY_PUBLIC_KEY, params) != 1
                    && pkey == NULL,
                "wrong parameter type is rejected");
            ERR_clear_error();
            EVP_PKEY_CTX_free(ctx);
        }
    }

    /*
     * K7 -- Provider atomic-keypair contract: reimport into an existing
     * EVP_PKEY is transactional; a mismatched
     * keypair must not partially replace the already valid key.
     */
    {
        EVP_PKEY *pkey = d00_key_from_seed(libctx, base->seed);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
            libctx, D00_ALG, D00_PROP);
        unsigned char wrong_public[D00_PUB_BYTES];
        unsigned char seed_out[D00_SEED_BYTES] = { 0 };
        unsigned char public_out[D00_PUB_BYTES] = { 0 };
        unsigned char signature[D00_SIG_BYTES] = { 0 };
        size_t output_length = 0;
        OSSL_PARAM params[3];
        int initialized;
        int reimport_result = 1;

        memcpy(wrong_public, POSITIVE_CASES[1].public_key,
            sizeof(wrong_public));
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, (void *)base->seed, D00_SEED_BYTES);
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, wrong_public, D00_PUB_BYTES);
        params[2] = OSSL_PARAM_construct_end();

        initialized = ctx != NULL && EVP_PKEY_fromdata_init(ctx) == 1;
        D00_CHECK(pkey != NULL && initialized,
            "transactional reimport setup");
        if (pkey != NULL && initialized)
            reimport_result = EVP_PKEY_fromdata(
                ctx, &pkey, EVP_PKEY_KEYPAIR, params);
        D00_CHECK(reimport_result != 1,
            "mismatched reimport is rejected");
        ERR_clear_error();

        D00_CHECK(pkey != NULL
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &output_length) == 1
                && output_length == D00_SEED_BYTES
                && memcmp(seed_out, base->seed, D00_SEED_BYTES) == 0
                && EVP_PKEY_get_octet_string_param(pkey,
                    OSSL_PKEY_PARAM_PUB_KEY, public_out,
                    sizeof(public_out), &output_length) == 1
                && output_length == D00_PUB_BYTES
                && memcmp(public_out, base->public_key,
                    D00_PUB_BYTES) == 0,
            "failed reimport leaves both original components unchanged");
        D00_CHECK(pkey != NULL
                && d00_digest_sign(libctx, pkey, base->message,
                    base->message_len, signature)
                && memcmp(signature, base->signature,
                    D00_SIG_BYTES) == 0,
            "failed reimport leaves the original signing key usable");

        OPENSSL_cleanse(seed_out, sizeof(seed_out));
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
    }

    /* Encoded-public setter policy. */
    {
        EVP_PKEY *pkey = d00_key_from_seed(libctx, base->seed);
        unsigned char different[38];

        memcpy(different, base->public_key, sizeof(different));
        different[1] ^= 1;
        D00_CHECK(pkey != NULL
                && EVP_PKEY_set1_encoded_public_key(pkey,
                    base->public_key, D00_PUB_BYTES) == 1,
            "matching encoded public key is accepted");
        D00_CHECK(pkey != NULL
                && EVP_PKEY_set1_encoded_public_key(pkey,
                    different, D00_PUB_BYTES) != 1,
            "different encoded public key cannot replace the pair");
        ERR_clear_error();
        EVP_PKEY_free(pkey);
    }

    /* Key generation produces a valid, self-consistent pair. */
    {
        EVP_PKEY *generated = d00_keygen(libctx);
        EVP_PKEY *reimported = NULL;
        unsigned char seed_out[38];
        unsigned char public_out[38];
        unsigned char sig[76];
        size_t out_len = 0;
        static const unsigned char probe[] = "draft-00 keygen probe";

        D00_CHECK(generated != NULL, "key generation");
        if (generated != NULL) {
            EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new_from_pkey(
                libctx, generated, D00_PROP);

            D00_CHECK(check_ctx != NULL
                    && EVP_PKEY_check(check_ctx) == 1,
                "generated pair validates");
            EVP_PKEY_CTX_free(check_ctx);

            D00_CHECK(EVP_PKEY_get_octet_string_param(generated,
                    OSSL_PKEY_PARAM_PRIV_KEY, seed_out,
                    sizeof(seed_out), &out_len) == 1
                    && out_len == D00_SEED_BYTES
                    && EVP_PKEY_get_octet_string_param(generated,
                        OSSL_PKEY_PARAM_PUB_KEY, public_out,
                        sizeof(public_out), &out_len) == 1
                    && out_len == D00_PUB_BYTES,
                "generated components export");

            reimported = d00_key_from_seed(libctx, seed_out);
            D00_CHECK(reimported != NULL
                    && EVP_PKEY_eq(generated, reimported) == 1,
                "generated seed reimports to an equal key");

            D00_CHECK(d00_digest_sign(libctx, generated, probe,
                    sizeof(probe) - 1, sig)
                    && d00_digest_verify(libctx, generated, probe,
                        sizeof(probe) - 1, sig, sizeof(sig)),
                "generated key signs and verifies");

            EVP_PKEY_free(reimported);
            EVP_PKEY_free(generated);
        }
    }

    /* Two generated keys are distinct and do not match. */
    {
        EVP_PKEY *first = d00_keygen(libctx);
        EVP_PKEY *second = d00_keygen(libctx);

        D00_CHECK(first != NULL && second != NULL
                && EVP_PKEY_eq(first, second) != 1,
            "independent generated keys do not match");
        ERR_clear_error();
        EVP_PKEY_free(first);
        EVP_PKEY_free(second);
    }

    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return d00_summary("provider_keymgmt");
}
