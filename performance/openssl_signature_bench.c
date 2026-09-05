#define _POSIX_C_SOURCE 200809L

/* Exact-count EVP control benchmark for the Ed301 receipt runner. */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static volatile unsigned char sink;

static int monotonic_ns(uint64_t *value)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0
            || now.tv_sec < 0 || now.tv_nsec < 0)
        return 0;
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000)
        + (uint64_t)now.tv_nsec;
    return 1;
}

static int parse_count(const char *text, size_t *value)
{
    char *end = NULL;
    uintmax_t parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-'
            || text[0] == '+')
        return 0;
    errno = 0;
    parsed = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0
            || parsed > 100000000U)
        return 0;
    *value = (size_t)parsed;
    return 1;
}

static int sign_once(OSSL_LIB_CTX *libctx, const char *properties,
    EVP_PKEY *key, const unsigned char *message, size_t message_length,
    unsigned char *signature, size_t *signature_length)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int ok = context != NULL
        && EVP_DigestSignInit_ex(context, NULL, NULL, libctx, properties,
            key, NULL) > 0
        && EVP_DigestSign(context, signature, signature_length,
            message, message_length) > 0;

    EVP_MD_CTX_free(context);
    return ok;
}

static int verify_once(OSSL_LIB_CTX *libctx, const char *properties,
    EVP_PKEY *key, const unsigned char *message, size_t message_length,
    const unsigned char *signature, size_t signature_length)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int result = context == NULL ? -1
        : EVP_DigestVerifyInit_ex(context, NULL, NULL, libctx, properties,
            key, NULL) <= 0 ? -1
        : EVP_DigestVerify(context, signature, signature_length,
            message, message_length);

    EVP_MD_CTX_free(context);
    return result;
}

static EVP_PKEY *generate_key(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, algorithm, properties);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
            || EVP_PKEY_keygen(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

int main(int argc, char **argv)
{
    const char *operation;
    const char *algorithm;
    const char *properties;
    const char *module_directory;
    const char *extra_provider_name;
    unsigned char message[64];
    unsigned char signature[256];
    size_t signature_length = sizeof(signature);
    size_t count;
    size_t index;
    uint64_t started;
    uint64_t finished;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *extra_provider = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *generated = NULL;
    int status = EXIT_FAILURE;

    if (argc != 7 || !parse_count(argv[6], &count)) {
        fprintf(stderr, "usage: %s <keygen|sign|verify> <algorithm> "
            "<properties|-> <module-dir|-> <provider|-> <count>\n", argv[0]);
        return EXIT_FAILURE;
    }
    operation = argv[1];
    algorithm = argv[2];
    properties = strcmp(argv[3], "-") == 0 ? NULL : argv[3];
    module_directory = argv[4];
    extra_provider_name = argv[5];
    if (strcmp(operation, "keygen") != 0 && strcmp(operation, "sign") != 0
            && strcmp(operation, "verify") != 0)
        goto done;

    for (index = 0; index < sizeof(message); index++)
        message[index] = (unsigned char)(index * 29U + 7U);

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || (strcmp(module_directory, "-") != 0
                && OSSL_PROVIDER_set_default_search_path(libctx,
                    module_directory) <= 0))
        goto done;
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    if (default_provider == NULL)
        goto done;
    if (strcmp(extra_provider_name, "-") != 0) {
        extra_provider = OSSL_PROVIDER_load(libctx, extra_provider_name);
        if (extra_provider == NULL)
            goto done;
    }

    if (strcmp(operation, "keygen") != 0) {
        key = generate_key(libctx, algorithm, properties);
        if (key == NULL)
            goto done;
        if (!sign_once(libctx, properties, key, message, sizeof(message),
                signature, &signature_length))
            goto done;
        if (verify_once(libctx, properties, key, message, sizeof(message),
                signature, signature_length) != 1)
            goto done;
    }

    if (!monotonic_ns(&started))
        goto done;
    for (index = 0; index < count; index++) {
        if (strcmp(operation, "keygen") == 0) {
            generated = generate_key(libctx, algorithm, properties);
            if (generated == NULL)
                goto done;
            sink ^= (unsigned char)(uintptr_t)generated;
            EVP_PKEY_free(generated);
            generated = NULL;
        } else if (strcmp(operation, "sign") == 0) {
            signature_length = sizeof(signature);
            if (!sign_once(libctx, properties, key, message, sizeof(message),
                    signature, &signature_length))
                goto done;
            sink ^= signature[0];
        } else {
            int result = verify_once(libctx, properties, key, message,
                sizeof(message), signature, signature_length);

            if (result != 1)
                goto done;
            sink ^= (unsigned char)result;
        }
    }
    if (!monotonic_ns(&finished) || finished < started)
        goto done;
    printf("RESULT operation=%s algorithm=%s count=%zu total_ns=%" PRIu64
        " mean_ns=%.1f\n", operation, algorithm, count, finished - started,
        (double)(finished - started) / (double)count);
    status = EXIT_SUCCESS;

done:
    if (status != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_free(generated);
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(extra_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
