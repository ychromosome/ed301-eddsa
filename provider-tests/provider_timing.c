#define _POSIX_C_SOURCE 200809L

/* dudect classes for the final Ed301 provider's secret-bearing operations. */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#define DUDECT_IMPLEMENTATION
#include "third_party/dudect/dudect.h"

#define ED301_BYTES 38U
#define ED301_SIGNATURE_BYTES 76U
#define ED301_NAME "Ed301-EdDSA-v1"
#define ED301_PROPERTIES "provider=ed301_eddsa_v1"
#define BATCH_MEASUREMENTS 2000U
#define CHUNK_SIZE sizeof(uint32_t)

enum {
    TEST_POSITIVE_CONTROL,
    TEST_PREPARED_SIGN,
    TEST_PRIVATE_IMPORT,
    TEST_COUNT
};

static const char *const TEST_LABELS[TEST_COUNT] = {
    "P0 positive-control",
    "T1 prepared-sign",
    "T2 private-seed-import"
};

static const unsigned char FIXED_SEED[ED301_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25
};

typedef struct timing_slot_st {
    EVP_PKEY *key;
    EVP_MD_CTX *signature;
    unsigned char seed[ED301_BYTES];
} TIMING_SLOT;

static OSSL_LIB_CTX *libctx;
static int current_test;
static TIMING_SLOT slots[BATCH_MEASUREMENTS];
static unsigned char signature_output[ED301_SIGNATURE_BYTES];
static const unsigned char message[64] = { 0x5a };
static size_t prepare_failures;
static size_t operation_failures;
static volatile uint64_t timing_sink;

static EVP_PKEY *private_key(const unsigned char seed[ED301_BYTES])
{
    return EVP_PKEY_new_raw_private_key_ex(
        libctx, ED301_NAME, ED301_PROPERTIES, seed, ED301_BYTES);
}

static void slot_clear(TIMING_SLOT *slot)
{
    EVP_MD_CTX_free(slot->signature);
    EVP_PKEY_free(slot->key);
    OPENSSL_cleanse(slot->seed, sizeof(slot->seed));
    slot->signature = NULL;
    slot->key = NULL;
}

static int prepare_slot(TIMING_SLOT *slot, int input_class)
{
    if (input_class == 0)
        memcpy(slot->seed, FIXED_SEED, sizeof(slot->seed));
    else if (RAND_bytes_ex(
            libctx, slot->seed, sizeof(slot->seed), 0) != 1)
        return 0;

    if (current_test == TEST_POSITIVE_CONTROL)
        return 1;
    if (current_test == TEST_PRIVATE_IMPORT)
        return 1;
    if (current_test != TEST_PREPARED_SIGN)
        return 0;

    slot->key = private_key(slot->seed);
    slot->signature = EVP_MD_CTX_new();
    return slot->key != NULL && slot->signature != NULL
        && EVP_DigestSignInit_ex(slot->signature, NULL, NULL,
            libctx, ED301_PROPERTIES, slot->key, NULL) == 1;
}

void prepare_inputs(
    dudect_config_t *configuration,
    uint8_t *input_data,
    uint8_t *classes)
{
    size_t index;

    for (index = 0; index < configuration->number_measurements; index++) {
        uint32_t slot_index = (uint32_t)index;

        slot_clear(&slots[index]);
        classes[index] = randombit();
        memcpy(input_data + index * configuration->chunk_size,
            &slot_index, sizeof(slot_index));
        if (!prepare_slot(&slots[index], classes[index]))
            prepare_failures++;
    }
}

uint8_t do_one_computation(uint8_t *data)
{
    uint32_t index;
    TIMING_SLOT *slot;
    int ok = 0;

    memcpy(&index, data, sizeof(index));
    slot = &slots[index];
    if (current_test == TEST_POSITIVE_CONTROL) {
        uint64_t accumulator = 0;
        size_t bit;

        for (bit = 0; bit < 8 * ED301_BYTES; bit++) {
            if (((slot->seed[bit / 8] >> (bit % 8)) & 1U) != 0) {
                accumulator += (accumulator ^ bit)
                    * UINT64_C(0x9e3779b97f4a7c15);
                accumulator = (accumulator << 13)
                    | (accumulator >> 51);
            }
        }
        timing_sink = accumulator;
        return 1;
    }
    if (current_test == TEST_PREPARED_SIGN) {
        size_t output_length = sizeof(signature_output);

        ok = slot->signature != NULL
            && EVP_DigestSign(slot->signature,
                signature_output, &output_length,
                message, sizeof(message)) == 1
            && output_length == sizeof(signature_output);
    } else if (current_test == TEST_PRIVATE_IMPORT) {
        slot->key = private_key(slot->seed);
        ok = slot->key != NULL;
    }
    if (!ok)
        operation_failures++;
    return (uint8_t)ok;
}

static double maximum_absolute_t(dudect_ctx_t *context)
{
    return fabs(t_compute(max_test(context)));
}

static dudect_state_t run_test(
    int test,
    size_t total_measurements,
    double *maximum_t,
    size_t *preparation_errors,
    size_t *operation_errors)
{
    dudect_config_t configuration;
    dudect_ctx_t context;
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    size_t batches = total_measurements / BATCH_MEASUREMENTS + 1;
    size_t index;

    current_test = test;
    operation_failures = 0;
    prepare_failures = 0;
    configuration.chunk_size = CHUNK_SIZE;
    configuration.number_measurements = BATCH_MEASUREMENTS;
    if (dudect_init(&context, &configuration) != 0) {
        *preparation_errors = 1;
        *operation_errors = 0;
        return DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    }
    for (index = 0; index < batches; index++)
        state = dudect_main(&context);
    *maximum_t = maximum_absolute_t(&context);
    dudect_free(&context);
    for (index = 0; index < BATCH_MEASUREMENTS; index++)
        slot_clear(&slots[index]);
    *preparation_errors = prepare_failures;
    *operation_errors = operation_failures;
    printf("%-24s max_abs_t=%.2f prepare_failures=%zu "
        "operation_failures=%zu dudect=%s\n",
        TEST_LABELS[test], *maximum_t, *preparation_errors,
        *operation_errors,
        state == DUDECT_LEAKAGE_FOUND
            ? "LEAKAGE_FOUND" : "NO_LEAKAGE_EVIDENCE");
    return state;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *ed301_provider = NULL;
    size_t total_measurements = 200000;
    dudect_state_t states[TEST_COUNT];
    double maximum_t[TEST_COUNT] = { 0 };
    size_t preparation_errors[TEST_COUNT] = { 0 };
    size_t operation_errors[TEST_COUNT] = { 0 };
    int test;
    int leakage = 0;
    int status = 2;

    if (argc < 2 || argc > 3) {
        fprintf(stderr,
            "usage: %s PROVIDER_MODULE_DIRECTORY [MEASUREMENTS]\n",
            argv[0]);
        return 2;
    }
    if (argc == 3) {
        char *end = NULL;
        unsigned long long parsed = strtoull(argv[2], &end, 10);

        if (end == NULL || *end != '\0'
                || parsed < 2 * DUDECT_ENOUGH_MEASUREMENTS) {
            fprintf(stderr, "MEASUREMENTS must be an integer >= %d\n",
                2 * DUDECT_ENOUGH_MEASUREMENTS);
            return 2;
        }
        total_measurements = (size_t)parsed;
    }

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) != 1
            || (default_provider = OSSL_PROVIDER_load(
                    libctx, "default")) == NULL
            || (ed301_provider = OSSL_PROVIDER_load(
                    libctx, "ed301_eddsa_v1")) == NULL) {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    printf("ed301_timing_tool=dudect measurements_per_test=%zu "
        "leak_threshold_abs_t=%d\n",
        total_measurements, t_threshold_moderate);
    for (test = 0; test < TEST_COUNT; test++) {
        states[test] = run_test(test, total_measurements,
            &maximum_t[test], &preparation_errors[test],
            &operation_errors[test]);
        if (preparation_errors[test] != 0 || operation_errors[test] != 0) {
            fprintf(stderr,
                "ed301_timing=ERROR test=%s prepare_failures=%zu "
                "operation_failures=%zu\n",
                TEST_LABELS[test], preparation_errors[test],
                operation_errors[test]);
            goto done;
        }
    }
    if (states[TEST_POSITIVE_CONTROL] != DUDECT_LEAKAGE_FOUND) {
        printf("ed301_timing=INCONCLUSIVE positive_control_max_t=%.2f\n",
            maximum_t[TEST_POSITIVE_CONTROL]);
        status = 3;
        goto done;
    }
    for (test = TEST_PREPARED_SIGN; test < TEST_COUNT; test++)
        leakage |= states[test] == DUDECT_LEAKAGE_FOUND;
    printf("ed301_timing=%s prepared_sign=%.2f private_seed_import=%.2f "
        "positive_control=%.2f\n",
        leakage ? "LEAK" : "PASS", maximum_t[TEST_PREPARED_SIGN],
        maximum_t[TEST_PRIVATE_IMPORT], maximum_t[TEST_POSITIVE_CONTROL]);
    status = leakage ? 1 : 0;

done:
    OPENSSL_cleanse(signature_output, sizeof(signature_output));
    OSSL_PROVIDER_unload(ed301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
