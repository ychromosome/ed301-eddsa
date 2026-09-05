/*
 * F4 regression: no provider-local spin/wait under delayed competing
 * registration.
 *
 * The host integration helper treats an incomplete or foreign registry as
 * unsafe and returns immediately.  Once an exact competing registration is
 * complete, an explicit caller retry succeeds.  A foreign conflict remains
 * blocked.  The provider contains no PID lock, scheduler loop or timeout.
 *
 * Lanes (each in its own process; the registry is process-global):
 *   exact-fast     first preflight fails immediately; retry after 50 ms works
 *   exact-stalled  first preflight fails immediately; retry after 3 s works
 *   conflict       initial and repeated preflights remain blocked
 */

#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include <openssl/objects.h>

#include "harness_common.h"

typedef struct competitor_st {
    long delay_milliseconds;
    int conflicting;
    _Atomic int prepared;
    _Atomic int completed;
    _Atomic int finished;
} COMPETITOR;

static void sleep_ms(long milliseconds)
{
    struct timespec delay = {
        milliseconds / 1000, (milliseconds % 1000) * 1000000L
    };

    nanosleep(&delay, NULL);
}

static double now_seconds(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

static void *competitor_main(void *argument)
{
    COMPETITOR *competitor = argument;
    int nid;

    if (competitor->conflicting) {
        nid = OBJ_create(ED301V1_OID_TEXT, "ED301V1-VAL03-COLLIDER",
            "ED301V1 val03 conflict object");
        atomic_store_explicit(
            &competitor->prepared, nid != NID_undef, memory_order_release);
        atomic_store_explicit(&competitor->completed,
            nid != NID_undef, memory_order_release);
        atomic_store_explicit(
            &competitor->finished, 1, memory_order_release);
        return NULL;
    }
    nid = OBJ_create(ED301V1_OID_TEXT, ED301V1_ALG, ED301V1_ALG);
    if (nid == NID_undef) {
        atomic_store_explicit(
            &competitor->finished, 1, memory_order_release);
        return NULL;
    }
    atomic_store_explicit(
        &competitor->prepared, 1, memory_order_release);
    sleep_ms(competitor->delay_milliseconds);
    atomic_store_explicit(&competitor->completed,
        OBJ_add_sigid(nid, NID_undef, nid) == 1,
        memory_order_release);
    atomic_store_explicit(&competitor->finished, 1, memory_order_release);
    return NULL;
}

static int run_lane(const char *label, const char *module_dir,
    long delay_milliseconds, int conflicting)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *v1 = NULL;
    COMPETITOR competitor = {
        delay_milliseconds, conflicting,
        ATOMIC_VAR_INIT(0), ATOMIC_VAR_INIT(0), ATOMIC_VAR_INIT(0)
    };
    pthread_t thread;
    double started;
    double elapsed;
    OSSL_PROVIDER *retry = NULL;
    int first_queue_ok;
    int lane_ok = 0;

    if (libctx == NULL)
        return 0;
    if (module_dir != NULL
            && OSSL_PROVIDER_set_default_search_path(libctx,
                module_dir) != 1)
        goto done;
    deflt = OSSL_PROVIDER_load(libctx, "default");
    if (deflt == NULL)
        goto done;

    if (pthread_create(&thread, NULL, competitor_main, &competitor) != 0)
        goto done;
    /* Enter the load only after the competitor's first visible step. */
    while (!atomic_load_explicit(
            &competitor.prepared, memory_order_acquire)
            && !atomic_load_explicit(
                &competitor.finished, memory_order_acquire))
        sleep_ms(1);
    if (!atomic_load_explicit(
            &competitor.prepared, memory_order_acquire)) {
        pthread_join(thread, NULL);
        fprintf(stderr, "%s: competitor failed before preparation\n", label);
        goto done;
    }
    sleep_ms(5);

    started = now_seconds();
    ed301v1_seed_error_sentinel();
    v1 = ed301v1_load_named(libctx, NULL, ED301V1_PKI_PROVIDER);
    elapsed = now_seconds() - started;
    first_queue_ok = ed301v1_queue_is_sentinel_only();
    pthread_join(thread, NULL);

    if (!atomic_load_explicit(
            &competitor.completed, memory_order_acquire)) {
        fprintf(stderr, "%s: competitor failed to finish\n", label);
        goto done;
    }
    ed301v1_seed_error_sentinel();
    retry = ed301v1_load_named(libctx, NULL, ED301V1_PKI_PROVIDER);
    printf("%s: unsafe first load %s in %.3f s; explicit retry %s\n",
        label, v1 == NULL ? "blocked" : "unexpectedly succeeded",
        elapsed, retry != NULL ? "succeeded" : "blocked");
    lane_ok = v1 == NULL && first_queue_ok && elapsed <= 1.0
        && ed301v1_queue_is_sentinel_only()
        && (conflicting
            ? retry == NULL
            : retry != NULL && ed301v1_registry_is_exact());
    if (!lane_ok)
        fprintf(stderr, "%s: host preflight/retry policy mismatch\n", label);

done:
    if (retry != NULL)
        OSSL_PROVIDER_unload(retry);
    if (v1 != NULL)
        OSSL_PROVIDER_unload(v1);
    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return lane_ok;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";
    const char *module_dir = argc > 2 ? argv[2] : NULL;

    ED301V1_REQUIRE_RUNTIME_BINDING();
    if (strcmp(mode, "exact-fast") == 0) {
        ED301V1_CHECK(run_lane("exact-fast (50 ms)", module_dir, 50, 0),
            "explicit retry succeeds after a fast exact competitor");
    } else if (strcmp(mode, "exact-stalled") == 0) {
        ED301V1_CHECK(run_lane("exact-stalled (3 s)", module_dir, 3000, 0),
            "first load does not spin; explicit retry succeeds later");
    } else if (strcmp(mode, "conflict") == 0) {
        ED301V1_CHECK(run_lane("conflict", module_dir, 0, 1),
            "persistent foreign conflict remains blocked without waiting");
    } else {
        fprintf(stderr, "usage: val03_retry "
            "exact-fast|exact-stalled|conflict [module-dir]\n");
        return 2;
    }
    return ed301v1_summary("val03_retry");
}
