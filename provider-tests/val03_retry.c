/*
 * VAL-03: the fixed registration-retry ceiling under delayed competing
 * registration.
 *
 * Validation finding (established with these reproducers on both the
 * sealed Experiment-2 module and the repaired module): OpenSSL's
 * core_obj_create is duplicate-tolerant and OBJ_add_sigid accepts an
 * exact re-registration, so a provider load that observes a
 * half-finished EXACT competing registration simply completes the
 * registration itself.  The wait-for-exact retry ceiling is therefore
 * never load-bearing for a delayed-but-successful competitor; it only
 * bounds how long a load facing a PERSISTENT foreign conflict spins
 * before failing closed, which is intentional.  The repair replaces the
 * scheduler-dependent bound (1024 bare sched_yield calls) with a
 * wall-clock bound (~0.5 s) so the fail-closed timing is deterministic.
 *
 * Lanes (each in its own process; the registry is process-global):
 *   exact-fast     competitor completes after 50 ms -> load succeeds
 *   exact-stalled  competitor stalls 3 s before its sigid step -> load
 *                  still succeeds (self-completion, ceiling not
 *                  load-bearing)
 *   conflict       competitor holds a foreign binding -> load fails
 *                  closed; the elapsed wall time is recorded to document
 *                  the bounded wait
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
        nid = OBJ_create(D00_OID_TEXT, "ED301D00-VAL03-COLLIDER",
            "ED301D00 val03 conflict object");
        atomic_store_explicit(
            &competitor->prepared, nid != NID_undef, memory_order_release);
        atomic_store_explicit(&competitor->completed,
            nid != NID_undef, memory_order_release);
        atomic_store_explicit(
            &competitor->finished, 1, memory_order_release);
        return NULL;
    }
    nid = OBJ_create(D00_OID_TEXT, D00_ALG, D00_ALG);
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
    long delay_milliseconds, int conflicting, int expect_success)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    COMPETITOR competitor = {
        delay_milliseconds, conflicting,
        ATOMIC_VAR_INIT(0), ATOMIC_VAR_INIT(0), ATOMIC_VAR_INIT(0)
    };
    pthread_t thread;
    double started;
    double elapsed;
    int load_ok;
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
    d00_seed_error_sentinel();
    draft = OSSL_PROVIDER_load(libctx, D00_PROVIDER);
    elapsed = now_seconds() - started;
    load_ok = draft != NULL;
    pthread_join(thread, NULL);

    if (!atomic_load_explicit(
            &competitor.completed, memory_order_acquire)) {
        fprintf(stderr, "%s: competitor failed to finish\n", label);
        goto done;
    }
    printf("%s: load %s in %.3f s\n", label,
        load_ok ? "succeeded" : "failed closed", elapsed);
    lane_ok = load_ok == expect_success
        && (expect_success
            ? d00_queue_is_sentinel_only() && d00_registry_is_exact()
            : d00_queue_has_sentinel_and_registration_error())
        && (expect_success || elapsed <= 1.5);
    if (!lane_ok)
        fprintf(stderr, "%s: expected %s\n", label,
            expect_success ? "success" : "fail-closed");

done:
    if (draft != NULL)
        OSSL_PROVIDER_unload(draft);
    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return lane_ok;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";
    const char *module_dir = argc > 2 ? argv[2] : NULL;

    D00_REQUIRE_RUNTIME_BINDING();
    if (strcmp(mode, "exact-fast") == 0) {
        D00_CHECK(run_lane("exact-fast (50 ms)", module_dir, 50, 0, 1),
            "load succeeds beside a competitor that completes quickly");
    } else if (strcmp(mode, "exact-stalled") == 0) {
        D00_CHECK(run_lane("exact-stalled (3 s)", module_dir, 3000, 0, 1),
            "load self-completes beside a stalled exact competitor "
            "(retry ceiling not load-bearing)");
    } else if (strcmp(mode, "conflict") == 0) {
        D00_CHECK(run_lane("conflict", module_dir, 0, 1, 0),
            "persistent foreign conflict fails closed within the "
            "bounded wait");
    } else {
        fprintf(stderr, "usage: val03_retry "
            "exact-fast|exact-stalled|conflict [module-dir]\n");
        return 2;
    }
    return d00_summary("val03_retry");
}
