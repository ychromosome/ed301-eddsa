/*
 * Fresh-process parallel FIRST-load races after F2/F4.
 *
 * The earlier parallel-load harness had already registered the ephemeral
 * OID serially before its threads started, so the initial
 * FREE -> OBJ_create -> OBJ_add_sigid transition was never raced.  This
 * harness re-executes itself so that EVERY raced load happens in a fresh
 * process whose object registry has never seen the identifier: the child
 * starts its threads, holds them at a pthread barrier and releases them
 * into simultaneous first loads.
 *
 * Child modes:
 *   same-dso       all threads load the same module file
 *   separate-copy  threads alternate between the module and a physically
 *                  separate byte-identical copy in per-thread lib contexts;
 *                  there is deliberately no provider-local registry lock
 *   conflict       the child pre-registers a conflicting binding for the
 *                  ephemeral OID, then races first loads: every load must
 *                  be blocked by the host preflight
 *
 * The child prints the exact registry state (NID and sigid mapping) before
 * and after the race so the preserved logs document the registry
 * transition.
 */

#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/objects.h>

#include "harness_common.h"

#define FRESH_THREADS 8
#define FRESH_REPEATS 10

typedef struct fresh_gate_st {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int ready;
    int start;
    int abort;
} FRESH_GATE;

typedef struct fresh_worker_st {
    FRESH_GATE *gate;
    const char *module_dir;
    int expect_success;
    int failed;
} FRESH_WORKER;

static int fresh_gate_wait(FRESH_GATE *gate)
{
    int proceed;

    pthread_mutex_lock(&gate->mutex);
    gate->ready++;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->start && !gate->abort)
        pthread_cond_wait(&gate->condition, &gate->mutex);
    proceed = !gate->abort;
    pthread_mutex_unlock(&gate->mutex);
    return proceed;
}

static void print_registry_state(const char *label)
{
    int nid = OBJ_txt2nid(D00_OID_TEXT);
    int signature_nid = NID_undef;
    int have_sigid = nid != NID_undef
        && OBJ_find_sigid_by_algs(&signature_nid, NID_undef, nid) == 1;

    printf("registry[%s]: nid=%d sigid=%s->%d\n", label, nid,
        have_sigid ? "self" : "absent", have_sigid ? signature_nid : -1);
    ERR_clear_error();
}

static void *fresh_worker_main(void *argument)
{
    FRESH_WORKER *worker = argument;
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = NULL;
    EVP_SIGNATURE *fetched = NULL;

    const int setup_ok = libctx != NULL
        && OSSL_PROVIDER_set_default_search_path(
            libctx, worker->module_dir) == 1;

    if (!fresh_gate_wait(worker->gate))
        goto done;
    if (!setup_ok) {
        worker->failed = 1;
        goto done;
    }

    deflt = OSSL_PROVIDER_load(libctx, "default");
    d00_seed_error_sentinel();
    draft = d00_load_named(libctx, NULL, D00_PROVIDER);
    if (worker->expect_success) {
        if (deflt == NULL || draft == NULL
                || !d00_queue_is_sentinel_only()) {
            worker->failed = 1;
            goto done;
        }
        fetched = EVP_SIGNATURE_fetch(libctx, D00_ALG, D00_PROP);
        if (fetched == NULL)
            worker->failed = 1;
    } else {
        if (draft != NULL || !d00_queue_is_sentinel_only())
            worker->failed = 1;
    }

done:
    ERR_clear_error();
    EVP_SIGNATURE_free(fetched);
    if (draft != NULL)
        OSSL_PROVIDER_unload(draft);
    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return NULL;
}

static int child_main(const char *mode, const char *dir_a,
    const char *dir_b)
{
    /* main() performs the binding check before the re-exec dispatch. */
    FRESH_GATE gate = {
        PTHREAD_MUTEX_INITIALIZER,
        PTHREAD_COND_INITIALIZER,
        0,
        0,
        0
    };
    pthread_t threads[FRESH_THREADS];
    FRESH_WORKER workers[FRESH_THREADS];
    int expect_success = 1;
    int index;
    int created = 0;
    int failed = 0;

    if (strcmp(mode, "conflict") == 0) {
        /*
         * Conflicting pre-registration in the fresh process: the OID is
         * bound to a foreign name before any provider load.
         */
        OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");

        if (deflt == NULL
                || OBJ_create(D00_OID_TEXT, "ED301D00-FRESH-COLLIDER",
                    "ED301D00 fresh conflict object") == NID_undef) {
            fprintf(stderr, "conflict preparation failed\n");
            OSSL_PROVIDER_unload(deflt);
            return 2;
        }
        OSSL_PROVIDER_unload(deflt);
        expect_success = 0;
    }

    print_registry_state("before-race");

    for (index = 0; index < FRESH_THREADS; index++) {
        workers[index].gate = &gate;
        workers[index].module_dir =
            (strcmp(mode, "separate-copy") == 0 && index % 2 == 1)
                ? dir_b : dir_a;
        workers[index].expect_success = expect_success;
        workers[index].failed = 0;
        if (pthread_create(&threads[index], NULL, fresh_worker_main,
                &workers[index]) != 0) {
            failed = 1;
            break;
        }
        created++;
    }
    pthread_mutex_lock(&gate.mutex);
    if (!failed) {
        while (gate.ready < created)
            pthread_cond_wait(&gate.condition, &gate.mutex);
        gate.start = 1;
    } else {
        gate.abort = 1;
    }
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);

    for (index = 0; index < created; index++) {
        pthread_join(threads[index], NULL);
        if (workers[index].failed)
            failed = 1;
    }
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    if (created != FRESH_THREADS)
        failed = 1;

    print_registry_state("after-race");

    if (expect_success && !d00_registry_is_exact()) {
        fprintf(stderr, "%s: final registry is not exact\n", mode);
        failed = 1;
    }

    if (failed) {
        fprintf(stderr, "%s: raced first load failed\n", mode);
        return 1;
    }
    printf("%s: %d simultaneous fresh first loads ok\n", mode,
        FRESH_THREADS);
    return 0;
}

static int spawn_child(const char *self, const char *mode,
    const char *dir_a, const char *dir_b)
{
    pid_t pid = fork();
    int status = -1;

    if (pid == 0) {
        execl(self, self, "child", mode, dir_a, dir_b, (char *)NULL);
        _exit(127);
    }
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int copy_file(const char *source, const char *destination)
{
    FILE *in = fopen(source, "rb");
    FILE *out = in == NULL ? NULL : fopen(destination, "wb");
    unsigned char buffer[65536];
    size_t chunk;
    int ok = in != NULL && out != NULL;

    while (ok && (chunk = fread(buffer, 1, sizeof(buffer), in)) > 0)
        ok = fwrite(buffer, 1, chunk, out) == chunk;
    if (in != NULL)
        fclose(in);
    if (out != NULL)
        ok = fclose(out) == 0 && ok;
    return ok;
}

int main(int argc, char **argv)
{
    D00_REQUIRE_RUNTIME_BINDING();
    const char *modules = getenv("OPENSSL_MODULES");
    char self[4096];
    char dir_b[4200];
    char module_a[4300];
    char module_b[4300];
    ssize_t self_length;
    int repeat;

    if (argc >= 5 && strcmp(argv[1], "child") == 0)
        return child_main(argv[2], argv[3], argv[4]);

    if (modules == NULL) {
        fprintf(stderr, "OPENSSL_MODULES must point at the module dir\n");
        return 2;
    }
    self_length = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (self_length <= 0)
        return 2;
    self[self_length] = '\0';

    /* Physically separate byte-identical module copy. */
    snprintf(dir_b, sizeof(dir_b), "%s/fresh-copy", modules);
    snprintf(module_a, sizeof(module_a), "%s/" D00_PROVIDER ".so",
        modules);
    snprintf(module_b, sizeof(module_b), "%s/" D00_PROVIDER ".so", dir_b);
    (void)mkdir(dir_b, 0755);
    D00_CHECK(copy_file(module_a, module_b),
        "separate module copy created");

    for (repeat = 0; repeat < FRESH_REPEATS; repeat++) {
        D00_CHECK(spawn_child(self, "same-dso", modules, dir_b) == 0,
            "fresh-process same-DSO first-load race (round %d)", repeat);
        D00_CHECK(spawn_child(self, "separate-copy", modules, dir_b) == 0,
            "fresh-process separate-copy first-load race (round %d)",
            repeat);
    }
    D00_CHECK(spawn_child(self, "conflict", modules, dir_b) == 0,
        "host preflight blocks a conflicting fresh-process registry");

    return d00_summary("provider_load_fresh");
}
