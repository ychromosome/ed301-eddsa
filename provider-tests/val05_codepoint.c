#define _POSIX_C_SOURCE 200809L

/*
 * VAL-05: private-use SignatureScheme code-point collision.
 *
 * This test is deliberately split into a parent and an argument-driven child.
 * The parent does not load a provider, create an OpenSSL object, or construct
 * an SSL context.  It re-executes the child once for each provider order, so
 * every order starts with a fresh process and a pristine object registry.
 *
 * A child records the two provider declarations, the exact TLS outcome,
 * decrypted alerts, the complete error queue, the ordered CertificateVerify
 * observations, and both application-data directions.  A failed handshake is
 * accepted only for the documented no-suitable-signature/handshake-failure
 * path, with no CertificateVerify and no application data.  A completed
 * handshake must verify the peer certificate, contain exactly one wire
 * CertificateVerify with 0xfe84 (one outgoing and one incoming observation),
 * and carry application data in both directions.  Any other failure is a test
 * failure; an arbitrary error is never promoted to PASS.
 *
 * The public OpenSSL 3.5.7 and 4.0.1 sources do not specify a duplicate
 * provider TLS-SIGALG policy.  The test therefore accepts only the two
 * observable, safe outcomes above and compares the complete result line from
 * both fresh-process orders.  The fixture's collider currently advertises
 * ED25519 without owning an ED25519 keymgmt; OpenSSL may consequently filter
 * that declaration before it enters libssl's usable list.  That limitation is
 * reported explicitly in the child record instead of being hidden.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "harness_common.h"
#include "vectors.h"

#define D00_TLS_SIGALG_CODE_POINT 0xfe84U
#define D00_TLS_SIGALG_IANA_NAME "ed301_eddsa_draft00_test"
#define SSL3_MT_CERTIFICATE_VERIFY_LOCAL 15
#define D00_CV_WIRE_BYTES ((size_t)(8 + D00_SIG_BYTES))

#define VAL05_MAX_CV_EVENTS 16
#define VAL05_MAX_ALERTS 16
#define VAL05_ERROR_BYTES 1024
#define VAL05_RESULT_BYTES 4096
#define VAL05_CHILD_OUTPUT_BYTES 65536
#define VAL05_CHILD_WAIT_ROUNDS 3000
#define VAL05_CHILD_SLEEP_NS 10000000L

typedef struct cv_event_st {
    char endpoint;             /* 'S' or 'C' */
    int outgoing;              /* 1 = written, 0 = read */
    unsigned int scheme;
    size_t signature_length;
    size_t wire_length;
} CV_EVENT;

typedef struct alert_event_st {
    char endpoint;
    int outgoing;
    unsigned int level;
    unsigned int description;
} ALERT_EVENT;

typedef struct trace_st {
    CV_EVENT cv[VAL05_MAX_CV_EVENTS];
    size_t cv_count;
    ALERT_EVENT alerts[VAL05_MAX_ALERTS];
    size_t alert_count;
    int overflow;
    int application_record_count;
} TRACE;

typedef struct callback_arg_st {
    char endpoint;
    TRACE *trace;
} CALLBACK_ARG;

typedef struct capability_capture_st {
    int entries;
    unsigned int code_point;
    char iana_name[96];
    char sigalg_name[96];
    char keytype[96];
} CAPABILITY_CAPTURE;

typedef struct tls_outcome_st {
    int provider_load_ok;
    int capability_ok;
    int setup_ok;
    int handshake_ok;
    long verify_result;
    int peer_certificate;
    int client_result;
    int server_result;
    int client_error;
    int server_error;
    int handshake_rounds;
    int application_client_to_server;
    int application_server_to_client;
    int collider_keymgmt_owned;
    char setup_stage[64];
    char error_text[VAL05_ERROR_BYTES];
    TRACE trace;
    CAPABILITY_CAPTURE draft_capability;
    CAPABILITY_CAPTURE collider_capability;
} TLS_OUTCOME;

typedef struct child_capture_st {
    char output[VAL05_CHILD_OUTPUT_BYTES];
    size_t output_length;
    char result_line[VAL05_RESULT_BYTES];
    pid_t pid;
    int result_found;
    int wait_failed;
    int timed_out;
    int signaled;
    int output_truncated;
    int exit_code;
} CHILD_CAPTURE;

static void append_text(char *destination, size_t capacity,
    const char *text)
{
    size_t used;
    size_t available;
    size_t length;

    if (destination == NULL || capacity == 0 || text == NULL)
        return;
    used = strlen(destination);
    if (used >= capacity - 1)
        return;
    available = capacity - used - 1;
    length = strlen(text);
    if (length > available)
        length = available;
    memcpy(destination + used, text, length);
    destination[used + length] = '\0';
}

static void record_error_queue(char *destination, size_t capacity)
{
    unsigned long code;
    char line[256];

    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, line, sizeof(line));
        if (destination[0] != '\0')
            append_text(destination, capacity, " | ");
        append_text(destination, capacity, line);
    }
}

static int copy_param_string(
    const OSSL_PARAM params[], const char *name,
    char *destination, size_t capacity)
{
    const OSSL_PARAM *parameter = OSSL_PARAM_locate_const(params, name);
    int length;

    if (parameter == NULL || parameter->data_type != OSSL_PARAM_UTF8_STRING
            || parameter->data == NULL || capacity == 0)
        return 0;
    length = snprintf(destination, capacity, "%s",
        (const char *)parameter->data);
    return length >= 0 && (size_t)length < capacity;
}

static int capability_callback(
    const OSSL_PARAM params[], void *argument)
{
    CAPABILITY_CAPTURE *capture = argument;
    const OSSL_PARAM *parameter;

    if (capture == NULL || params == NULL)
        return 0;
    capture->entries++;
    parameter = OSSL_PARAM_locate_const(params,
        OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT);
    if (parameter == NULL
            || !OSSL_PARAM_get_uint(parameter, &capture->code_point)
            || !copy_param_string(params,
                OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,
                capture->iana_name, sizeof(capture->iana_name))
            || !copy_param_string(params,
                OSSL_CAPABILITY_TLS_SIGALG_NAME,
                capture->sigalg_name, sizeof(capture->sigalg_name))
            || !copy_param_string(params,
                OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE,
                capture->keytype, sizeof(capture->keytype)))
        return 0;
    return 1;
}

static int inspect_capability(
    OSSL_PROVIDER *provider, CAPABILITY_CAPTURE *capture)
{
    if (provider == NULL || capture == NULL)
        return 0;
    memset(capture, 0, sizeof(*capture));
    if (OSSL_PROVIDER_get_capabilities(provider, "TLS-SIGALG",
            capability_callback, capture) != 1)
        return 0;
    return capture->entries == 1
        && capture->code_point == D00_TLS_SIGALG_CODE_POINT;
}

static int capability_matches(
    const CAPABILITY_CAPTURE *capture, const char *iana_name,
    const char *sigalg_name, const char *keytype)
{
    return capture != NULL && capture->entries == 1
        && capture->code_point == D00_TLS_SIGALG_CODE_POINT
        && strcmp(capture->iana_name, iana_name) == 0
        && strcmp(capture->sigalg_name, sigalg_name) == 0
        && strcmp(capture->keytype, keytype) == 0;
}

static void msg_callback(
    int write_p,
    int version,
    int content_type,
    const void *buffer,
    size_t length,
    SSL *ssl,
    void *argument)
{
    CALLBACK_ARG *callback = argument;
    TRACE *trace;
    const unsigned char *bytes = buffer;

    (void)version;
    (void)ssl;
    if (callback == NULL || (trace = callback->trace) == NULL
            || bytes == NULL)
        return;
    if (content_type == SSL3_RT_HANDSHAKE && length >= 8
            && bytes[0] == SSL3_MT_CERTIFICATE_VERIFY_LOCAL) {
        CV_EVENT *event;

        if (trace->cv_count >= VAL05_MAX_CV_EVENTS) {
            trace->overflow = 1;
            return;
        }
        event = &trace->cv[trace->cv_count++];
        event->endpoint = callback->endpoint;
        event->outgoing = write_p != 0;
        event->scheme = ((unsigned int)bytes[4] << 8) | bytes[5];
        event->signature_length = ((size_t)bytes[6] << 8) | bytes[7];
        event->wire_length = length;
    } else if (content_type == SSL3_RT_ALERT && length >= 2) {
        ALERT_EVENT *event;

        if (trace->alert_count >= VAL05_MAX_ALERTS) {
            trace->overflow = 1;
            return;
        }
        event = &trace->alerts[trace->alert_count++];
        event->endpoint = callback->endpoint;
        event->outgoing = write_p != 0;
        event->level = bytes[0];
        event->description = bytes[1];
    } else if (content_type == SSL3_RT_APPLICATION_DATA) {
        trace->application_record_count++;
    }
}

static X509 *make_self_signed(EVP_PKEY *pkey, const char *common_name)
{
    X509 *certificate = X509_new();
    X509_NAME *name = X509_NAME_new();
    int ok = 0;

    if (certificate == NULL || name == NULL)
        goto done;
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)common_name, -1, -1, 0) != 1
            || X509_set_version(certificate, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(certificate), 11) != 1
            || X509_gmtime_adj(X509_getm_notBefore(certificate), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) == NULL
            || X509_set_subject_name(certificate, name) != 1
            || X509_set_issuer_name(certificate, name) != 1
            || X509_set_pubkey(certificate, pkey) != 1
            || X509_sign(certificate, pkey, NULL) <= 0)
        goto done;
    ok = 1;

done:
    X509_NAME_free(name);
    if (!ok) {
        X509_free(certificate);
        return NULL;
    }
    return certificate;
}

static int pump_handshake(SSL *server, SSL *client, TLS_OUTCOME *outcome)
{
    int round;

    for (round = 0; round < 200; round++) {
        int client_result = SSL_do_handshake(client);
        int client_error = client_result == 1 ? SSL_ERROR_NONE
            : SSL_get_error(client, client_result);
        int server_result = SSL_do_handshake(server);
        int server_error = server_result == 1 ? SSL_ERROR_NONE
            : SSL_get_error(server, server_result);

        outcome->client_result = client_result;
        outcome->server_result = server_result;
        outcome->client_error = client_error;
        outcome->server_error = server_error;
        outcome->handshake_rounds = round + 1;
        if (client_result == 1 && server_result == 1)
            return 1;
        if (client_error != SSL_ERROR_NONE
                && client_error != SSL_ERROR_WANT_READ
                && client_error != SSL_ERROR_WANT_WRITE)
            return 0;
        if (server_error != SSL_ERROR_NONE
                && server_error != SSL_ERROR_WANT_READ
                && server_error != SSL_ERROR_WANT_WRITE)
            return 0;
    }
    return 0;
}

static int exchange_application_data(
    SSL *sender, SSL *receiver, unsigned char sent, unsigned char *received)
{
    int write_done = 0;
    int read_done = 0;
    int round;

    for (round = 0; round < 64; round++) {
        if (!write_done) {
            int result = SSL_write(sender, &sent, 1);
            int error = result == 1 ? SSL_ERROR_NONE
                : SSL_get_error(sender, result);

            if (result == 1)
                write_done = 1;
            else if (error != SSL_ERROR_WANT_READ
                    && error != SSL_ERROR_WANT_WRITE)
                return 0;
        }
        if (!read_done) {
            unsigned char byte = 0;
            int result = SSL_read(receiver, &byte, 1);
            int error = result == 1 ? SSL_ERROR_NONE
                : SSL_get_error(receiver, result);

            if (result == 1) {
                if (received != NULL)
                    *received = byte;
                read_done = 1;
            } else if (error != SSL_ERROR_WANT_READ
                    && error != SSL_ERROR_WANT_WRITE)
                return 0;
        }
        if (write_done && read_done)
            return 1;
    }
    return 0;
}

static int exact_certificate_verify(const TRACE *trace)
{
    const CV_EVENT *first;
    const CV_EVENT *second;

    if (trace == NULL || trace->overflow || trace->cv_count != 2)
        return 0;
    first = &trace->cv[0];
    second = &trace->cv[1];
    return first->endpoint == 'S' && first->outgoing
        && first->scheme == D00_TLS_SIGALG_CODE_POINT
        && first->signature_length == D00_SIG_BYTES
        && first->wire_length == D00_CV_WIRE_BYTES
        && second->endpoint == 'C' && !second->outgoing
        && second->scheme == D00_TLS_SIGALG_CODE_POINT
        && second->signature_length == D00_SIG_BYTES
        && second->wire_length == D00_CV_WIRE_BYTES;
}

static int fatal_collision_alert(const TRACE *trace)
{
    size_t index;

    if (trace == NULL || trace->overflow)
        return 0;
    for (index = 0; index < trace->alert_count; index++) {
        const ALERT_EVENT *event = &trace->alerts[index];

        if (event->level == SSL3_AL_FATAL) {
            if (event->description == SSL_AD_HANDSHAKE_FAILURE
                    || event->description == SSL_AD_ILLEGAL_PARAMETER)
                return 1;
        }
    }
    return 0;
}

static int exact_collision_alert_trace(const TRACE *trace)
{
    size_t index;

    if (trace == NULL || trace->overflow || trace->alert_count == 0)
        return 0;
    for (index = 0; index < trace->alert_count; index++) {
        const ALERT_EVENT *event = &trace->alerts[index];

        if (event->level != SSL3_AL_FATAL
                || (event->description != SSL_AD_HANDSHAKE_FAILURE
                    && event->description != SSL_AD_ILLEGAL_PARAMETER))
            return 0;
    }
    return 1;
}

static int error_mentions_signature(const char *error_text)
{
    return error_text != NULL
        && (strstr(error_text, "signature") != NULL
            || strstr(error_text, "sigalg") != NULL
            || strstr(error_text, "SignatureScheme") != NULL);
}

static int collision_rejected_cleanly(const TLS_OUTCOME *outcome)
{
    return outcome != NULL && !outcome->handshake_ok
        && outcome->trace.cv_count == 0
        && outcome->trace.application_record_count == 0
        && !outcome->application_client_to_server
        && !outcome->application_server_to_client
        && exact_collision_alert_trace(&outcome->trace)
        && error_mentions_signature(outcome->error_text);
}

static int outcome_is_accepted(const TLS_OUTCOME *outcome)
{
    const int completed = outcome != NULL && outcome->handshake_ok;
    const int completed_ok = completed
        && outcome->verify_result == X509_V_OK
        && outcome->peer_certificate
        && exact_certificate_verify(&outcome->trace)
        && outcome->application_client_to_server
        && outcome->application_server_to_client
        && outcome->trace.alert_count == 0
        && outcome->error_text[0] == '\0';

    if (outcome == NULL || !outcome->provider_load_ok
            || !outcome->capability_ok || !outcome->setup_ok)
        return 0;
    if (completed)
        return completed_ok;
    return collision_rejected_cleanly(outcome);
}

static void print_alerts(const TLS_OUTCOME *outcome)
{
    size_t index;

    for (index = 0; index < outcome->trace.alert_count; index++) {
        const ALERT_EVENT *event = &outcome->trace.alerts[index];

        printf("VAL05_ALERT endpoint=%c direction=%s level=%u "
            "description=%u\n", event->endpoint,
            event->outgoing ? "out" : "in", event->level,
            event->description);
    }
}

static void format_alert_fingerprint(
    const TRACE *trace, char *destination, size_t capacity)
{
    size_t index;

    if (trace == NULL || trace->alert_count == 0) {
        snprintf(destination, capacity, "-");
        return;
    }
    destination[0] = '\0';
    for (index = 0; index < trace->alert_count; index++) {
        const ALERT_EVENT *event = &trace->alerts[index];
        char component[64];

        snprintf(component, sizeof(component), "%c/%c/%u/%u;",
            event->endpoint, event->outgoing ? '>' : '<', event->level,
            event->description);
        append_text(destination, capacity, component);
    }
}

static void print_outcome(const char *order, const TLS_OUTCOME *outcome)
{
    char alert_fingerprint[1024];
    const char *errors = outcome->error_text[0] == '\0'
        ? "-" : outcome->error_text;

    format_alert_fingerprint(&outcome->trace, alert_fingerprint,
        sizeof(alert_fingerprint));
    printf("VAL05_PID pid=%ld\n", (long)getpid());
    printf("VAL05_ORDER %s\n", order);
    printf("VAL05_CAPABILITY draft=%d collider=%d draft_iana=%s "
        "draft_name=%s draft_keytype=%s collider_iana=%s "
        "collider_name=%s collider_keytype=%s draft_cp=0x%04x "
        "collider_cp=0x%04x collider_keymgmt_owned=%d\n",
        capability_matches(&outcome->draft_capability,
            D00_TLS_SIGALG_IANA_NAME, D00_ALG, D00_ALG),
        capability_matches(&outcome->collider_capability,
            "collider_fe84", "ED25519", "ED25519"),
        outcome->draft_capability.iana_name,
        outcome->draft_capability.sigalg_name,
        outcome->draft_capability.keytype,
        outcome->collider_capability.iana_name,
        outcome->collider_capability.sigalg_name,
        outcome->collider_capability.keytype,
        outcome->draft_capability.code_point,
        outcome->collider_capability.code_point,
        outcome->collider_keymgmt_owned);
    print_alerts(outcome);
    printf("VAL05_RESULT accepted=%d provider_load=%d capability=%d "
        "setup=%d setup_stage=%s handshake=%d verify=%ld peer_certificate=%d "
        "client_result=%d client_error=%d server_result=%d server_error=%d "
        "rounds=%d cv_count=%zu cv_exact=%d app_c2s=%d app_s2c=%d "
        "app_records=%d alert_count=%zu fatal_collision_alert=%d "
        "collider_keymgmt_owned=%d alert_trace=%s error=%s\n",
        outcome_is_accepted(outcome), outcome->provider_load_ok,
        outcome->capability_ok, outcome->setup_ok,
        outcome->setup_stage[0] == '\0' ? "none" : outcome->setup_stage,
        outcome->handshake_ok, outcome->verify_result,
        outcome->peer_certificate, outcome->client_result,
        outcome->client_error, outcome->server_result,
        outcome->server_error, outcome->handshake_rounds,
        outcome->trace.cv_count, exact_certificate_verify(&outcome->trace),
        outcome->application_client_to_server,
        outcome->application_server_to_client,
        outcome->trace.application_record_count,
        outcome->trace.alert_count, fatal_collision_alert(&outcome->trace),
        outcome->collider_keymgmt_owned, alert_fingerprint, errors);
    if (!outcome->collider_keymgmt_owned)
        printf("VAL05_LIMITATION collider_fe84 declares ED25519 but does "
            "not own an ED25519 keymgmt; libssl may filter that capability\n");
}

static int child_main(const char *order)
{
    const int draft_first = strcmp(order, "draft-then-collider") == 0;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *draft_provider = NULL;
    OSSL_PROVIDER *collider_provider = NULL;
    EVP_KEYMGMT *collider_keymgmt = NULL;
    const OSSL_PROVIDER *keymgmt_owner = NULL;
    EVP_PKEY *server_key = NULL;
    X509 *server_certificate = NULL;
    SSL_CTX *server_context = NULL;
    SSL_CTX *client_context = NULL;
    SSL *server = NULL;
    SSL *client = NULL;
    BIO *server_bio = NULL;
    BIO *client_bio = NULL;
    X509_STORE *client_store;
    CALLBACK_ARG server_callback = { 'S', NULL };
    CALLBACK_ARG client_callback = { 'C', NULL };
    TLS_OUTCOME outcome;
    unsigned char received;
    int accepted;

    memset(&outcome, 0, sizeof(outcome));
    outcome.verify_result = -1;
    if (!draft_first && strcmp(order, "collider-then-draft") != 0) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "bad-order");
        print_outcome(order, &outcome);
        D00_CHECK(0, "unknown child order '%s'", order);
        return d00_summary("val05_codepoint-child");
    }

    ERR_clear_error();
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (draft_first) {
        draft_provider = OSSL_PROVIDER_load(NULL, D00_PROVIDER);
        collider_provider = OSSL_PROVIDER_load(NULL, "collider_fe84");
    } else {
        collider_provider = OSSL_PROVIDER_load(NULL, "collider_fe84");
        draft_provider = OSSL_PROVIDER_load(NULL, D00_PROVIDER);
    }
    outcome.provider_load_ok = default_provider != NULL
        && draft_provider != NULL && collider_provider != NULL;
    if (!outcome.provider_load_ok) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "provider-load");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }

    outcome.capability_ok = inspect_capability(
            draft_provider, &outcome.draft_capability)
        && inspect_capability(collider_provider, &outcome.collider_capability)
        && capability_matches(&outcome.draft_capability,
            D00_TLS_SIGALG_IANA_NAME, D00_ALG, D00_ALG)
        && capability_matches(&outcome.collider_capability,
            "collider_fe84", "ED25519", "ED25519");
    if (!outcome.capability_ok) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "capability-inspection");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }

    collider_keymgmt = EVP_KEYMGMT_fetch(NULL, "ED25519", NULL);
    keymgmt_owner = collider_keymgmt == NULL
        ? NULL : EVP_KEYMGMT_get0_provider(collider_keymgmt);
    if (keymgmt_owner != NULL) {
        const char *owner_name = OSSL_PROVIDER_get0_name(keymgmt_owner);

        outcome.collider_keymgmt_owned = owner_name != NULL
            && strcmp(owner_name, "collider_fe84") == 0;
    }
    EVP_KEYMGMT_free(collider_keymgmt);
    collider_keymgmt = NULL;
    ERR_clear_error();

    server_key = d00_keygen(NULL);
    if (server_key == NULL) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "draft-keygen");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }
    server_certificate = make_self_signed(server_key,
        "val05 collision server");
    if (server_certificate == NULL) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "certificate");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }

    server_context = SSL_CTX_new(TLS_server_method());
    client_context = SSL_CTX_new(TLS_client_method());
    if (server_context == NULL || client_context == NULL) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "ssl-context");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }
    client_store = SSL_CTX_get_cert_store(client_context);
    if (SSL_CTX_use_certificate(server_context, server_certificate) != 1
            || SSL_CTX_use_PrivateKey(server_context, server_key) != 1
            || SSL_CTX_check_private_key(server_context) != 1
            || client_store == NULL
            || X509_STORE_add_cert(client_store, server_certificate) != 1) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "credentials");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }
    SSL_CTX_set_verify(client_context, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_set_min_proto_version(server_context, TLS1_3_VERSION) != 1
            || SSL_CTX_set_max_proto_version(server_context,
                TLS1_3_VERSION) != 1
            || SSL_CTX_set_min_proto_version(client_context,
                TLS1_3_VERSION) != 1
            || SSL_CTX_set_max_proto_version(client_context,
                TLS1_3_VERSION) != 1
            || SSL_CTX_set1_groups_list(server_context, "X25519") != 1
            || SSL_CTX_set1_groups_list(client_context, "X25519") != 1) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "protocol-or-groups");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }

    memset(&outcome.trace, 0, sizeof(outcome.trace));
    server_callback.trace = &outcome.trace;
    client_callback.trace = &outcome.trace;
    SSL_CTX_set_msg_callback(server_context, msg_callback);
    SSL_CTX_set_msg_callback_arg(server_context, &server_callback);
    SSL_CTX_set_msg_callback(client_context, msg_callback);
    SSL_CTX_set_msg_callback_arg(client_context, &client_callback);
    server = SSL_new(server_context);
    client = SSL_new(client_context);
    if (server == NULL || client == NULL
            || BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) != 1) {
        snprintf(outcome.setup_stage, sizeof(outcome.setup_stage),
            "ssl-objects");
        record_error_queue(outcome.error_text, sizeof(outcome.error_text));
        goto done;
    }
    SSL_set_bio(server, server_bio, server_bio);
    SSL_set_bio(client, client_bio, client_bio);
    server_bio = NULL;
    client_bio = NULL;
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);
    outcome.setup_ok = 1;
    ERR_clear_error();
    outcome.handshake_ok = pump_handshake(server, client, &outcome);
    outcome.verify_result = SSL_get_verify_result(client);
    if (outcome.handshake_ok) {
        X509 *peer = SSL_get1_peer_certificate(client);

        outcome.peer_certificate = peer != NULL;
        X509_free(peer);
        received = 0;
        if (exchange_application_data(client, server, 0xa5, &received)
                && received == 0xa5)
            outcome.application_client_to_server = 1;
        received = 0;
        if (exchange_application_data(server, client, 0x5a, &received)
                && received == 0x5a)
            outcome.application_server_to_client = 1;
    }
    record_error_queue(outcome.error_text, sizeof(outcome.error_text));

done:
    accepted = outcome_is_accepted(&outcome);
    print_outcome(order, &outcome);
    D00_CHECK(accepted,
        "%s: only a fully verified handshake or an explicit clean "
        "signature collision rejection is acceptable", order);
    SSL_free(server);
    SSL_free(client);
    BIO_free(server_bio);
    BIO_free(client_bio);
    SSL_CTX_free(server_context);
    SSL_CTX_free(client_context);
    X509_free(server_certificate);
    EVP_PKEY_free(server_key);
    EVP_KEYMGMT_free(collider_keymgmt);
    if (collider_provider != NULL)
        OSSL_PROVIDER_unload(collider_provider);
    if (draft_provider != NULL)
        OSSL_PROVIDER_unload(draft_provider);
    if (default_provider != NULL)
        OSSL_PROVIDER_unload(default_provider);
    return d00_summary("val05_codepoint-child");
}

static int read_child_output(int fd, CHILD_CAPTURE *capture)
{
    unsigned char extra;
    ssize_t count;

    if (lseek(fd, 0, SEEK_SET) < 0)
        return 0;
    capture->output_length = 0;
    while (capture->output_length + 1 < sizeof(capture->output)) {
        count = read(fd, capture->output + capture->output_length,
            sizeof(capture->output) - capture->output_length - 1);
        if (count == 0)
            break;
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        capture->output_length += (size_t)count;
    }
    capture->output[capture->output_length] = '\0';
    if (capture->output_length + 1 >= sizeof(capture->output)) {
        do {
            count = read(fd, &extra, sizeof(extra));
        } while (count < 0 && errno == EINTR);
        capture->output_truncated = count > 0;
    }
    return 1;
}

static int extract_result_line(CHILD_CAPTURE *capture)
{
    const char *prefix = "VAL05_RESULT ";
    const char *start = strstr(capture->output, prefix);
    const char *end;
    size_t length;

    if (start == NULL)
        return 0;
    end = strchr(start, '\n');
    if (end == NULL)
        end = start + strlen(start);
    length = (size_t)(end - start);
    if (length >= sizeof(capture->result_line))
        return 0;
    memcpy(capture->result_line, start, length);
    capture->result_line[length] = '\0';
    capture->result_found = 1;
    return strstr(capture->result_line, "accepted=1") != NULL;
}

static int spawn_child(
    const char *self, const char *order, CHILD_CAPTURE *capture)
{
    char temporary_path[] = "/tmp/ed301-val05-XXXXXX";
    struct timespec pause_time = { 0, VAL05_CHILD_SLEEP_NS };
    int fd = mkstemp(temporary_path);
    pid_t child;
    int status = 0;
    int round;

    memset(capture, 0, sizeof(*capture));
    if (fd < 0)
        return 0;
    child = fork();
    if (child == 0) {
        if (dup2(fd, STDOUT_FILENO) < 0
                || dup2(fd, STDERR_FILENO) < 0)
            _exit(126);
        close(fd);
        execl(self, self, "--child", order, (char *)NULL);
        _exit(127);
    }
    close(fd);
    capture->pid = child;
    if (child < 0) {
        unlink(temporary_path);
        return 0;
    }
    for (round = 0; round < VAL05_CHILD_WAIT_ROUNDS; round++) {
        pid_t waited = waitpid(child, &status, WNOHANG);

        if (waited == child)
            break;
        if (waited < 0) {
            if (errno == EINTR)
                continue;
            capture->wait_failed = 1;
            (void)kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR)
                continue;
            break;
        }
        (void)nanosleep(&pause_time, NULL);
    }
    if (round == VAL05_CHILD_WAIT_ROUNDS && !capture->wait_failed) {
        capture->timed_out = 1;
        (void)kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR)
            continue;
    }
    fd = open(temporary_path, O_RDONLY);
    if (fd >= 0) {
        if (!read_child_output(fd, capture))
            capture->wait_failed = 1;
        close(fd);
    } else {
        capture->wait_failed = 1;
    }
    unlink(temporary_path);
    if (WIFEXITED(status))
        capture->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        capture->signaled = 1;
    (void)extract_result_line(capture);
    return !capture->wait_failed;
}

static int child_result_accepted(const CHILD_CAPTURE *capture)
{
    return capture != NULL && capture->result_found
        && strstr(capture->result_line, "accepted=1") != NULL;
}

static void print_child_capture(const char *order, const CHILD_CAPTURE *capture)
{
    printf("--- %s child capture (pid=%ld exit=%d timeout=%d signal=%d "
        "truncated=%d) ---\n", order, (long)capture->pid,
        capture->exit_code, capture->timed_out, capture->signaled,
        capture->output_truncated);
    fputs(capture->output, stdout);
    if (capture->output_length == 0
            || capture->output[capture->output_length - 1] != '\n')
        fputc('\n', stdout);
}

int main(int argc, char **argv)
{
    char self[PATH_MAX];
    ssize_t self_length;
    CHILD_CAPTURE draft_first;
    CHILD_CAPTURE collider_first;
    int draft_spawned;
    int collider_spawned;

    D00_REQUIRE_RUNTIME_BINDING();
    D00_REQUIRE_TLS_RUNTIME_BINDING();
    if (argc == 3 && strcmp(argv[1], "--child") == 0)
        return child_main(argv[2]);
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--child order]\n", argv[0]);
        return 2;
    }
    self_length = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (self_length <= 0 || (size_t)self_length >= sizeof(self)) {
        fprintf(stderr, "cannot resolve executable path for fresh child\n");
        return 2;
    }
    self[self_length] = '\0';

    draft_spawned = spawn_child(self, "draft-then-collider", &draft_first);
    collider_spawned = spawn_child(self, "collider-then-draft", &collider_first);
    print_child_capture("draft-then-collider", &draft_first);
    print_child_capture("collider-then-draft", &collider_first);
    D00_CHECK(draft_spawned && child_result_accepted(&draft_first)
            && draft_first.exit_code == 0 && !draft_first.timed_out
            && !draft_first.signaled && !draft_first.output_truncated,
        "draft-then-collider fresh child exits zero with accepted result");
    D00_CHECK(collider_spawned && child_result_accepted(&collider_first)
            && collider_first.exit_code == 0 && !collider_first.timed_out
            && !collider_first.signaled && !collider_first.output_truncated,
        "collider-then-draft fresh child exits zero with accepted result");
    D00_CHECK(child_result_accepted(&draft_first)
            && child_result_accepted(&collider_first)
            && strcmp(draft_first.result_line,
                collider_first.result_line) == 0,
        "provider load orders have identical outcome/error/alert result");
    return d00_summary("val05_codepoint");
}
