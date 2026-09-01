/*
 * Acceptance section 5 (TLS 1.3, explicitly ephemeral test profile),
 * repaired for FBL-09 (ordered CertificateVerify observation), FBL-14
 * (deployment-like leaf chains) and VAL-05 (negative-control reasons).
 *
 * PKI model: one self-signed CA (CA:TRUE, keyCertSign) is the ONLY trust
 * anchor.  Server and client present CA:FALSE leaf certificates with
 * digitalSignature key usage, the appropriate extended key usage and DNS
 * subject alternative names; the client validates the server name.
 *
 * Observation model: every decrypted TLS 1.3 handshake message seen by
 * SSL_CTX_set_msg_callback is recorded as an ordered event carrying
 * endpoint, read/write direction, handshake type, SignatureScheme (for
 * CertificateVerify) and length.  The harness asserts the exact expected
 * incoming and outgoing CertificateVerify sequence for server
 * authentication and mutual TLS, and proves with synthetic missing,
 * reordered, wrong-first/correct-last and one-direction-only sequences
 * that the checker fails them.
 *
 * Independent CertificateVerify lane: the explicit message callbacks also
 * retain every complete outgoing handshake message in one monotonic raw
 * handshake stream, with sender-indexed message records.  For each outgoing
 * CertificateVerify the stream prefix is snapshotted before that message,
 * the exact 76-byte signature vector is copied, and TLS 1.3 TBS is rebuilt as
 * 64 spaces || the role context || NUL || the negotiated ciphersuite hash.
 * HRR is rejected (this lane intentionally has no transcript rewrite).  The
 * resulting TBS is checked through a fresh Ed301 provider EVP public-key
 * operation, not through libssl's CertificateVerify verifier.  Only SHA-256
 * hashes of raw transcript prefixes, TBS and signatures are logged.
 */

#include <openssl/encoder.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "harness_common.h"
#include "vectors.h"

#define ED301V1_TLS_SIGALG_CODE_POINT 0xfe84
#define SSL3_MT_SERVER_HELLO_LOCAL 2
#define SSL3_MT_CERTIFICATE_VERIFY_LOCAL 15
#define MAX_EVENTS 64
#define MAX_HANDSHAKE_MESSAGES 128
#define MAX_HANDSHAKE_TRACE_BYTES ((size_t)(256 * 1024))
#define TLS13_TBS_PREFIX_BYTES ((size_t)(64 + 33 + 1))
#define TLS13_HRR_RANDOM_BYTES ((size_t)32)
#define ED301V1_CV_WIRE_BYTES ((size_t)(8 + ED301V1_SIG_BYTES))

#define TLS13_SERVER_CV_CONTEXT "TLS 1.3, server CertificateVerify"
#define TLS13_CLIENT_CV_CONTEXT "TLS 1.3, client CertificateVerify"

#define SERVER_NAME "server.v1.test.example"
#define CLIENT_NAME "client.v1.test.example"

static EVP_PKEY *reload_private_key_through_pem(EVP_PKEY *source)
{
    OSSL_ENCODER_CTX *encoder = source == NULL ? NULL
        : OSSL_ENCODER_CTX_new_for_pkey(source, EVP_PKEY_KEYPAIR, "PEM",
            "PrivateKeyInfo", ED301V1_PKI_PROP);
    unsigned char *pem = NULL;
    size_t pem_length = 0;
    BIO *bio = NULL;
    EVP_PKEY *loaded = NULL;

    if (encoder != NULL
            && OSSL_ENCODER_to_data(encoder, &pem, &pem_length) == 1
            && pem != NULL && pem_length <= INT_MAX)
        bio = BIO_new_mem_buf(pem, (int)pem_length);
    if (bio != NULL)
        loaded = PEM_read_bio_PrivateKey_ex(
            bio, NULL, NULL, NULL, NULL, NULL);
    BIO_free(bio);
    OPENSSL_clear_free(pem, pem_length);
    OSSL_ENCODER_CTX_free(encoder);
    return loaded;
}

typedef struct cv_event_st {
    char endpoint;        /* 'S' or 'C': which SSL_CTX observed it */
    int outgoing;         /* 1 = written by that endpoint, 0 = read */
    int message_type;     /* TLS handshake message type */
    unsigned int scheme;  /* SignatureScheme for CertificateVerify */
    size_t signature_length;
    size_t length;        /* handshake message length */
} CV_EVENT;

/*
 * One complete outgoing handshake message.  The message bytes live in the
 * one monotonic transcript below; these records partition that byte stream by
 * sender without maintaining a second mutable copy of handshake material.
 */
typedef struct handshake_message_st {
    char sender;
    unsigned int message_type;
    size_t transcript_offset;
    size_t length;
} HANDSHAKE_MESSAGE;

/*
 * The outgoing CertificateVerify as observed before libssl consumes it.  The
 * raw signature is copied from the exact TLS vector; TBS and hashes are filled
 * only after the negotiated ciphersuite is known.  No plaintext handshake
 * bytes are printed.
 */
typedef struct cv_capture_st {
    char sender;
    unsigned int scheme;
    int wire_valid;
    size_t wire_length;
    size_t transcript_length_before;
    size_t message_count_before;
    size_t sender_bytes_before;
    size_t sender_message_count_before;
    unsigned char signature[ED301V1_SIG_BYTES];
    unsigned char tbs[TLS13_TBS_PREFIX_BYTES + EVP_MAX_MD_SIZE];
    size_t tbs_length;
    unsigned char negotiated_transcript_hash[EVP_MAX_MD_SIZE];
    size_t negotiated_transcript_hash_length;
    unsigned char transcript_sha256[SHA256_DIGEST_LENGTH];
    unsigned char sender_transcript_sha256[SHA256_DIGEST_LENGTH];
    unsigned char tbs_sha256[SHA256_DIGEST_LENGTH];
    unsigned char signature_sha256[SHA256_DIGEST_LENGTH];
    int provider_verified;
} CV_CAPTURE;

typedef struct global_trace_st {
    CV_EVENT events[MAX_EVENTS];
    size_t count;
    int overflow;
    unsigned char transcript[MAX_HANDSHAKE_TRACE_BYTES];
    size_t transcript_length;
    HANDSHAKE_MESSAGE messages[MAX_HANDSHAKE_MESSAGES];
    size_t message_count;
    size_t sender_bytes[2];
    size_t sender_message_counts[2];
    CV_CAPTURE captures[2];
    size_t capture_count;
    int wire_overflow;
    int hrr_seen;
} GLOBAL_TRACE;

typedef struct capture_view_st {
    char endpoint;
    GLOBAL_TRACE *trace;
} CAPTURE;

static int sender_index(char endpoint)
{
    return endpoint == 'S' ? 0 : endpoint == 'C' ? 1 : -1;
}

static int is_tls13_hrr(const unsigned char *bytes, size_t length)
{
    static const unsigned char hrr_random[TLS13_HRR_RANDOM_BYTES] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
        0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
        0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };

    /* Handshake header (4) + legacy_version (2) precedes random. */
    return length >= 6 + TLS13_HRR_RANDOM_BYTES
        && bytes[0] == SSL3_MT_SERVER_HELLO_LOCAL
        && memcmp(bytes + 6, hrr_random, TLS13_HRR_RANDOM_BYTES) == 0;
}

static void append_outgoing_handshake(
    GLOBAL_TRACE *trace,
    char sender,
    const unsigned char *bytes,
    size_t length)
{
    HANDSHAKE_MESSAGE *message;
    int index = sender_index(sender);

    if (trace == NULL || bytes == NULL || index < 0
            || trace->transcript_length > MAX_HANDSHAKE_TRACE_BYTES
            || length > MAX_HANDSHAKE_TRACE_BYTES - trace->transcript_length
            || trace->message_count >= MAX_HANDSHAKE_MESSAGES) {
        if (trace != NULL)
            trace->wire_overflow = 1;
        return;
    }

    message = &trace->messages[trace->message_count++];
    message->sender = sender;
    message->message_type = bytes[0];
    message->transcript_offset = trace->transcript_length;
    message->length = length;
    memcpy(trace->transcript + trace->transcript_length, bytes, length);
    trace->transcript_length += length;
    trace->sender_bytes[index] += length;
    trace->sender_message_counts[index]++;
}

static void capture_outgoing_cv(
    GLOBAL_TRACE *trace,
    char sender,
    const unsigned char *bytes,
    size_t length,
    unsigned int scheme,
    size_t signature_length)
{
    CV_CAPTURE *capture;
    int index = sender_index(sender);
    int valid;

    if (trace == NULL || bytes == NULL || index < 0
            || trace->capture_count >= sizeof(trace->captures)
            / sizeof(trace->captures[0])) {
        if (trace != NULL)
            trace->wire_overflow = 1;
        return;
    }

    valid = length == ED301V1_CV_WIRE_BYTES
        && length >= ED301V1_CV_WIRE_BYTES
        && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 80
        && bytes[6] == 0 && bytes[7] == (unsigned char)ED301V1_SIG_BYTES
        && signature_length == ED301V1_SIG_BYTES;

    capture = &trace->captures[trace->capture_count++];
    memset(capture, 0, sizeof(*capture));
    capture->sender = sender;
    capture->scheme = scheme;
    capture->wire_length = length;
    capture->wire_valid = valid;
    capture->transcript_length_before = trace->transcript_length;
    capture->message_count_before = trace->message_count;
    capture->sender_bytes_before = trace->sender_bytes[index];
    capture->sender_message_count_before = trace->sender_message_counts[index];
    if (valid)
        memcpy(capture->signature, bytes + 8, ED301V1_SIG_BYTES);
    else
        trace->wire_overflow = 1;
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
    CAPTURE *capture = argument;
    const unsigned char *bytes = buffer;
    unsigned int scheme = 0;
    size_t signature_length = 0;

    (void)version;
    (void)ssl;
    if (capture == NULL || capture->trace == NULL || bytes == NULL
            || content_type != SSL3_RT_HANDSHAKE || length < 4)
        return;
    if ((((size_t)bytes[1] << 16) | ((size_t)bytes[2] << 8)
                | (size_t)bytes[3])
            != length - 4)
        capture->trace->wire_overflow = 1;
    if (bytes[0] == SSL3_MT_SERVER_HELLO_LOCAL
            && is_tls13_hrr(bytes, length))
        capture->trace->hrr_seen = 1;
    if (bytes[0] == SSL3_MT_CERTIFICATE_VERIFY_LOCAL) {
        CV_EVENT *event;

        if (capture->trace->count >= MAX_EVENTS) {
            capture->trace->overflow = 1;
            return;
        }
        event = &capture->trace->events[capture->trace->count++];

        event->endpoint = capture->endpoint;
        event->outgoing = write_p;
        event->message_type = bytes[0];
        if (length >= 6)
            scheme = ((unsigned int)bytes[4] << 8) | bytes[5];
        if (length >= 8)
            signature_length = ((size_t)bytes[6] << 8) | bytes[7];
        event->scheme = scheme;
        event->signature_length = signature_length;
        event->length = length;
        if (write_p)
            capture_outgoing_cv(capture->trace, capture->endpoint, bytes,
                length, scheme, signature_length);
    }
    if (write_p)
        append_outgoing_handshake(capture->trace, capture->endpoint, bytes,
            length);
}

/*
 * Exact-sequence checker for CertificateVerify events.  The expected
 * sequence lists (endpoint, outgoing, scheme) triples in observation
 * order; any missing, extra, reordered or wrong-scheme event fails.
 */
typedef struct cv_expect_st {
    char endpoint;
    int outgoing;
    unsigned int scheme;
} CV_EXPECT;

static int cv_sequence_matches(
    const CV_EVENT *events,
    size_t event_count,
    const CV_EXPECT *expected,
    size_t expected_count)
{
    size_t index;

    if (event_count != expected_count)
        return 0;
    for (index = 0; index < expected_count; index++) {
        if (events[index].endpoint != expected[index].endpoint
                || events[index].outgoing != expected[index].outgoing
                || events[index].scheme != expected[index].scheme
                || events[index].message_type
                    != SSL3_MT_CERTIFICATE_VERIFY_LOCAL
                || events[index].signature_length != ED301V1_SIG_BYTES
                || events[index].length != ED301V1_CV_WIRE_BYTES)
            return 0;
    }
    return 1;
}

/* ---------------------------------------------------------------- PKI */

static int add_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *extension;
    int ok;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer != NULL ? issuer : cert, cert, NULL, NULL,
        0);
    extension = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (extension == NULL)
        return 0;
    ok = X509_add_ext(cert, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return ok;
}

static X509_NAME *make_name(const char *common_name)
{
    X509_NAME *name = X509_NAME_new();

    if (name == NULL
            || X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                (const unsigned char *)"Ed301-EdDSA-v1 TLS (test-only)",
                -1, -1, 0) != 1
            || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char *)common_name, -1, -1, 0) != 1) {
        X509_NAME_free(name);
        return NULL;
    }
    return name;
}

/*
 * Issue one certificate.  is_ca selects the CA profile (CA:TRUE,
 * keyCertSign) versus the leaf profile (CA:FALSE, digitalSignature, the
 * given EKU and a DNS SAN).
 */
static X509 *issue_cert(
    const char *subject_cn,
    const char *dns_name,
    const char *extended_key_usage,
    X509 *issuer_cert,
    EVP_PKEY *subject_key,
    EVP_PKEY *issuer_key,
    int is_ca,
    long serial)
{
    X509 *cert = X509_new();
    X509_NAME *subject = make_name(subject_cn);
    int ok = 0;

    if (cert == NULL || subject == NULL)
        goto done;
    if (X509_set_version(cert, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) != 1
            || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 3600) == NULL
            || X509_set_subject_name(cert, subject) != 1
            || X509_set_issuer_name(cert, issuer_cert != NULL
                ? X509_get_subject_name(issuer_cert) : subject) != 1
            || X509_set_pubkey(cert, subject_key) != 1)
        goto done;
    if (is_ca) {
        if (!add_ext(cert, issuer_cert, NID_basic_constraints,
                "critical,CA:TRUE")
                || !add_ext(cert, issuer_cert, NID_key_usage,
                    "critical,keyCertSign,cRLSign"))
            goto done;
    } else {
        char san[128];

        snprintf(san, sizeof(san), "DNS:%s", dns_name);
        if (!add_ext(cert, issuer_cert, NID_basic_constraints,
                "critical,CA:FALSE")
                || !add_ext(cert, issuer_cert, NID_key_usage,
                    "critical,digitalSignature")
                || !add_ext(cert, issuer_cert, NID_ext_key_usage,
                    extended_key_usage)
                || !add_ext(cert, issuer_cert, NID_subject_alt_name, san))
            goto done;
    }
    if (X509_sign(cert, issuer_key, NULL) <= 0)
        goto done;
    ok = 1;

done:
    X509_NAME_free(subject);
    if (!ok) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

/* ---------------------------------------------------------------- TLS */

static int pump_handshake(SSL *server, SSL *client)
{
    int rounds;

    for (rounds = 0; rounds < 200; rounds++) {
        int client_result = SSL_do_handshake(client);
        int client_error = client_result == 1 ? SSL_ERROR_NONE
            : SSL_get_error(client, client_result);
        int server_result = SSL_do_handshake(server);
        int server_error = server_result == 1 ? SSL_ERROR_NONE
            : SSL_get_error(server, server_result);

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

typedef struct tls_options_st {
    int mutual;
    int force_tls12;
    const char *client_sigalgs;
    const char *expected_hostname; /* NULL: use SERVER_NAME */
} TLS_OPTIONS;

typedef struct tls_outcome_st {
    int handshake_ok;
    long verify_result;       /* client's X509 chain result */
    int peer_cert_present;
    int client_peer_matches_server;
    int server_peer_matches_client;
    int group_x25519;
    int cv_trace_ok;
    int cv_provider_ok;
    int no_hrr;
    char handshake_digest_name[32];
    GLOBAL_TRACE trace;
    unsigned char application_byte;
    char error_reason[256];   /* first error-stack reason on failure */
} TLS_OUTCOME;

static int hash_sha256(
    const unsigned char *bytes,
    size_t length,
    unsigned char digest[SHA256_DIGEST_LENGTH])
{
    unsigned int digest_length = 0;

    return EVP_Digest(bytes, length, digest, &digest_length, EVP_sha256(),
        NULL) == 1 && digest_length == SHA256_DIGEST_LENGTH;
}

static int trace_prefix_is_well_formed(
    const GLOBAL_TRACE *trace,
    const CV_CAPTURE *capture);

static int hash_sender_prefix_sha256(
    const GLOBAL_TRACE *trace,
    const CV_CAPTURE *capture,
    unsigned char digest[SHA256_DIGEST_LENGTH])
{
    EVP_MD_CTX *context = NULL;
    unsigned int digest_length = 0;
    size_t index;
    int ok = 0;

    if (trace == NULL || capture == NULL
            || !trace_prefix_is_well_formed(trace, capture))
        return 0;
    context = EVP_MD_CTX_new();
    if (context == NULL
            || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto done;
    for (index = 0; index < capture->message_count_before; index++) {
        const HANDSHAKE_MESSAGE *message = &trace->messages[index];

        if (message->sender == capture->sender
                && EVP_DigestUpdate(context,
                    trace->transcript + message->transcript_offset,
                    message->length) != 1)
            goto done;
    }
    ok = EVP_DigestFinal_ex(context, digest, &digest_length) == 1
        && digest_length == SHA256_DIGEST_LENGTH;

done:
    EVP_MD_CTX_free(context);
    return ok;
}

static int trace_prefix_is_well_formed(
    const GLOBAL_TRACE *trace,
    const CV_CAPTURE *capture)
{
    size_t index;
    size_t offset = 0;
    size_t sender_bytes = 0;
    size_t sender_message_count = 0;
    int sender;

    if (trace == NULL || capture == NULL
            || capture->message_count_before > trace->message_count
            || capture->transcript_length_before > trace->transcript_length)
        return 0;
    sender = sender_index(capture->sender);
    if (sender < 0)
        return 0;
    for (index = 0; index < capture->message_count_before; index++) {
        const HANDSHAKE_MESSAGE *message = &trace->messages[index];

        if (message->transcript_offset != offset
                || offset > trace->transcript_length
                || message->length > trace->transcript_length - offset)
            return 0;
        offset += message->length;
        if (message->sender == capture->sender)
            sender_bytes += message->length;
        if (message->sender == capture->sender)
            sender_message_count++;
    }
    return offset == capture->transcript_length_before
        && sender_bytes == capture->sender_bytes_before
        && sender_message_count == capture->sender_message_count_before;
}

static int build_cv_tbs(
    const GLOBAL_TRACE *trace,
    CV_CAPTURE *capture,
    const EVP_MD *handshake_digest)
{
    const char *context;
    size_t context_length;
    int digest_size;
    unsigned int digest_length = 0;

    if (trace == NULL || capture == NULL || handshake_digest == NULL)
        return 0;
    context = capture->sender == 'S'
        ? TLS13_SERVER_CV_CONTEXT : TLS13_CLIENT_CV_CONTEXT;
    context_length = strlen(context);
    digest_size = EVP_MD_get_size(handshake_digest);
    if (context_length != 33 || digest_size <= 0
            || digest_size > EVP_MAX_MD_SIZE
            || !trace_prefix_is_well_formed(trace, capture)
            || EVP_Digest(trace->transcript,
                capture->transcript_length_before,
                capture->negotiated_transcript_hash, &digest_length,
                handshake_digest, NULL) != 1
            || digest_length != (unsigned int)digest_size)
        return 0;

    memset(capture->tbs, 0x20, 64);
    memcpy(capture->tbs + 64, context, context_length);
    capture->tbs[64 + context_length] = 0;
    memcpy(capture->tbs + TLS13_TBS_PREFIX_BYTES,
        capture->negotiated_transcript_hash, digest_length);
    capture->negotiated_transcript_hash_length = digest_length;
    capture->tbs_length = TLS13_TBS_PREFIX_BYTES + digest_length;
    return capture->tbs_length <= sizeof(capture->tbs)
        && hash_sha256(trace->transcript,
            capture->transcript_length_before, capture->transcript_sha256)
        && hash_sender_prefix_sha256(trace, capture,
            capture->sender_transcript_sha256)
        && hash_sha256(capture->tbs, capture->tbs_length,
            capture->tbs_sha256)
        && hash_sha256(capture->signature, ED301V1_SIG_BYTES,
            capture->signature_sha256);
}

/*
 * Verify the captured TBS through a fresh provider public-key object.  This
 * deliberately does not call SSL's CertificateVerify verifier and does not
 * use SSL_get_verify_result; only the provider EVP one-shot raw operation is
 * used for this check.
 */
static int provider_verify_cv(X509 *certificate, const CV_CAPTURE *capture)
{
    EVP_PKEY *certificate_key = NULL;
    unsigned char public_key[ED301V1_PUB_BYTES];
    size_t public_key_length = sizeof(public_key);
    int ok = 0;

    if (certificate == NULL || capture == NULL || !capture->wire_valid
            || capture->tbs_length == 0)
        return 0;
    certificate_key = X509_get_pubkey(certificate);
    if (certificate_key != NULL
            && EVP_PKEY_get_octet_string_param(certificate_key,
                OSSL_PKEY_PARAM_PUB_KEY, public_key, sizeof(public_key),
                &public_key_length) == 1
            && public_key_length == sizeof(public_key))
        ok = ed301v1_triple_accepts(NULL, public_key, public_key_length,
            capture->tbs, capture->tbs_length, capture->signature,
            ED301V1_SIG_BYTES);
    EVP_PKEY_free(certificate_key);
    return ok;
}

static void print_hash(FILE *stream, const unsigned char *digest, size_t length)
{
    size_t index;

    for (index = 0; index < length; index++)
        fprintf(stream, "%02x", (unsigned int)digest[index]);
}

static void log_cv_capture(
    const CV_CAPTURE *capture,
    size_t sequence,
    const char *digest_name)
{
    fprintf(stdout,
        "TLS13_CV sender=%c sequence=%zu scheme=0x%04x "
        "wire_bytes=%zu transcript_prefix_bytes=%zu sender_prefix_bytes=%zu "
        "sender_messages=%zu "
        "hash=%s transcript_hash=",
        capture->sender, sequence, capture->scheme, capture->wire_length,
        capture->transcript_length_before, capture->sender_bytes_before,
        capture->sender_message_count_before,
        digest_name != NULL ? digest_name : "unknown");
    print_hash(stdout, capture->negotiated_transcript_hash,
        capture->negotiated_transcript_hash_length);
    fputs(" transcript_sha256=", stdout);
    print_hash(stdout, capture->transcript_sha256, SHA256_DIGEST_LENGTH);
    fputs(" sender_transcript_sha256=", stdout);
    print_hash(stdout, capture->sender_transcript_sha256,
        SHA256_DIGEST_LENGTH);
    fputs(" tbs_sha256=", stdout);
    print_hash(stdout, capture->tbs_sha256, SHA256_DIGEST_LENGTH);
    fputs(" signature_sha256=", stdout);
    print_hash(stdout, capture->signature_sha256, SHA256_DIGEST_LENGTH);
    fprintf(stdout, " provider_verify=%d\n", capture->provider_verified);
}

static int finalize_cv_trace(
    SSL *client,
    X509 *server_cert,
    X509 *client_cert,
    int mutual,
    TLS_OUTCOME *outcome)
{
    const SSL_CIPHER *cipher;
    const EVP_MD *handshake_digest;
    const char *digest_name;
    size_t expected_count = mutual ? 2 : 1;
    size_t index;
    int all_provider_verified = 1;

    if (outcome == NULL)
        return 0;
    outcome->no_hrr = !outcome->trace.hrr_seen;
    cipher = client == NULL ? NULL : SSL_get_current_cipher(client);
    handshake_digest = cipher == NULL
        ? NULL : SSL_CIPHER_get_handshake_digest(cipher);
    digest_name = handshake_digest == NULL
        ? NULL : EVP_MD_get0_name(handshake_digest);
    if (digest_name != NULL)
        snprintf(outcome->handshake_digest_name,
            sizeof(outcome->handshake_digest_name), "%s", digest_name);

    if (!outcome->no_hrr || outcome->trace.overflow
            || outcome->trace.wire_overflow
            || outcome->trace.capture_count != expected_count
            || handshake_digest == NULL)
        return 0;

    for (index = 0; index < outcome->trace.capture_count; index++) {
        CV_CAPTURE *capture = &outcome->trace.captures[index];
        X509 *certificate = capture->sender == 'S'
            ? server_cert : client_cert;

        if (!capture->wire_valid
                || capture->scheme != ED301V1_TLS_SIGALG_CODE_POINT
                || capture->sender != (index == 0 ? 'S' : 'C')
                || (index != 0
                    && capture->transcript_length_before
                        <= outcome->trace.captures[index - 1]
                            .transcript_length_before)
                || !build_cv_tbs(&outcome->trace, capture,
                    handshake_digest)) {
            all_provider_verified = 0;
            continue;
        }
        capture->provider_verified = provider_verify_cv(certificate, capture);
        if (!capture->provider_verified)
            all_provider_verified = 0;
        log_cv_capture(capture, index, digest_name);
    }
    outcome->cv_provider_ok = all_provider_verified;
    outcome->cv_trace_ok = all_provider_verified;
    return outcome->cv_trace_ok;
}

static void record_error_reason(TLS_OUTCOME *outcome)
{
    unsigned long code = ERR_peek_error();

    if (code != 0)
        ERR_error_string_n(code, outcome->error_reason,
            sizeof(outcome->error_reason));
}

static int run_tls(
    X509 *trust_anchor,
    X509 *server_cert,
    EVP_PKEY *server_key,
    X509 *client_cert,
    EVP_PKEY *client_key,
    const TLS_OPTIONS *options,
    TLS_OUTCOME *outcome)
{
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    SSL *server = NULL;
    SSL *client = NULL;
    BIO *server_bio = NULL;
    BIO *client_bio = NULL;
    X509_STORE *client_store;
    const char *stage = "context";
    CAPTURE client_capture = { 'C', &outcome->trace };
    CAPTURE server_capture = { 'S', &outcome->trace };
    int ok = 0;

    memset(outcome, 0, sizeof(*outcome));
    outcome->verify_result = -1;
    if (server_ctx == NULL || client_ctx == NULL)
        goto done;

    stage = "server credentials";
    if (SSL_CTX_use_certificate(server_ctx, server_cert) != 1
            || SSL_CTX_use_PrivateKey(server_ctx, server_key) != 1
            || SSL_CTX_check_private_key(server_ctx) != 1)
        goto done;

    stage = "client trust anchor";
    client_store = SSL_CTX_get_cert_store(client_ctx);
    if (client_store == NULL
            || X509_STORE_add_cert(client_store, trust_anchor) != 1)
        goto done;
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);

    stage = "mutual credentials";
    if (options->mutual) {
        X509_STORE *server_store = SSL_CTX_get_cert_store(server_ctx);

        if (client_cert == NULL || client_key == NULL
                || SSL_CTX_use_certificate(client_ctx, client_cert) != 1
                || SSL_CTX_use_PrivateKey(client_ctx, client_key) != 1
                || server_store == NULL
                || X509_STORE_add_cert(server_store, trust_anchor) != 1)
            goto done;
        SSL_CTX_set_verify(server_ctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

    stage = "protocol versions";
    if (options->force_tls12) {
        if (SSL_CTX_set_max_proto_version(server_ctx, TLS1_2_VERSION) != 1
                || SSL_CTX_set_max_proto_version(client_ctx,
                    TLS1_2_VERSION) != 1)
            goto done;
    } else {
        if (SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION) != 1
                || SSL_CTX_set_min_proto_version(client_ctx,
                    TLS1_3_VERSION) != 1
                || SSL_CTX_set_max_proto_version(server_ctx,
                    TLS1_3_VERSION) != 1
                || SSL_CTX_set_max_proto_version(client_ctx,
                    TLS1_3_VERSION) != 1)
            goto done;
    }

    stage = "groups";
    if (SSL_CTX_set1_groups_list(server_ctx, "X25519") != 1
            || SSL_CTX_set1_groups_list(client_ctx, "X25519") != 1)
        goto done;

    stage = "sigalgs";
    if (options->client_sigalgs != NULL
            && SSL_CTX_set1_sigalgs_list(client_ctx,
                options->client_sigalgs) != 1)
        goto done;

    SSL_CTX_set_msg_callback(client_ctx, msg_callback);
    SSL_CTX_set_msg_callback_arg(client_ctx, &client_capture);
    SSL_CTX_set_msg_callback(server_ctx, msg_callback);
    SSL_CTX_set_msg_callback_arg(server_ctx, &server_capture);

    stage = "ssl objects";
    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    if (server == NULL || client == NULL
            || BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) != 1)
        goto done;
    SSL_set_bio(server, server_bio, server_bio);
    SSL_set_bio(client, client_bio, client_bio);
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);

    stage = "hostname";
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    /* SSL_set1_host is deprecated in OpenSSL 4.0; the hostname under
     * test is always a DNS name here. */
    if (SSL_set1_dnsname(client,
            options->expected_hostname != NULL
                ? options->expected_hostname : SERVER_NAME) != 1)
        goto done;
#else
    if (SSL_set1_host(client,
            options->expected_hostname != NULL
                ? options->expected_hostname : SERVER_NAME) != 1)
        goto done;
#endif

    stage = NULL;
    ok = 1;
    outcome->handshake_ok = pump_handshake(server, client);
    outcome->verify_result = SSL_get_verify_result(client);
    outcome->no_hrr = !outcome->trace.hrr_seen;
    if (!outcome->handshake_ok)
        record_error_reason(outcome);
    if (outcome->handshake_ok) {
        X509 *server_peer = SSL_get1_peer_certificate(client);
        X509 *client_peer = options->mutual
            ? SSL_get1_peer_certificate(server) : NULL;

        outcome->peer_cert_present = server_peer != NULL;
        outcome->client_peer_matches_server = server_peer != NULL
            && X509_cmp(server_peer, server_cert) == 0;
        outcome->server_peer_matches_client = !options->mutual
            || (client_peer != NULL && client_cert != NULL
                && X509_cmp(client_peer, client_cert) == 0);
        finalize_cv_trace(client, server_peer, client_peer, options->mutual,
            outcome);
        X509_free(server_peer);
        X509_free(client_peer);
        outcome->group_x25519 =
            SSL_get_negotiated_group(client) == NID_X25519;

        {
            unsigned char byte = 0x42;
            unsigned char received = 0;

            if (SSL_write(client, &byte, 1) == 1
                    && SSL_read(server, &received, 1) == 1
                    && received == 0x42
                    && SSL_write(server, &received, 1) == 1
                    && SSL_read(client, &byte, 1) == 1)
                outcome->application_byte = byte;
        }
    }

done:
    if (!ok && stage != NULL) {
        fprintf(stderr, "run_tls setup failed at stage: %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    ERR_clear_error();
    return ok;
}

int main(void)
{
    ED301V1_REQUIRE_RUNTIME_BINDING();
    ED301V1_REQUIRE_TLS_RUNTIME_BINDING();
    ed301v1_property = ED301V1_TLS_PROP;
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *v1 =
        ed301v1_load_named(NULL, NULL, ED301V1_TLS_PROVIDER);
    OSSL_PROVIDER *pki =
        ed301v1_load_named(NULL, NULL, ED301V1_PKI_PROVIDER);
    EVP_PKEY *ca_key = ed301v1_keygen(NULL);
    EVP_PKEY *ca2_key = ed301v1_keygen(NULL);
    EVP_PKEY *server_source_key = ed301v1_keygen(NULL);
    EVP_PKEY *server_key = reload_private_key_through_pem(server_source_key);
    EVP_PKEY *client_key = ed301v1_keygen(NULL);
    X509 *ca_cert = NULL;
    X509 *ca2_cert = NULL;
    X509 *server_cert = NULL;
    X509 *client_cert = NULL;
    TLS_OPTIONS options;
    TLS_OUTCOME outcome;

    ED301V1_CHECK(deflt != NULL && v1 != NULL && pki != NULL,
        "TLS and PKI providers loaded");
    ED301V1_CHECK(ca_key != NULL && ca2_key != NULL && server_key != NULL
            && client_key != NULL && server_source_key != NULL
            && EVP_PKEY_eq(server_source_key, server_key) == 1
            && strcmp(OSSL_PROVIDER_get0_name(
                EVP_PKEY_get0_provider(server_key)),
                ED301V1_TLS_PROVIDER) == 0,
        "TLS keys; server private key reloaded through generic PEM decoding");
    EVP_PKEY_free(server_source_key);
    server_source_key = NULL;
    OSSL_PROVIDER_unload(pki);
    pki = NULL;
    if (ca_key == NULL || ca2_key == NULL || server_key == NULL
            || client_key == NULL)
        return ed301v1_summary("provider_tls");

    /* Deployment-like PKI (FBL-14): CA anchor, CA:FALSE leaves. */
    ca_cert = issue_cert("Ed301-EdDSA-v1 TLS test CA", NULL, NULL, NULL, ca_key,
        ca_key, 1, 1);
    ca2_cert = issue_cert("Ed301-EdDSA-v1 untrusted CA", NULL, NULL, NULL,
        ca2_key, ca2_key, 1, 2);
    ED301V1_CHECK(ca_cert != NULL && ca2_cert != NULL, "CA certificates");
    if (ca_cert == NULL || ca2_cert == NULL)
        return ed301v1_summary("provider_tls");
    server_cert = issue_cert("Ed301-EdDSA-v1 TLS server leaf", SERVER_NAME,
        "serverAuth", ca_cert, server_key, ca_key, 0, 3);
    client_cert = issue_cert("Ed301-EdDSA-v1 TLS client leaf", CLIENT_NAME,
        "clientAuth", ca_cert, client_key, ca_key, 0, 4);
    ED301V1_CHECK(server_cert != NULL && client_cert != NULL,
        "leaf certificates (CA:FALSE, digitalSignature, EKU, SAN)");
    if (server_cert == NULL || client_cert == NULL)
        return ed301v1_summary("provider_tls");

    {
        SSL_CTX *mismatch = SSL_CTX_new(TLS_server_method());
        int accepted = mismatch != NULL
            && SSL_CTX_use_certificate(mismatch, server_cert) == 1
            && SSL_CTX_use_PrivateKey(mismatch, ca2_key) == 1
            && SSL_CTX_check_private_key(mismatch) == 1;

        ED301V1_CHECK(!accepted,
            "SSL_CTX rejects a certificate/private-key mismatch");
        SSL_CTX_free(mismatch);
        ERR_clear_error();
    }

    /* Server authentication over X25519 with hostname validation. */
    memset(&options, 0, sizeof(options));
    ED301V1_CHECK(run_tls(ca_cert, server_cert, server_key, NULL, NULL,
            &options, &outcome) == 1,
        "TLS run executes");
    ED301V1_CHECK(outcome.handshake_ok, "TLS 1.3 handshake completes");
    ED301V1_CHECK(outcome.group_x25519, "X25519 key exchange negotiated");
    ED301V1_CHECK(outcome.peer_cert_present
            && outcome.client_peer_matches_server
            && outcome.verify_result == X509_V_OK,
        "leaf chain verified against the CA-only trust anchor "
        "(verify result %ld)", outcome.verify_result);
    ED301V1_CHECK(outcome.no_hrr && outcome.cv_trace_ok
            && outcome.cv_provider_ok
            && outcome.trace.capture_count == 1
            && outcome.handshake_digest_name[0] != '\0',
        "server CertificateVerify TBS/wire independently reconstructed and "
        "verified through the provider");
    ED301V1_CHECK(outcome.application_byte == 0x42, "application data flows");

    /*
     * FBL-09: exact expected CertificateVerify sequence.  The server
     * writes exactly one CertificateVerify with the ephemeral scheme and
     * the client reads exactly that one; no other CertificateVerify may
     * be observed in either direction.
     */
    {
        static const CV_EXPECT expected_server_auth[] = {
            { 'S', 1, ED301V1_TLS_SIGALG_CODE_POINT }, /* server writes CV */
            { 'C', 0, ED301V1_TLS_SIGALG_CODE_POINT }, /* client reads CV */
        };

        ED301V1_CHECK(!outcome.trace.overflow
                && cv_sequence_matches(outcome.trace.events,
                    outcome.trace.count,
                expected_server_auth, 2),
            "server-auth global CertificateVerify sequence exact "
            "(%zu events, overflow=%d)",
            outcome.trace.count, outcome.trace.overflow);
    }

    /* Mutual TLS: both CertificateVerify messages, exact sequence. */
    memset(&options, 0, sizeof(options));
    options.mutual = 1;
    ED301V1_CHECK(run_tls(ca_cert, server_cert, server_key, client_cert,
            client_key, &options, &outcome) == 1,
        "mutual TLS run executes");
    ED301V1_CHECK(outcome.handshake_ok, "mutual TLS 1.3 handshake completes");
    ED301V1_CHECK(outcome.verify_result == X509_V_OK,
        "mutual TLS chain verified");
    ED301V1_CHECK(outcome.client_peer_matches_server
            && outcome.server_peer_matches_client,
        "mutual TLS wire peer certificates match the independently "
        "verified server/client CertificateVerify keys");
    ED301V1_CHECK(outcome.no_hrr && outcome.cv_trace_ok
            && outcome.cv_provider_ok
            && outcome.trace.capture_count == 2
            && outcome.handshake_digest_name[0] != '\0'
            && outcome.trace.captures[0].sender == 'S'
            && outcome.trace.captures[1].sender == 'C',
        "mutual TLS server/client CertificateVerify TBS/wire independently "
        "reconstructed and verified through the provider");
    {
        static const CV_EXPECT expected_mutual[] = {
            { 'S', 1, ED301V1_TLS_SIGALG_CODE_POINT }, /* writes own CV    */
            { 'C', 0, ED301V1_TLS_SIGALG_CODE_POINT }, /* reads server CV  */
            { 'C', 1, ED301V1_TLS_SIGALG_CODE_POINT }, /* writes own CV    */
            { 'S', 0, ED301V1_TLS_SIGALG_CODE_POINT }, /* reads client CV  */
        };

        ED301V1_CHECK(!outcome.trace.overflow
                && cv_sequence_matches(outcome.trace.events,
                    outcome.trace.count, expected_mutual, 4),
            "mutual TLS global CertificateVerify sequence exact "
            "(%zu events, overflow=%d)",
            outcome.trace.count, outcome.trace.overflow);
    }

    /*
     * FBL-09 synthetic controls: the checker must fail missing,
     * reordered, wrong-first/correct-last and one-direction-only
     * sequences.
     */
    {
        static const CV_EXPECT expected[] = {
            { 'C', 0, ED301V1_TLS_SIGALG_CODE_POINT },
            { 'C', 1, ED301V1_TLS_SIGALG_CODE_POINT },
        };
        CV_EVENT synthetic[4];

        memset(synthetic, 0, sizeof(synthetic));
        ED301V1_CHECK(!cv_sequence_matches(synthetic, 0, expected, 2),
            "synthetic missing sequence fails");

        synthetic[0] = (CV_EVENT){ 'C', 1,
            SSL3_MT_CERTIFICATE_VERIFY_LOCAL,
            ED301V1_TLS_SIGALG_CODE_POINT, ED301V1_SIG_BYTES,
            ED301V1_CV_WIRE_BYTES };
        synthetic[1] = (CV_EVENT){ 'C', 0,
            SSL3_MT_CERTIFICATE_VERIFY_LOCAL,
            ED301V1_TLS_SIGALG_CODE_POINT, ED301V1_SIG_BYTES,
            ED301V1_CV_WIRE_BYTES };
        ED301V1_CHECK(!cv_sequence_matches(synthetic, 2, expected, 2),
            "synthetic reordered sequence fails");

        synthetic[0] = (CV_EVENT){ 'C', 0,
            SSL3_MT_CERTIFICATE_VERIFY_LOCAL, 0x0807,
            ED301V1_SIG_BYTES, ED301V1_CV_WIRE_BYTES };
        synthetic[1] = (CV_EVENT){ 'C', 1,
            SSL3_MT_CERTIFICATE_VERIFY_LOCAL,
            ED301V1_TLS_SIGALG_CODE_POINT, ED301V1_SIG_BYTES,
            ED301V1_CV_WIRE_BYTES };
        ED301V1_CHECK(!cv_sequence_matches(synthetic, 2, expected, 2),
            "synthetic wrong-first/correct-last sequence fails");

        synthetic[0] = (CV_EVENT){ 'C', 0,
            SSL3_MT_CERTIFICATE_VERIFY_LOCAL,
            ED301V1_TLS_SIGALG_CODE_POINT, ED301V1_SIG_BYTES,
            ED301V1_CV_WIRE_BYTES };
        ED301V1_CHECK(!cv_sequence_matches(synthetic, 1, expected, 2),
            "synthetic one-direction-only sequence fails");

        synthetic[1] = synthetic[0];
        synthetic[2] = synthetic[0];
        ED301V1_CHECK(!cv_sequence_matches(synthetic, 3, expected, 2),
            "synthetic duplicate/extra sequence fails");
    }

    /* FBL-14 negative controls, each with its expected reason. */
    {
        /* Wrong hostname. */
        memset(&options, 0, sizeof(options));
        options.expected_hostname = "wrong.v1.test.example";
        ED301V1_CHECK(run_tls(ca_cert, server_cert, server_key, NULL, NULL,
                &options, &outcome) == 1,
            "wrong-hostname run executes");
        ED301V1_CHECK(!outcome.handshake_ok
                && outcome.verify_result == X509_V_ERR_HOSTNAME_MISMATCH,
            "wrong hostname fails with HOSTNAME_MISMATCH (got %ld)",
            outcome.verify_result);

        /* Wrong EKU: server presents a clientAuth-only leaf. */
        {
            X509 *wrong_eku = issue_cert("Ed301-EdDSA-v1 wrong-EKU leaf",
                SERVER_NAME, "clientAuth", ca_cert, server_key, ca_key, 0,
                5);

            memset(&options, 0, sizeof(options));
            ED301V1_CHECK(wrong_eku != NULL
                    && run_tls(ca_cert, wrong_eku, server_key, NULL, NULL,
                        &options, &outcome) == 1,
                "wrong-EKU run executes");
            ED301V1_CHECK(!outcome.handshake_ok
                    && outcome.verify_result
                        == X509_V_ERR_INVALID_PURPOSE,
                "wrong EKU fails with INVALID_PURPOSE (got %ld)",
                outcome.verify_result);
            X509_free(wrong_eku);
        }

        /* Wrong CA flag: trust anchor is a CA:FALSE certificate. */
        {
            X509 *fake_ca = issue_cert("Ed301-EdDSA-v1 non-CA issuer",
                "issuer.v1.test.example", "serverAuth", NULL, ca2_key,
                ca2_key, 0, 6);
            X509 *bad_leaf = fake_ca == NULL ? NULL
                : issue_cert("Ed301-EdDSA-v1 leaf under non-CA", SERVER_NAME,
                    "serverAuth", fake_ca, server_key, ca2_key, 0, 7);

            memset(&options, 0, sizeof(options));
            ED301V1_CHECK(fake_ca != NULL && bad_leaf != NULL
                    && run_tls(fake_ca, bad_leaf, server_key, NULL, NULL,
                        &options, &outcome) == 1,
                "non-CA-issuer run executes");
            ED301V1_CHECK(!outcome.handshake_ok
                    && outcome.verify_result == X509_V_ERR_INVALID_CA,
                "CA:FALSE issuer fails with INVALID_CA (got %ld)",
                outcome.verify_result);
            X509_free(bad_leaf);
            X509_free(fake_ca);
        }

        /* Untrusted CA: leaf signed by a CA outside the trust store. */
        {
            X509 *foreign_leaf = issue_cert("Ed301-EdDSA-v1 foreign leaf",
                SERVER_NAME, "serverAuth", ca2_cert, server_key, ca2_key,
                0, 8);

            memset(&options, 0, sizeof(options));
            ED301V1_CHECK(foreign_leaf != NULL
                    && run_tls(ca_cert, foreign_leaf, server_key, NULL,
                        NULL, &options, &outcome) == 1,
                "untrusted-CA run executes");
            ED301V1_CHECK(!outcome.handshake_ok
                    && outcome.verify_result
                        == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                "untrusted CA fails with UNABLE_TO_GET_ISSUER_CERT_LOCALLY "
                "(got %ld)", outcome.verify_result);
            X509_free(foreign_leaf);
        }

        /* Corrupted certificate signature. */
        {
            X509 *corrupt = issue_cert("Ed301-EdDSA-v1 corrupt leaf",
                SERVER_NAME, "serverAuth", ca_cert, server_key, ca_key, 0,
                9);
            const ASN1_BIT_STRING *signature = NULL;
            const X509_ALGOR *algorithm = NULL;

            if (corrupt != NULL) {
                X509_get0_signature(&signature, &algorithm, corrupt);
                if (signature != NULL
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
                        && ASN1_STRING_get_length(signature) > 0)
#else
                        && ASN1_STRING_length(signature) > 0)
#endif
                    ((unsigned char *)ASN1_STRING_get0_data(
                        signature))[8] ^= 1;
            }
            memset(&options, 0, sizeof(options));
            ED301V1_CHECK(corrupt != NULL
                    && run_tls(ca_cert, corrupt, server_key, NULL, NULL,
                        &options, &outcome) == 1,
                "corrupted-signature run executes");
            ED301V1_CHECK(!outcome.handshake_ok
                    && outcome.verify_result
                        == X509_V_ERR_CERT_SIGNATURE_FAILURE,
                "corrupted signature fails with "
                "CERT_SIGNATURE_FAILURE (got %ld)",
                outcome.verify_result);
            X509_free(corrupt);
        }
    }

    /*
     * VAL-05: strengthened protocol negative controls.  Each failure
     * must carry the expected reason; the matching positive control is
     * the successful server-auth lane above.
     */
    memset(&options, 0, sizeof(options));
    options.client_sigalgs =
        "ECDSA+SHA256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256";
    ED301V1_CHECK(run_tls(ca_cert, server_cert, server_key, NULL, NULL,
            &options, &outcome) == 1,
        "no-common-sigalg run executes");
    ED301V1_CHECK(!outcome.handshake_ok
            && strstr(outcome.error_reason, "signature") != NULL,
        "handshake fails without a common signature scheme "
        "(reason: %s)", outcome.error_reason);

    memset(&options, 0, sizeof(options));
    options.force_tls12 = 1;
    ED301V1_CHECK(run_tls(ca_cert, server_cert, server_key, NULL, NULL,
            &options, &outcome) == 1,
        "TLS 1.2 run executes");
    ED301V1_CHECK(!outcome.handshake_ok
            && (strstr(outcome.error_reason, "signature") != NULL
                || strstr(outcome.error_reason, "sigalg") != NULL
                || strstr(outcome.error_reason,
                    "no shared cipher") != NULL),
        "handshake fails under TLS 1.2 (Ed301-EdDSA-v1 credentials unusable: "
        "%s)", outcome.error_reason);

    /* Capability visibility only while the provider is loaded. */
    {
        SSL_CTX *bare;

        OSSL_PROVIDER_unload(v1);
        v1 = NULL;
        bare = SSL_CTX_new(TLS_server_method());
        ED301V1_CHECK(bare != NULL
                && (SSL_CTX_use_certificate(bare, server_cert) != 1
                    || SSL_CTX_use_PrivateKey(bare, server_key) != 1
                    || SSL_CTX_check_private_key(bare) != 1),
            "server credentials unusable once the provider is unloaded");
        ERR_clear_error();
        SSL_CTX_free(bare);
    }

    X509_free(server_cert);
    X509_free(client_cert);
    X509_free(ca_cert);
    X509_free(ca2_cert);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(ca2_key);
    EVP_PKEY_free(server_source_key);
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(client_key);
    if (v1 != NULL)
        OSSL_PROVIDER_unload(v1);
    OSSL_PROVIDER_unload(pki);
    OSSL_PROVIDER_unload(deflt);
    return ed301v1_summary("provider_tls");
}
