/*
 * VAL-01 / B1-DER: one-object DER stream boundary.
 *
 * The provider decoder owns exactly one canonical DER object per decode
 * call.  It reads the two-byte outer header first, validates tag 0x30
 * and the canonical short-form body length (0x45 for PKCS#8, 0x41 for
 * SPKI), and only then reads exactly the declared body.  It never
 * probes for pending bytes, never reads one byte ahead and never
 * requires stream EOF: bytes or complete objects after the decoded one
 * stay in the BIO for the caller.  A no-trailing-data policy for
 * whole-buffer callers lives outside the decoder; the whole-buffer lane
 * below exercises that policy at caller level.
 *
 * Framework boundary recorded during the earlier VAL-01 repair:
 * OSSL_DECODER cannot rewind a non-seekable BIO between candidate
 * decoders, so every lane here binds exactly one decoder from this
 * provider (PKCS#8 or SPKI DER, as the lane requires).
 *
 * With D00_EXPECT_LEGACY=1 the lanes flip to the sealed Experiment-2
 * expectations (trailing byte rejected, live pair misclassified), and
 * D00_LEGACY_SOCKET=1 runs only the socket probe under an external
 * timeout to record the legacy blocking behaviour.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/core_object.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>

#include "harness_common.h"
#include "vectors.h"

#define D00_PKCS8_DECODER_PROPS \
    "provider=ed301_eddsa_draft00,input=der,structure=PrivateKeyInfo"
#define D00_SPKI_DECODER_PROPS \
    "provider=ed301_eddsa_draft00,input=der,structure=SubjectPublicKeyInfo"

static int legacy_expectations(void)
{
    const char *value = getenv("D00_EXPECT_LEGACY");

    return value != NULL && strcmp(value, "1") == 0;
}

/* Construct callback: records that the provider decoder produced a key. */
static int record_construct(
    OSSL_DECODER_INSTANCE *decoder_instance,
    const OSSL_PARAM *params,
    void *construct_argument)
{
    int *constructed = construct_argument;
    const OSSL_PARAM *parameter =
        OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);

    (void)decoder_instance;
    if (parameter == NULL || parameter->data == NULL
            || strcmp(parameter->data, D00_ALG) != 0)
        return 0;
    *constructed = 1;
    return 1;
}

/*
 * One decode call through exactly one provider decoder (PKCS#8 or SPKI
 * DER; see the framework boundary above).  Returns 1 when that call
 * constructed a draft-00 key object.
 */
static int decode_one(OSSL_LIB_CTX *libctx, BIO *bio, int is_public)
{
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new();
    OSSL_DECODER *decoder = OSSL_DECODER_fetch(libctx, D00_ALG,
        is_public ? D00_SPKI_DECODER_PROPS : D00_PKCS8_DECODER_PROPS);
    int constructed = 0;
    int ok;

    if (dctx == NULL || decoder == NULL
            || OSSL_DECODER_CTX_add_decoder(dctx, decoder) != 1
            || OSSL_DECODER_CTX_set_selection(dctx,
                is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR) != 1
            || OSSL_DECODER_CTX_set_input_type(dctx, "DER") != 1
            || OSSL_DECODER_CTX_set_input_structure(dctx,
                is_public ? "SubjectPublicKeyInfo"
                          : "PrivateKeyInfo") != 1
            || OSSL_DECODER_CTX_set_construct(dctx, record_construct) != 1
            || OSSL_DECODER_CTX_set_construct_data(dctx,
                &constructed) != 1) {
        OSSL_DECODER_free(decoder);
        OSSL_DECODER_CTX_free(dctx);
        ERR_clear_error();
        return 0;
    }
    ok = OSSL_DECODER_from_bio(dctx, bio) == 1 && constructed;
    OSSL_DECODER_free(decoder);
    OSSL_DECODER_CTX_free(dctx);
    ERR_clear_error();
    return ok;
}

/*
 * Caller-side whole-buffer control: the provider decoder stops after one
 * object, so a caller that requires "exactly one object, nothing after"
 * checks the unconsumed remainder itself.
 */
static int whole_buffer_accepts(
    OSSL_LIB_CTX *libctx,
    const unsigned char *data,
    size_t data_len,
    int is_public)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey, "DER",
        is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
        D00_ALG, is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
        libctx, D00_PROP);
    const unsigned char *cursor = data;
    size_t remaining = data_len;
    int ok;

    ok = ctx != NULL
        && OSSL_DECODER_from_data(ctx, &cursor, &remaining) == 1
        && remaining == 0 && pkey != NULL;
    OSSL_DECODER_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    ERR_clear_error();
    return ok;
}

/*
 * One-byte-chunk source BIO: serves the stream one byte per read call
 * and does not prebuffer, seek or copy away the boundary under test.
 * Leftover bytes are proven by real reads from this same BIO.
 */
typedef struct {
    const unsigned char *data;
    size_t length;
    size_t offset;
} CHUNK_SOURCE;

static BIO_METHOD *chunk_method;

static int fd_write_all(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < length) {
        const ssize_t written = write(fd, bytes + offset, length - offset);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        return 0;
    }
    return 1;
}

static int chunk_read_ex(
    BIO *bio, char *out, size_t out_length, size_t *read_length)
{
    CHUNK_SOURCE *source = BIO_get_data(bio);

    *read_length = 0;
    if (source == NULL || out == NULL || out_length == 0)
        return 0;
    if (source->offset >= source->length)
        return 0;               /* EOF */
    out[0] = (char)source->data[source->offset++];
    *read_length = 1;
    return 1;
}

static long chunk_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    (void)bio;
    (void)num;
    (void)ptr;
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

static BIO *chunk_bio(CHUNK_SOURCE *source)
{
    BIO *bio;

    if (chunk_method == NULL) {
        chunk_method = BIO_meth_new(
            BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
            "d00 one-byte chunk source");
        if (chunk_method == NULL
                || BIO_meth_set_read_ex(chunk_method, chunk_read_ex) != 1
                || BIO_meth_set_ctrl(chunk_method, chunk_ctrl) != 1) {
            BIO_meth_free(chunk_method);
            chunk_method = NULL;
            return NULL;
        }
    }
    bio = BIO_new(chunk_method);
    if (bio != NULL) {
        BIO_set_data(bio, source);
        BIO_set_init(bio, 1);
    }
    return bio;
}

static unsigned char *make_der(
    OSSL_LIB_CTX *libctx, int is_public, size_t *der_len)
{
    EVP_PKEY *source = d00_key_from_seed(libctx, POSITIVE_CASES[0].seed);
    OSSL_ENCODER_CTX *ectx = source == NULL ? NULL
        : OSSL_ENCODER_CTX_new_for_pkey(source,
            is_public ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, "DER",
            is_public ? "SubjectPublicKeyInfo" : "PrivateKeyInfo",
            D00_PROP);
    unsigned char *der = NULL;

    *der_len = 0;
    if (ectx == NULL || OSSL_ENCODER_to_data(ectx, &der, der_len) != 1) {
        OPENSSL_free(der);
        der = NULL;
    }
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_free(source);
    return der;
}

int main(void)
{
    D00_REQUIRE_RUNTIME_BINDING();

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *draft = d00_load(libctx, &deflt);
    unsigned char *pkcs8 = NULL;
    unsigned char *spki = NULL;
    size_t pkcs8_len = 0;
    size_t spki_len = 0;
    const int legacy = legacy_expectations();
    int kind;
    int exit_code = 0;

    /*
     * D00_LEGACY_SOCKET=1: socket-only probe used with the sealed
     * Experiment-2 module under an external timeout: the legacy probe
     * blocks in bio_read_ex and never returns, so the external timeout
     * (recorded exit 124) is the blocking counter-evidence.
     */
    if (getenv("D00_LEGACY_SOCKET") != NULL) {
        int fds[2] = { -1, -1 };
        BIO *bio = NULL;

        if (draft == NULL) {
            exit_code = 2;
            goto cleanup;
        }
        pkcs8 = make_der(libctx, 0, &pkcs8_len);
        if (pkcs8 == NULL
                || socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0
                || !fd_write_all(fds[1], pkcs8, pkcs8_len)) {
            exit_code = 2;
            goto legacy_cleanup;
        }
        bio = BIO_new_socket(fds[0], BIO_NOCLOSE);
        if (bio == NULL) {
            exit_code = 2;
            goto legacy_cleanup;
        }
        printf("socket decode returned (%s)\n",
            decode_one(libctx, bio, 0) ? "accepted" : "rejected");
legacy_cleanup:
        BIO_free(bio);
        if (fds[0] >= 0)
            close(fds[0]);
        if (fds[1] >= 0)
            close(fds[1]);
        goto cleanup;
    }

    alarm(30);
    D00_CHECK(draft != NULL, "provider load");
    pkcs8 = make_der(libctx, 0, &pkcs8_len);
    spki = make_der(libctx, 1, &spki_len);
    D00_CHECK(pkcs8 != NULL && pkcs8_len == 71,
        "PKCS#8 DER produced (%zu bytes)", pkcs8_len);
    D00_CHECK(spki != NULL && spki_len == 67,
        "SPKI DER produced (%zu bytes)", spki_len);
    if (pkcs8 == NULL || pkcs8_len != 71
            || spki == NULL || spki_len != 67) {
        exit_code = d00_summary("val01_decoder_bio");
        goto cleanup;
    }

    /* Sealed Experiment-2 expectations (legacy module only). */
    if (legacy) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO *reader = NULL;
        BIO *writer = NULL;
        int pair_ok;

        D00_CHECK(bio != NULL
                && BIO_write(bio, pkcs8, (int)pkcs8_len) == (int)pkcs8_len
                && BIO_write(bio, "\x00", 1) == 1
                && !decode_one(libctx, bio, 0),
            "LEGACY: memory BIO with a trailing byte is rejected");
        BIO_free(bio);
        bio = BIO_new(BIO_s_mem());
        D00_CHECK(bio != NULL
                && BIO_write(bio, pkcs8, (int)pkcs8_len) == (int)pkcs8_len
                && decode_one(libctx, bio, 0),
            "memory BIO with the exact object decodes");
        BIO_free(bio);
        pair_ok = BIO_new_bio_pair(&reader, 0, &writer, 0) == 1;
        if (pair_ok)
            pair_ok = BIO_write(writer, pkcs8, (int)pkcs8_len)
                == (int)pkcs8_len;
        D00_CHECK(pair_ok, "pair-live setup");
        if (pair_ok)
            D00_CHECK(!decode_one(libctx, reader, 0),
                "LEGACY: live BIO pair retry misclassified as trailing "
                "data (Experiment-2 defect confirmed)");
        BIO_free(reader);
        BIO_free(writer);
    }

    /* Per-structure boundary lanes: PKCS#8 (71) and SPKI (67). */
    for (kind = 0; !legacy && kind < 2; kind++) {
        const int is_public = kind == 1;
        const unsigned char *der = is_public ? spki : pkcs8;
        const size_t der_len = is_public ? spki_len : pkcs8_len;
        const char *label = is_public ? "SPKI" : "PKCS#8";
        const unsigned char body_length = (unsigned char)(der_len - 2);
        const unsigned char bad_headers[4][2] = {
            { 0x31, body_length },                      /* wrong tag */
            { 0x30, (unsigned char)(body_length - 1) }, /* wrong length */
            { 0x30, 0x81 },                             /* long form */
            { 0x30, 0x80 },                             /* indefinite */
        };
        static const char *const bad_names[4] = {
            "wrong-tag", "wrong-length", "long-form", "indefinite",
        };
        size_t i;

        /* Exact object from a memory BIO. */
        {
            BIO *bio = BIO_new(BIO_s_mem());

            D00_CHECK(bio != NULL
                    && BIO_write(bio, der, (int)der_len) == (int)der_len
                    && decode_one(libctx, bio, is_public),
                "%s: memory BIO with the exact object decodes", label);
            BIO_free(bio);
        }

        /* One-byte-chunk source; sentinel proven by a real read. */
        {
            unsigned char stream[72];
            CHUNK_SOURCE source = { stream, der_len + 1, 0 };
            BIO *bio = chunk_bio(&source);
            unsigned char byte = 0;

            memcpy(stream, der, der_len);
            stream[der_len] = 0xa5;
            D00_CHECK(bio != NULL && decode_one(libctx, bio, is_public),
                "%s: one-byte-chunk source decodes", label);
            D00_CHECK(BIO_read(bio, &byte, 1) == 1 && byte == 0xa5
                    && BIO_read(bio, &byte, 1) <= 0,
                "%s: exactly one sentinel byte remains after the object",
                label);
            BIO_free(bio);
        }

        /* EOF inside the declared body fails closed. */
        {
            BIO *header_only = BIO_new(BIO_s_mem());
            BIO *partial = BIO_new(BIO_s_mem());

            D00_CHECK(header_only != NULL
                    && BIO_write(header_only, der, 2) == 2
                    && !decode_one(libctx, header_only, is_public),
                "%s: EOF directly after a valid header is rejected",
                label);
            D00_CHECK(partial != NULL
                    && BIO_write(partial, der, (int)der_len - 1)
                        == (int)der_len - 1
                    && !decode_one(libctx, partial, is_public),
                "%s: EOF one byte before the end of the body is rejected",
                label);
            BIO_free(header_only);
            BIO_free(partial);
        }

        /* Truncated outer header (one byte, then EOF). */
        {
            BIO *bio = BIO_new(BIO_s_mem());

            D00_CHECK(bio != NULL && BIO_write(bio, der, 1) == 1
                    && !decode_one(libctx, bio, is_public),
                "%s: truncated one-byte outer header is rejected", label);
            BIO_free(bio);
        }

        /*
         * Malformed outer headers on a blocking socket with the writer
         * open: rejection must not read the body (the sentinel byte is
         * still there) and must not block (watchdog).
         */
        for (i = 0; i < 4; i++) {
            int fds[2] = { -1, -1 };
            BIO *bio = NULL;
            unsigned char byte = 0;
            int setup_ok;

            setup_ok = socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
            if (setup_ok)
                setup_ok = fd_write_all(fds[1], bad_headers[i], 2)
                    && fd_write_all(fds[1], "\xa5", 1);
            D00_CHECK(setup_ok,
                "%s: %s header setup", label, bad_names[i]);
            if (!setup_ok) {
                if (fds[0] >= 0)
                    close(fds[0]);
                if (fds[1] >= 0)
                    close(fds[1]);
                continue;
            }
            bio = BIO_new_socket(fds[0], BIO_NOCLOSE);
            D00_CHECK(bio != NULL,
                "%s: %s socket BIO", label, bad_names[i]);
            if (bio != NULL) {
                D00_CHECK(!decode_one(libctx, bio, is_public),
                "%s: %s outer header is rejected before the body",
                label, bad_names[i]);
                D00_CHECK(read(fds[0], &byte, 1) == 1 && byte == 0xa5,
                    "%s: sentinel after the %s header remains unread",
                    label, bad_names[i]);
            }
            BIO_free(bio);
            close(fds[0]);
            close(fds[1]);
        }

        /* A complete second object after a rejected header stays intact. */
        {
            int fds[2] = { -1, -1 };
            BIO *bio = NULL;
            const unsigned char wrong_tag[2] = { 0x31, body_length };
            int setup_ok;

            setup_ok = socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
            if (setup_ok)
                setup_ok = fd_write_all(fds[1], wrong_tag, 2)
                    && fd_write_all(fds[1], der, der_len);
            D00_CHECK(setup_ok,
                "%s: wrong-tag-then-object setup", label);
            if (setup_ok) {
                bio = BIO_new_socket(fds[0], BIO_NOCLOSE);
                D00_CHECK(bio != NULL, "%s: wrong-tag socket BIO", label);
                if (bio != NULL) {
                    D00_CHECK(!decode_one(libctx, bio, is_public),
                        "%s: wrong-tag object is rejected", label);
                    D00_CHECK(decode_one(libctx, bio, is_public),
                        "%s: the untouched second object then decodes",
                        label);
                }
            }
            BIO_free(bio);
            if (fds[0] >= 0)
                close(fds[0]);
            if (fds[1] >= 0)
                close(fds[1]);
        }
    }

    /* pair-live: nonblocking retry source, writer stays open. */
    if (!legacy) {
        BIO *reader = NULL;
        BIO *writer = NULL;
        int setup_ok;

        setup_ok = BIO_new_bio_pair(&reader, 0, &writer, 0) == 1;
        if (setup_ok)
            setup_ok = BIO_write(writer, pkcs8, (int)pkcs8_len)
                == (int)pkcs8_len;
        D00_CHECK(setup_ok, "pair-live setup");
        /* The writer side stays open: no BIO_shutdown_wr. */
        if (setup_ok)
            D00_CHECK(decode_one(libctx, reader, 0),
                "live BIO pair with open writer decodes (retry source)");
        BIO_free(reader);
        BIO_free(writer);
    }

    /* socket-live: blocking stream, writer open; must return. */
    if (!legacy) {
        int fds[2] = { -1, -1 };
        BIO *bio = NULL;
        unsigned char after = 0;
        int setup_ok;

        setup_ok = socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
        if (setup_ok)
            setup_ok = fd_write_all(fds[1], pkcs8, pkcs8_len);
        D00_CHECK(setup_ok, "socket setup");
        if (setup_ok) {
            bio = BIO_new_socket(fds[0], BIO_NOCLOSE);
            D00_CHECK(bio != NULL, "socket BIO");
            if (bio != NULL) {
                D00_CHECK(decode_one(libctx, bio, 0),
                    "blocking socket with open writer decodes without "
                    "blocking");
                after = 0xab;
                D00_CHECK(fd_write_all(fds[1], &after, 1)
                        && read(fds[0], &after, 1) == 1 && after == 0xab,
                    "bytes written after the object remain readable");
            }
        }
        BIO_free(bio);
        if (fds[0] >= 0)
            close(fds[0]);
        if (fds[1] >= 0)
            close(fds[1]);
    }

    /* Two concatenated objects, two one-object calls, one sentinel. */
    if (!legacy) {
        int fds[2] = { -1, -1 };
        BIO *bio = NULL;
        unsigned char byte = 0;
        int setup_ok;

        setup_ok = socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
        if (setup_ok)
            setup_ok = fd_write_all(fds[1], pkcs8, pkcs8_len)
                && fd_write_all(fds[1], spki, spki_len)
                && fd_write_all(fds[1], "\xa5", 1);
        D00_CHECK(setup_ok, "concatenated objects setup");
        if (setup_ok) {
            bio = BIO_new_socket(fds[0], BIO_NOCLOSE);
            D00_CHECK(bio != NULL, "concatenated objects socket BIO");
            if (bio != NULL) {
                D00_CHECK(decode_one(libctx, bio, 0),
                    "first of two concatenated objects decodes");
                D00_CHECK(decode_one(libctx, bio, 1),
                    "second concatenated object decodes from the same "
                    "stream");
                D00_CHECK(read(fds[0], &byte, 1) == 1 && byte == 0xa5,
                    "sentinel after both objects remains unread");
            }
        }
        BIO_free(bio);
        if (fds[0] >= 0)
            close(fds[0]);
        if (fds[1] >= 0)
            close(fds[1]);
    }

    /* Whole-buffer trailing data: caller policy, not the decoder. */
    if (!legacy) {
        for (kind = 0; kind < 2; kind++) {
            const int is_public = kind == 1;
            const unsigned char *der = is_public ? spki : pkcs8;
            const size_t der_len = is_public ? spki_len : pkcs8_len;
            const char *label = is_public ? "SPKI" : "PKCS#8";
            unsigned char padded[72];
            CHUNK_SOURCE source = { padded, der_len + 1, 0 };
            BIO *bio;
            unsigned char byte = 0;

            memcpy(padded, der, der_len);
            padded[der_len] = 0xa5;
            bio = chunk_bio(&source);
            D00_CHECK(bio != NULL
                    && decode_one(libctx, bio, is_public),
                "%s: provider decoder accepts the object ahead of a "
                "trailing byte", label);
            if (bio != NULL)
                D00_CHECK(BIO_read(bio, &byte, 1) == 1 && byte == 0xa5,
                    "%s: trailing byte stays in the BIO for the caller",
                    label);
            D00_CHECK(!whole_buffer_accepts(
                    libctx, padded, der_len + 1, is_public),
                "%s: caller whole-buffer policy rejects trailing byte",
                label);
            D00_CHECK(whole_buffer_accepts(
                    libctx, der, der_len, is_public),
                "%s: caller whole-buffer policy accepts exact buffer",
                label);
            BIO_free(bio);
        }
    }

    exit_code = d00_summary("val01_decoder_bio");

cleanup:
    OPENSSL_free(pkcs8);
    OPENSSL_free(spki);
    BIO_meth_free(chunk_method);
    chunk_method = NULL;
    OSSL_PROVIDER_unload(draft);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return exit_code;
}
