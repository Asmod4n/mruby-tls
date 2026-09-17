/* Two sessions, one process, no socket at all.
 *
 * The transport here is two byte queues in memory. That is the whole
 * point: if a TLS session can be driven over this, it can be driven
 * over anything a caller can write four callbacks for - a ring, a
 * message queue, a handle that has no file descriptor.
 *
 * It is C and not C++ on purpose. The API has to be callable from C,
 * and the only way to be sure is to call it from C.
 *
 * Build: see the Rakefile's examples task, or by hand -
 *   cc -std=c11 -Iinclude -c examples/session_pipe.c
 *   c++ -std=c++20 -Iinclude -Isrc -c src/tls_*.cpp
 *   c++ *.o $(pkg-config --libs libssl libcrypto) -o session_pipe
 */

#include <mruby/tls.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One direction of the pipe. A ring would be neater; a growing buffer
 * is clearer, and this is an example. */
struct queue {
  unsigned char bytes[64 * 1024];
  size_t head;
  size_t tail;
};

static size_t queue_held(const struct queue *q) { return q->tail - q->head; }

/* What one side sees: it reads from one queue and writes to the other. */
struct side {
  struct queue *in;
  struct queue *out;
  const char *name;
};

static mrb_tls_io_status side_read(void *ctx, void *buf, size_t cap, size_t *got, int *err)
{
  struct side *s = ctx;
  *err = 0;
  const size_t held = queue_held(s->in);
  if (held == 0) return MRB_TLS_IO_AGAIN;
  const size_t take = held < cap ? held : cap;
  memcpy(buf, s->in->bytes + s->in->head, take);
  s->in->head += take;
  if (s->in->head == s->in->tail) { s->in->head = 0; s->in->tail = 0; }
  *got = take;
  return MRB_TLS_IO_DONE;
}

static mrb_tls_io_status side_write(void *ctx, const void *buf, size_t len, size_t *put, int *err)
{
  struct side *s = ctx;
  *err = 0;
  const size_t room = sizeof s->out->bytes - s->out->tail;
  if (room == 0) return MRB_TLS_IO_AGAIN;
  const size_t take = len < room ? len : room;
  memcpy(s->out->bytes + s->out->tail, buf, take);
  s->out->tail += take;
  *put = take;
  return MRB_TLS_IO_DONE;
}

/* A self-signed certificate, made at build time by the Rakefile. */
static char *slurp(const char *path, size_t *len)
{
  FILE *f = fopen(path, "rb");
  if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
  fseek(f, 0, SEEK_END);
  const long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *text = malloc((size_t)size + 1);
  if (!text || fread(text, 1, (size_t)size, f) != (size_t)size) {
    fprintf(stderr, "cannot read %s\n", path);
    exit(1);
  }
  text[size] = 0;
  fclose(f);
  *len = (size_t)size;
  return text;
}

static void say_failure(const char *what, const mrb_tls_error *error)
{
  fprintf(stderr, "%s: %s (kind %d, number %d)\n", what, mrb_tls_error_text(error),
          (int)mrb_tls_error_kind_of(error), mrb_tls_error_number(error));
}

int main(int argc, char **argv)
{
  const char *cert_path = argc > 1 ? argv[1] : "examples/cert.pem";
  const char *key_path = argc > 2 ? argv[2] : "examples/key.pem";

  size_t cert_len = 0, key_len = 0;
  char *cert = slurp(cert_path, &cert_len);
  char *key = slurp(key_path, &key_len);

  mrb_tls_config *server_config = mrb_tls_config_new();
  mrb_tls_config *client_config = mrb_tls_config_new();
  if (!server_config || !client_config) { fprintf(stderr, "no config\n"); return 1; }

  if (mrb_tls_config_set_certificate(server_config, cert, cert_len) != MRB_TLS_OK) {
    say_failure("certificate", mrb_tls_config_error(server_config));
    return 1;
  }
  if (mrb_tls_config_set_private_key(server_config, key, key_len) != MRB_TLS_OK) {
    say_failure("private key", mrb_tls_config_error(server_config));
    return 1;
  }
  /* The client trusts that one certificate and nothing else, which is
     what makes this example need no certificate authority. */
  if (mrb_tls_config_set_trust_file(client_config, cert_path) != MRB_TLS_OK) {
    say_failure("trust", mrb_tls_config_error(client_config));
    return 1;
  }
  const char *offered[] = {"h2", "http/1.1"};
  mrb_tls_config_set_alpn(server_config, offered, 2);
  mrb_tls_config_set_alpn(client_config, offered, 2);

  static struct queue to_server, to_client;
  struct side server_side = {&to_server, &to_client, "server"};
  struct side client_side = {&to_client, &to_server, "client"};

  mrb_tls_io server_io = {0};
  server_io.ctx = &server_side;
  server_io.read = side_read;
  server_io.write = side_write;
  mrb_tls_io client_io = server_io;
  client_io.ctx = &client_side;

  mrb_tls_session *server = mrb_tls_session_new(server_config, MRB_TLS_SERVER, &server_io);
  mrb_tls_session *client = mrb_tls_session_new(client_config, MRB_TLS_CLIENT, &client_io);
  if (!server || !client) { fprintf(stderr, "no session\n"); return 1; }
  if (mrb_tls_session_set_server_name(client, "localhost") != MRB_TLS_OK) {
    say_failure("server name", mrb_tls_session_error(client));
    return 1;
  }

  /* Step them alternately. Neither blocks: each says again and the
     other side then has something to read. */
  int rounds = 0;
  mrb_tls_status cs = MRB_TLS_AGAIN_READ, ss = MRB_TLS_AGAIN_READ;
  while ((cs != MRB_TLS_OK || ss != MRB_TLS_OK) && rounds++ < 64) {
    if (cs != MRB_TLS_OK) cs = mrb_tls_session_handshake(client);
    if (ss != MRB_TLS_OK) ss = mrb_tls_session_handshake(server);
    if (cs == MRB_TLS_FAILED) { say_failure("client handshake", mrb_tls_session_error(client)); return 1; }
    if (ss == MRB_TLS_FAILED) { say_failure("server handshake", mrb_tls_session_error(server)); return 1; }
  }
  if (cs != MRB_TLS_OK || ss != MRB_TLS_OK) {
    fprintf(stderr, "the handshake did not settle in %d rounds\n", rounds);
    return 1;
  }

  size_t alpn_len = 0;
  const char *alpn = mrb_tls_session_alpn(server, &alpn_len);
  printf("handshake: %s, %s, alpn %.*s\n", mrb_tls_session_version(server),
         mrb_tls_session_cipher(server), (int)alpn_len, alpn);

  const mrb_tls_mode mode = mrb_tls_session_mode(server);
  if (mode == MRB_TLS_MODE_KERNEL) {
    printf("records: kernel\n");
  } else {
    printf("records: userspace (%s)\n",
           mrb_tls_error_text(mrb_tls_session_fallback_reason(server)));
  }

  /* One message each way. */
  static const char hello[] = "GET / HTTP/1.1\r\n\r\n";
  size_t put = 0;
  if (mrb_tls_session_write(client, hello, sizeof hello - 1, &put) != MRB_TLS_OK) {
    say_failure("client write", mrb_tls_session_error(client));
    return 1;
  }
  char heard[256];
  size_t got = 0;
  if (mrb_tls_session_read(server, heard, sizeof heard, &got) != MRB_TLS_OK) {
    say_failure("server read", mrb_tls_session_error(server));
    return 1;
  }
  if (got != sizeof hello - 1 || memcmp(heard, hello, got) != 0) {
    fprintf(stderr, "the server heard %zu bytes and not what was sent\n", got);
    return 1;
  }
  printf("plaintext: %zu bytes crossed and matched\n", got);

  mrb_tls_session_close(client);
  mrb_tls_session_free(client);
  mrb_tls_session_free(server);
  mrb_tls_config_free(client_config);
  mrb_tls_config_free(server_config);
  free(cert);
  free(key);
  return 0;
}
