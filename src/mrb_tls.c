#include "mruby/tls.h"
#include "mrb_tls.h"

static void
mrb_tls_config_free(mrb_state *mrb, void *p)
{
  tls_config_free(p);
}

static const struct mrb_data_type tls_config_type = {
  "$i_tls_config", mrb_tls_config_free,
};

static inline int
mrb_conf_tls(mrb_state *mrb, tls_t *ctx, mrb_value config_obj)
{
  mrb_data_check_type(mrb, config_obj, &tls_config_type);
  return tls_configure(ctx, (tls_config_t *) DATA_PTR(config_obj));
}

static mrb_value
mrb_tls_config_new(mrb_state *mrb, mrb_value self)
{
  tls_config_t *config;

  errno = 0;
  config = tls_config_new();
  if (config)
    mrb_data_init(self, config, &tls_config_type);
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));

  return self;
}

static mrb_value
mrb_tls_config_set_ca_file(mrb_state *mrb, mrb_value self)
{
  char *ca_file;

  mrb_get_args(mrb, "z", &ca_file);

  errno = 0;

  if (tls_config_set_ca_file((tls_config_t *) DATA_PTR(self), ca_file) == 0)
    return self;
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_ca_path(mrb_state *mrb, mrb_value self)
{
  char *ca_path;

  mrb_get_args(mrb, "z", &ca_path);

  errno = 0;

  if (tls_config_set_ca_path((tls_config_t *) DATA_PTR(self), ca_path) == 0)
    return self;
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_cert_file(mrb_state *mrb, mrb_value self)
{
  char *cert_file;

  mrb_get_args(mrb, "z", &cert_file);

  errno = 0;

  if (tls_config_set_cert_file((tls_config_t *) DATA_PTR(self), cert_file) == 0)
    return self;
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_cert_mem(mrb_state *mrb, mrb_value self)
{
  char *cert;
  mrb_int cert_len;

  mrb_get_args(mrb, "s", &cert, &cert_len);

  errno = 0;

  if (tls_config_set_cert_mem((tls_config_t *) DATA_PTR(self),
    (uint8_t *) cert, (size_t) cert_len) == 0)
    return self;

  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_ciphers(mrb_state *mrb, mrb_value self)
{
  char *ciphers;

  mrb_get_args(mrb, "z", &ciphers);

  errno = 0;

  if (tls_config_set_ciphers((tls_config_t *) DATA_PTR(self), ciphers) == 0)
    return self;
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_ecdhecurve(mrb_state *mrb, mrb_value self)
{
  char *ecdhecurve;

  mrb_get_args(mrb, "z", &ecdhecurve);

  errno = 0;

  if (tls_config_set_ecdhecurve((tls_config_t *) DATA_PTR(self),
    ecdhecurve) == 0)
    return self;

  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_key_file(mrb_state *mrb, mrb_value self)
{
  char *key_file;

  mrb_get_args(mrb, "z", &key_file);

  errno = 0;

  if (tls_config_set_key_file((tls_config_t *) DATA_PTR(self), key_file) == 0)
    return self;
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_key_mem(mrb_state *mrb, mrb_value self)
{
  char *key;
  mrb_int key_len;

  mrb_get_args(mrb, "s", &key, &key_len);

  errno = 0;

  if (tls_config_set_key_mem((tls_config_t *) DATA_PTR(self),
    (uint8_t *) key, (size_t) key_len) == 0)
    return self;

  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static mrb_value
mrb_tls_config_set_protocols(mrb_state *mrb, mrb_value self)
{
  mrb_int protocols;

  mrb_get_args(mrb, "i", &protocols);

  if (protocols < 0||protocols > UINT32_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "protocols it out of range");

  tls_config_set_protocols((tls_config_t *) DATA_PTR(self),
    (uint32_t) protocols);

  return self;
}

static mrb_value
mrb_tls_config_set_verify_depth(mrb_state *mrb, mrb_value self)
{
  mrb_int verify_depth;

  mrb_get_args(mrb, "i", &verify_depth);

  if (verify_depth < INT_MIN||verify_depth > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "verify_depth it out of range");

  tls_config_set_verify_depth((tls_config_t *) DATA_PTR(self),
    (int) verify_depth);

  return self;
}

static mrb_value
mrb_tls_config_clear_keys(mrb_state *mrb, mrb_value self)
{
  tls_config_clear_keys((tls_config_t *) DATA_PTR(self));
  return self;
}

static mrb_value
mrb_tls_load_file(mrb_state *mrb, mrb_value self)
{
  char *file, *password = NULL;

  mrb_get_args(mrb, "z|z", &file, &password);

  size_t len;
  uint8_t *cert;

  errno = 0;
  cert = tls_load_file((const char *) file, &len, password);
  if (cert) {
    return mrb_str_new(mrb, (const char *) cert, len);
    free(cert);
  }
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
}

static void
mrb_tls_free(mrb_state *mrb, void *p)
{
  tls_free(p);
}

static const struct mrb_data_type tls_type = {
  "$i_tls", mrb_tls_free,
};

static mrb_value
mrb_tls_client(mrb_state *mrb, mrb_value self)
{
  tls_t *ctx;
  mrb_value config_obj;

  errno = 0;
  ctx = tls_client();
  if (ctx) {
    mrb_data_init(self, ctx, &tls_type);

    if (mrb_get_args(mrb, "|o", &config_obj) == 1 &&
      mrb_conf_tls(mrb, ctx, config_obj) == -1)
      mrb_raise(mrb, E_TLS_ERROR, tls_error(ctx));
  }
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));

  return self;
}

static mrb_value
mrb_tls_server(mrb_state *mrb, mrb_value self)
{
  tls_t *ctx;
  mrb_value config_obj;

  errno = 0;
  ctx = tls_server();
  if (ctx) {
    mrb_data_init(self, ctx, &tls_type);

    if (mrb_get_args(mrb, "|o", &config_obj) == 1 &&
      mrb_conf_tls(mrb, ctx, config_obj) == -1)
      mrb_raise(mrb, E_TLS_ERROR, tls_error(ctx));
  }
  else
  if (errno == ENOMEM) {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else
    mrb_raise(mrb, E_TLS_ERROR, strerror(errno));

  return self;
}

static mrb_value
mrb_tls_configure(mrb_state *mrb, mrb_value self)
{
  mrb_value config_obj;

  mrb_get_args(mrb, "o", &config_obj);

  if (mrb_conf_tls(mrb, (tls_t *) DATA_PTR(self), config_obj) == 0)
    return self;
  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_reset(mrb_state *mrb, mrb_value self)
{
  tls_reset((tls_t *) DATA_PTR(self));
  return self;
}

static mrb_value
mrb_tls_accept_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int socket;

  mrb_get_args(mrb, "i", &socket);

  if (socket < INT_MIN||socket > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "socket it out of range");

  mrb_value cctx_val = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA,
    mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Server")));
  tls_t *cctx = NULL;

  if (tls_accept_socket((tls_t *) DATA_PTR(self), &cctx, (int) socket) == 0)
    mrb_data_init(cctx_val, cctx, &tls_type);
  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));

  return cctx_val;
}

static mrb_value
mrb_tls_connect(mrb_state *mrb, mrb_value self)
{
  char *host, *port = NULL;

  mrb_get_args(mrb, "z|z", &host, &port);

  int rc;

  connect:
  rc = tls_connect((tls_t *) DATA_PTR(self), host, port);

  if (rc == 0)
    return self;
  else
  if (rc == TLS_READ_AGAIN || rc == TLS_WRITE_AGAIN)
    goto connect;
  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_connect_fds(mrb_state *mrb, mrb_value self)
{
  mrb_int fd_read, fd_write;
  char *hostname;

  mrb_get_args(mrb, "iiz", &fd_read, &fd_write, &hostname);

  if (fd_read < INT_MIN||fd_read > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "fd_read it out of range");

  if (fd_write < INT_MIN||fd_write > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "fd_write it out of range");

  if (tls_connect_fds((tls_t *) DATA_PTR(self),
    (int) fd_read, (int) fd_write, hostname) == 0)
    return self;

  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_connect_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int socket;
  char *hostname;

  mrb_get_args(mrb, "iz", &socket, &hostname);

  if (socket < INT_MIN||socket > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "socket it out of range");

  if (tls_connect_socket((tls_t *) DATA_PTR(self),
    (int) socket, hostname) == 0)
    return self;

  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_read(mrb_state *mrb, mrb_value self)
{
  mrb_int buf_len = 16384;

  mrb_get_args(mrb, "|i", &buf_len);

  mrb_value buf = mrb_str_buf_new(mrb, buf_len);
  size_t outlen;
  int rc;

  read:
  rc = tls_read((tls_t *) DATA_PTR(self), RSTRING_PTR(buf), RSTRING_CAPA(buf), &outlen);

  if (rc == 0)
    return mrb_str_resize(mrb, buf, (mrb_int) outlen);
  else
  if (rc == TLS_READ_AGAIN || rc == TLS_WRITE_AGAIN)
    goto read;
  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_write(mrb_state *mrb, mrb_value self)
{
  char *buf;
  mrb_int buf_len;

  mrb_get_args(mrb, "s", &buf, &buf_len);

  size_t outlen;
  int rc;

  do {
    rc = tls_write((tls_t *) DATA_PTR(self), buf, (size_t) buf_len, &outlen);
    if (rc == 0)
      break;
    else
    if (rc == TLS_READ_AGAIN || rc == TLS_WRITE_AGAIN)
      continue;
    else
      mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
  } while(1);

  return self;
}

static mrb_value
mrb_tls_close(mrb_state *mrb, mrb_value self)
{
  int rc;

  close:
  rc = tls_close((tls_t *) DATA_PTR(self));

  if (rc == 0)
    return self;
  else
  if (rc == TLS_READ_AGAIN || rc == TLS_WRITE_AGAIN)
    goto close;
  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

void
mrb_mruby_tls_gem_init(mrb_state* mrb) {
  struct RClass *tls_mod, *tls_proto_mod, *tls_conf_c, *tls_cli_c, *tls_server_c;

  tls_mod = mrb_define_module(mrb, "Tls");
  mrb_define_class_under(mrb, tls_mod, "Error", E_RUNTIME_ERROR);
  mrb_define_module_function(mrb, tls_mod, "load_file", mrb_tls_load_file, MRB_ARGS_ARG(1, 2));

  tls_proto_mod = mrb_define_module_under(mrb, tls_mod, "Protocol");
  mrb_define_const(mrb, tls_proto_mod, "TLSv1_0", mrb_fixnum_value(TLS_PROTOCOL_TLSv1_0));
  mrb_define_const(mrb, tls_proto_mod, "TLSv1_1", mrb_fixnum_value(TLS_PROTOCOL_TLSv1_1));
  mrb_define_const(mrb, tls_proto_mod, "TLSv1_2", mrb_fixnum_value(TLS_PROTOCOL_TLSv1_2));
  mrb_define_const(mrb, tls_proto_mod, "TLSv1",   mrb_fixnum_value(TLS_PROTOCOL_TLSv1));
  mrb_define_const(mrb, tls_proto_mod, "Default", mrb_fixnum_value(TLS_PROTOCOLS_DEFAULT));


  tls_conf_c = mrb_define_class_under(mrb, tls_mod, "Config", mrb->object_class);
  MRB_SET_INSTANCE_TT(tls_conf_c, MRB_TT_DATA);
  mrb_define_method(mrb, tls_conf_c, "initialize",    mrb_tls_config_new,               MRB_ARGS_NONE());
  mrb_define_method(mrb, tls_conf_c, "ca_file=",      mrb_tls_config_set_ca_file,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "ca_path=",      mrb_tls_config_set_ca_path,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "cert_file=",    mrb_tls_config_set_cert_file,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "cert_mem=",     mrb_tls_config_set_cert_mem,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "ciphers=",      mrb_tls_config_set_ciphers,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "ecdhecurve=",   mrb_tls_config_set_ecdhecurve,    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "key_file=",     mrb_tls_config_set_key_file,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "key_mem=",      mrb_tls_config_set_key_mem,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "protocols=",    mrb_tls_config_set_protocols,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "verify_depth=", mrb_tls_config_set_verify_depth,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_conf_c, "clear_keys",    mrb_tls_config_clear_keys,        MRB_ARGS_NONE());

  tls_cli_c = mrb_define_class_under(mrb, tls_mod, "Client", mrb->object_class);
  MRB_SET_INSTANCE_TT(tls_cli_c, MRB_TT_DATA);
  mrb_define_method(mrb, tls_cli_c, "initialize",      mrb_tls_client,         MRB_ARGS_OPT(1));
  mrb_define_method(mrb, tls_cli_c, "configure",       mrb_tls_configure,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_cli_c, "reset",           mrb_tls_reset,          MRB_ARGS_NONE());
  mrb_define_method(mrb, tls_cli_c, "connect",         mrb_tls_connect,        MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, tls_cli_c, "connect_fds",     mrb_tls_connect_fds,    MRB_ARGS_REQ(3));
  mrb_define_method(mrb, tls_cli_c, "connect_socket",  mrb_tls_connect_socket, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, tls_cli_c, "read",            mrb_tls_read,           MRB_ARGS_OPT(1));
  mrb_define_method(mrb, tls_cli_c, "write",           mrb_tls_write,          MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_cli_c, "close",           mrb_tls_close,          MRB_ARGS_NONE());

  tls_server_c = mrb_define_class_under(mrb, tls_mod, "Server", mrb->object_class);
  MRB_SET_INSTANCE_TT(tls_server_c, MRB_TT_DATA);
  mrb_define_method(mrb, tls_server_c, "initialize",    mrb_tls_server,         MRB_ARGS_OPT(1));
  mrb_define_method(mrb, tls_server_c, "configure",     mrb_tls_configure,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_server_c, "accept_socket", mrb_tls_accept_socket,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_server_c, "reset",         mrb_tls_reset,          MRB_ARGS_NONE());
  mrb_define_method(mrb, tls_server_c, "read",          mrb_tls_read,           MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_server_c, "write",         mrb_tls_write,          MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_server_c, "close",         mrb_tls_close,          MRB_ARGS_NONE());

  errno = 0;

  if (tls_init() == -1) {
    if (errno == ENOMEM) {
      mrb->out_of_memory = TRUE;
      mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
    }
    else
      mrb_raise(mrb, E_TLS_ERROR, strerror(errno));
  }
}

void
mrb_mruby_tls_gem_final(mrb_state* mrb) {
  /* finalizer */
}
