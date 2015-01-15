#include "mruby/tls.h"
#include "mrb_tls.h"

static mrb_value
mrb_tls_init(mrb_state *mrb, mrb_value self)
{
  if (tls_init() == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

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

  config = (tls_config_t *) DATA_PTR(self);
  if (config)
    mrb_free(mrb, config);

  mrb_data_init(self, NULL, &tls_config_type);
  config = tls_config_new();
  if (config) {
    mrb_data_init(self, config, &tls_config_type);
    return self;
  }
  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_ca_file(mrb_state *mrb, mrb_value self)
{
  char *ca_file;
  mrb_int ca_file_len;

  mrb_get_args(mrb, "s", &ca_file, &ca_file_len);

  if (tls_config_set_ca_file((tls_config_t *) DATA_PTR(self),
    ca_file) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_ca_path(mrb_state *mrb, mrb_value self)
{
  char *ca_path;
  mrb_int ca_path_len;

  mrb_get_args(mrb, "s", &ca_path, &ca_path_len);

  if (tls_config_set_ca_path((tls_config_t *) DATA_PTR(self),
    ca_path) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_cert_file(mrb_state *mrb, mrb_value self)
{
  char *cert_file;
  mrb_int cert_file_len;

  mrb_get_args(mrb, "s", &cert_file, &cert_file_len);

  if (tls_config_set_cert_file((tls_config_t *) DATA_PTR(self),
    cert_file) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_cert_mem(mrb_state *mrb, mrb_value self)
{
  char *cert;
  mrb_int cert_len;

  mrb_get_args(mrb, "s", &cert, &cert_len);

  if (tls_config_set_cert_mem((tls_config_t *) DATA_PTR(self),
    (uint8_t *) cert, cert_len) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_ciphers(mrb_state *mrb, mrb_value self)
{
  char *ciphers;
  mrb_int ciphers_len;

  mrb_get_args(mrb, "s", &ciphers, &ciphers_len);

  if (tls_config_set_ciphers((tls_config_t *) DATA_PTR(self),
    ciphers) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_ecdhcurve(mrb_state *mrb, mrb_value self)
{
  char *ecdhcurve;
  mrb_int ecdhcurve_len;

  mrb_get_args(mrb, "s", &ecdhcurve, &ecdhcurve_len);

  if (tls_config_set_ecdhcurve((tls_config_t *) DATA_PTR(self),
    ecdhcurve) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_key_file(mrb_state *mrb, mrb_value self)
{
  char *key_file;
  mrb_int key_file_len;

  mrb_get_args(mrb, "s", &key_file, &key_file_len);

  if (tls_config_set_key_file((tls_config_t *) DATA_PTR(self),
    key_file) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_key_mem(mrb_state *mrb, mrb_value self)
{
  char *key;
  mrb_int key_len;

  mrb_get_args(mrb, "s", &key, &key_len);

  if (tls_config_set_key_mem((tls_config_t *) DATA_PTR(self),
    (uint8_t *) key, key_len) == 0)
    return self;

  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_tls_config_set_protocols(mrb_state *mrb, mrb_value self)
{
  mrb_int protocols;

  mrb_get_args(mrb, "i", &protocols);

  tls_config_set_protocols((tls_config_t *) DATA_PTR(self), protocols);
  return self;
}

static mrb_value
mrb_tls_config_set_verify_depth(mrb_state *mrb, mrb_value self)
{
  mrb_int verify_depth;

  mrb_get_args(mrb, "i", &verify_depth);

  tls_config_set_verify_depth((tls_config_t *) DATA_PTR(self),
    verify_depth);
  return self;
}

static mrb_value
mrb_tls_config_clear_keys(mrb_state *mrb, mrb_value self)
{
  tls_config_clear_keys((tls_config_t *) DATA_PTR(self));
  return self;
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

  ctx = (tls_t *) DATA_PTR(self);
  if (ctx)
    mrb_free(mrb, ctx);

  mrb_data_init(self, NULL, &tls_type);
  ctx = tls_client();
  if (ctx) {
    mrb_data_init(self, ctx, &tls_type);

    if (mrb_get_args(mrb, "|o", &config_obj) == 1 &&
      mrb_conf_tls(mrb, ctx, config_obj) == -1) {
      mrb->out_of_memory = TRUE;
      mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
    }

    return self;
  }
  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

/*static mrb_value
mrb_tls_server(mrb_state *mrb, mrb_value self)
{
  tls_t *ctx;
  mrb_value config_obj;

  ctx = (tls_t *) DATA_PTR(self);
  if (ctx)
    mrb_free(mrb, ctx);

  mrb_data_init(self, NULL, &tls_type);
  ctx = tls_server();
  if (ctx) {
    mrb_data_init(self, ctx, &tls_type);

    if (mrb_get_args(mrb, "|o", &config_obj) == 1 &&
      mrb_conf_tls(mrb, ctx, config_obj) == -1) {
      mrb->out_of_memory = TRUE;
      mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
    }

    return self;
  }
  else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}*/

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
mrb_tls_connect(mrb_state *mrb, mrb_value self)
{
  char *host;
  mrb_int host_len;
  char *port;
  mrb_int port_len;

  mrb_get_args(mrb, "ss", &host, &host_len, &port, &port_len);
  if (tls_connect((tls_t *) DATA_PTR(self), host, port) == 0)
      return self;

  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_connect_fds(mrb_state *mrb, mrb_value self)
{
  mrb_int fd_read, fd_write;
  char *hostname;
  mrb_int hostname_len;

  mrb_get_args(mrb, "iis", &fd_read, &fd_write, &hostname, &hostname_len);

  if (tls_connect_fds((tls_t *) DATA_PTR(self),
    fd_read, fd_write, hostname) == 0)
    return self;

  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_connect_socket(mrb_state *mrb, mrb_value self)
{
  mrb_int socket;
  char *hostname;
  mrb_int hostname_len;

  mrb_get_args(mrb, "is", &socket, &hostname, &hostname_len);

  if (tls_connect_socket((tls_t *) DATA_PTR(self),
    socket, hostname) == 0)
    return self;

  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_read(mrb_state *mrb, mrb_value self)
{
  mrb_int buf_len = 16384;
  size_t outlen;

  if (mrb_get_args(mrb, "|i", &buf_len) == 1)
    if (buf_len <= 0 || buf_len >= MRB_INT_MAX)
      mrb_raise(mrb, E_RANGE_ERROR, "buf_len is out of range");

  char buf[buf_len];
  if (tls_read((tls_t *) DATA_PTR(self), buf, sizeof(buf), &outlen) == 0)
    return mrb_str_new(mrb, buf, outlen);

  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

static mrb_value
mrb_tls_write(mrb_state *mrb, mrb_value self)
{
  char *buf;
  mrb_int buf_len;
  size_t outlen;
  size_t written = 0;

  mrb_get_args(mrb, "s", &buf, &buf_len);

  do {
    if (tls_write((tls_t *) DATA_PTR(self), buf, buf_len, &outlen) == 0)
      written += outlen;
    else
      mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
  } while(written != buf_len);

  return self;
}

static mrb_value
mrb_tls_close(mrb_state *mrb, mrb_value self)
{
  if (tls_close((tls_t *) DATA_PTR(self)) == 0)
    return self;

  else
    mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t *) DATA_PTR(self)));
}

void
mrb_mruby_tls_gem_init(mrb_state* mrb) {
  struct RClass *tls_class;
  tls_class = mrb_define_module(mrb, "Tls");
  mrb_define_module_function(mrb, tls_class, "init", mrb_tls_init, MRB_ARGS_NONE());

  struct RClass *tls_error_class;
  tls_error_class = mrb_define_class_under(mrb, tls_class, "Error", E_RUNTIME_ERROR);

  struct RClass *tls_config_class;
  tls_config_class = mrb_define_class_under(mrb, tls_class, "Config", mrb->object_class);
  MRB_SET_INSTANCE_TT(tls_config_class, MRB_TT_DATA);
  mrb_define_method(mrb, tls_config_class, "initialize",        mrb_tls_config_new,               MRB_ARGS_NONE());
  mrb_define_method(mrb, tls_config_class, "set_ca_file",       mrb_tls_config_set_ca_file,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_ca_path",       mrb_tls_config_set_ca_path,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_cert_file",     mrb_tls_config_set_cert_file,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_cert_mem",      mrb_tls_config_set_cert_mem,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_ciphers",       mrb_tls_config_set_ciphers,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_ecdhcurve",     mrb_tls_config_set_ecdhcurve,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_key_file",      mrb_tls_config_set_key_file,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_key_mem",       mrb_tls_config_set_key_mem,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_protocols",     mrb_tls_config_set_protocols,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "set_verify_depth",  mrb_tls_config_set_verify_depth,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_config_class, "clear_keys",        mrb_tls_config_clear_keys,        MRB_ARGS_NONE());

  struct RClass *tls_client_class;
  tls_client_class = mrb_define_class_under(mrb, tls_class, "Client", mrb->object_class);
  MRB_SET_INSTANCE_TT(tls_client_class, MRB_TT_DATA);
  mrb_define_method(mrb, tls_client_class, "initialize",      mrb_tls_client,         MRB_ARGS_OPT(1));
  mrb_define_method(mrb, tls_client_class, "configure",       mrb_tls_configure,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_client_class, "reset",           mrb_tls_reset,          MRB_ARGS_NONE());
  mrb_define_method(mrb, tls_client_class, "connect",         mrb_tls_connect,        MRB_ARGS_REQ(2));
  mrb_define_method(mrb, tls_client_class, "connect_fds",     mrb_tls_connect_fds,    MRB_ARGS_REQ(3));
  mrb_define_method(mrb, tls_client_class, "connect_socket",  mrb_tls_connect_socket, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, tls_client_class, "read",            mrb_tls_read,           MRB_ARGS_OPT(1));
  mrb_define_method(mrb, tls_client_class, "write",           mrb_tls_write,          MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_client_class, "close",           mrb_tls_close,          MRB_ARGS_NONE());

/*  struct RClass *tls_server_class;
  tls_server_class = mrb_define_class_under(mrb, tls_class, "Server", mrb->object_class);
  MRB_SET_INSTANCE_TT(tls_server_class, MRB_TT_DATA);
  mrb_define_method(mrb, tls_server_class, "initialize",    mrb_tls_server,         MRB_ARGS_OPT(1));
  mrb_define_method(mrb, tls_server_class, "configure",     mrb_tls_configure,      MRB_ARGS_REQ(1));
  //mrb_define_method(mrb, tls_server_class, "accept_socket", mrb_tls_accept_socket,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_server_class, "reset",         mrb_tls_reset,          MRB_ARGS_NONE());
  mrb_define_method(mrb, tls_server_class, "read",          mrb_tls_read,           MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_server_class, "write",         mrb_tls_write,          MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tls_server_class, "close",         mrb_tls_close,          MRB_ARGS_NONE());*/
}

void
mrb_mruby_tls_gem_final(mrb_state* mrb) {
  /* finalizer */
}
