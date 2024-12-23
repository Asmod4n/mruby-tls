#include "mruby/tls.h"
#include "mrb_tls.h"

static mrb_value
mrb_tls_config_new(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    tls_config_t* config = tls_config_new();
    if (config) {
        mrb_data_init(self, config, &tls_config_type);
    } else {
        mrb_sys_fail(mrb, "tls_config_new");
    }

    return self;
}

static mrb_value
mrb_tls_config_error(mrb_state *mrb, mrb_value self)
{
    if (errno) {
        mrb_sys_fail(mrb, tls_config_error((tls_config_t*)DATA_PTR(self)));
    } else {
        mrb_raise(mrb, E_TLS_CONFIG_ERROR, tls_config_error((tls_config_t*)DATA_PTR(self)));
    }

    return self;
}

static mrb_value
mrb_tls_config_parse_protocols(mrb_state* mrb, mrb_value self)
{
    char* protostr;

    mrb_get_args(mrb, "z", &protostr);

    uint32_t protocols;

    errno = 0;

    if (tls_config_parse_protocols(&protocols, protostr) == 0) {
        return mrb_int_value(mrb, protocols);
    } else {
        return mrb_tls_config_error(mrb, self);
    }
}

static mrb_value
mrb_tls_config_set_ca_file(mrb_state* mrb, mrb_value self)
{
    char* ca_file;

    mrb_get_args(mrb, "z", &ca_file);

    errno = 0;
    if (tls_config_set_ca_file((tls_config_t*)DATA_PTR(self), ca_file) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_ca_path(mrb_state* mrb, mrb_value self)
{
    char* ca_path;

    mrb_get_args(mrb, "z", &ca_path);

    errno = 0;
    if (tls_config_set_ca_path((tls_config_t*)DATA_PTR(self), ca_path) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_cert_file(mrb_state* mrb, mrb_value self)
{
    char* cert_file;

    mrb_get_args(mrb, "z", &cert_file);

    errno = 0;
    if (tls_config_set_cert_file((tls_config_t*)DATA_PTR(self), cert_file) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_cert_mem(mrb_state* mrb, mrb_value self)
{
    char* cert;
    mrb_int cert_len;

    mrb_get_args(mrb, "s", &cert, &cert_len);

    errno = 0;
    if (tls_config_set_cert_mem((tls_config_t*)DATA_PTR(self),
            (uint8_t*)cert, cert_len) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_ciphers(mrb_state* mrb, mrb_value self)
{
    char* ciphers;

    mrb_get_args(mrb, "z", &ciphers);

    errno = 0;
    if (tls_config_set_ciphers((tls_config_t*)DATA_PTR(self), ciphers) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_ecdhecurve(mrb_state* mrb, mrb_value self)
{
    char* ecdhecurve;

    mrb_get_args(mrb, "z", &ecdhecurve);

    errno = 0;
    if (tls_config_set_ecdhecurve((tls_config_t*)DATA_PTR(self), ecdhecurve) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_key_file(mrb_state* mrb, mrb_value self)
{
    char* key_file;

    mrb_get_args(mrb, "z", &key_file);

    errno = 0;
    if (tls_config_set_key_file((tls_config_t*)DATA_PTR(self), key_file) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_key_mem(mrb_state* mrb, mrb_value self)
{
    char* key;
    mrb_int key_len;

    mrb_get_args(mrb, "s", &key, &key_len);

    errno = 0;
    if (tls_config_set_key_mem((tls_config_t*)DATA_PTR(self), (uint8_t*)key, key_len) == -1) {
        mrb_tls_config_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_config_set_protocols(mrb_state* mrb, mrb_value self)
{
    mrb_int protocols;

    mrb_get_args(mrb, "i", &protocols);

    tls_config_set_protocols((tls_config_t*)DATA_PTR(self), (int) protocols);

    return self;
}

static mrb_value
mrb_tls_config_set_verify_depth(mrb_state* mrb, mrb_value self)
{
    mrb_int verify_depth;

    mrb_get_args(mrb, "i", &verify_depth);

    tls_config_set_verify_depth((tls_config_t*)DATA_PTR(self), (int) verify_depth);

    return self;
}

static mrb_value
mrb_tls_config_clear_keys(mrb_state* mrb, mrb_value self)
{
    tls_config_clear_keys((tls_config_t*)DATA_PTR(self));
    return self;
}

static mrb_value
mrb_tls_config_verify(mrb_state* mrb, mrb_value self)
{
    tls_config_verify((tls_config_t*)DATA_PTR(self));
    return self;
}

static mrb_value
mrb_tls_config_noverify(mrb_state* mrb, mrb_value self)
{
    char* mode;

    mrb_get_args(mrb, "z", &mode);

    if (strcmp(mode, "cert") == 0) {
        tls_config_insecure_noverifycert((tls_config_t*)DATA_PTR(self));
    } else if (strcmp(mode, "name") == 0) {
        tls_config_insecure_noverifyname((tls_config_t*)DATA_PTR(self));
    } else if (strcmp(mode, "time") == 0) {
        tls_config_insecure_noverifytime((tls_config_t*)DATA_PTR(self));
    } else {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "unknown noverify mode");
    }

    return self;
}

static mrb_value
mrb_tls_load_file(mrb_state* mrb, mrb_value self)
{
    char *file, *password = NULL;

    mrb_get_args(mrb, "z|z!", &file, &password);

    errno = 0;
    size_t len = 0;
    uint8_t* cert = tls_load_file((const char*)file, &len, password);

    mrb_value retval_str = self;

    if (cert) {
        struct mrb_jmpbuf* prev_jmp = mrb->jmp;
        struct mrb_jmpbuf c_jmp;

        MRB_TRY(&c_jmp)
        {
            mrb->jmp = &c_jmp;
            retval_str = mrb_str_new(mrb, (const char *) cert, len);
            tls_unload_file(cert, len);
            mrb->jmp = prev_jmp;
        }
        MRB_CATCH(&c_jmp)
        {
            mrb->jmp = prev_jmp;
            tls_unload_file(cert, len);
            MRB_THROW(mrb->jmp);
        }
        MRB_END_EXC(&c_jmp);
    } else {
        mrb_sys_fail(mrb, "tls_load_file");
    }

    return retval_str;
}

MRB_INLINE int
mrb_tls_configure(mrb_state* mrb, tls_t* ctx, mrb_value config_obj)
{
    mrb_data_check_type(mrb, config_obj, &tls_config_type);
    return tls_configure(ctx, (tls_config_t*)DATA_PTR(config_obj));
}

static mrb_value
mrb_tls_error(mrb_state *mrb, mrb_value self)
{
    if (errno) {
        mrb_sys_fail(mrb, tls_error((tls_t*)DATA_PTR(self)));
    } else {
        mrb_raise(mrb, E_TLS_ERROR, tls_error((tls_t*)DATA_PTR(self)));
    }

    return self;
}

static mrb_value
mrb_tls_client(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    tls_t* ctx = tls_client();
    if (ctx) {
        mrb_data_init(self, ctx, &tls_type);
        mrb_value config_obj;
        if (mrb_get_args(mrb, "|o", &config_obj) == 0) {
            if (tls_configure(ctx, NULL) == -1) {
                mrb_tls_error(mrb, self);
            }
        } else {
            if (mrb_tls_configure(mrb, ctx, config_obj) == 0) {
                mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@config"), config_obj);
            } else {
                mrb_tls_error(mrb, self);
            }
        }
    } else {
        mrb_sys_fail(mrb, "tls_client");
    }

    return self;
}

static mrb_value
mrb_tls_server(mrb_state* mrb, mrb_value self)
{
    mrb_value config_obj;

    mrb_get_args(mrb, "o", &config_obj);

    errno = 0;
    tls_t* ctx = tls_server();
    if (ctx) {
        mrb_data_init(self, ctx, &tls_type);
        if (mrb_tls_configure(mrb, ctx, config_obj) == 0) {
            mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@config"), config_obj);
        } else {
            mrb_tls_error(mrb, self);
        }
    } else {
        mrb_sys_fail(mrb, "tls_server");
    }

    return self;
}

static mrb_value
mrb_tls_set_config(mrb_state* mrb, mrb_value self)
{
    mrb_value config_obj;

    mrb_get_args(mrb, "o", &config_obj);

    errno = 0;
    if (mrb_tls_configure(mrb, (tls_t*)DATA_PTR(self), config_obj) == 0) {
        mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@config"), config_obj);
    } else {
        mrb_tls_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_reset(mrb_state* mrb, mrb_value self)
{
    tls_reset((tls_t*)DATA_PTR(self));
    return self;
}

static mrb_value
mrb_tls_accept_socket(mrb_state* mrb, mrb_value self)
{
    mrb_value socket;

    mrb_get_args(mrb, "o", &socket);

    tls_t* cctx = NULL;
    errno = 0;
    if (tls_accept_socket((tls_t*)DATA_PTR(self), &cctx, (int) mrb_integer(mrb_convert_type(mrb, socket, MRB_TT_INTEGER, "Integer", "fileno"))) == 0) {
        struct RData* client_data = mrb_data_object_alloc(mrb,
            mrb_class_get_under(mrb,
              mrb_module_get(mrb, "Tls"), "Client"),
            cctx, &tls_type);
        mrb_value client = mrb_obj_value(client_data);
        mrb_iv_set(mrb, client, mrb_intern_lit(mrb, "socket"), socket);
        return client;
    } else {
        return mrb_tls_error(mrb, self);
    }
}

static mrb_value
mrb_tls_connect(mrb_state* mrb, mrb_value self)
{
    char *host, *port = NULL;

    mrb_get_args(mrb, "z|z!", &host, &port);

    errno = 0;
    if (tls_connect((tls_t*)DATA_PTR(self), host, port) == -1) {
        mrb_tls_error(mrb, self);
    }

    return self;
}

static mrb_value
mrb_tls_connect_fds(mrb_state* mrb, mrb_value self)
{
    mrb_value fd_read, fd_write;
    char* hostname;

    mrb_get_args(mrb, "ooz", &fd_read, &fd_write, &hostname);

    errno = 0;
    if (tls_connect_fds((tls_t*)DATA_PTR(self),
        (int) mrb_integer(mrb_convert_type(mrb, fd_read, MRB_TT_INTEGER, "Integer", "fileno")),
        (int) mrb_integer(mrb_convert_type(mrb, fd_write, MRB_TT_INTEGER, "Integer", "fileno")),
        hostname) == -1) {
        mrb_tls_error(mrb, self);
    }
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fd_read"), fd_read);
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fd_write"), fd_write);

    return self;
}

static mrb_value
mrb_tls_connect_socket(mrb_state* mrb, mrb_value self)
{
    mrb_value socket;
    char* hostname;

    mrb_get_args(mrb, "oz", &socket, &hostname);

    errno = 0;
    if (tls_connect_socket((tls_t*)DATA_PTR(self),
        (int) mrb_integer(mrb_convert_type(mrb, socket, MRB_TT_INTEGER, "Integer", "fileno")), hostname) == -1) {
        mrb_tls_error(mrb, self);
    }

    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "socket"), socket);

    return self;
}

static mrb_value
mrb_tls_read(mrb_state* mrb, mrb_value self)
{
    mrb_int buf_len = 9000;
    mrb_get_args(mrb, "|i", &buf_len);

    errno = 0;
    mrb_value buf = mrb_str_buf_new(mrb, buf_len);
    while (TRUE) {
        ssize_t rc = tls_read((tls_t*)DATA_PTR(self), RSTRING_PTR(buf), RSTRING_CAPA(buf));
        switch (rc) {
            case TLS_WANT_POLLOUT:
            case TLS_WANT_POLLIN:
                continue;
                break;
            case -1:
                return mrb_tls_error(mrb, self);
            default:
                return mrb_str_resize(mrb, buf, rc);
        }
    }
}

static mrb_value
mrb_tls_read_nonblock(mrb_state* mrb, mrb_value self)
{
    mrb_int buf_len = 9000;
    mrb_get_args(mrb, "|i", &buf_len);

    errno = 0;
    mrb_value buf = mrb_str_buf_new(mrb, buf_len);
    ssize_t rc = tls_read((tls_t*)DATA_PTR(self), RSTRING_PTR(buf), RSTRING_CAPA(buf));
    switch (rc) {
        case TLS_WANT_POLLOUT:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollout"));
        case TLS_WANT_POLLIN:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollin"));
        case -1:
            return mrb_tls_error(mrb, self);
        default:
            return mrb_str_resize(mrb, buf, rc);
    }
}

static mrb_value
mrb_tls_write(mrb_state *mrb, mrb_value self)
{
    char *buf;
    mrb_int len;

    mrb_get_args(mrb, "s", &buf, &len);

    ssize_t ret = 0;

    while (len > 0) {
        ssize_t tmp = tls_write((tls_t*) DATA_PTR(self), buf, len);
        switch (tmp) {
            case TLS_WANT_POLLOUT:
            case TLS_WANT_POLLIN:
                continue;
                break;
            case -1:
                return mrb_tls_error(mrb, self);
            default: {
                buf += tmp;
                len -= tmp;
                ret += tmp;
            }
        }
    }

    return mrb_int_value(mrb, ret);
}

static mrb_value
mrb_tls_write_nonblock(mrb_state* mrb, mrb_value self)
{
    char* buf;
    mrb_int len;

    mrb_get_args(mrb, "s", &buf, &len);

    errno = 0;
    ssize_t rc = tls_write((tls_t*)DATA_PTR(self), buf, len);
    switch (rc) {
        case TLS_WANT_POLLOUT:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollout"));
        case TLS_WANT_POLLIN:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollin"));
        case -1:
            return mrb_tls_error(mrb, self);
        default:
            return mrb_int_value(mrb, rc);
    }
}

static mrb_value
mrb_tls_close(mrb_state *mrb, mrb_value self)
{
    errno = 0;

    mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "socket"));
    mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "fd_read"));
    mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "fd_write"));

    while (TRUE) {
        switch (tls_close((tls_t*)DATA_PTR(self))) {
            case 0:
                return self;
            case TLS_WANT_POLLOUT:
            case TLS_WANT_POLLIN:
                continue;
                break;
            default:
                return mrb_tls_error(mrb, self);
        }
    }
}

static mrb_value
mrb_tls_close_nonblock(mrb_state *mrb, mrb_value self)
{
    errno = 0;

    switch (tls_close((tls_t*)DATA_PTR(self))) {
        case 0: {
            mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "socket"));
            mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "fd_read"));
            mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "fd_write"));
            return self;
        }
        case TLS_WANT_POLLOUT:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollout"));
        case TLS_WANT_POLLIN:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollin"));
        default:
            return mrb_tls_error(mrb, self);
    }
}

static mrb_value
mrb_tls_handshake(mrb_state *mrb, mrb_value self)
{
    errno = 0;

    while (TRUE) {
        switch (tls_handshake((tls_t*)DATA_PTR(self))) {
            case 0:
                return self;
            case TLS_WANT_POLLOUT:
            case TLS_WANT_POLLIN:
                continue;
                break;
            default:
                return mrb_tls_error(mrb, self);
        }
    }
}

static mrb_value
mrb_tls_handshake_nonblock(mrb_state *mrb, mrb_value self)
{
    errno = 0;

    switch (tls_handshake((tls_t*)DATA_PTR(self))) {
        case 0:
            return self;
        case TLS_WANT_POLLOUT:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollout"));
        case TLS_WANT_POLLIN:
            return mrb_symbol_value(mrb_intern_lit(mrb, "tls_want_pollin"));
        default:
            return mrb_tls_error(mrb, self);
    }
}

static mrb_value
mrb_tls_conn_version(mrb_state *mrb, mrb_value self)
{
    errno = 0;
    const char *version = tls_conn_version((tls_t*)DATA_PTR(self));
    if (version) {
        return mrb_str_new_cstr(mrb, version);
    } else {
        return mrb_tls_error(mrb, self);
    }
}

static mrb_value
mrb_tls_conn_cipher(mrb_state *mrb, mrb_value self)
{
    errno = 0;
    const char *cipher = tls_conn_cipher((tls_t*)DATA_PTR(self));
    if (cipher) {
        return mrb_str_new_cstr(mrb, cipher);
    } else {
        return mrb_tls_error(mrb, self);
    }
}

void
mrb_mruby_tls_gem_init(mrb_state* mrb)
{
    struct RClass *tls_mod, *tls_proto_mod, *tls_conf_c, *tls_ctx_c, *tls_cli_c, *tls_server_c;

    tls_mod = mrb_define_module(mrb, "Tls");
    mrb_define_module_function(mrb, tls_mod, "load_file", mrb_tls_load_file, MRB_ARGS_ARG(1, 1));

    tls_proto_mod = mrb_define_module_under(mrb, tls_mod, "Protocol");
    mrb_define_const(mrb, tls_proto_mod, "TLSv1_0", mrb_int_value(mrb, TLS_PROTOCOL_TLSv1_0));
    mrb_define_const(mrb, tls_proto_mod, "TLSv1_1", mrb_int_value(mrb, TLS_PROTOCOL_TLSv1_1));
    mrb_define_const(mrb, tls_proto_mod, "TLSv1_2", mrb_int_value(mrb, TLS_PROTOCOL_TLSv1_2));
#ifdef TLS_PROTOCOL_TLSv1_3
    mrb_define_const(mrb, tls_proto_mod, "TLSv1_3", mrb_int_value(mrb, TLS_PROTOCOL_TLSv1_3));
#endif
    mrb_define_const(mrb, tls_proto_mod, "TLSv1", mrb_int_value(mrb, TLS_PROTOCOL_TLSv1));
    mrb_define_const(mrb, tls_proto_mod, "All", mrb_int_value(mrb, TLS_PROTOCOLS_ALL));
    mrb_define_const(mrb, tls_proto_mod, "Default", mrb_int_value(mrb, TLS_PROTOCOLS_DEFAULT));

    tls_conf_c = mrb_define_class_under(mrb, tls_mod, "Config", mrb->object_class);
    MRB_SET_INSTANCE_TT(tls_conf_c, MRB_TT_DATA);
    mrb_define_method(mrb, tls_conf_c, "initialize", mrb_tls_config_new, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_conf_c, "parse_protocols", mrb_tls_config_parse_protocols, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "ca_file=", mrb_tls_config_set_ca_file, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "ca_path=", mrb_tls_config_set_ca_path, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "cert_file=", mrb_tls_config_set_cert_file, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "cert_mem=", mrb_tls_config_set_cert_mem, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "ciphers=", mrb_tls_config_set_ciphers, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "ecdhecurve=", mrb_tls_config_set_ecdhecurve, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "key_file=", mrb_tls_config_set_key_file, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "key_mem=", mrb_tls_config_set_key_mem, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "protocols=", mrb_tls_config_set_protocols, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "verify_depth=", mrb_tls_config_set_verify_depth, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_conf_c, "clear_keys", mrb_tls_config_clear_keys, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_conf_c, "verify", mrb_tls_config_verify, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_conf_c, "noverify", mrb_tls_config_noverify, MRB_ARGS_REQ(1));

    tls_ctx_c = mrb_define_class_under(mrb, tls_mod, "Context", mrb->object_class);
    MRB_SET_INSTANCE_TT(tls_ctx_c, MRB_TT_DATA);
    mrb_define_method(mrb, tls_ctx_c, "configure", mrb_tls_set_config, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_ctx_c, "reset", mrb_tls_reset, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_ctx_c, "read", mrb_tls_read, MRB_ARGS_OPT(1));
    mrb_define_method(mrb, tls_ctx_c, "read_nonblock", mrb_tls_read_nonblock, MRB_ARGS_OPT(1));
    mrb_define_method(mrb, tls_ctx_c, "write", mrb_tls_write, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_ctx_c, "write_nonblock", mrb_tls_write_nonblock, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_ctx_c, "close", mrb_tls_close, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_ctx_c, "close_nonblock", mrb_tls_close_nonblock, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_ctx_c, "handshake", mrb_tls_handshake, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_ctx_c, "handshake_nonblock", mrb_tls_handshake_nonblock, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_ctx_c, "version", mrb_tls_conn_version, MRB_ARGS_NONE());
    mrb_define_method(mrb, tls_ctx_c, "cipher", mrb_tls_conn_cipher, MRB_ARGS_NONE());

    tls_cli_c = mrb_define_class_under(mrb, tls_mod, "Client", tls_ctx_c);
    mrb_define_method(mrb, tls_cli_c, "initialize", mrb_tls_client, MRB_ARGS_OPT(1));
    mrb_define_method(mrb, tls_cli_c, "connect", mrb_tls_connect, MRB_ARGS_ARG(1, 1));
    mrb_define_method(mrb, tls_cli_c, "connect_fds", mrb_tls_connect_fds, MRB_ARGS_REQ(3));
    mrb_define_method(mrb, tls_cli_c, "connect_socket", mrb_tls_connect_socket, MRB_ARGS_REQ(2));

    tls_server_c = mrb_define_class_under(mrb, tls_mod, "Server", tls_ctx_c);
    mrb_define_method(mrb, tls_server_c, "initialize", mrb_tls_server, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, tls_server_c, "accept_socket", mrb_tls_accept_socket, MRB_ARGS_REQ(1));

    errno = 0;
    if (tls_init() == -1) {
        if (errno == ENOMEM) {
          mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
        } else {
          mrb_sys_fail(mrb, "tls_init");
        }
    }
}

void mrb_mruby_tls_gem_final(mrb_state* mrb) {}
