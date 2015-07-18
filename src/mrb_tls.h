#ifndef MRB_TLS_H
#define MRB_TLS_H

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/variable.h>

typedef struct tls tls_t;
typedef struct tls_config tls_config_t;

static void
mrb_tls_config_free(mrb_state *mrb, void *p)
{
  tls_config_free(p);
}

static const struct mrb_data_type tls_config_type = {
  "$i_tls_config", mrb_tls_config_free,
};

static void
mrb_tls_free(mrb_state *mrb, void *p)
{
  tls_free(p);
}

static const struct mrb_data_type tls_type = {
  "$i_tls", mrb_tls_free,
};

#endif
