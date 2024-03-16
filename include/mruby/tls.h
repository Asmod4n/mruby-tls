#ifndef MRUBY_TLS_H
#define MRUBY_TLS_H

#include <mruby.h>

MRB_BEGIN_DECL

#define E_TLS_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Error"))
#define E_TLS_CONFIG_ERROR (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Config"), "Error"))

MRB_END_DECL

#endif
