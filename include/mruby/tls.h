#ifndef MRUBY_TLS_H
#define MRUBY_TLS_H

#include <mruby.h>

#ifdef __cplusplus
extern "C" {
#endif

#define E_TLS_ERROR mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Error")

#ifdef __cplusplus
}
#endif

#endif
