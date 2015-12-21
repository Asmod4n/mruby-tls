#ifndef MRUBY_TLS_H
#define MRUBY_TLS_H

#include <mruby.h>

#ifdef __cplusplus
extern "C" {
#endif

#define E_TLS_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Error"))
#define E_TLS_WANT_POLLIN (mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "WantPollin"))
#define E_TLS_WANT_POLLOUT (mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "WantPollout"))

#ifdef __cplusplus
}
#endif

#endif
