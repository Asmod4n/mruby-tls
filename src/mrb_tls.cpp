// The one translation unit. It selects a backend and nothing else.
//
// Each backend header defines the entire gem: the Ruby classes
// (Tls::Config, Tls::Context, Tls::Client, Tls::Server), gem_init, and
// the MRB_API memory functions declared in include/mruby/tls.h. Nothing
// is shared between them and nothing needs to be - two TLS libraries
// have no common internals worth abstracting, and a layer pretending
// otherwise would be a second contract to keep in step with the first.
//
// So the seam is this #if and include/mruby/tls.h, which is already
// written free of provider types for exactly this reason. Adding a
// backend means adding a header and a branch here.
#ifdef _WIN32
#include "backend_schannel.hpp"
#else
#include "backend_openssl.hpp"
#endif
