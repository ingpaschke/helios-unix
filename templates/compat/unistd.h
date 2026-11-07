#ifndef HU_OVERLAY_UNISTD_H
#define HU_OVERLAY_UNISTD_H
#include "native/unistd.h"

/* Native vfork shares memory. Use hu_spawn for independent child tasks. */
#undef fork
#define fork(...) ((int)sizeof(char[-1]))
#ifndef HU_ENABLE_NATIVE_VFORK
#define vfork(...) ((int)sizeof(char[-1]))
#endif
#endif
