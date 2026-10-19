#pragma once

#if defined(SODIUM_VMPROTECT)

#include <VMProtectSDK.h>

#define SODIUM_VMP_MUTATION(tag)   VMProtectBeginMutation(tag)
#define SODIUM_VMP_VIRTUALIZE(tag) VMProtectBeginVirtualization(tag)
#define SODIUM_VMP_ULTRA(tag)      VMProtectBeginUltra(tag)
#define SODIUM_VMP_END()           VMProtectEnd()

#else

#define SODIUM_VMP_MUTATION(tag)   ((void)0)
#define SODIUM_VMP_VIRTUALIZE(tag) ((void)0)
#define SODIUM_VMP_ULTRA(tag)      ((void)0)
#define SODIUM_VMP_END()           ((void)0)

#endif