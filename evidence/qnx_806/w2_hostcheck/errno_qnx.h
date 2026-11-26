/* errno_qnx.h - host check: gives the macOS build the QNX 8.0.6 numbers of the seven errno names whose values differ (SDK errno.h lines 64, 104, 168-169 and the ones below).
   Included with -include; <errno.h> is pulled in first so that its include guard keeps the system header from redefining the names. */
#include <errno.h>
#undef ETIME
#define ETIME 62
#undef ECANCELED
#define ECANCELED 47
#undef EALREADY
#define EALREADY 237
#undef ENOMSG
#define ENOMSG 35
#undef EBADMSG
#define EBADMSG 77
#undef ESTALE
#define ESTALE 122
#ifndef EBADE
#define EBADE 50
#endif
