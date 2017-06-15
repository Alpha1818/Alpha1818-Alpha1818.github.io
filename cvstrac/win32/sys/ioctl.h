/*
 * <sys/ioctl.h>
 *
 * Overrides ioctl() with ioctlsocket(). Plain #define
 * is not enough because of last parameter incompatibility of both functions.
 *
 * $Id: ioctl.h,v 1.1 2007/11/03 02:00:08 ono Exp $
 */

#ifndef COMPAT_SYS_IOCTL_H
#define COMPAT_SYS_IOCTL_H

#include <winioctl.h>
#include <stdarg.h>

#ifndef __WINSOCKIOCTL__
#define __WINSOCKIOCTL__
static inline int ioctl(int fd, int request, ...)
{
  va_list ap;
  unsigned long *foo;

  va_start(ap, request);
  foo = va_arg(ap, unsigned long*);
  va_end(ap);

  return ioctlsocket(fd, request, foo);

}
#endif

#endif /* COMPAT_SYS_IOCTL_H */
