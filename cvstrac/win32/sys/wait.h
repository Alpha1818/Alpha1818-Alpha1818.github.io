/*
 * <sys/wait.h>
 *
 * Functions wait() and waitpid() returning always -1 on Windows. This is enough
 * to make the code to compile.
 *
 * $Id: wait.h,v 1.1 2007/11/03 02:00:08 ono Exp $
 */

#ifndef COMPAT_SYS_WAIT_H
#define COMPAT_SYS_WAIT_H

#define WHOHANG 0

#define wait(x) (-1)
#define waitpid(x, y, z) (-1)

#endif /* COMPAT_SYS_WAIT_H */
