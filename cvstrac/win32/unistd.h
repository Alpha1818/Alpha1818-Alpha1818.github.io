/* 
 * <unistd.h>
 *
 * Missing in Windows. Windows also misses strncasecmp().
 *
 * $Id: unistd.h,v 1.1 2007/11/03 02:00:08 ono Exp $
 */

#ifndef COMPAT_UNISTD_H
#define COMPAT_UNISTD_H

#define strncasecmp strnicmp

#endif /* COMPAT_UNISTD_H */
