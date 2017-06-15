/*
 * <sys/socket.h>
 *
 * Wrappers for socket functions present on UNIX but not directly available on
 * Windows.
 *
 * $Id: socket.h,v 1.1 2007/11/03 02:00:08 ono Exp $
 */

#ifndef COMPAT_SYS_SOCKET_H
#define COMPAT_SYS_SOCKET_H

#include <winsock2.h>

/* Force linking with WinSock library */
#ifdef _MSC_VER
# pragma link "Ws2_32.lib"
#endif

#define write(handle,buf,len) send(handle,(void *)buf,len,0)
#define read(handle,buf,len) recv(handle,(void *)buf,len,0)
#define close(handle) closesocket(handle)

#undef EINPROGRESS
#undef ENOTCONN
#undef EINTR
#define EINPROGRESS WSAEINPROGRESS
#define ENOTCONN WSAENOTCONN
#define EINTR WSAEINTR
#define vsnprintf _vsnprintf
#define snprintf _snprintf
#define socklen_t int
#define fork() (-1)
#endif /* COMPAT_SYS_SOCKET_H */
