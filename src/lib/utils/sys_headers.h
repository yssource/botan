
#ifndef BOTAN_SYSTEM_HEADERS_H_
#define BOTAN_SYSTEM_HEADERS_H_

#include <botan/types.h>

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_ // stop windows.h including winsock.h
   #include <windows.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <sys/types.h>
   #include <sys/mman.h>
   #include <sys/resource.h>
   #include <sys/stat.h>
   #include <sys/time.h>
   #include <dirent.h>
   #include <dlfcn.h>
   #include <errno.h>
   #include <fcntl.h>
   #include <setjmp.h>
   #include <signal.h>
   #include <stdlib.h>
   #include <termios.h>
   #include <unistd.h>
   #undef B0
#endif

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <netdb.h>
#elif defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   #include <ws2tcpip.h>
#endif

#if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
  #include <sys/sysctl.h>
#endif

#endif
