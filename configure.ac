#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([xcb], [1.0.0], [mengxiaoye@dce.com.cn])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/xcb-wk2.c])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

# Checks for libraries.
# FIXME

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h    \
netinet/in.h stddef.h stdlib.h string.h strings.h sys/socket.h       \
sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([clock_gettime gethostbyname gettimeofday inet_ntoa   \
localtime_r memchr memmove memset mkdir munmap select socket         \
strcasecmp strchr strerror strncasecmp strspn strstr])

AC_CONFIG_FILES([Makefile
                 conf/Makefile
                 devel/Makefile
                 include/Makefile
                 src/Makefile
                 xspeed/Makefile])
AC_OUTPUT

echo "
######################################################################
($PACKAGE_NAME) Version $PACKAGE_VERSION
Prefix....: $prefix
Compiler..: $CC $CFLAGS $CPPFLAGS
Linker....: $LD $LDFLAGS $LIBS
######################################################################
"

