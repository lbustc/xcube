sbin_PROGRAMS = xcb-exp
xcb_exp_SOURCES = $(top_srcdir)/src/mem.c $(top_srcdir)/src/logger.c           \
$(top_srcdir)/src/config.c xcb-exp.cpp
xcb_exp_CPPFLAGS = -I$(top_srcdir)/include
xcb_exp_CFLAGS = -Wall -Winline
xcb_exp_LDADD = DFITCTraderApi.so
xcb_exp_LDFLAGS = -ltcmalloc

