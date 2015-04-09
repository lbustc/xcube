sbin_PROGRAMS = xcb-dp2 xcb-wk2 xcb-pb2 xcb-compact xcb-cli xcb-sim
xcb_dp2_SOURCES = mem.c dlist.c table.c ring.c heap.c dstr.c logger.c config.c \
event.c net.c thrpool.c pgmsock.c utilities.c networking.c basics.c xcb-dp2.c
xcb_dp2_CPPFLAGS = -I$(top_srcdir)/include -I/usr/include/pgm-5.1
xcb_dp2_CFLAGS = -Wall -Winline -pthread
xcb_dp2_LDFLAGS = -lrt -lpgm -ltcmalloc
xcb_wk2_SOURCES = mem.c dlist.c table.c ring.c heap.c dstr.c logger.c config.c \
event.c net.c loader.c thrpool.c db.c pgmsock.c utilities.c networking.c       \
basics.c xcb-wk2.c
xcb_wk2_CPPFLAGS = -I$(top_srcdir)/include -I/usr/include/pgm-5.1
xcb_wk2_CFLAGS = -Wall -Winline -pthread -rdynamic
xcb_wk2_LDFLAGS = -lrt -ldl -lm -lpgm -lleveldb -ltcmalloc
xcb_pb2_SOURCES = mem.c dlist.c table.c ring.c heap.c dstr.c logger.c config.c \
event.c net.c thrpool.c db.c pgmsock.c utilities.c networking.c basics.c       \
custom.c xcb-pb2.c
xcb_pb2_CPPFLAGS = -I$(top_srcdir)/include -I/usr/include/pgm-5.1
xcb_pb2_CFLAGS = -Wall -Winline -pthread
xcb_pb2_LDFLAGS = -lrt -lpgm -lleveldb -ltcmalloc
xcb_compact_SOURCES = mem.c dlist.c table.c ring.c heap.c dstr.c logger.c      \
config.c event.c net.c loader.c thrpool.c db.c utilities.c networking.c        \
basics.c custom.c xcb-compact.c
xcb_compact_CPPFLAGS = -I$(top_srcdir)/include
xcb_compact_CFLAGS = -Wall -Winline -pthread -rdynamic
xcb_compact_LDFLAGS = -lrt -ldl -lm -lleveldb -ltcmalloc
xcb_cli_SOURCES = mem.c dstr.c net.c xcb-cli.c
xcb_cli_CPPFLAGS = -I$(top_srcdir)/include
xcb_cli_CFLAGS = -Wall -pthread
xcb_cli_LDFLAGS = -lreadline -ltermcap -ltcmalloc
xcb_sim_SOURCES = mem.c dstr.c net.c xcb-sim.c
xcb_sim_CPPFLAGS = -I$(top_srcdir)/include
xcb_sim_CFLAGS = -Wall -pthread
xcb_sim_LDFLAGS = -ltcmalloc

lib_LTLIBRARIES = app_test.la app_pd.la app_kline.la
app_test_la_SOURCES = app_test.c
app_test_la_CPPFLAGS = -I$(top_srcdir)/include
app_test_la_CFLAGS = -fPIC -Wall
app_test_la_LDFLAGS = -module -avoid-version -ltcmalloc
app_pd_la_SOURCES = app_pd.c
app_pd_la_CPPFLAGS = -I$(top_srcdir)/include
app_pd_la_CFLAGS = -fPIC -Wall -pthread
app_pd_la_LDFLAGS = -module -avoid-version -ltcmalloc
app_kline_la_SOURCES = app_kline.c
app_kline_la_CPPFLAGS = -I$(top_srcdir)/include
app_kline_la_CFLAGS = -fPIC -Wall -pthread
app_kline_la_LDFLAGS = -module -avoid-version -ltcmalloc

