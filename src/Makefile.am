lib_LTLIBRARIES = libpblc.la
libpblc_la_SOURCES = pblc.c msg.c
libpblc_la_LDFLAGS = $(MSGPACK_LIBS)
libpblc_la_CFLAGS = $(MSGPACK_CFLAGS)

pblcincludedir = $(includedir)/pblc
pblcinclude_HEADERS = pblc.h

AM_CFLAGS = -Wall -Werror

#### UNIT TESTS #####
CLEANFILES = *.gcda *.gcno *_xunit.xml
noinst_PROGRAMS =
TESTS =

# tests
pblc_test_CFLAGS = $(UNITTEST_CFLAGS)
pblc_test_LDFLAGS = $(UNITTEST_LIBS)
pblc_test_SOURCES = pblc_test.c
TESTS += pblc_test

# msg tests
msg_test_CFLAGS = $(UNITTEST_CFLAGS) $(MSGPACK_CFLAGS)
msg_test_LDFLAGS = $(UNITTEST_LIBS) $(MSGPACK_LIBS)
msg_test_SOURCES = msg_test.c msg.c
TESTS += msg_test

# --- End UNIT TEST

# Make TESTS be programs which are not installed
noinst_PROGRAMS += $(TESTS)
