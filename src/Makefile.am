libpblc_la_SOURCES = pblc.c
lib_LTLIBRARIES = libpblc.la

pblcincludedir = $(includdir)/pblc
pblcinclude_HEADERS = pblc.h

#### UNIT TESTS #####
CLEANFILES = *.gcda *.gcno *_xunit.xml
noinst_PROGRAMS =
TESTS =

# tests
pblc_test_CFLAGS = $(UNITTEST_CFLAGS)
pblc_test_LDFLAGS = $(UNITTEST_LIBS)
pblc_test_SOURCES = pblc_test.c
TESTS += pblc_test

# --- End UNIT TEST

# Make TESTS be programs which are not installed
noinst_PROGRAMS += $(TESTS)
