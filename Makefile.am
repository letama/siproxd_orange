ACLOCAL_AMFLAGS = -I m4



pkglibdir = $(libdir)/siproxd

pkglib_LTLIBRARIES = plugin_orange.la

plugin_orange_la_SOURCES = src/plugin_orange.c src/plugin_orange.h \
			   src/auth.c src/auth.h \
			   src/base64.c src/base64.h \
			   src/md5.c src/md5.h \
			   src/salsa20-orange.c src/salsa20-orange.h \
			   src/salsa20-init_state.c src/salsa20-init_state.h \
			   src/utils.c src/utils.h src/sha1.c src/sha1.h

plugin_orange_la_CFLAGS = -g -Wall -Werror -I../src -lhybris-common

plugin_orange_la_LDFLAGS = -module



