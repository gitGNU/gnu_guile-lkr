## Process this file with automake to produce Makefile.in.
##
##  	Copyright (C) 2016 Kirk Zurell.
##
##   guile-linux-key-retention is free software; you can redistribute
##   it and/or modify it under the terms of the GNU Lesser General
##   Public License as published by the Free Software Foundation;
##   either version 3, or (at your option) any later version.
##
##   guile-linux-key-retention is distributed in the hope that it will
##   be useful, but WITHOUT ANY WARRANTY; without even the implied
##   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
##   See the GNU Lesser General Public License for more details.
##
##   You should have received a copy of the GNU Lesser General Public
##   License along with guile-linux-key-retention; see the file
##   COPYING.LESSER. If not, write to the Free Software Foundation,
##   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# Because srcdir might be read-only.
#VPATH = $(srcdir) $(builddir)

ACLOCAL_AMFLAGS = -I m4

guile_ext_ddir = $(GUILE_EXT_DIR)
lib_LTLIBRARIES = libguile-linux-key-retention.la
#guile_ext_d_LTLIBRARIES = libguile-linux-key-retention.la
info_TEXINFOS = guile-linux-key-retention.texi

# Create Guile gsubrs through snarfing.
main.x : $(srcdir)/main.c

libguile_linux_key_retention_la_SOURCES = main.c
nodist_libguile_linux_key_retention_la_SOURCES = main.x 
libguile_linux_key_retention_la_LDFLAGS = -export-dynamic

libguile_linux_key_retention_la_CFLAGS = $(GUILE_CFLAGS)
libguile_linux_key_retention_la_LIBADD = $(GUILE_LIBS) 

EXTRA_DIST = guile-lkr-debug guile-lkr.conf guile-linux-key-retention.scm

dist_bin_SCRIPTS = guile-lkr-debug

guilelkrsite_ddir = @GUILE_SITE@/linux-key-retention
dist_guilelkrsite_d_SCRIPTS = guile-linux-key-retention.scm

#rkconf_ddir = $(sysconfdir)/request-key.d
rkconf_ddir = /etc/request-key.d
dist_rkconf_d_SCRIPTS = guile-lkr.conf


# For snarfing Guile functions.
snarfcppopts = $(DEFS) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) $(GUILE_CFLAGS)
SUFFIXES = .x
.c.x:
	guile-snarf -o $@ $< $(snarfcppopts)
