dnl   Configuration script for guile-linux-key-retention.
dnl   Process this file with autoconf to produce configure.

define(GUILE_CONFIGURE_COPYRIGHT,[[

Copyright (C) 2016 Kirk Zurell.

This file is part of guile-linux-key-retention.

guile-linux-key-retention is free software; you can redistribute it
and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either version
3, or (at your option) any later version.

guile-linux-key-retention is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with GUILE; see the file COPYING.LESSER.  If not, write
to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
Floor, Boston, MA 02110-1301, USA.

]])

AC_INIT([guile-linux-key-retention], [0.0.1], [kirk@kirk.zurell.name])
AM_INIT_AUTOMAKE
LT_INIT

CFLAGS=""

dnl Recommended for libtoolize.
AC_CONFIG_MACRO_DIR([m4])

AC_CHECK_HEADERS([errno.h])
AC_CHECK_HEADERS([libguile.h])
AC_CHECK_HEADERS([keyutils.h])

AC_SEARCH_LIBS([scm_init_guile], [guile])
AC_SEARCH_LIBS([add_key], [keyutils])

# Find a C compiler.
AC_PROG_CC

# Check for Guile
PKG_CHECK_MODULES([GUILE], [guile-2.0],
  [guile_ext_dir=`pkg-config guile-2.0 --variable=extensiondir`]
)
GUILE_FLAGS
GUILE_SITE_DIR

# Generate a Makefile, based on the results.
AC_OUTPUT(Makefile)
