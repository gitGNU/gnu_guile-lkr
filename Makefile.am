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


ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libguile-linux-key-retention.la
info_TEXINFOS = guile-linux-key-retention.texi

libguile_linux_key_retention_la_SOURCES = main.c
libguile_linux_key_retention_la_LDFLAGS = -export-dynamic

libguile_linux_key_retention_la_CFLAGS = $(GUILE_CFLAGS)
libguile_linux_key_retention_la_LIBADD = $(GUILE_LIBS) 
