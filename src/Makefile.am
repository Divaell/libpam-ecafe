# Copyright (C) 2009 Guillaume Viguier-Just
#
# Author: Guillaume Viguier-Just <guillaume@wedus.org>
#
# This file is part of pam_ecafe.
#
# pam_ecafe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pam_ecafe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pam_ecafe.  If not, see <http://www.gnu.org/licenses/>.

AM_CFLAGS = -DSBINDIR=\"@sbindir@\" @GLIB_CFLAGS@ @DBUS_GLIB_CFLAGS@

pamdir = @PAM_MODDIR@
pam_LTLIBRARIES = pam_ecafe.la

pam_ecafe_la_SOURCES = pam_ecafe.c
pam_ecafe_la_LDFLAGS = -module -avoid-version
pam_ecafe_la_LIBADD = @DBUS_GLIB_LIBS@ @GLIB_LIBS@
pam_ecafe_la_CFLAGS = $(AM_CFLAGS)

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@