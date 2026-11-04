## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES += libproxyscan.la
libproxyscan_la_SOURCES = mod.proxyscan/proxyscan.cc
libproxyscan_la_LDFLAGS = -module -export-dynamic
libproxyscan_la_CXXFLAGS = -I$(top_srcdir)/include \
	-I$(top_srcdir)/libgnuworld \
	-I$(top_srcdir)/libnotifier

EXTRA_DIST += \
	mod.proxyscan/proxyscan.h
