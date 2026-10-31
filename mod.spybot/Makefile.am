## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES += libspybot.la
libspybot_la_SOURCES = mod.spybot/spybot.cc
libspybot_la_LDFLAGS = -module -export-dynamic
libspybot_la_CXXFLAGS = -I$(top_srcdir)/include \
	-I$(top_srcdir)/libgnuworld \
	-I$(top_srcdir)/libnotifier

EXTRA_DIST += \
	mod.spybot/spybot.h
