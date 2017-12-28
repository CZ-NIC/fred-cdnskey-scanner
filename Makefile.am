ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = \
		$(GETDNS_CPPFLAGS) \
		$(GETDNSEXTRA_CPPFLAGS) \
		$(LIBEVENT_CPPFLAGS) \
		$(BOOST_CPPFLAGS) \
		-I${srcdir}

AM_LDFLAGS = $(BOOST_LDFLAGS)

AM_CXXFLAGS = \
		$(GETDNS_CXXFLAGS) \
		$(GETDNSEXTRA_CXXFLAGS) \
		$(LIBEVENT_CXXFLAGS) \
		-fdiagnostics-color=always \
		-W \
		-Wall \
		-Wextra \
		-ggdb \
		-O0

SUBDIRS = .

bin_PROGRAMS = cdnskey-scanner

cdnskey_scanner_SOURCES = \
	src/main.cc \
	src/hostname_resolver.cc \
	src/insecure_cdnskey_resolver.cc \
	src/secure_cdnskey_resolver.cc \
	src/time_unit.cc \
	src/event/base.cc \
	src/getdns/error.cc \
	src/getdns/data.cc \
	src/getdns/context.cc \
	src/getdns/extensions.cc \
	src/getdns/rrtype.cc \
	src/getdns/solver.cc \
	src/util/pipe.cc \
	src/util/fork.cc \
	src/hostname_resolver.hh \
	src/time_unit.hh \
	src/getdns/transport.hh \
	src/getdns/data.hh \
	src/getdns/context.hh \
	src/getdns/extensions.hh \
	src/getdns/solver.hh \
	src/getdns/request.hh \
	src/getdns/error.hh \
	src/getdns/rrtype.hh \
	src/getdns/exception.hh \
	src/getdns/solver_fwd.hh \
	src/insecure_cdnskey_resolver.hh \
	src/secure_cdnskey_resolver.hh \
	src/hostname_resolver.hh \
	src/time_unit.hh \
	src/event/base.hh \
	src/util/fork.hh \
	src/util/pipe.hh \
	test/data.txt

cdnskey_scanner_LDADD = \
		$(GETDNS_LIBS) \
		$(GETDNSEXTRA_LIBS) \
		$(LIBEVENT_LIBS) \
		$(BOOST_SYSTEM_LIB)

check: $(bin_PROGRAMS)
	@./$(bin_PROGRAMS) 5 \
--hostname_resolvers "172.20.20.253" \
--cdnskey_resolvers "172.16.1.183" \
--dnssec_trust_anchors ". 257 3 8 \
AwEAAdAjHYjqJ6ovPqU+mVFrrvIaqPiQfmNRbv4LX/A0xqcgL\
ZjVC4Mw1bNgU+yvE4J3ICiYk2nKRdYY+9OmKdkb1o7Pl6K7uC\
q2PiIBFOtj610B+eS7xvhOp9JnXXKcCg/tgkMCAPZ89RczNmQ\
BJtFzjgytjNPNgl2a2ApOKXOVE5xFL6YcWW0p8rPdCnNE2HUQ\
wIJTnxkWf/cLY4gY21TWKIfsE024qXE+8jxbHIFpDzAG5VrnN\
E0yS2p24ad45IlhHHJI1K076lKOAXRpv7S7HE0JbTx3SxFcNr\
wRdX3WM/pkFxgBzrTk1bpcWWUbLX3mb5nZPv9v0RQ4qYoo11a\
xAU8=" < ${srcdir}/test/data.txt
