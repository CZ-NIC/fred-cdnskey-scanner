AC_PREREQ([2.59])
AC_INIT([cdnskey-scanner], [1.0.0])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([src/main.cc])
AC_CONFIG_MACRO_DIR([m4])

AC_LANG(C++)

: ${CFLAGS=""}   AC_PROG_CC
: ${CXXFLAGS=""} AC_PROG_CXX

AX_BOOST_BASE
AX_BOOST_SYSTEM

PKG_CHECK_MODULES(GETDNS, [getdns >= 1.1.2])
PKG_CHECK_MODULES(GETDNSEXTRA, [getdns_ext_event >= 1.1.2])
PKG_CHECK_MODULES(LIBEVENT, [libevent >= 2.0.0])

AC_CHECK_FUNCS([clock_gettime],,[AC_MSG_ERROR([Function clock_gettime not found])])
AC_CHECK_FUNCS([dup2],,[AC_MSG_ERROR([Function dup2 not found])])
AC_CHECK_FUNCS([strerror],,[AC_MSG_ERROR([Function strerror not found])])
AC_CHECK_FUNCS([read],,[AC_MSG_ERROR([Function read not found])])
AC_CHECK_FUNCS([close],,[AC_MSG_ERROR([Function close not found])])
AC_CHECK_FUNCS([fork],,[AC_MSG_ERROR([Function fork not found])])
AC_CHECK_FUNCS([waitpid],,[AC_MSG_ERROR([Function waitpid not found])])
AC_CHECK_FUNCS([kill],,[AC_MSG_ERROR([Function kill not found])])

AC_CHECK_HEADER([fcntl.h],,[AC_MSG_ERROR([Header fcntl.h not found])])
AC_CHECK_HEADER([stdint.h],,[AC_MSG_ERROR([Header stdint.h not found])])
AC_CHECK_HEADER([signal.h],,[AC_MSG_ERROR([Header signal.h not found])])
AC_CHECK_HEADER([time.h],,[AC_MSG_ERROR([Header time.h not found])])
AC_CHECK_HEADER([sys/time.h],,[AC_MSG_ERROR([Header sys/time.h not found])])
AC_CHECK_HEADER([sys/stat.h],,[AC_MSG_ERROR([Header sys/stat.h not found])])
AC_CHECK_HEADER([sys/resource.h],,[AC_MSG_ERROR([Header sys/resource.h not found])])
AC_CHECK_HEADER([sys/types.h],,[AC_MSG_ERROR([Header sys/types.h not found])])
AC_CHECK_HEADER([sys/wait.h],,[AC_MSG_ERROR([Header sys/wait.h not found])])
AC_CHECK_HEADER([unistd.h],,[AC_MSG_ERROR([Header unistd.h not found])])

AC_CHECK_HEADER([boost/archive/iterators/base64_from_binary.hpp],,[AC_MSG_ERROR([Header boost/archive/iterators/base64_from_binary.hpp not found])])
AC_CHECK_HEADER([boost/archive/iterators/binary_from_base64.hpp],,[AC_MSG_ERROR([Header boost/archive/iterators/binary_from_base64.hpp not found])])
AC_CHECK_HEADER([boost/archive/iterators/ostream_iterator.hpp],,[AC_MSG_ERROR([Header boost/archive/iterators/ostream_iterator.hpp not found])])
AC_CHECK_HEADER([boost/archive/iterators/transform_width.hpp],,[AC_MSG_ERROR([Header boost/archive/iterators/transform_width.hpp not found])])
AC_CHECK_HEADER([boost/algorithm/string/classification.hpp],,[AC_MSG_ERROR([Header boost/algorithm/string/classification.hpp not found])])
AC_CHECK_HEADER([boost/algorithm/string.hpp],,[AC_MSG_ERROR([Header boost/algorithm/string.hpp not found])])
AC_CHECK_HEADER([boost/algorithm/string/predicate.hpp],,[AC_MSG_ERROR([Header boost/algorithm/string/predicate.hpp not found])])
AC_CHECK_HEADER([boost/algorithm/string/split.hpp],,[AC_MSG_ERROR([Header boost/algorithm/string/split.hpp not found])])
AC_CHECK_HEADER([boost/asio/ip/address.hpp],,[AC_MSG_ERROR([Header boost/asio/ip/address.hpp not found])])
AC_CHECK_HEADER([boost/lexical_cast.hpp],,[AC_MSG_ERROR([Header boost/lexical_cast.hpp not found])])
AC_CHECK_HEADER([boost/noncopyable.hpp],,[AC_MSG_ERROR([Header boost/noncopyable.hpp not found])])
AC_CHECK_HEADER([boost/optional.hpp],,[AC_MSG_ERROR([Header boost/optional.hpp not found])])
AC_CHECK_HEADER([boost/shared_ptr.hpp],,[AC_MSG_ERROR([Header boost/shared_ptr.hpp not found])])
AC_CHECK_HEADER([boost/variant.hpp],,[AC_MSG_ERROR([Header boost/variant.hpp not found])])
AC_CHECK_HEADER([boost/variant/variant.hpp],,[AC_MSG_ERROR([Header boost/variant/variant.hpp not found])])

AC_CHECK_HEADER([event2/event.h],,[AC_MSG_ERROR([Header event2/event.h not found])])

AC_CHECK_HEADER([getdns/getdns_ext_libevent.h],,[AC_MSG_ERROR([Header getdns/getdns_ext_libevent.h not found])])
AC_CHECK_HEADER([getdns/getdns_extra.h],,[AC_MSG_ERROR([Header getdns/getdns_extra.h not found])])
AC_CHECK_HEADER([getdns/getdns.h],,[AC_MSG_ERROR([Header getdns/getdns.h not found])])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

