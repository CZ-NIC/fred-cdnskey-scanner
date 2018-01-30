cmake_minimum_required(VERSION 2.8)

# CentOS 7 contains cmake 2.8.12 and boost 1.53.0 (these are _not_ in the devtoolset)

project(cdnskey-scanner CXX)

set(cdnskey-scanner_VERSION_MAJOR 1)
set(cdnskey-scanner_VERSION_MINOR 0)
set(cdnskey-scanner_VERSION_PATCH 2)

add_executable(cdnskey-scanner src/main.cc)

target_sources(cdnskey-scanner
	PRIVATE src/main.cc
	PRIVATE src/hostname_resolver.cc
	PRIVATE src/insecure_cdnskey_resolver.cc
	PRIVATE src/secure_cdnskey_resolver.cc
	PRIVATE src/time_unit.cc
	PRIVATE src/event/base.cc
	PRIVATE src/getdns/error.cc
	PRIVATE src/getdns/data.cc
	PRIVATE src/getdns/context.cc
	PRIVATE src/getdns/extensions.cc
	PRIVATE src/getdns/rrtype.cc
	PRIVATE src/getdns/solver.cc
	PRIVATE src/util/pipe.cc
	PRIVATE src/util/fork.cc
	PRIVATE src/hostname_resolver.hh
	PRIVATE src/time_unit.hh
	PRIVATE src/getdns/transport.hh
	PRIVATE src/getdns/data.hh
	PRIVATE src/getdns/context.hh
	PRIVATE src/getdns/extensions.hh
	PRIVATE src/getdns/solver.hh
	PRIVATE src/getdns/request.hh
	PRIVATE src/getdns/error.hh
	PRIVATE src/getdns/rrtype.hh
	PRIVATE src/getdns/exception.hh
	PRIVATE src/getdns/solver_fwd.hh
	PRIVATE src/insecure_cdnskey_resolver.hh
	PRIVATE src/secure_cdnskey_resolver.hh
	PRIVATE src/hostname_resolver.hh
	PRIVATE src/time_unit.hh
	PRIVATE src/event/base.hh
	PRIVATE src/util/fork.hh
	PRIVATE src/util/pipe.hh
	PRIVATE test/data.txt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -std=c++14 -ggdb -Wall -Wextra -fdiagnostics-color=auto")

include_directories("." PRIVATE)

find_package(Boost 1.53.0 COMPONENTS system REQUIRED)
target_link_libraries(cdnskey-scanner ${Boost_SYSTEM_LIBRARY})
target_include_directories(cdnskey-scanner PUBLIC ${Boost_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)

pkg_search_module(GETDNS REQUIRED getdns>=1.2.1)
target_include_directories(cdnskey-scanner PUBLIC ${GETDNS_INCLUDE_DIRS})
target_compile_options(cdnskey-scanner PUBLIC ${GETDNS_CXXFLAGS})
target_link_libraries(cdnskey-scanner ${GETDNS_LIBRARIES})

pkg_search_module(GETDNSEXTRA REQUIRED getdns_ext_event>=1.2.1)
target_include_directories(cdnskey-scanner PUBLIC ${GETDNSEXTRA_INCLUDE_DIRS})
target_compile_options(cdnskey-scanner PUBLIC ${GETDNSEXTRA_CXXFLAGS})
target_link_libraries(cdnskey-scanner ${GETDNSEXTRA_LIBRARIES})

pkg_search_module(LIBEVENT REQUIRED libevent>=2.0.0)
target_include_directories(cdnskey-scanner PUBLIC ${LIBEVENT_INCLUDE_DIRS})
target_compile_options(cdnskey-scanner PUBLIC ${LIBEVENT_CXXFLAGS})
target_link_libraries(cdnskey-scanner ${LIBEVENT_LIBRARIES})
