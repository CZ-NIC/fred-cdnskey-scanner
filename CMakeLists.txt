cmake_minimum_required(VERSION 2.8)

# CentOS 7 contains cmake 2.8.12 and boost 1.53.0 (these are _not_ in the devtoolset)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

project(cdnskey-scanner CXX)

if(NOT VERSION)
    execute_process(COMMAND "git" "describe"
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                    OUTPUT_VARIABLE RAWVERSION)
    string(REGEX REPLACE "-.*\n" "" VERSION ${RAWVERSION})
endif()

add_executable(cdnskey-scanner src/main.cc
	src/hostname_resolver.cc
	src/insecure_cdnskey_resolver.cc
	src/secure_cdnskey_resolver.cc
	src/time_unit.cc
	src/event/base.cc
	src/getdns/error.cc
	src/getdns/data.cc
	src/getdns/context.cc
	src/getdns/extensions.cc
	src/getdns/rrtype.cc
	src/getdns/solver.cc
	src/util/pipe.cc
	src/util/fork.cc
	src/hostname_resolver.hh
	src/time_unit.hh
	src/getdns/transport.hh
	src/getdns/data.hh
	src/getdns/context.hh
	src/getdns/extensions.hh
	src/getdns/solver.hh
	src/getdns/request.hh
	src/getdns/error.hh
	src/getdns/rrtype.hh
	src/getdns/exception.hh
	src/getdns/solver_fwd.hh
	src/insecure_cdnskey_resolver.hh
	src/secure_cdnskey_resolver.hh
	src/hostname_resolver.hh
	src/time_unit.hh
	src/event/base.hh
	src/util/fork.hh
	src/util/pipe.hh
	test/data.txt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -std=c++14 -ggdb -Wall -Wextra -fdiagnostics-color=auto")

include_directories("${CMAKE_SOURCE_DIR}" PRIVATE)

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

install(TARGETS cdnskey-scanner DESTINATION bin)

enable_testing()
add_test(NAME smoke
         COMMAND bash ${CMAKE_SOURCE_DIR}/test/smoke.sh ./cdnskey-scanner)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)

SET(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_SOURCE_IGNORE_FILES "_CPack_Packages;CMakeCache;CPack*;cmake_install.cmake;CMakeFiles;CTestTestfile*;.git*")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "cdnskey-scanner-${VERSION}")
include(CPack)
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
