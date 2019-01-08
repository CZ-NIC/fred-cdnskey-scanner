cmake_minimum_required(VERSION 3.5)

find_program(GIT_PROGRAM git)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

set(program_name cdnskey-scanner)
project(${program_name} CXX)

macro(set_default variable_name variable_value)
    if(NOT ${variable_name})
        set(${variable_name} ${variable_value})
    endif()
endmacro()

set_default(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set_default(TARBALL_FILE_NAME fred-cdnskey-scanner)

if(NOT VERSION)
    execute_process(COMMAND "git" "describe" "--tags"
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                    OUTPUT_VARIABLE RAWVERSION)
    string(REGEX REPLACE "(-.*)?\n" "" VERSION "${RAWVERSION}")
endif()

add_executable(${program_name} src/main.cc)

target_sources(${program_name}
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

set_target_properties(${program_name} PROPERTIES
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_compile_options(${program_name}
    PRIVATE -O2
    PRIVATE -ggdb
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -fdiagnostics-color=auto
)

include_directories("${CMAKE_SOURCE_DIR}" PRIVATE)

find_package(Boost 1.53.0 COMPONENTS system REQUIRED)
target_link_libraries(${program_name} ${Boost_SYSTEM_LIBRARY})
target_include_directories(${program_name} PUBLIC ${Boost_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)

pkg_search_module(GETDNS REQUIRED getdns>=1.2.1)
target_include_directories(${program_name} PUBLIC ${GETDNS_INCLUDE_DIRS})
target_compile_options(${program_name} PUBLIC ${GETDNS_CXXFLAGS})
target_link_libraries(${program_name} ${GETDNS_LIBRARIES})

pkg_search_module(GETDNSEXTRA REQUIRED getdns_ext_event>=1.2.1)
target_include_directories(${program_name} PUBLIC ${GETDNSEXTRA_INCLUDE_DIRS})
target_compile_options(${program_name} PUBLIC ${GETDNSEXTRA_CXXFLAGS})
target_link_libraries(${program_name} ${GETDNSEXTRA_LIBRARIES})

pkg_search_module(LIBEVENT REQUIRED libevent>=2.0.0)
target_include_directories(${program_name} PUBLIC ${LIBEVENT_INCLUDE_DIRS})
target_compile_options(${program_name} PUBLIC ${LIBEVENT_CXXFLAGS})
target_link_libraries(${program_name} ${LIBEVENT_LIBRARIES})

include(CheckIncludeFileCXX)

function(abort_if_headers_not_found)
    foreach(header_name ${ARGN})
        check_include_file_cxx(${header_name} FOUND${header_name})
        if(NOT FOUND${header_name})
            message(FATAL_ERROR "Header ${header_name} not found!")
        endif()
    endforeach()
endfunction()

abort_if_headers_not_found(
    fcntl.h
    sys/time.h
    sys/stat.h
    sys/resource.h
    sys/types.h
    sys/wait.h
    event2/event.h
    getdns/getdns_ext_libevent.h
    getdns/getdns_extra.h
    getdns/getdns.h
    boost/archive/iterators/base64_from_binary.hpp
    boost/archive/iterators/binary_from_base64.hpp
    boost/archive/iterators/ostream_iterator.hpp
    boost/archive/iterators/transform_width.hpp
    boost/algorithm/string/classification.hpp
    boost/algorithm/string.hpp
    boost/algorithm/string/predicate.hpp
    boost/algorithm/string/split.hpp
    #boost/asio/ip/address.hpp
    boost/lexical_cast.hpp
    boost/optional.hpp
    boost/variant.hpp
    boost/variant/variant.hpp
)

include(CheckFunctionExists)
function(abort_if_functions_not_found function_name)
    foreach(function_name ${ARGN})
        check_function_exists(${function_name} FOUND${function_name})
        if(NOT FOUND${function_name})
            message(FATAL_ERROR "Function ${function_name} not found!")
        endif()
    endforeach()
endfunction()

abort_if_functions_not_found(
    clock_gettime
    dup2
    strerror
    read
    close
    fork
    waitpid
    kill
)

install(TARGETS ${program_name} DESTINATION bin)
add_custom_target(uninstall COMMAND rm ${CMAKE_INSTALL_PREFIX}/bin/${program_name})

enable_testing()
add_test(NAME smoke
         COMMAND bash ${CMAKE_SOURCE_DIR}/test/smoke.sh ./${program_name})

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)


if(EXISTS ${CMAKE_SOURCE_DIR}/.git AND GIT_PROGRAM)
    if(NOT TARGET dist)
        add_custom_target(dist
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${TARBALL_FILE_NAME}/ HEAD | gzip > ${CMAKE_BINARY_DIR}/${TARBALL_FILE_NAME}.tar.gz
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    endif()

    if(NOT TARGET distcheck)
        set(DISTCHECK_BUILD_DIR "_build")
        set(DISTCHECK_INSTALL_DIR "_inst")
        if(${CMAKE_GENERATOR} STREQUAL "Ninja")
            set(DISTCHECK_BUILD_CMD "ninja")
            set(DISTCHECK_MAKEFLAGS "")
        else()
            set(DISTCHECK_BUILD_CMD "make")
            execute_process(COMMAND "grep" "-c" "model name" "/proc/cpuinfo"
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_VARIABLE NOCPUS)
            string(REGEX REPLACE "\n" "" NOCPUS ${NOCPUS})
            set(DISTCHECK_MAKEFLAGS "MAKEFLAGS=-j${NOCPUS}")
        endif()
        add_custom_target(distcheck
            COMMAND
            rm -rf ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR} ${TARBALL_FILE_NAME}
            && mkdir ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR}
            && (tar xzf ${TARBALL_FILE_NAME}.tar.gz
                || (echo 'Error: failed to unpack the archive' 2>&1\; false))
            && (cd ${DISTCHECK_BUILD_DIR}
                && (cmake -G${CMAKE_GENERATOR} -DCMAKE_INSTALL_PREFIX=../${DISTCHECK_INSTALL_DIR} ../${TARBALL_FILE_NAME}
                    || (echo 'Error: failed to configure the archive' 2>&1\; false))
                && (${DISTCHECK_MAKEFLAGS} ${DISTCHECK_BUILD_CMD}
                    || (echo 'Error: the build target failed ' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} install
                    || (echo 'Error: the install target failed' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} uninstall
                    || (echo 'Error: the uninstall target failed' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} clean
                    || (echo 'Error: the clean target failed' 2>&1\; false)))
            && rm -rf ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR} ${TARBALL_FILE_NAME}
            && echo 'PASS: ' ${TARBALL_FILE_NAME}.tar.gz 'is ready for distribution.'
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Checking the distribution archive...")
        add_dependencies(distcheck dist)
    endif()
else()
    message(STATUS "no git -- not including dist and distcheck targets")
endif()
