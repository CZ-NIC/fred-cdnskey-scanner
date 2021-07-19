cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

if (POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif ()

# The following must be set BEFORE doing project() or enable_language().
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type defined; defaulting to 'Debug'")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "The type of build. Possible values are: Debug, Release, RelWithDebInfo and MinSizeRel.")
endif ()

set(PACKAGE "fred-cdnskey-scanner")
set(PACKAGE_NAME "cdnskey-scanner")
set(PACKAGE_VERSION "2.0.0")
set(PACKAGE_BUGREPORT "devops@nic.cz")
set(PACKAGE_URL "https://gitlab.office.nic.cz/fred/cdnskey-scanner")

# Dont forget to put a dash in front of the release candidate!!!
# That is how it is done with semantic versioning!
set(RELEASE_CANDIDATE "~rc1")

set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}${RELEASE_CANDIDATE}")
set(PACKAGE_TARNAME "${PACKAGE}-${PACKAGE_VERSION}${RELEASE_CANDIDATE}")

set(CDNSKEY_SCANNER_VERSION "${PACKAGE_VERSION}${RELEASE_CANDIDATE}")
set(CDNSKEY_SCANNER_NUMERIC_VERSION 0x02000001)


project(CdnskeyScanner VERSION ${PACKAGE_VERSION} LANGUAGES CXX)

find_program(GIT_PROGRAM git)

macro(normalize_path variable_name variable_value)
    string(REGEX REPLACE "//+" "/" "${variable_name}" "${variable_value}")
    if(NOT "${${variable_name}}" STREQUAL "/")
        string(REGEX REPLACE "/$" "" "${variable_name}" "${${variable_name}}")
    endif()
endmacro()

macro(set_default_path variable_name variable_value)
    if(NOT ${variable_name})
        normalize_path(${variable_name} ${variable_value})
    endif()
endmacro()

normalize_path(NORMALIZED_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
if("${NORMALIZED_INSTALL_PREFIX}" STREQUAL "/usr/local")
    set(USR_PREFIX "")
    set(USR_SHARE_PREFIX "")
else()
    set(USR_SHARE_PREFIX "/usr")
    if(USE_USR_PREFIX)
        set(USR_PREFIX "/usr")
    else()
        set(USR_PREFIX "")
    endif()
endif()

option(CMAKE_EXPORT_COMPILE_COMMANDS "If enabled, generates a compile_commands.json file containing the exact compiler calls." ON)
set_default_path(BINDIR ${CMAKE_INSTALL_PREFIX}/${USR_PREFIX}/bin)

add_executable(cdnskey-scanner
    src/hostname_resolver.cc
    src/insecure_cdnskey_resolver.cc
    src/main.cc
    src/secure_cdnskey_resolver.cc
    src/time_unit.cc
    src/event/base.cc
    src/getdns/exception.cc
    src/getdns/extensions_set.cc
    src/getdns/data.cc
    src/getdns/context.cc
    src/util/fork.cc
    src/util/pipe.cc)

set_target_properties(cdnskey-scanner PROPERTIES
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

target_compile_options(cdnskey-scanner
    PRIVATE
        $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -O2 -fdiagnostics-color=auto -ggdb -grecord-gcc-switches>)

find_package(Boost 1.53.0 COMPONENTS system REQUIRED)
target_link_libraries(cdnskey-scanner Boost::system)
target_include_directories(cdnskey-scanner PUBLIC ${CMAKE_SOURCE_DIR})

set(3RD_PARTY_GETDNS_DIR ${CMAKE_SOURCE_DIR}/3rd_party/getdns CACHE STRING "Source directory of getdns.")
if(NOT EXISTS ${3RD_PARTY_GETDNS_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "Sources of 'getdns' not found, no ${3RD_PARTY_GETDNS_DIR}/CMakeLists.txt exists. "
                        "Use -D3RD_PARTY_GETDNS_DIR=<path_to_getdns> to specify location of 'getdns'.")
endif()

include(CMakeDependentOption)
option(ENABLE_SHARED "Build shared libraries." OFF)
option(ENABLE_STATIC "Build static libraries." ON)
option(ENABLE_DEBUG_ALL "Enable all debugging messages." OFF)
option(ENABLE_UNBOUND_EVENT_API "Enable usage of libunbound's event API." OFF)
cmake_dependent_option(ENABLE_DEBUG_REQ "Enable request debugging messages." OFF "NOT ENABLE_DEBUG_ALL" ON)
cmake_dependent_option(ENABLE_DEBUG_SCHED "Enable scheduling debugging messages." OFF "NOT ENABLE_DEBUG_ALL" ON)
cmake_dependent_option(ENABLE_DEBUG_STUB "Enable stub debugging messages." OFF "NOT ENABLE_DEBUG_ALL" ON)
cmake_dependent_option(ENABLE_DEBUG_DAEMON "Enable daemon debugging messages." OFF "NOT ENABLE_DEBUG_ALL" ON)
cmake_dependent_option(ENABLE_DEBUG_DNSSEC "Enable DNSSEC debugging messages." OFF "NOT ENABLE_DEBUG_ALL" ON)
cmake_dependent_option(ENABLE_DEBUG_SERVER "Enable server debugging messages." OFF "NOT ENABLE_DEBUG_ALL" ON)
cmake_dependent_option(ENABLE_DEBUG_ANCHOR "Enable anchor debugging messages." OFF "NOT ENABLE_DEBUG_ALL" ON)
option(BUILD_DOXYGEN "Build source documentation." OFF)
option(BUILD_EXAMPLES "Compile the example programs." OFF)
option(BUILD_GETDNS_QUERY "Compile and install the getdns_query tool." OFF)
option(BUILD_GETDNS_SERVER_MON "Compile and install the getdns_server_mon tool." OFF)
option(BUILD_STUBBY "Compile and install stubby, the (stub) resolver daemon." OFF)
option(BUILD_LIBEV "Build libev support library if available." OFF)
option(BUILD_LIBEVENT2 "Build libevent2 support library if available." ON)
option(BUILD_LIBUV "Build libuv support library available." OFF)
add_subdirectory(${3RD_PARTY_GETDNS_DIR} 3rd_party/getdns EXCLUDE_FROM_ALL)
target_link_libraries(cdnskey-scanner
    getdns
    getdns_ext_event)

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
    boost/archive/iterators/base64_from_binary.hpp
    boost/archive/iterators/binary_from_base64.hpp
    boost/archive/iterators/ostream_iterator.hpp
    boost/archive/iterators/transform_width.hpp
    boost/algorithm/string/classification.hpp
    boost/algorithm/string.hpp
    boost/algorithm/string/predicate.hpp
    boost/algorithm/string/split.hpp
    boost/lexical_cast.hpp
    boost/optional.hpp)

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
    dup2
    strerror
    read
    close
    fork
    waitpid
    kill)

install(TARGETS cdnskey-scanner DESTINATION ${BINDIR})
add_custom_target(uninstall COMMAND rm ${BINDIR}/cdnskey-scanner)

enable_testing()
add_test(NAME smoke
         COMMAND bash ${CMAKE_SOURCE_DIR}/test/smoke.sh ./${program_name})

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)


if(EXISTS ${CMAKE_SOURCE_DIR}/.git AND GIT_PROGRAM)
    if(NOT TARGET dist)
        add_custom_target(dist_getdns
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${PACKAGE_TARNAME}/3rd_party/getdns/ HEAD > ${CMAKE_BINARY_DIR}/.getdns.tar
            WORKING_DIRECTORY ${3RD_PARTY_GETDNS_DIR})
        add_custom_target(dist_getdns_jsmn
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${PACKAGE_TARNAME}/3rd_party/getdns/src/jsmn/ HEAD > ${CMAKE_BINARY_DIR}/.getdns_jsmn.tar
            WORKING_DIRECTORY ${3RD_PARTY_GETDNS_DIR}/src/jsmn)
        add_custom_target(dist_getdns_ssl_dane
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${PACKAGE_TARNAME}/3rd_party/getdns/src/ssl_dane/ HEAD > ${CMAKE_BINARY_DIR}/.getdns_ssl_dane.tar
            WORKING_DIRECTORY ${3RD_PARTY_GETDNS_DIR}/src/ssl_dane)
        add_custom_target(dist_getdns_yxml
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${PACKAGE_TARNAME}/3rd_party/getdns/src/yxml/ HEAD > ${CMAKE_BINARY_DIR}/.getdns_yxml.tar
            WORKING_DIRECTORY ${3RD_PARTY_GETDNS_DIR}/src/yxml)
        add_custom_target(dist_getdns_stubby
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${PACKAGE_TARNAME}/3rd_party/getdns/stubby/ HEAD > ${CMAKE_BINARY_DIR}/.getdns_stubby.tar
            WORKING_DIRECTORY ${3RD_PARTY_GETDNS_DIR}/stubby)
        add_custom_target(dist
            COMMAND ${GIT_PROGRAM} archive --format=tar --prefix=${PACKAGE_TARNAME}/ HEAD > ${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar
            COMMAND tar --concatenate --file=${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar ${CMAKE_BINARY_DIR}/.getdns.tar
            COMMAND rm ${CMAKE_BINARY_DIR}/.getdns.tar
            COMMAND tar --concatenate --file=${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar ${CMAKE_BINARY_DIR}/.getdns_jsmn.tar
            COMMAND rm ${CMAKE_BINARY_DIR}/.getdns_jsmn.tar
            COMMAND tar --concatenate --file=${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar ${CMAKE_BINARY_DIR}/.getdns_ssl_dane.tar
            COMMAND rm ${CMAKE_BINARY_DIR}/.getdns_ssl_dane.tar
            COMMAND tar --concatenate --file=${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar ${CMAKE_BINARY_DIR}/.getdns_yxml.tar
            COMMAND rm ${CMAKE_BINARY_DIR}/.getdns_yxml.tar
            COMMAND tar --concatenate --file=${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar ${CMAKE_BINARY_DIR}/.getdns_stubby.tar
            COMMAND rm ${CMAKE_BINARY_DIR}/.getdns_stubby.tar
            COMMAND cat ${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar | gzip > ${CMAKE_BINARY_DIR}/${PACKAGE_TARNAME}.tar.gz
            COMMAND rm ${CMAKE_BINARY_DIR}/.${PACKAGE_TARNAME}.tar
            DEPENDS dist_getdns dist_getdns_jsmn dist_getdns_ssl_dane dist_getdns_yxml dist_getdns_stubby
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    endif()

    if(NOT TARGET distcheck)
        set(DISTCHECK_BUILD_DIR "_build")
        set(DISTCHECK_INSTALL_DIR "_inst")
        if(${CMAKE_GENERATOR} STREQUAL "Ninja")
            set(DISTCHECK_BUILD_CMD "ninja")
            set(DISTCHECK_MAKEFLAGS "")
        else()
            set(DISTCHECK_BUILD_CMD "$(MAKE)")
            execute_process(COMMAND "grep" "-c" "model name" "/proc/cpuinfo"
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_VARIABLE NOCPUS)
            string(REGEX REPLACE "\n" "" NOCPUS ${NOCPUS})
            set(DISTCHECK_MAKEFLAGS "MAKEFLAGS=-j${NOCPUS}")
        endif()
        add_custom_target(distcheck
            COMMAND
            rm -rf ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR} ${PACKAGE_TARNAME}
            && mkdir ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR}
            && (tar xzf ${PACKAGE_TARNAME}.tar.gz
                || (echo 'Error: failed to unpack the archive' 2>&1\; false))
            && (cd ${DISTCHECK_BUILD_DIR}
                && (${CMAKE_COMMAND} -G${CMAKE_GENERATOR} -DCMAKE_INSTALL_PREFIX=../${DISTCHECK_INSTALL_DIR} ../${PACKAGE_TARNAME}
                    || (echo 'Error: failed to configure the archive' 2>&1\; false))
                && (${DISTCHECK_MAKEFLAGS} ${DISTCHECK_BUILD_CMD}
                    || (echo 'Error: the build target failed ' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} install
                    || (echo 'Error: the install target failed' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} uninstall
                    || (echo 'Error: the uninstall target failed' 2>&1\; false))
                && (${DISTCHECK_BUILD_CMD} clean
                    || (echo 'Error: the clean target failed' 2>&1\; false)))
            && rm -rf ${DISTCHECK_BUILD_DIR} ${DISTCHECK_INSTALL_DIR} ${PACKAGE_TARNAME}
            && echo 'PASS: ' ${PACKAGE_TARNAME}.tar.gz 'is ready for distribution.'
            DEPENDS dist
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Checking the distribution archive...")
    endif()
else()
    message(STATUS "no git -- not including dist and distcheck targets")
endif()
