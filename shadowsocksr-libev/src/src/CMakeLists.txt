
set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES_SNI
        http.c
        http.h
        tls.c
        tls.h
        rule.c
        rule.h)

set(SOURCE_FILES_OBFS
        obfs/verify.c
        obfs/verify.h
        obfs/tls1.2_ticket.c
        obfs/tls1.2_ticket.h
        obfs/obfsutil.c
        obfs/obfsutil.h
        obfs/obfs.c
        obfs/obfs.h
        obfs/http_simple.c
        obfs/http_simple.h
        obfs/crc32.c
        obfs/crc32.h
        obfs/base64.c
        obfs/base64.h
        obfs/auth_chain.c
        obfs/auth_chain.h
        obfs/auth.c
        obfs/auth.h)

set(SOURCE_FILES_LOCAL
        utils.c
        utils.h
        jconf.c
        jconf.h
        json.c
        json.h
        encrypt.c
        encrypt.h
        udprelay.c
        udprelay.h
        cache.c
        cache.h
        acl.c
        acl.h
        netutils.c
        netutils.h
        local.c
        local.h
        ${SOURCE_FILES_OBFS}
        ${SOURCE_FILES_SNI})

set(SOURCE_FILES_TUNNEL
        utils.c
        utils.h
        jconf.c
        jconf.h
        json.c
        json.h
        encrypt.c
        encrypt.h
        udprelay.c
        udprelay.h
        cache.c
        cache.h
        netutils.c
        netutils.h
        tunnel.c
        tunnel.h)

set(SOURCE_FILES_SERVER
        utils.c
        utils.h
        jconf.c
        jconf.h
        json.c
        json.h
        encrypt.c
        encrypt.h
        udprelay.c
        udprelay.h
        cache.c
        cache.h
        acl.c
        acl.h
        resolv.c
        resolv.h
        netutils.c
        netutils.h
        server.c
        server.h
        ${SOURCE_FILES_OBFS}
        ${SOURCE_FILES_SNI})

set(SOURCE_FILES_MANAGER
        utils.c
        utils.h
        jconf.c
        jconf.h
        json.c
        json.h
        manager.c)

set(SOURCE_FILES_REDIR
        utils.c
        utils.h
        jconf.c
        jconf.h
        json.c
        json.h
        encrypt.c
        encrypt.h
        netutils.c
        netutils.h
        cache.c
        cache.h
        udprelay.c
        udprelay.h
        redir.c
        redir.h
        ${SOURCE_FILES_SNI})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${libev_include_dirs})
include_directories(${libcork_include_dirs})
include_directories(${libipset_include_dirs})
include_directories(${libudns_include_dirs})
include_directories(${libsodium_include_dirs})


if (WIN32)
    list ( APPEND SOURCE_FILES_LOCAL win32.c )
    list ( APPEND SOURCE_FILES_TUNNEL win32.c )
    list ( APPEND SOURCE_FILES_SERVER win32.c )
endif ()

add_executable(ss_local ${SOURCE_FILES_LOCAL})
#add_executable(ss_tunnel ${SOURCE_FILES_TUNNEL})
#add_executable(ss_server ${SOURCE_FILES_SERVER})
#add_executable(ss_manager ${SOURCE_FILES_MANAGER})
add_executable(ss_redir ${SOURCE_FILES_REDIR})
add_library(libshadowsocks-libev ${SOURCE_FILES_LOCAL})

set_target_properties(ss_local PROPERTIES
        COMPILE_DEFINITIONS MODULE_LOCAL
        )
#set_target_properties(ss_tunnel PROPERTIES
#        COMPILE_DEFINITIONS MODULE_TUNNEL
#        )
#set_target_properties(ss_server PROPERTIES
#        COMPILE_DEFINITIONS MODULE_REMOTE
#        )
#set_target_properties(ss_manager PROPERTIES
#        COMPILE_DEFINITIONS MODULE_MANAGER
#        )
set_target_properties(ss_redir PROPERTIES
        COMPILE_DEFINITIONS MODULE_REDIR
        )
target_compile_definitions(libshadowsocks-libev
        PRIVATE MODULE_LOCAL LIB_ONLY
        )
set_target_properties(libshadowsocks-libev PROPERTIES SUFFIX ".la")

set (ss_lib_common
        ev
        m
        libcork)

set (ss_lib_net
        ${ss_lib_common}
        ${LIBCRYPTO}
        libipset
        ${PCRE_LIBRARIES}
        udns
        sodium
        )

if (WIN32)
    list ( APPEND ss_lib_net Ws2_32 )
endif()

target_link_libraries(ss_local
        ${ss_lib_net}
)
#target_link_libraries(ss_tunnel
#        ${ss_lib_net}
#        )
#target_link_libraries(ss_server
#        ${ss_lib_net}
#        )
#target_link_libraries(ss_manager
#        ${ss_lib_common}
#        )
target_link_libraries(ss_redir
        ${ss_lib_net}
        )