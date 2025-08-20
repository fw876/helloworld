cmake_minimum_required(VERSION 2.8.4)
project(libsodium_Cmake C CXX ASM)

#TODO?: Add mmx, SSE2, SSE3, SSSE3 checks.
#TODO?: More of the emscripten stuff.

INCLUDE(CheckCCompilerFlag)


#----------------------------------------------------------
######################### OPTIONS #########################
#----------------------------------------------------------
# Default values
set (LIBSODIUM_BUILD_SHARED_LIBRARIES OFF)
set (ENABLE_BLOCKING_RANDOM ON)
set (ENABLE_MINIMAL_BUILD OFF)
set (ENABLE_TESTS OFF)
set (DISABLE_ASM ON)
set (DISABLE_PIE OFF)
set (DISABLE_SSP ON)

#OPTION(LIBSODIUM_BUILD_SHARED_LIBRARIES "Build the library dynamically (ON/TRUE) or statically (OFF/FALSE).")
#OPTION(ENABLE_BLOCKING_RANDOM           "Enable this switch only if /dev/urandom is totally broken on the target platform.")
#OPTION(ENABLE_MINIMAL_BUILD             "Only compile the minimum set of functions required for the high-level API.")
#OPTION(ENABLE_TESTS                     "Enable testing.")
#OPTION(DISABLE_ASM                      "Disable AMD64 assembly implementations.")
#OPTION(DISABLE_PIE                      "Do not produce position independent executables.")
#OPTION(DISABLE_SSP                      "Do not compile with -fstack-protector.")


#----------------------------------------------------------
######################### VERSION #########################
#----------------------------------------------------------

SET(VERSION 1.0.3)
SET(SODIUM_LIBRARY_VERSION_MAJOR 7)
SET(SODIUM_LIBRARY_VERSION_MINOR 5)
SET(DLL_VERSION 6)

SET(SODIUM_LIBRARY_VERSION "15:0:2")
#                            | | |
#                     +------+ | +---+
#                     |        |     |
#                  current:revision:age
#                     |        |     |
#                     |        |     +- increment if interfaces have been added
#                     |        |        set to zero if interfaces have been removed
#                     |        |        or changed
#                     |        +- increment if source code has changed
#                     |           set to zero if current is incremented
#                     +- increment if interfaces have been added, removed or changed

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/src/libsodium/include/sodium/version.h)


#----------------------------------------------------------
###################### SYSTEM CHECKS ######################
#----------------------------------------------------------

MESSAGE("---------------- PERFORMING SYSTEM CHECKS. ----------------")

# MSVC does not provide inline in C (only CXX)
IF(MSVC)
    ADD_DEFINITIONS("-Dinline=__inline")
ENDIF(MSVC)

#Endianess check
INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(BIG_ENDIAN)

IF(${BIG_ENDIAN})
    SET(IS_BIG_ENDIAN ON)
    ADD_DEFINIIONS("-DNATIVE_BIG_ENDIAN=1")
    MESSAGE("System is in Big Endian.")
ELSE(${BIG_ENDIAN})
    SET(IS_BIG_ENDIAN OFF)
    ADD_DEFINITIONS("-DNATIVE_LITTLE_ENDIAN=1")
    MESSAGE("System is in Little Endian.")
ENDIF(${BIG_ENDIAN})


IF(EMSCRIPTEN)
    SET(DISABLE_ASM ON)
    MESSAGE("Compiling to javascript, disabling asm implementations.")
ENDIF()


IF(MSYS OR MINGW OR CYGWIN)
    SET(DISABLE_PIE ON)
ENDIF()


#TI mode check
IF(${IS_BIGENDIAN})
    TRY_COMPILE(HAVE_TI_MODE_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_TI_MODE.c COMPILE_DEFINITIONS -DNATIVE_BIG_ENDIAN=1)
ELSE(${IS_BIGENDIAN})
    TRY_COMPILE(HAVE_TI_MODE_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_TI_MODE.c COMPILE_DEFINITIONS -DNATIVE_LITTLE_ENDIAN=1)
ENDIF(${IS_BIGENDIAN})

IF(HAVE_TI_MODE_COMPILE)

    SET(libsodium_HEADERS ${libsodium_HEADERS}
#        src/libsodium/crypto_scalarmult/curve25519/donna_c64/api.h
    )

    SET(libsodium_SOURCE ${libsodium_SOURCE}
        src/libsodium/crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.c
    )

    ADD_DEFINITIONS(-DHAVE_TI_MODE)

    MESSAGE("Gcc TI Mode is available.")

ELSE(HAVE_TI_MODE_COMPILE)

    SET(libsodium_HEADERS ${libsodium_HEADERS}
#        src/libsodium/crypto_scalarmult/curve25519/ref10/api.h
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe.h
        src/libsodium/crypto_scalarmult/curve25519/ref10/montgomery.h
        src/libsodium/crypto_scalarmult/curve25519/ref10/pow225521.h

    )

    SET(libsodium_SOURCE ${libsodium_SOURCE}
        src/libsodium/crypto_scalarmult/curve25519/ref10/curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_0_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_1_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_add_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_copy_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_cswap_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_frombytes_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_invert_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul121666_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sq_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sub_curve25519_ref10.c
        src/libsodium/crypto_scalarmult/curve25519/ref10/fe_tobytes_curve25519_ref10.c
    )

    MESSAGE("Gcc TI Mode is not available.")

ENDIF(HAVE_TI_MODE_COMPILE)


#Check if weak symbols are supported.
TRY_COMPILE(HAVE_WEAK_SYMBOLS_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_WEAK_SYMBOLS.c)
IF(HAVE_WEAK_SYMBOLS_COMPILE)
    ADD_DEFINITIONS("-DHAVE_WEAK_SYMBOLS")
    MESSAGE("Weak Symbols are supported.")
ELSE(HAVE_WEAK_SYMBOLS_COMPILE)
    MESSAGE("Weak Symbols are not supported.")
    SET(TEST ON)
ENDIF(HAVE_WEAK_SYMBOLS_COMPILE)


#Is __STDC_LIMIT_MACROS needed check.
TRY_COMPILE(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/IS_STDC_LIMIT_MACROS_NEEDED.c)
IF(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE)
    #If this works then we dont need to define __STDC_LIMIT_MACROS and __STDC_CONSTANT_MACROS.
    MESSAGE("__STDC_LIMIT_MACROS and __STDC_CONSTANT_MACROS not needed.")
ELSE(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE)
    ADD_DEFINITIONS("-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS")
    MESSAGE("__STDC_LIMIT_MACROS and __STDC_CONSTANT_MACROS is needed and was added to the definitions.")
ENDIF(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE)


#Is there a functionnal ASM compiler
SET(CMAKE_ASM_SOURCE_FILE_EXTENSIONS "s;S")
ENABLE_LANGUAGE(ASM)

IF(CMAKE_ASM_COMPILER_WORKS)
    SET(ASSEMBLER_AVAILABLE ON)
    MESSAGE("An ASM compiler has been found and is functionnal.")
ELSE(CMAKE_ASM_COMPILER_WORKS)
    SET(ASSEMBLER_AVAILABLE OFF)
    MESSAGE(FATAL "An ASM compiler has not been found or is not functionnal.")
ENDIF(CMAKE_ASM_COMPILER_WORKS)


#cpuid instruction check
TRY_COMPILE(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_CPUID.c)
IF(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE)
    SET(IS_CPUID_INSTRUCTION_AVAILABLE ON)
    ADD_DEFINITIONS("-DHAVE_CPUID")
    MESSAGE("Cpuid instruction is available.")
ELSE(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE)
    SET(IS_CPUID_INSTRUCTION_AVAILABLE OFF)
    MESSAGE("Cpuid instruction is not available.")
ENDIF(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE)


#Have AMD64 ASM check
IF(DISABLE_ASM)

    MESSAGE("AMD64 ASM implementations have been disabled.")

    SET(libsodium_HEADERS ${libsodium_HEADERS}
#        src/libsodium/crypto_stream/salsa20/ref/api.h
    )

    SET(libsodium_SOURCE ${libsodium_SOURCE}
        src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c
        src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c
    )

ELSE(DISABLE_ASM)

    IF(ASSEMBLER_AVAILABLE)

        TRY_COMPILE(HAVE_AMD64_ASM_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_AMD64_ASM.c)
        IF(HAVE_AMD64_ASM_COMPILE)
            ADD_DEFINITIONS(-DHAVE_AMD64_ASM=1)

            SET(libsodium_HEADERS ${libsodium_HEADERS}
#                src/libsodium/crypto_stream/salsa20/amd64_xmm6/api.h
            )

            SET(libsodium_SOURCE ${libsodium_SOURCE}
                src/libsodium/crypto_stream/salsa20/amd64_xmm6/stream_salsa20_amd64_xmm6.S
            )

            MESSAGE("AMD64 ASM is available.")

        ELSE(HAVE_AMD64_ASM_COMPILE)

            SET(libsodium_HEADERS ${libsodium_HEADERS}
#                src/libsodium/crypto_stream/salsa20/ref/api.h
            )

            SET(libsodium_SOURCE ${libsodium_SOURCE}
                src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c
                src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c
            )

            MESSAGE("AMD64 ASM is not available.")

        ENDIF(HAVE_AMD64_ASM_COMPILE)
    ENDIF(ASSEMBLER_AVAILABLE)
ENDIF(DISABLE_ASM)


MESSAGE("---------------- DONE WITH SYSTEM CHECKS. -----------------")
MESSAGE("                                                           ")


#----------------------------------------------------------
################### COMPILER FLAG CHECKS ##################
#----------------------------------------------------------

#Compiler flag check macro definition.
MACRO(CHECK_COMPILER_FLAG)

    SET(FLAG "-${ARGV0}")
    SET(IS_${ARGV0}_AVAILABLE)

    CHECK_C_COMPILER_FLAG(${FLAG} IS_${ARGV0}_AVAILABLE)

    IF(IS_${ARGV0}_AVAILABLE)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
        MESSAGE("Checking if ${FLAG} is available... It is available.")
    ELSE(IS_${ARGV0}_AVAILABLE)
        MESSAGE("Checking if ${FLAG} is available... It is not available.")
    ENDIF(IS_${ARGV0}_AVAILABLE)

ENDMACRO(CHECK_COMPILER_FLAG)


MESSAGE("------------- PERFORMING COMPILER FLAG CHECKS. ------------")


#Check if debug mode is active
IF(CMAKE_BUILD_TYPE MATCHES Debug)
    MESSAGE("-- Debug build enabled. --")
    ADD_DEFINITIONS("-DDEBUG=1")
    CHECK_COMPILER_FLAG(O)
    CHECK_COMPILER_FLAG(g3)
ELSE(CMAKE_BUILD_TYPE MATCHES Debug)
    MESSAGE("-- Release build enabled. --")
    CHECK_COMPILER_FLAG(O3)
ENDIF(CMAKE_BUILD_TYPE MATCHES Debug)

#Check if -std=c99 is available.
CHECK_COMPILER_FLAG(std=c99)

#Check if -D_FORTIFY_SOURCE=2 is available.
CHECK_COMPILER_FLAG(D_FORTIFY_SOURCE=2)

#Check if clang and if -Wno-unknown-warning-option is available.
IF("${CMAKE_C_COMPILER_ID}" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    CHECK_COMPILER_FLAG(Wno-unknown-warning-option)
ENDIF()

IF(NOT (MSYS OR MINGW OR CYGWIN))
    #Check if -fPIC is available.
    CHECK_COMPILER_FLAG(fPIC)
ELSE(NOT (MSYS OR MINGW OR CYGWIN))
    CHECK_COMPILER_FLAG(Wl,--dynamicbase)
    CHECK_COMPILER_FLAG(Wl,--nxcompat)
ENDIF(NOT (MSYS OR MINGW OR CYGWIN))

#Check if -fPIE is available.
IF(NOT DISABLE_PIE)
    CHECK_COMPILER_FLAG(fPIE)
ENDIF(NOT DISABLE_PIE)

#Check if -Wall is available.
CHECK_COMPILER_FLAG(Wall)

#Check if -Wextra is available.
CHECK_COMPILER_FLAG(Wextra)

#Check if -fvisibility=hidden is available
CHECK_COMPILER_FLAG(fvisibility=hidden)

#Check if -fno-strict-aliasing is available.
CHECK_COMPILER_FLAG(fno-strict-aliasing)

#Check if -fno-strict-overflow is available.
CHECK_COMPILER_FLAG(fno-strict-overflow)
IF(NOT IS_fno-strict-overflow_AVAILABLE)
    #If -fno-strict-overflow is not available, try with -fwrapv.
    CHECK_COMPILER_FLAG(fwrapv)
ENDIF()

IF(NOT DISABLE_SSP)
    #Check if -fstack-protector is available.
    CHECK_COMPILER_FLAG(fstack-protector)
ENDIF(NOT DISABLE_SSP)

#Check if -Winit-self is available.
CHECK_COMPILER_FLAG(Winit-self)

#Check if -Wwrite-strings is available.
CHECK_COMPILER_FLAG(Wwrite-strings)

#Check if -Wdiv-by-zero is available.
CHECK_COMPILER_FLAG(Wdiv-by-zero)

#Check if -Wsometimes-uninitialized is available.
CHECK_COMPILER_FLAG(Wsometimes-uninitialized)

#Check if -Wbad-function-cast is available.
CHECK_COMPILER_FLAG(Wbad-function-cast)

#Check if -Wcast-align is available.
CHECK_COMPILER_FLAG(Wcast-align)

#Check if -Wcast-qual is available.
CHECK_COMPILER_FLAG(Wcast-qual)

#Check if -Wchar-subscripts is available.
CHECK_COMPILER_FLAG(Wchar-subscripts)

#Check if -Wcomment is available.
CHECK_COMPILER_FLAG(Wcomment)

#Check if -Wfloat-equal is available.
CHECK_COMPILER_FLAG(Wfloat-equal)

#Check if -Wformat=2 is available.
CHECK_COMPILER_FLAG(Wformat=2)

#Check if -Wimplicit is available.
CHECK_COMPILER_FLAG(Wimplicit)

#Check if -Wmissing-declarations is available.
CHECK_COMPILER_FLAG(Wmissing-declarations)

#Check if -Wmissing-prototypes is available.
CHECK_COMPILER_FLAG(Wmissing-prototypes)

#Check if -Wnormalized=id is available.
CHECK_COMPILER_FLAG(Wnormalized=id)

#Check if -Woverride-init is available.
CHECK_COMPILER_FLAG(Woverride-init)

#Check if -Wparentheses is available.
CHECK_COMPILER_FLAG(Wparentheses)

#Check if -Wpointer-arith is available.
CHECK_COMPILER_FLAG(Wpointer-arith)

#Check if -Wredundant-decls is available.
CHECK_COMPILER_FLAG(Wredundant-decls)

#Check if -Wstrict-prototypes is available.
CHECK_COMPILER_FLAG(Wstrict-prototypes)

#Check if -Wswitch-enum is available.
CHECK_COMPILER_FLAG(Wswitch-enum)

#Check if -Wvariable-dec is available.
CHECK_COMPILER_FLAG(Wvariable-decl)

##Check if -Wl,-z,relro is available.
#CHECK_COMPILER_FLAG(Wl,-z,relro)
#
##Check if -Wl,-z,now is available.
#CHECK_COMPILER_FLAG(Wl,-z,now)
#
##Check if -Wl,-z,noexecstack is available.
#CHECK_COMPILER_FLAG(Wl,-z,noexecstack)

#Check if -Wl,--verbose is available and enable it.
#CHECK_COMPILER_FLAG(Wl,--verbose)


MESSAGE("------------- DONE WITH COMPILER FLAG CHECKS. -------------")
MESSAGE("                                                           ")


#----------------------------------------------------------
##################### SOURCE / HEADERS ####################
#----------------------------------------------------------

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium)
#For version.h.in to version.h
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/src/libsodium/include/sodium)

SET(libsodium_HEADERS ${libsodium_HEADERS}
    src/libsodium/include/sodium.h
    src/libsodium/include/sodium/core.h
    src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h
    src/libsodium/include/sodium/crypto_auth.h
    src/libsodium/include/sodium/crypto_auth_hmacsha256.h
    src/libsodium/include/sodium/crypto_auth_hmacsha512.h
    src/libsodium/include/sodium/crypto_auth_hmacsha512256.h
    src/libsodium/include/sodium/crypto_box.h
    src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h
    src/libsodium/include/sodium/crypto_core_hsalsa20.h
    src/libsodium/include/sodium/crypto_core_salsa20.h
    src/libsodium/include/sodium/crypto_core_salsa2012.h
    src/libsodium/include/sodium/crypto_core_salsa208.h
    src/libsodium/include/sodium/crypto_generichash.h
    src/libsodium/include/sodium/crypto_generichash_blake2b.h
    src/libsodium/include/sodium/crypto_hash.h
    src/libsodium/include/sodium/crypto_hash_sha256.h
    src/libsodium/include/sodium/crypto_hash_sha512.h
    src/libsodium/include/sodium/crypto_onetimeauth.h
    src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h
    src/libsodium/include/sodium/crypto_pwhash_scryptsalsa208sha256.h
    src/libsodium/include/sodium/crypto_scalarmult.h
    src/libsodium/include/sodium/crypto_scalarmult_curve25519.h
    src/libsodium/include/sodium/crypto_secretbox.h
    src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h
    src/libsodium/include/sodium/crypto_shorthash.h
    src/libsodium/include/sodium/crypto_shorthash_siphash24.h
    src/libsodium/include/sodium/crypto_sign.h
    src/libsodium/include/sodium/crypto_sign_ed25519.h
    src/libsodium/include/sodium/crypto_sign_edwards25519sha512batch.h
    src/libsodium/include/sodium/crypto_stream.h
    src/libsodium/include/sodium/crypto_stream_aes128ctr.h
    src/libsodium/include/sodium/crypto_stream_chacha20.h
    src/libsodium/include/sodium/crypto_stream_salsa20.h
    src/libsodium/include/sodium/crypto_stream_salsa2012.h
    src/libsodium/include/sodium/crypto_stream_salsa208.h
    src/libsodium/include/sodium/crypto_stream_xsalsa20.h
    src/libsodium/include/sodium/crypto_int32.h
    src/libsodium/include/sodium/crypto_int64.h
    src/libsodium/include/sodium/crypto_uint16.h
    src/libsodium/include/sodium/crypto_uint32.h
    src/libsodium/include/sodium/crypto_uint64.h
    src/libsodium/include/sodium/crypto_uint8.h
    src/libsodium/include/sodium/crypto_verify_16.h
    src/libsodium/include/sodium/crypto_verify_32.h
    src/libsodium/include/sodium/crypto_verify_64.h
    src/libsodium/include/sodium/export.h
    src/libsodium/include/sodium/randombytes.h
    src/libsodium/include/sodium/randombytes_salsa20_random.h
    src/libsodium/include/sodium/randombytes_sysrandom.h
    src/libsodium/include/sodium/runtime.h
    src/libsodium/include/sodium/utils.h
    ${CMAKE_CURRENT_BINARY_DIR}/src/libsodium/include/sodium/version.h
#    src/libsodium/crypto_auth/hmacsha256/cp/api.h
#    src/libsodium/crypto_auth/hmacsha512/cp/api.h
#    src/libsodium/crypto_auth/hmacsha512256/cp/api.h
#    src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/api.h
#    src/libsodium/crypto_core/hsalsa20/ref2/api.h
#    src/libsodium/crypto_core/salsa20/ref/api.h
    src/libsodium/crypto_generichash/blake2/ref/blake2-impl.h
    src/libsodium/crypto_generichash/blake2/ref/blake2.h
    src/libsodium/crypto_generichash/blake2/ref/blake2b-round.h
#    src/libsodium/crypto_hash/sha256/cp/api.h
#    src/libsodium/crypto_hash/sha512/cp/api.h
    src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.h
    src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna32.h
    src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt.h
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.h
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/sysendian.h
#    src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/api.h
#    src/libsodium/crypto_shorthash/siphash24/ref/api.h
    src/libsodium/crypto_sign/ed25519/ref10/base.h
    src/libsodium/crypto_sign/ed25519/ref10/base2.h
#    src/libsodium/crypto_sign/ed25519/ref10/api.h
    src/libsodium/crypto_sign/ed25519/ref10/d.h
    src/libsodium/crypto_sign/ed25519/ref10/d2.h
    src/libsodium/crypto_sign/ed25519/ref10/fe.h
    src/libsodium/crypto_sign/ed25519/ref10/ge.h
    src/libsodium/crypto_sign/ed25519/ref10/ge_add.h
    src/libsodium/crypto_sign/ed25519/ref10/ge_madd.h
    src/libsodium/crypto_sign/ed25519/ref10/ge_msub.h
    src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.h
    src/libsodium/crypto_sign/ed25519/ref10/ge_sub.h
    src/libsodium/crypto_sign/ed25519/ref10/pow22523.h
    src/libsodium/crypto_sign/ed25519/ref10/pow225521.h
    src/libsodium/crypto_sign/ed25519/ref10/sc.h
    src/libsodium/crypto_sign/ed25519/ref10/sqrtm1.h
#    src/libsodium/crypto_stream/chacha20/ref/api.h
#    src/libsodium/crypto_stream/xsalsa20/ref/api.h
#    src/libsodium/crypto_verify/16/ref/api.h
#    src/libsodium/crypto_verify/32/ref/api.h
#    src/libsodium/crypto_verify/64/ref/api.h
)

SET(libsodium_SOURCE ${libsodium_SOURCE}
    src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
    src/libsodium/crypto_auth/crypto_auth.c
    src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256_api.c
    src/libsodium/crypto_auth/hmacsha256/cp/hmac_hmacsha256.c
    src/libsodium/crypto_auth/hmacsha256/cp/verify_hmacsha256.c
    src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512_api.c
    src/libsodium/crypto_auth/hmacsha512/cp/hmac_hmacsha512.c
    src/libsodium/crypto_auth/hmacsha512/cp/verify_hmacsha512.c
    src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256_api.c
    src/libsodium/crypto_auth/hmacsha512256/cp/hmac_hmacsha512256.c
    src/libsodium/crypto_auth/hmacsha512256/cp/verify_hmacsha512256.c
    src/libsodium/crypto_box/crypto_box.c
    src/libsodium/crypto_box/crypto_box_easy.c
    src/libsodium/crypto_box/crypto_box_seal.c
    src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c
    src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/after_curve25519xsalsa20poly1305.c
    src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/before_curve25519xsalsa20poly1305.c
    src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/box_curve25519xsalsa20poly1305.c
    src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/keypair_curve25519xsalsa20poly1305.c
    src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20.c
    src/libsodium/crypto_core/hsalsa20/core_hsalsa20_api.c
    src/libsodium/crypto_core/salsa20/ref/core_salsa20.c
    src/libsodium/crypto_core/salsa20/core_salsa20_api.c
    src/libsodium/crypto_generichash/crypto_generichash.c
    src/libsodium/crypto_generichash/blake2/generichash_blake2_api.c
    src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-ref.c
    src/libsodium/crypto_generichash/blake2/ref/blake2b-ref.c
    src/libsodium/crypto_generichash/blake2/ref/generichash_blake2b.c
    src/libsodium/crypto_hash/crypto_hash.c
    src/libsodium/crypto_hash/sha256/hash_sha256_api.c
    src/libsodium/crypto_hash/sha256/cp/hash_sha256.c
    src/libsodium/crypto_hash/sha512/hash_sha512_api.c
    src/libsodium/crypto_hash/sha512/cp/hash_sha512.c
    src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c
    src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
#    src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305_api.c
#    src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305_try.c
#    src/libsodium/crypto_onetimeauth/poly1305/donna/auth_poly1305_donna.c
    src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
    src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c
    src/libsodium/crypto_scalarmult/crypto_scalarmult.c
    src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c
    src/libsodium/crypto_secretbox/crypto_secretbox.c
    src/libsodium/crypto_secretbox/crypto_secretbox_easy.c
    src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c
    src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c
    src/libsodium/crypto_shorthash/crypto_shorthash.c
    src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24_api.c
    src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24.c
    src/libsodium/crypto_sign/crypto_sign.c
    src/libsodium/crypto_sign/ed25519/sign_ed25519_api.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_0.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_1.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_add.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_cmov.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_copy.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_frombytes.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_invert.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_isnegative.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_isnonzero.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_mul.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_neg.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_pow22523.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_sq.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_sq2.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_sub.c
    src/libsodium/crypto_sign/ed25519/ref10/fe_tobytes.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_add.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_double_scalarmult.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_frombytes.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_madd.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_msub.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p2_0.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p3_0.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p3_dbl.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_cached.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_p2.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_p3_tobytes.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_precomp_0.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_scalarmult_base.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_sub.c
    src/libsodium/crypto_sign/ed25519/ref10/ge_tobytes.c
    src/libsodium/crypto_sign/ed25519/ref10/keypair.c
    src/libsodium/crypto_sign/ed25519/ref10/open.c
    src/libsodium/crypto_sign/ed25519/ref10/sc_muladd.c
    src/libsodium/crypto_sign/ed25519/ref10/sc_reduce.c
    src/libsodium/crypto_sign/ed25519/ref10/sign.c
    src/libsodium/crypto_stream/crypto_stream.c
    src/libsodium/crypto_stream/chacha20/stream_chacha20.c
    src/libsodium/crypto_stream/chacha20/ref/stream_chacha20_ref.c
    src/libsodium/crypto_stream/salsa20/stream_salsa20_api.c
    src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20_api.c
    src/libsodium/crypto_stream/xsalsa20/ref/stream_xsalsa20.c
    src/libsodium/crypto_stream/xsalsa20/ref/xor_xsalsa20.c
    src/libsodium/crypto_verify/16/verify_16_api.c
    src/libsodium/crypto_verify/16/ref/verify_16.c
    src/libsodium/crypto_verify/32/verify_32_api.c
    src/libsodium/crypto_verify/32/ref/verify_32.c
    src/libsodium/crypto_verify/64/verify_64_api.c
    src/libsodium/crypto_verify/64/ref/verify_64.c
    src/libsodium/randombytes/randombytes.c
    src/libsodium/randombytes/salsa20/randombytes_salsa20_random.c
    src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
    src/libsodium/sodium/core.c
    src/libsodium/sodium/runtime.c
    src/libsodium/sodium/utils.c
    src/libsodium/sodium/version.c
)


#----------------------------------------------------------
################### MINIMAL BUILD CHECK ###################
#----------------------------------------------------------

IF(NOT ENABLE_MINIMAL_BUILD)

    SET(libsodium_HEADERS ${libsodium_HEADERS}
#        src/libsodium/crypto_core/salsa2012/ref/api.h
#        src/libsodium/crypto_core/salsa208/ref/api.h
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/api.h
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/fe25519.h
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/ge25519.h
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/sc25519.h
#        src/libsodium/crypto_stream/aes128ctr/portable/api.h
        src/libsodium/crypto_stream/aes128ctr/portable/common.h
        src/libsodium/crypto_stream/aes128ctr/portable/consts.h
        src/libsodium/crypto_stream/aes128ctr/portable/int128.h
        src/libsodium/crypto_stream/aes128ctr/portable/types.h
#        src/libsodium/crypto_stream/salsa2012/ref/api.h
#        src/libsodium/crypto_stream/salsa208/ref/api.h
    )

    SET(libsodium_SOURCE ${libsodium_SOURCE}
        src/libsodium/crypto_core/salsa2012/ref/core_salsa2012.c
        src/libsodium/crypto_core/salsa2012/core_salsa2012_api.c
        src/libsodium/crypto_core/salsa208/ref/core_salsa208.c
        src/libsodium/crypto_core/salsa208/core_salsa208_api.c
#        src/libsodium/crypto_sign/edwards25519sha512batch/sign_edwards25519sha512batch_api.c
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/fe25519_edwards25519sha512batch.c
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/ge25519_edwards25519sha512batch.c
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/sc25519_edwards25519sha512batch.c
#        src/libsodium/crypto_sign/edwards25519sha512batch/ref/sign_edwards25519sha512batch.c
        src/libsodium/crypto_stream/aes128ctr/portable/afternm_aes128ctr.c
        src/libsodium/crypto_stream/aes128ctr/stream_aes128ctr_api.c
        src/libsodium/crypto_stream/aes128ctr/portable/beforenm_aes128ctr.c
        src/libsodium/crypto_stream/aes128ctr/portable/common_aes128ctr.c
        src/libsodium/crypto_stream/aes128ctr/portable/stream_aes128ctr.c
        src/libsodium/crypto_stream/aes128ctr/portable/int128_aes128ctr.c
        src/libsodium/crypto_stream/salsa2012/stream_salsa2012_api.c
        src/libsodium/crypto_stream/aes128ctr/portable/xor_afternm_aes128ctr.c
        src/libsodium/crypto_stream/aes128ctr/portable/consts_aes128ctr.c
        src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012.c
        src/libsodium/crypto_stream/salsa2012/ref/xor_salsa2012.c
        src/libsodium/crypto_stream/salsa208/stream_salsa208_api.c
        src/libsodium/crypto_stream/salsa208/ref/stream_salsa208.c
        src/libsodium/crypto_stream/salsa208/ref/xor_salsa208.c
    )

ENDIF(NOT ENABLE_MINIMAL_BUILD)


#----------------------------------------------------------
######################### LIBRARY #########################
#----------------------------------------------------------

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/build")


IF(ENABLE_BLOCKING_RANDOM)
    ADD_DEFINITIONS("-DUSE_BLOCKING_RANDOM")
ENDIF(ENABLE_BLOCKING_RANDOM)

IF(LIBSODIUM_BUILD_SHARED_LIBRARIES)
    ADD_LIBRARY(sodium SHARED ${libsodium_HEADERS} ${libsodium_SOURCE})
ELSE(LIBSODIUM_BUILD_SHARED_LIBRARIES)
    ADD_DEFINITIONS("-DSODIUM_STATIC")
    ADD_LIBRARY(sodium STATIC ${libsodium_HEADERS} ${libsodium_SOURCE})
ENDIF(LIBSODIUM_BUILD_SHARED_LIBRARIES)

SET_TARGET_PROPERTIES(sodium PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib
    PROJECT_LABEL "libsodium"
)

set(libsodium_include_dirs
        ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium
        ${CMAKE_CURRENT_BINARY_DIR}/src/libsodium/include
        CACHE INTERNAL "libipset library" FORCE
        )

#----------------------------------------------------------
########################## TESTS ##########################
#----------------------------------------------------------

IF(${ENABLE_TESTS})

    ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/test/default)
    ENABLE_TESTING()

    ADD_TEST(NAME aead_chacha20poly1305_test COMMAND aead_chacha20poly1305 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME auth_test                  COMMAND auth                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME auth2_test                 COMMAND auth2                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME auth3_test                 COMMAND auth3                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME auth5_test                 COMMAND auth5                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME auth6_test                 COMMAND auth6                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME auth7_test                 COMMAND auth7                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box_test                   COMMAND box                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box2_test                  COMMAND box2                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box7_test                  COMMAND box7                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box8_test                  COMMAND box8                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box_easy_test              COMMAND box_easy              WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box_easy2_test             COMMAND box_easy2             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box_seal_test              COMMAND box_seal              WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME box_seed_test              COMMAND box_seed              WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME chacha20_test              COMMAND chacha20              WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME core1_test                 COMMAND core1                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME core2_test                 COMMAND core2                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME core3_test                 COMMAND core3                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME core4_test                 COMMAND core4                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME core5_test                 COMMAND core5                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME core6_test                 COMMAND core6                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME ed25519_convert_test       COMMAND ed25519_convert       WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME generichash_test           COMMAND generichash           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME generichash2_test          COMMAND generichash2          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME generichash3_test          COMMAND generichash3          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME hash_test                  COMMAND hash                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME hash3_test                 COMMAND hash3                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME onetimeauth_test           COMMAND onetimeauth           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME onetimeauth2_test          COMMAND onetimeauth2          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME onetimeauth7_test          COMMAND onetimeauth7          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME pwhash_test                COMMAND pwhash                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME pwhash_scrypt_ll_test      COMMAND pwhash_scrypt_ll      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME randombytes_test           COMMAND randombytes           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME scalarmult_test            COMMAND scalarmult            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME scalarmult2_test           COMMAND scalarmult2           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME scalarmult5_test           COMMAND scalarmult5           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME scalarmult6_test           COMMAND scalarmult6           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME scalarmult7_test           COMMAND scalarmult7           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME secretbox_test             COMMAND secretbox             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME secretbox2_test            COMMAND secretbox2            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME secretbox7_test            COMMAND secretbox7            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME secretbox8_test            COMMAND secretbox8            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME secretbox_easy_test        COMMAND secretbox_easy        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME secretbox_easy2_test       COMMAND secretbox_easy2       WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME shorthash_test             COMMAND shorthash             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME sign_test                  COMMAND sign                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME sodium_core_test           COMMAND sodium_core           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME sodium_utils_test          COMMAND sodium_utils          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME sodium_utils2_test         COMMAND sodium_utils2         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME sodium_utils3_test         COMMAND sodium_utils3         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME sodium_version_test        COMMAND sodium_version        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME stream_test                COMMAND stream                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME stream2_test               COMMAND stream2               WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME stream3_test               COMMAND stream3               WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME stream4_test               COMMAND stream4               WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)
    ADD_TEST(NAME verify1_test               COMMAND verify1               WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test/default/)

    SET_TESTS_PROPERTIES(aead_chacha20poly1305_test PROPERTIES DEPENDS aead_chacha20poly1305)
    SET_TESTS_PROPERTIES(auth_test                  PROPERTIES DEPENDS auth)
    SET_TESTS_PROPERTIES(auth2_test                 PROPERTIES DEPENDS auth2)
    SET_TESTS_PROPERTIES(auth3_test                 PROPERTIES DEPENDS auth3)
    SET_TESTS_PROPERTIES(auth5_test                 PROPERTIES DEPENDS auth5)
    SET_TESTS_PROPERTIES(auth6_test                 PROPERTIES DEPENDS auth6)
    SET_TESTS_PROPERTIES(auth7_test                 PROPERTIES DEPENDS auth7)
    SET_TESTS_PROPERTIES(box_test                   PROPERTIES DEPENDS box)
    SET_TESTS_PROPERTIES(box2_test                  PROPERTIES DEPENDS box2)
    SET_TESTS_PROPERTIES(box7_test                  PROPERTIES DEPENDS box7)
    SET_TESTS_PROPERTIES(box8_test                  PROPERTIES DEPENDS box8)
    SET_TESTS_PROPERTIES(box_easy_test              PROPERTIES DEPENDS box_easy)
    SET_TESTS_PROPERTIES(box_easy2_test             PROPERTIES DEPENDS box_easy2)
    SET_TESTS_PROPERTIES(box_seal_test              PROPERTIES DEPENDS box_seal)
    SET_TESTS_PROPERTIES(box_seed_test              PROPERTIES DEPENDS box_seed)
    SET_TESTS_PROPERTIES(chacha20_test              PROPERTIES DEPENDS chacha20)
    SET_TESTS_PROPERTIES(core1_test                 PROPERTIES DEPENDS core1)
    SET_TESTS_PROPERTIES(core2_test                 PROPERTIES DEPENDS core2)
    SET_TESTS_PROPERTIES(core3_test                 PROPERTIES DEPENDS core3)
    SET_TESTS_PROPERTIES(core4_test                 PROPERTIES DEPENDS core4)
    SET_TESTS_PROPERTIES(core5_test                 PROPERTIES DEPENDS core5)
    SET_TESTS_PROPERTIES(core6_test                 PROPERTIES DEPENDS core6)
    SET_TESTS_PROPERTIES(ed25519_convert_test       PROPERTIES DEPENDS ed25519_convert)
    SET_TESTS_PROPERTIES(generichash_test           PROPERTIES DEPENDS generichash)
    SET_TESTS_PROPERTIES(generichash2_test          PROPERTIES DEPENDS generichash2)
    SET_TESTS_PROPERTIES(generichash3_test          PROPERTIES DEPENDS generichash3)
    SET_TESTS_PROPERTIES(hash_test                  PROPERTIES DEPENDS hash)
    SET_TESTS_PROPERTIES(hash3_test                 PROPERTIES DEPENDS hash3)
    SET_TESTS_PROPERTIES(onetimeauth_test           PROPERTIES DEPENDS onetimeauth)
    SET_TESTS_PROPERTIES(onetimeauth2_test          PROPERTIES DEPENDS onetimeauth2)
    SET_TESTS_PROPERTIES(onetimeauth7_test          PROPERTIES DEPENDS onetimeauth7)
    SET_TESTS_PROPERTIES(pwhash_test                PROPERTIES DEPENDS pwhash)
    SET_TESTS_PROPERTIES(pwhash_scrypt_ll_test      PROPERTIES DEPENDS pwhash_scrypt_ll)
    SET_TESTS_PROPERTIES(randombytes_test           PROPERTIES DEPENDS randombytes)
    SET_TESTS_PROPERTIES(scalarmult_test            PROPERTIES DEPENDS scalarmult)
    SET_TESTS_PROPERTIES(scalarmult2_test           PROPERTIES DEPENDS scalarmult2)
    SET_TESTS_PROPERTIES(scalarmult5_test           PROPERTIES DEPENDS scalarmult5)
    SET_TESTS_PROPERTIES(scalarmult6_test           PROPERTIES DEPENDS scalarmult6)
    SET_TESTS_PROPERTIES(scalarmult7_test           PROPERTIES DEPENDS scalarmult7)
    SET_TESTS_PROPERTIES(secretbox_test             PROPERTIES DEPENDS secretbox)
    SET_TESTS_PROPERTIES(secretbox2_test            PROPERTIES DEPENDS secretbox2)
    SET_TESTS_PROPERTIES(secretbox7_test            PROPERTIES DEPENDS secretbox7)
    SET_TESTS_PROPERTIES(secretbox8_test            PROPERTIES DEPENDS secretbox8)
    SET_TESTS_PROPERTIES(secretbox_easy_test        PROPERTIES DEPENDS secretbox_easy)
    SET_TESTS_PROPERTIES(secretbox_easy2_test       PROPERTIES DEPENDS secretbox_easy2)
    SET_TESTS_PROPERTIES(shorthash_test             PROPERTIES DEPENDS shorthash)
    SET_TESTS_PROPERTIES(sign_test                  PROPERTIES DEPENDS sign)
    SET_TESTS_PROPERTIES(sodium_core_test           PROPERTIES DEPENDS sodium_core)
    SET_TESTS_PROPERTIES(sodium_utils_test          PROPERTIES DEPENDS sodium_utils)
    SET_TESTS_PROPERTIES(sodium_utils2_test         PROPERTIES DEPENDS sodium_utils2)
    SET_TESTS_PROPERTIES(sodium_utils3_test         PROPERTIES DEPENDS sodium_utils3)
    SET_TESTS_PROPERTIES(sodium_version_test        PROPERTIES DEPENDS sodium_version)
    SET_TESTS_PROPERTIES(stream_test                PROPERTIES DEPENDS stream)
    SET_TESTS_PROPERTIES(stream2_test               PROPERTIES DEPENDS stream2)
    SET_TESTS_PROPERTIES(stream3_test               PROPERTIES DEPENDS stream3)
    SET_TESTS_PROPERTIES(stream4_test               PROPERTIES DEPENDS stream4)
    SET_TESTS_PROPERTIES(verify1_test               PROPERTIES DEPENDS verify1)

ENDIF(${ENABLE_TESTS})
