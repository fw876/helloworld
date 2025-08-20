INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../../include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../../include/sodium)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/test/quirks)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../quirks)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

#For version.h.in to version.h
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/../../src/libsodium/include)

#ADD_DEFINITIONS("-DTEST_SRCDIR=${CMAKE_CURRENT_SOURCE_DIR}")

SET(LIBSODIUM_LIB_PATH sodium)

ADD_EXECUTABLE       (aead_chacha20poly1305 cmptest.h aead_chacha20poly1305.c)
TARGET_LINK_LIBRARIES(aead_chacha20poly1305 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (auth                  cmptest.h auth.c)
TARGET_LINK_LIBRARIES(auth                  ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (auth2                 cmptest.h auth2.c)
TARGET_LINK_LIBRARIES(auth2                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (auth3                 cmptest.h auth3.c)
TARGET_LINK_LIBRARIES(auth3                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (auth5                 cmptest.h auth5.c ${CMAKE_CURRENT_SOURCE_DIR}/../quirks/quirks.h)
TARGET_LINK_LIBRARIES(auth5                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (auth6                 cmptest.h auth6.c ${CMAKE_CURRENT_SOURCE_DIR}/../quirks/quirks.h)
TARGET_LINK_LIBRARIES(auth6                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (auth7                 cmptest.h auth7.c ${CMAKE_CURRENT_SOURCE_DIR}/../quirks/quirks.h)
TARGET_LINK_LIBRARIES(auth7                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box                   cmptest.h box.c)
TARGET_LINK_LIBRARIES(box                   ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box2                  cmptest.h box2.c)
TARGET_LINK_LIBRARIES(box2                  ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box7                  cmptest.h box7.c)
TARGET_LINK_LIBRARIES(box7                  ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box8                  cmptest.h box8.c)
TARGET_LINK_LIBRARIES(box8                  ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box_easy              cmptest.h box_easy.c)
TARGET_LINK_LIBRARIES(box_easy              ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box_easy2             cmptest.h box_easy2.c)
TARGET_LINK_LIBRARIES(box_easy2             ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box_seal              cmptest.h box_seal.c)
TARGET_LINK_LIBRARIES(box_seal              ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (box_seed              cmptest.h box_seed.c)
TARGET_LINK_LIBRARIES(box_seed              ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (chacha20              cmptest.h chacha20.c)
TARGET_LINK_LIBRARIES(chacha20              ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (core1                 cmptest.h core1.c)
TARGET_LINK_LIBRARIES(core1                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (core2                 cmptest.h core2.c)
TARGET_LINK_LIBRARIES(core2                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (core3                 cmptest.h core3.c)
TARGET_LINK_LIBRARIES(core3                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (core4                 cmptest.h core4.c)
TARGET_LINK_LIBRARIES(core4                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (core5                 cmptest.h core5.c)
TARGET_LINK_LIBRARIES(core5                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (core6                 cmptest.h core6.c)
TARGET_LINK_LIBRARIES(core6                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (ed25519_convert       cmptest.h ed25519_convert.c)
TARGET_LINK_LIBRARIES(ed25519_convert       ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (generichash           cmptest.h generichash.c)
TARGET_LINK_LIBRARIES(generichash           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (generichash2          cmptest.h generichash2.c)
TARGET_LINK_LIBRARIES(generichash2          ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (generichash3          cmptest.h generichash3.c)
TARGET_LINK_LIBRARIES(generichash3          ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (hash                  cmptest.h hash.c)
TARGET_LINK_LIBRARIES(hash                  ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (hash3                 cmptest.h hash3.c)
TARGET_LINK_LIBRARIES(hash3                 ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (onetimeauth           cmptest.h onetimeauth.c)
TARGET_LINK_LIBRARIES(onetimeauth           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (onetimeauth2          cmptest.h onetimeauth2.c)
TARGET_LINK_LIBRARIES(onetimeauth2          ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (onetimeauth7          cmptest.h onetimeauth7.c)
TARGET_LINK_LIBRARIES(onetimeauth7          ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (pwhash                cmptest.h pwhash.c)
TARGET_LINK_LIBRARIES(pwhash                ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (pwhash_scrypt_ll      cmptest.h pwhash_scrypt_ll.c)
TARGET_LINK_LIBRARIES(pwhash_scrypt_ll      ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (randombytes           cmptest.h randombytes.c)
TARGET_LINK_LIBRARIES(randombytes           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (scalarmult            cmptest.h scalarmult.c)
TARGET_LINK_LIBRARIES(scalarmult            ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (scalarmult2           cmptest.h scalarmult2.c)
TARGET_LINK_LIBRARIES(scalarmult2           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (scalarmult5           cmptest.h scalarmult5.c)
TARGET_LINK_LIBRARIES(scalarmult5           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (scalarmult6           cmptest.h scalarmult6.c)
TARGET_LINK_LIBRARIES(scalarmult6           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (scalarmult7           cmptest.h scalarmult7.c)
TARGET_LINK_LIBRARIES(scalarmult7           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (secretbox             cmptest.h secretbox.c)
TARGET_LINK_LIBRARIES(secretbox             ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (secretbox2            cmptest.h secretbox2.c)
TARGET_LINK_LIBRARIES(secretbox2            ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (secretbox7            cmptest.h secretbox7.c)
TARGET_LINK_LIBRARIES(secretbox7            ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (secretbox8            cmptest.h secretbox8.c)
TARGET_LINK_LIBRARIES(secretbox8            ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (secretbox_easy        cmptest.h secretbox_easy.c)
TARGET_LINK_LIBRARIES(secretbox_easy        ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (secretbox_easy2       cmptest.h secretbox_easy2.c)
TARGET_LINK_LIBRARIES(secretbox_easy2       ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (shorthash             cmptest.h shorthash.c)
TARGET_LINK_LIBRARIES(shorthash             ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (sign                  cmptest.h sign.c)
TARGET_LINK_LIBRARIES(sign                  ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (sodium_core           cmptest.h sodium_core.c)
TARGET_LINK_LIBRARIES(sodium_core           ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (sodium_utils          cmptest.h sodium_utils.c)
TARGET_LINK_LIBRARIES(sodium_utils          ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (sodium_utils2         cmptest.h sodium_utils2.c)
TARGET_LINK_LIBRARIES(sodium_utils2         ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (sodium_utils3         cmptest.h sodium_utils3.c)
TARGET_LINK_LIBRARIES(sodium_utils3         ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (sodium_version        cmptest.h sodium_version.c)
TARGET_LINK_LIBRARIES(sodium_version        ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (stream                cmptest.h stream.c)
TARGET_LINK_LIBRARIES(stream                ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (stream2               cmptest.h stream2.c)
TARGET_LINK_LIBRARIES(stream2               ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (stream3               cmptest.h stream3.c)
TARGET_LINK_LIBRARIES(stream3               ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (stream4               cmptest.h stream4.c)
TARGET_LINK_LIBRARIES(stream4               ${LIBSODIUM_LIB_PATH})

ADD_EXECUTABLE       (verify1               cmptest.h verify1.c)
TARGET_LINK_LIBRARIES(verify1               ${LIBSODIUM_LIB_PATH})


SET(ADDITIONAL_CLEAN_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/aead_chacha20poly1305.res
    ${CMAKE_CURRENT_SOURCE_DIR}/auth.res
    ${CMAKE_CURRENT_SOURCE_DIR}/auth2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/auth3.res
    ${CMAKE_CURRENT_SOURCE_DIR}/auth5.res
    ${CMAKE_CURRENT_SOURCE_DIR}/auth6.res
    ${CMAKE_CURRENT_SOURCE_DIR}/auth7.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box7.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box8.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box_easy.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box_easy2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box_seal.res
    ${CMAKE_CURRENT_SOURCE_DIR}/box_seed.res
    ${CMAKE_CURRENT_SOURCE_DIR}/chacha20.res
    ${CMAKE_CURRENT_SOURCE_DIR}/core1.res
    ${CMAKE_CURRENT_SOURCE_DIR}/core2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/core3.res
    ${CMAKE_CURRENT_SOURCE_DIR}/core4.res
    ${CMAKE_CURRENT_SOURCE_DIR}/core5.res
    ${CMAKE_CURRENT_SOURCE_DIR}/core6.res
    ${CMAKE_CURRENT_SOURCE_DIR}/ed25519_convert.res
    ${CMAKE_CURRENT_SOURCE_DIR}/generichash.res
    ${CMAKE_CURRENT_SOURCE_DIR}/generichash2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/generichash3.res
    ${CMAKE_CURRENT_SOURCE_DIR}/hash.res
    ${CMAKE_CURRENT_SOURCE_DIR}/hash2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/hash3.res
    ${CMAKE_CURRENT_SOURCE_DIR}/onetimeauth.res
    ${CMAKE_CURRENT_SOURCE_DIR}/onetimeauth2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/onetimeauth7.res
    ${CMAKE_CURRENT_SOURCE_DIR}/pwhash.res
    ${CMAKE_CURRENT_SOURCE_DIR}/pwhash_scrypt_ll.res
    ${CMAKE_CURRENT_SOURCE_DIR}/randombytes.res
    ${CMAKE_CURRENT_SOURCE_DIR}/scalarmult.res
    ${CMAKE_CURRENT_SOURCE_DIR}/scalarmult2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/scalarmult5.res
    ${CMAKE_CURRENT_SOURCE_DIR}/scalarmult6.res
    ${CMAKE_CURRENT_SOURCE_DIR}/scalarmult7.res
    ${CMAKE_CURRENT_SOURCE_DIR}/secretbox.res
    ${CMAKE_CURRENT_SOURCE_DIR}/secretbox2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/secretbox7.res
    ${CMAKE_CURRENT_SOURCE_DIR}/secretbox8.res
    ${CMAKE_CURRENT_SOURCE_DIR}/secretbox_easy.res
    ${CMAKE_CURRENT_SOURCE_DIR}/secretbox_easy2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/shorthash.res
    ${CMAKE_CURRENT_SOURCE_DIR}/sign.res
    ${CMAKE_CURRENT_SOURCE_DIR}/sodium_core.res
    ${CMAKE_CURRENT_SOURCE_DIR}/sodium_utils.res
    ${CMAKE_CURRENT_SOURCE_DIR}/sodium_utils2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/sodium_utils3.res
    ${CMAKE_CURRENT_SOURCE_DIR}/sodium_version.res
    ${CMAKE_CURRENT_SOURCE_DIR}/stream.res
    ${CMAKE_CURRENT_SOURCE_DIR}/stream2.res
    ${CMAKE_CURRENT_SOURCE_DIR}/stream3.res
    ${CMAKE_CURRENT_SOURCE_DIR}/stream4.res
    ${CMAKE_CURRENT_SOURCE_DIR}/verify1.res
)

SET_DIRECTORY_PROPERTIES(PROPERTIES
ADDITIONAL_MAKE_CLEAN_FILES "${ADDITIONAL_CLEAN_FILES}")
