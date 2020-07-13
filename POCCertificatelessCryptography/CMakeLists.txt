cmake_minimum_required(VERSION 3.10)
project(POCCertificatelessCryptography C)

set(CMAKE_C_STANDARD 11)

include_directories(PUBLIC ${CMAKE_SOURCE_DIR}/libs/relic-target/include)
include_directories(PUBLIC ${CMAKE_SOURCE_DIR}/libs/relic/include)
include_directories(PUBLIC ${CMAKE_SOURCE_DIR}/libs/unqlite)
include_directories(.)

link_libraries(${CMAKE_SOURCE_DIR}/libs/relic-target/lib/librelic.so)
link_libraries(${CMAKE_SOURCE_DIR}/libs/unqlite/libunqlite.a)
link_libraries(sodium)
link_libraries(nsl)
link_libraries(pthread)
link_libraries(binn)

set(COMMON_SOURCES cipherPOC.c cipherPOC.h signaturePOC.c signaturePOC.h utils/base64.c utils/base64.h)
set(CLIENT_SOURCES client/mainClient.c utils/aesUtils.c utils/aesUtils.h)
set(SERVER_SOURCES server/mainServer.c)
set(TEST_SOURCES test/fullTest.c utils/aesUtils.c utils/aesUtils.h)

add_executable(mainClient ${CLIENT_SOURCES} ${COMMON_SOURCES})
add_executable(mainServer ${SERVER_SOURCES} ${COMMON_SOURCES})
add_executable(testAlgo ${TEST_SOURCES} ${COMMON_SOURCES})