cmake_minimum_required(VERSION 3.0)

project(sdktest)

set(PARENT_DIR ${CMAKE_CURRENT_LIST_DIR}/../)

set(SSL_LIB ${CMAKE_CURRENT_LIST_DIR}/../../)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

set(PROJECT_LINK_LIBS libutil.a libcrypto.a libssl.a)

link_directories(${PARENT_DIR}/util/lib ${SSL_LIB}/static)

include_directories(${PARENT_DIR}/util/include ${SSL_LIB}/include)

add_executable(sdktest main.c)

target_link_libraries(sdktest ${PROJECT_LINK_LIBS})


