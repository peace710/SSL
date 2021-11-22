cmake_minimum_required(VERSION 3.0)

project(util)

set(SSL_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../../)

set(PROJECT_LINK_LIBS libcrypto.a libssl.a)

include_directories(include ${SSL_LIB}/include)

link_directories(${SSL_LIB}/static)

file(GLOB SOURCE "src/*.c")

add_library(util STATIC ${SOURCE})

target_link_libraries(util ${PROJECT_LINK_LIBS})

set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set_target_properties(util PROPERTIES LINKER_LANGUAGE C)
