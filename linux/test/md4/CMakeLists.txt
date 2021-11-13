cmake_minimum_required(VERSION 3.0)

project(test)

MESSAGE("-- Path is ${CMAKE_CURRENT_LIST_DIR}")

set(LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../)

set(PARENT_DIR ${CMAKE_CURRENT_LIST_DIR}/../)

MESSAGE("-- Lib dir is ${LIB_DIR}")

MESSAGE("-- Parent dir is ${PARENT_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

set(PROJECT_LINK_LIBS libcrypto.a libssl.a libio_util.a)

link_directories(${LIB_DIR}/static ${PARENT_DIR}/ioutil)

include_directories(${LIB_DIR}/include ${PARENT_DIR}/ioutil)

add_executable(md4 main.cpp)

target_link_libraries(md4 ${PROJECT_LINK_LIBS})


