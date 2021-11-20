cmake_minimum_required(VERSION 3.0)

project(test)

set(LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../)

set(PARENT_DIR ${CMAKE_CURRENT_LIST_DIR}/../)

set(PROJECT_LINK_LIBS  libio_util.a)

link_directories(${LIB_DIR}/static ${PARENT_DIR}/ioutil)

include_directories(${LIB_DIR}/include ${PARENT_DIR}/ioutil)

add_executable(hex main.c)

target_link_libraries(hex ${PROJECT_LINK_LIBS})


