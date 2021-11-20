cmake_minimum_required(VERSION 3.0)

project(sdktest)

set(PARENT_DIR ${CMAKE_CURRENT_LIST_DIR}/../)

Message("======>${PARENT_DIR}\n")

set(PROJECT_LINK_LIBS libutil.a)

link_directories(${PARENT_DIR}/util/lib)

include_directories(${PARENT_DIR}/util/include)

add_executable(hextest main.c)

target_link_libraries(hextest ${PROJECT_LINK_LIBS})


