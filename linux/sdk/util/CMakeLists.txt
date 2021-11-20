cmake_minimum_required(VERSION 3.0)

project(util)

include_directories(include)

file(GLOB SOURCE "src/*.c")

add_library(util STATIC ${SOURCE})

set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set_target_properties(util PROPERTIES LINKER_LANGUAGE C)
