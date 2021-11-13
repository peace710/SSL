cmake_minimum_required(VERSION 3.0)

set(LIBIO_UTIL io_util.cpp io_util.h)

add_library(io_util STATIC ${LIBIO_UTIL})

set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(io_util PROPERTIES LINKER_LANGUAGE C)
