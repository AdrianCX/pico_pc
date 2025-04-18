cmake_minimum_required(VERSION 3.12)

project("pico_hole")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_compile_options(-O2
  -Wall
  -Wno-unused-result
  -Wno-format
  -Wno-unused-function
  -Wno-maybe-uninitialized
  -Werror
  )

set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

add_subdirectory(pico_dns)
add_subdirectory(pico_hole)
