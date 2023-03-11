cmake_minimum_required(VERSION 3.12)

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

add_subdirectory(pico_dns)
add_subdirectory(pico_hole)
