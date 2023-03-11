add_executable(pico_hole
  main.c
  dns_server.cpp
  check_allowed.cpp
  )

target_include_directories(pico_hole PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(pico_hole
        pico_dns
        )
