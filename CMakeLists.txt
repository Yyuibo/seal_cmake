cmake_minimum_required(VERSION 3.13)

project(seal_test)

add_executable(test test.cpp)

SET(SEAL_DIR "/home/ubuntu/flpsi/SEAL/build/cmake")
find_package(SEAL)

if(NOT SEAL_FOUND)
    message("seal not found")
endif()

target_link_libraries(test SEAL::seal)
