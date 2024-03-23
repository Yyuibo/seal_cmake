cmake_minimum_required(VERSION 3.13)
set(VCPKG_ROOT "/home/yuibo/code/vcpkg")
set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")

project(seal_test)

set(zstd_DIR "${VCPKG_ROOT}/packages/zstd_x64-linux/share/zstd")
set(Microsoft.GSL_DIR "${VCPKG_ROOT}/packages/ms-gsl_x64-linux/share/Microsoft.GSL")
SET(SEAL_DIR "${VCPKG_ROOT}/packages/seal_x64-linux/share/seal")
find_package(SEAL 4.1 CONFIG REQUIRED)

add_executable(test test.cc)

target_link_libraries(test PRIVATE SEAL::seal)
