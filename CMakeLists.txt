# matth-x/MicroFtp
# Copyright Matthias Akstaller 2023
# MIT License

cmake_minimum_required(VERSION 3.13)

set(MF_SRC
    src/MicroFtp/FtpClient.cpp
)

set(MF_TEST_SRC
    test/main.cpp
)

project(MicroFtp
    VERSION 0.0.1
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(microftp_test ${MF_SRC} ${MF_TEST_SRC})

target_include_directories(microftp_test PRIVATE
    src
)

add_compile_definitions(
    #MBEDTLS_ERROR_C
)

add_subdirectory(lib/mbedtls)
target_link_libraries(microftp_test PUBLIC 
    mbedtls
    mbedcrypto
    mbedx509
)
