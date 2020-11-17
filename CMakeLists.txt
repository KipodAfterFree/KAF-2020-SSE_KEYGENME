cmake_minimum_required(VERSION 3.4)
project(SSE_KEYGENME)

add_executable(SSE_KEYGENME src/main.c)

target_compile_options(SSE_KEYGENME PRIVATE -march=native)
