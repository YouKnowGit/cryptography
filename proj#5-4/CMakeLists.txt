cmake_minimum_required(VERSION 3.16)
project(proj_5_4 C)

set(CMAKE_C_STANDARD 11)

include_directories(.)
include_directories(__MACOSX)

add_executable(proj_5_4
        __MACOSX/._pkcs.h
        __MACOSX/._pkcs.skeleton.c
        __MACOSX/._sha2.c
        __MACOSX/._sha2.h
        __MACOSX/._test.c
        pkcs.c
        pkcs.h
        sha2.c
        sha2.h
        test.c pkcs_v2.c)
