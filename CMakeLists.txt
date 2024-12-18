cmake_minimum_required(VERSION 3.15)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Release>:Release>")

project(windows7)

add_library(api-ms-win-core-path-l1-1-0 SHARED api-ms-win-core-path-blender.c)
install(TARGETS api-ms-win-core-path-l1-1-0)
