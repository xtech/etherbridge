cmake_minimum_required(VERSION 3.16)
project(etherbridge)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(ext)
add_executable(etherbridge src/main.cpp)

target_link_libraries(etherbridge PRIVATE CL11 spdlog pthread)
