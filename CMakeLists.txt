cmake_minimum_required(VERSION 3.29)
project(royooscan C)

set(CMAKE_C_STANDARD 11)

add_executable(royooscan main.c)

target_link_libraries(royooscan ws2_32)
