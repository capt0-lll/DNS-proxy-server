cmake_minimum_required(VERSION 3.28)
project(testTask1 C)

set(CMAKE_C_STANDARD 11)

add_executable(testTask1 main.c
        src/server.c
        inc/server.h)

target_include_directories(testTask1 PRIVATE ${PROJECT_SOURCE_DIR}/src
        PRIVATE ${PROJECT_SOURCE_DIR}/inc
)

target_link_libraries(testTask1 PRIVATE cjson)