cmake_minimum_required(VERSION 3.10)
project(vrscene2json LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(vrscene2json
    src/main.cpp
    src/VrSceneParser.cpp
    external/miniz_tinfl.c
)

target_include_directories(vrscene2json PRIVATE src external)
