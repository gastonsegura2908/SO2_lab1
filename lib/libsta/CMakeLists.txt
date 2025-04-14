cmake_minimum_required(VERSION 3.25 FATAL_ERROR)

project(
    "StaticModulesLib"
    VERSION 1.0.0
    DESCRIPTION "Modules AlertInvasion & SuppliesData"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)

include_directories(include)

file(GLOB_RECURSE SOURCES "src/*.c")
add_library(${PROJECT_NAME} STATIC ${SOURCES})

target_link_libraries(${PROJECT_NAME} cjson)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../external/cJSON)


