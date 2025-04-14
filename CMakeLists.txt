# Minimum required cmake version for this project
cmake_minimum_required(VERSION 3.25 FATAL_ERROR)

# Project details
project(
    "EXEC_TP1_SO2"
    VERSION 1.0.0
    DESCRIPTION "socket and IPC project for SO2"
    LANGUAGES C
)

# Enable testing
include(CTest)

set(CMAKE_C_STANDARD 17)

# Include directory where to find headers
include_directories(include)

# Module to fetch a repository
include(FetchContent)

set(UNITY_GIT_URL "https://github.com/ThrowTheSwitch/Unity.git")
set(CJSON_GIT_URL "https://github.com/DaveGamble/cJSON.git")

# Enable debug
set(FETCHCONTENT_QUIET OFF)

FetchContent_Declare(
    Unity
    GIT_REPOSITORY ${UNITY_GIT_URL}
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/Unity 
    UPDATE_COMMAND ""
)

FetchContent_GetProperties(Unity)
if(NOT unity_POPULATED)
    FetchContent_Populate(Unity)
    add_subdirectory(${unity_SOURCE_DIR} ${unity_BINARY_DIR})
endif()

FetchContent_Declare(
    cJSON
    GIT_REPOSITORY ${CJSON_GIT_URL}
    GIT_TAG master 
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/cJSON
    UPDATE_COMMAND "" 
)

# Wait for repo ready
set(ENABLE_CJSON_TEST Off CACHE BOOL "Disable cJSON tests")

FetchContent_GetProperties(cJSON)
if(NOT cJSON_POPULATED)
    FetchContent_Populate(cJSON)
    add_subdirectory(${cjson_SOURCE_DIR} ${cjson_BINARY_DIR})
endif()

file(GLOB_RECURSE SOURCE_CLIENT "src/client.c")
file(GLOB_RECURSE SOURCE_SERVER "src/server.c")


# Create executable
add_executable(${PROJECT_NAME}_client ${SOURCE_CLIENT})
add_executable(${PROJECT_NAME}_server ${SOURCE_SERVER})

# Add libraries, finds other CMakeLists.txt
add_subdirectory(lib/libdyn)
add_subdirectory(lib/libsta)

target_include_directories(${PROJECT_NAME}_server PUBLIC lib/libdyn/include lib/libsta/include)

target_link_libraries(${PROJECT_NAME}_server cjson StaticModulesLib DynamicModuleLib)

# Link libraries, specify Project Name defined in CMakeLists.txt of each library
target_link_libraries(${PROJECT_NAME}_server cjson)

# Add cJSON library
target_include_directories(${PROJECT_NAME}_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/cJSON)

# Add tests
if(RUN_TESTS EQUAL 1 OR RUN_COVERAGE EQUAL 1)
    add_subdirectory(tests)
endif()

