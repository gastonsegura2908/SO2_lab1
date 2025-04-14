cmake_minimum_required(VERSION 3.25 FATAL_ERROR)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)

file(GLOB TESTS_FILES ${CMAKE_CURRENT_SOURCE_DIR}/unit/*.c)

file(GLOB SRC_FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib//src/.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libsta/src/AlertInvasion.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libsta/src/SuppliesData.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libdyn/src/EmergencyNotification.c
    )


add_compile_definitions(TEST)

if(RUN_COVERAGE)
    message("Coverage enabled")
    find_program(LCOV_PATH lcov)
        if(NOT LCOV_PATH)
        message(FATAL_ERROR "lcov not fund! aborting...")
    endif()

    find_program(GCOV_PATH gcov)
        if(NOT GCOV_PATH)
        message(FATAL_ERROR "gcov not fund! aborting...")
    endif()

    find_program(GENHTML_PATH genhtml)
    if(NOT GENHTML_PATH)
        message(FATAL_ERROR "gcov not fund! aborting...")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fprofile-arcs -ftest-coverage --coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov --coverage")
endif()

add_executable(test_${PROJECT_NAME} ${TESTS_FILES} ${SRC_FILES})

target_link_libraries(test_${PROJECT_NAME} unity cjson)

target_include_directories(test_${PROJECT_NAME} PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/../external/cJSON
	${CMAKE_CURRENT_SOURCE_DIR}/../lib/libdyn/include
	${CMAKE_CURRENT_SOURCE_DIR}/../lib/libsta/include
)

add_test(NAME test_${PROJECT_NAME} COMMAND test_${PROJECT_NAME})



