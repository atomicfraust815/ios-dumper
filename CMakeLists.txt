cmake_minimum_required(VERSION 3.21)

project(iosdumper VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "iosdumper currently supports Windows x64 only")
endif()

add_library(iosdumper_config STATIC
    src/config.cpp
    src/config.hpp
    src/json.hpp
)
target_include_directories(iosdumper_config PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(iosdumper_config PUBLIC cxx_std_17)

add_executable(iosdumper src/main.cpp)
target_link_libraries(iosdumper PRIVATE iosdumper_config)
target_compile_features(iosdumper PRIVATE cxx_std_17)

if(MSVC)
    set_property(TARGET iosdumper iosdumper_config PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_options(iosdumper PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(iosdumper_config PRIVATE /W4 /permissive- /utf-8)
endif()

add_custom_command(TARGET iosdumper POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/signatures.json"
            "$<TARGET_FILE_DIR:iosdumper>/signatures.json"
    VERBATIM
)

include(CTest)
if(BUILD_TESTING)
    add_executable(config_tests tests/config_tests.cpp)
    target_link_libraries(config_tests PRIVATE iosdumper_config)
    target_compile_features(config_tests PRIVATE cxx_std_17)
    if(MSVC)
        set_property(TARGET config_tests PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        target_compile_options(config_tests PRIVATE /W4 /permissive- /utf-8)
    endif()
    add_test(NAME config_tests COMMAND config_tests)
endif()
