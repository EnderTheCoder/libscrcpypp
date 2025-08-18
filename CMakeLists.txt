cmake_minimum_required(VERSION 3.25)
project(scrcpy++ VERSION 1.8.3)
if (WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00)
    add_compile_definitions(NOMINMAX)
endif ()
set(CMAKE_CXX_STANDARD 23)
set(ENV{PKG_CONFIGFLAGS} "--static")

find_package(Boost 1.80.0 COMPONENTS filesystem system REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(OpenCV 4.0 REQUIRED)
pkg_check_modules(LIBAV REQUIRED IMPORTED_TARGET
        libavdevice
        libavfilter
        libavformat
        libavcodec
        libswresample
        libswscale
        libavutil
)
include_directories(${Boost_INCLUDE_DIRS})

add_library(scrcpy++ STATIC src/client.cpp src/decoder.cpp src/frame.cpp src/control_msg.cpp)
target_include_directories(scrcpy++ PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include/scrcpy++>
)
target_link_libraries(scrcpy++
        PUBLIC Boost::filesystem
        PUBLIC Boost::system
        PUBLIC PkgConfig::LIBAV
        PUBLIC ${OpenCV_LIBS}
        PUBLIC $<$<PLATFORM_ID:Windows>:ws2_32>
)

add_executable(scrcpy++-video-test)
target_include_directories(scrcpy++-video-test PUBLIC test)
target_sources(scrcpy++-video-test PRIVATE test/video_test.cpp)
target_link_libraries(scrcpy++-video-test PRIVATE scrcpy++)

add_executable(scrcpy++-video-test-async)
target_include_directories(scrcpy++-video-test-async PUBLIC test)
target_sources(scrcpy++-video-test-async PRIVATE test/video_test_async.cpp)
target_link_libraries(scrcpy++-video-test-async PRIVATE scrcpy++)


add_executable(scrcpy++-control-test)
target_include_directories(scrcpy++-control-test PUBLIC test)
target_sources(scrcpy++-control-test PRIVATE test/control_test.cpp)
target_link_libraries(scrcpy++-control-test PRIVATE scrcpy++)


install(TARGETS scrcpy++
        ARCHIVE DESTINATION lib
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/scrcpy++Config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/scrcpy++Config.cmake
        INSTALL_DESTINATION lib/cmake/scrcpy++
)

write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/scrcpy++ConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
)
install(TARGETS scrcpy++
        EXPORT scrcpy++Targets
        ARCHIVE DESTINATION lib
        INCLUDES DESTINATION include
)

install(EXPORT scrcpy++Targets
        FILE scrcpy++Targets.cmake
        NAMESPACE scrcpy::
        DESTINATION lib/cmake/scrcpy++
)

install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/scrcpy++Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/scrcpy++ConfigVersion.cmake
        DESTINATION lib/cmake/scrcpy++
)

install(FILES src/client.hpp src/decoder.hpp src/frame.hpp src/control_msg.hpp
        DESTINATION include/scrcpy++
)
