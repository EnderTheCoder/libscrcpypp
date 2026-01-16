cmake_minimum_required(VERSION 3.25)
project(scrcpy++ VERSION 1.9.2)

if (WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00)
    add_compile_definitions(NOMINMAX)
endif ()

set(CMAKE_CXX_STANDARD 23)

if (WIN32)
    set(BOOST_COMPONENTS filesystem system process program_options)
else()
    set(BOOST_COMPONENTS filesystem system program_options)
endif()

find_package(Boost 1.80.0 COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
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
        PRIVATE Boost::filesystem
        PRIVATE Boost::system
        PRIVATE Boost::program_options
        PUBLIC PkgConfig::LIBAV
        PUBLIC ${OpenCV_LIBS}
        PRIVATE $<$<PLATFORM_ID:Windows>:ws2_32>
)

if (WIN32)
    target_link_libraries(scrcpy++ PRIVATE Boost::process)
endif()

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

add_executable(scrcpy++-reconnect-test)
target_include_directories(scrcpy++-reconnect-test PUBLIC test)
target_sources(scrcpy++-reconnect-test PRIVATE test/reconnect_test.cpp)
target_link_libraries(scrcpy++-reconnect-test PRIVATE scrcpy++)
