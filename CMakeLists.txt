cmake_minimum_required(VERSION 3.8)
project(fan-test)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(3rd-party/googletest-main)

add_library(fan-interceptor OBJECT
    src/interceptor_types.cpp
    src/interceptor_l1.cpp
    src/interceptor_l2.cpp
    src/l2_cache.cpp
    src/utils.cpp)

target_include_directories(fan-interceptor INTERFACE src)

add_executable(iceptor-tester src/iceptor-tester.cpp)
target_link_libraries(iceptor-tester fan-interceptor)

enable_testing()
add_executable(unit-tests test/basic-tests.cpp test/layer2.cpp test/cache.cpp)
target_link_libraries(unit-tests GTest::gtest_main gmock fan-interceptor)

include(GoogleTest)
gtest_discover_tests(unit-tests)
# set_tests_properties("DeferredDispatcher.WaitOnCancelling" PROPERTIES TIMEOUT 0.5)
