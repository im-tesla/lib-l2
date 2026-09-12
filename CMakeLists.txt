cmake_minimum_required(VERSION 3.16)
project(lib-l2 CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(lib-l2 src/example.cpp)
target_include_directories(lib-l2 PRIVATE src)

if(WIN32)
    target_link_libraries(lib-l2 PRIVATE ws2_32 iphlpapi)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(lib-l2 PRIVATE dl)
endif()
