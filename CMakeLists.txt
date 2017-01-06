# Basic CMake project
cmake_minimum_required(VERSION 2.8.11)


project(rct)

#boost testing libraries
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.58 REQUIRED COMPONENTS unit_test_framework date_time regex)

#Boost includes
#target_include_directories(rct PRIVATE ${Boost_INCLUDE_DIRS})

#make executable
FILE(GLOB srcs *.cpp)
list(REMOVE_ITEM srcs "keccak2.cpp")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w -std=c++11 -fpermissive")
ADD_EXECUTABLE(rct ${srcs})


target_link_libraries(rct ${Boost_LIBRARIES})