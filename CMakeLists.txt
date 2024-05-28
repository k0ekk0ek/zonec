cmake_minimum_required(VERSION 3.10)
project(zonec VERSION 4.3.9 LANGUAGES C)

find_package(FLEX 2.6.4 REQUIRED)
find_package(BISON 3.0.4 REQUIRED)

bison_target(
  zparser zparser.y
  ${CMAKE_CURRENT_BINARY_DIR}/zparser.c
  DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/zparser.h)

flex_target(
  zlexer zlexer.lex
  ${CMAKE_CURRENT_BINARY_DIR}/zlexer.c)

add_flex_bison_dependency(zlexer zparser)

add_library(zonec ${FLEX_zlexer_OUTPUTS} ${BISON_zparser_OUTPUTS} dns.c zonec.c rdata.c dname.c util.c b64_pton.c region-allocator.c)

target_include_directories(
  zonec PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
               $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)

add_executable(zonec-test main.c)
target_link_libraries(zonec-test zonec)
