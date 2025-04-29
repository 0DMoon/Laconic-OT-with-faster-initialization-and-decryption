cmake_minimum_required( VERSION 3.21 )
project(myLaconicPSI) # project name

# add_library(relic SHARED IMPORTED GLOBAL)
# set_target_properties(relic PROPERTIES IMPORTED_LOCATION /usr/local/lib/libglpk.so)
add_library(pbc SHARED IMPORTED GLOBAL)
set_target_properties(pbc PROPERTIES IMPORTED_LOCATION /usr/local/lib/libpbc.so)

SET(COMMON_FLAGS "-Wall -march=native -Wfatal-errors")
SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
SET(CMAKE_CXX_FLAGS_DEBUG  "-O2 -g -ggdb")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -std=c++17 -lpthread -lpbc -lgmp")

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)
# INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/lib)
INCLUDE_DIRECTORIES(/usr/local/include/pbc)
aux_source_directory(. DIR_SRCS)

add_executable(${PROJECT_NAME} ${DIR_SRCS})

# find_package(libpbc REQUIRED)
target_link_libraries(${PROJECT_NAME} gmp pbc)