
project(blacklist)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

add_executable(${PROJECT_NAME}
    blacklist.cpp
)

target_link_libraries(${PROJECT_NAME}
    pcap
)

# vim: ts=4 sw=4 et
