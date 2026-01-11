cmake_minimum_required(VERSION 3.12)

project(IPFLow)

add_executable("${PROJECT_NAME}" src/network_flow/main.cpp src/network_flow/hash_functions.cpp)

include_directories(${PROJECT_SOURCE_DIR}/include)

find_package(PcapPlusPlus REQUIRED)

# We want to have the binary compiled in the same folder as the code
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
