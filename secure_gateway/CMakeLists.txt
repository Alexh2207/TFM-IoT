cmake_minimum_required(VERSION 3.12)
project (secure_gateway)

# Set C++11
set(CMAKE_CXX_STANDARD 17)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

set(PcapPlusPlus_ROOT /home/ahontanb/TFM/secure_gateway/pcaplusplus/pcapplusplus-24.09-ubuntu-22.04-gcc-11.4.0-x86_64/ CACHE PATH "")

list(APPEND CMAKE_MODULE_PATH "/usr/local/lib/cmake/")

find_package(PcapPlusPlus REQUIRED)
find_package(PahoMqttCpp REQUIRED)
find_package(jsoncpp REQUIRED)
find_package(OpenSSL)

FILE(GLOB Sources src/*.cpp)


add_executable(secure_gateway ${Sources})

set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++ PahoMqttCpp::paho-mqttpp3 jsoncpp_lib)