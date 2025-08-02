cmake_minimum_required(VERSION 3.26)
project(client)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)

FetchContent_Declare(
        cryptopp
        GIT_REPOSITORY https://github.com/weidai11/cryptopp.git
        GIT_TAG        CRYPTOPP_8_9_0
)
set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CRYPTOPP_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cryptopp)

add_executable(client
        main.cpp
        Client.cpp
        Connection.cpp
        CryptoManager.cpp
)

target_include_directories(client PRIVATE
        ${cryptopp_SOURCE_DIR}
)

target_link_libraries(client PRIVATE
        cryptopp-static
)
