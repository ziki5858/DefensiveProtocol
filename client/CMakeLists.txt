cmake_minimum_required(VERSION 3.26)
project(client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------------
# Fetch & build Crypto++
# --------------------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(
        cryptopp
        GIT_REPOSITORY https://github.com/weidai11/cryptopp.git
        GIT_TAG        CRYPTOPP_8_9_0
)
set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CRYPTOPP_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cryptopp)

# Disable SIMD instructions that cause build errors with MinGW
add_definitions(
        -DCRYPTOPP_DISABLE_ASM
        -DCRYPTOPP_DISABLE_SSSE3
        -DCRYPTOPP_DISABLE_SSE4
        -DCRYPTOPP_DISABLE_AESNI
        -DCRYPTOPP_DISABLE_SHA
)

# Build static library from all .cpp files in cryptopp
file(GLOB CRYPTOPP_SOURCES "${cryptopp_SOURCE_DIR}/*.cpp")
add_library(cryptopp STATIC ${CRYPTOPP_SOURCES})
target_include_directories(cryptopp PUBLIC ${cryptopp_SOURCE_DIR})

# --------------------------------------------------------------------------
# Client executable
# --------------------------------------------------------------------------
add_executable(client
        main.cpp
        Client.cpp
        Connection.cpp
        CryptoManager.cpp
        ProtocolBuilder.cpp
        ProtocolParser.cpp
)

# Link Crypto++ and Winsock
target_link_libraries(client PRIVATE cryptopp ws2_32)
