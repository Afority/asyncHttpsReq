cmake_minimum_required(VERSION 3.16)

project(asyncHttpsRequests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(asyncHttpsRequests
  main.cpp

  network.cpp
  network.h
  crypto.cpp
  crypto.h

  json.hpp
)

find_package(OpenSSL REQUIRED)

target_link_libraries(asyncHttpsRequests PRIVATE OpenSSL::SSL OpenSSL::Crypto)


include(GNUInstallDirs)
install(TARGETS asyncHttpsRequests
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
