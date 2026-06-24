# Copyright (c) 2026 DPTechnics BV
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.
#
# Author: Daan Pape <daan@dptechnics.com>

cmake_minimum_required(VERSION 3.21)
project(bluecherry-lite LANGUAGES C)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if(OPENSSL_FOUND)
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
endif()

set(SOURCES
    src/bclite.c
)

option(BC_LOG_ENABLE "Enable BlueCherry logging" ON)

add_library(bluecherry-lite SHARED ${SOURCES})

set_target_properties(bluecherry-lite PROPERTIES C_STANDARD 99 C_EXTENSIONS ON)
target_compile_options(bluecherry-lite PRIVATE -Wall -Wextra)

if(BC_LOG_ENABLE)
    target_compile_definitions(bluecherry-lite PRIVATE BC_LOG_ENABLE=1)
endif()
target_include_directories(bluecherry-lite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/inc)
target_link_libraries(bluecherry-lite OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# bluecherry-lite library installation
install(TARGETS bluecherry-lite DESTINATION lib)

# Install the header files
install(FILES "inc/bclite.h" DESTINATION "include/bluecherry" COMPONENT Headers)
