cmake_minimum_required(VERSION 2.6)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)
ADD_DEFINITIONS(-I..)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/..)
ADD_LIBRARY(ubus_publish STATIC ubus_publish.c)
FIND_LIBRARY(ubox_library NAMES ubox)
FIND_LIBRARY(ubus_library NAMES ubus)
TARGET_LINK_LIBRARIES(ubus_publish ${ubox_library} ${ubus_library} )
