cmake_minimum_required(VERSION 2.6)

ADD_DEFINITIONS(-I..)
FIND_LIBRARY(ubox_library NAMES ubox)
FIND_LIBRARY(ubus_library NAMES ubus)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/..)
ADD_LIBRARY(ubus_publish STATIC ubus_publish.c)
TARGET_LINK_LIBRARIES(ubus_publish ${ubox_library} ${ubus_library} )
