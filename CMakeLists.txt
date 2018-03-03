cmake_minimum_required(VERSION 2.6)

PROJECT(rawsocketrcv)
ADD_DEFINITIONS(-Wall -W -fPIE -Os -Werror -Wmissing-declarations)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -c -pipe -g -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --std=gnu99 -g3")

FIND_LIBRARY(ubox_library NAMES ubox)
FIND_PATH(ubox_include_dir libubox/uloop.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

 
FIND_LIBRARY(ubus_library NAMES ubus)
FIND_PATH(ubus_include_dir libubus.h)
INCLUDE_DIRECTORIES(${ubus_include_dir})

ADD_SUBDIRECTORY(modules/ubus)

FIND_LIBRARY(pcap_library NAMES pcap)
FIND_PATH(pcap_include_dir pcap.h)
INCLUDE_DIRECTORIES(${pcap_include_dir})

FIND_LIBRARY(thread_library NAMES pthread)
FIND_PATH(tread_include_dir thread)
INCLUDE_DIRECTORIES(${thread_include_dir})




ADD_EXECUTABLE(rawsocketrcv main.cpp)
SET_TARGET_PROPERTIES(rawsocketrcv PROPERTIES OUTPUT_NAME rawsocketrcv)
TARGET_LINK_LIBRARIES(rawsocketrcv ${thread_library} ${pcap_library} ubus_publish ${ubox_library} ${ubus_library})

#INSTALL(TARGETS ubus cli
#	LIBRARY DESTINATION lib
#	RUNTIME DESTINATION bin
#)
#INSTALL(TARGETS ubusd
#	RUNTIME DESTINATION sbin
#)

#INSTALL(FILES ubusmsg.h ubus_common.h libubus.h DESTINATION include)
