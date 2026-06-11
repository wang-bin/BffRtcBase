cmake_minimum_required(VERSION 3.16.0)

project(rtcbase)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-fno-rtti)# -fno-exceptions)
add_definitions(-DJSON_NOEXCEPTION)

add_library(${PROJECT_NAME} MODULE
    protobuf-c/protobuf-c.c
    Cert.cpp
    DateTime.cpp
    HttpClient.cpp
    laser-ca.der.c
    NodeSelector.cpp
    rtc.pb-c.c
    Signal.cpp
    SignalChannel.cpp
    SniUrl.cpp
    stun_test.cpp
    WebSocket.cpp
)
target_link_libraries(${PROJECT_NAME} PRIVATE z)
if(ANDROID)
  target_link_libraries(${PROJECT_NAME} PRIVATE log)
  include_directories(JMI)
  target_sources(${PROJECT_NAME} PRIVATE
    stun_test.cpp
    stun_jni.cpp
    curl_websocket_jni.cpp
    jmi.cpp
  )
  set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs)
  if(EXISTS ${LIBS_DIR}/include)
    include_directories(${LIBS_DIR}/include)
    target_link_directories(${PROJECT_NAME} PRIVATE ${LIBS_DIR}/${CMAKE_ANDROID_ARCH_ABI})
    target_link_libraries(${PROJECT_NAME} PRIVATE curl ssl crypto)
  endif()
endif()