cmake_minimum_required(VERSION 3.16.0)

project(rtcbase)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden) # or target property <LANG>_VISIBILITY_PRESET
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_OBJC_VISIBILITY_PRESET hidden)
set(CMAKE_OBJCXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

add_compile_options(-Oz -gdwarf-5 -g1 -flto=thin -ffunction-sections -fdata-sections -fno-rtti)# -fno-exceptions)
add_link_options(-Wl,--gc-sections -Wl,--icf=safe)
add_definitions(-DJSON_NOEXCEPTION)

add_library(${PROJECT_NAME} MODULE
    protobuf-c/protobuf-c.c
    Cert.cpp
    DateTime.cpp
    HttpClient.cpp
    laser-ca.der.c
    Log.cpp
    NodeSelector.cpp
    rtc.pb-c.c
    Signal.cpp
    SignalChannel.cpp
    SniUrl.cpp
    stun_test.cpp
    WebSocket.cpp
)
#set_target_properties(${PROJECT_NAME} PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON) # CMAKE_ANDROID_NDK_VERSION not defined, will use gold linker
target_link_libraries(${PROJECT_NAME} PRIVATE z)
if(ANDROID)
  target_link_libraries(${PROJECT_NAME} PRIVATE log)
  include_directories(JMI)
  target_sources(${PROJECT_NAME} PRIVATE
    stun_test.cpp
    stun_jni.cpp
    curl_websocket_jni.cpp
    curl_http_jni.cpp
    jmi.cpp
  )
  set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs)
  if(EXISTS ${LIBS_DIR}/include)
    include_directories(${LIBS_DIR}/include)
    target_link_directories(${PROJECT_NAME} PRIVATE ${LIBS_DIR}/${CMAKE_ANDROID_ARCH_ABI})
    target_link_libraries(${PROJECT_NAME} PRIVATE curl ssl crypto)
  endif()
endif()