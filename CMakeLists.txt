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

include(xcfwk.cmake)

add_compile_options(-Oz -gdwarf-5 -g1 -flto=thin -fno-rtti)# -fno-exceptions)
if(ANDROID)
  add_compile_options(-ffunction-sections -fdata-sections)
  add_link_options(-Wl,--gc-sections -Wl,--icf=safe -flto=thin)
endif()
add_definitions(-DJSON_NOEXCEPTION)

# libev backends (epoll/kqueue/...) are #included by ev.c — do not compile them separately
add_library(libev OBJECT
    libev/ev.c
)
target_include_directories(libev PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libev)

add_library(quic OBJECT
    quic/src/conn.cc
    quic/src/listener.cc
    quic/src/socket.cc
)
target_include_directories(quic PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/quic/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libev
)

add_library(${PROJECT_NAME} MODULE
    protobuf-c/protobuf-c.c
    Cert.cpp
    DateTime.cpp
    HttpClient.cpp
    laser-ca.der.c
    Log.cpp
    NodeSelector.cpp
    PbCJson.cpp
    rtc.pb-c.c
    Signal.cpp
    SignalChannel.cpp
    SniUrl.cpp
    stun_test.cpp
    WebSocket.cpp
)
#set_target_properties(${PROJECT_NAME} PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON) # CMAKE_ANDROID_NDK_VERSION not defined, will use gold linker
target_link_libraries(${PROJECT_NAME} PRIVATE libev quic z)


if(ANDROID)
  set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs)
  target_link_libraries(${PROJECT_NAME} PRIVATE log)
  include_directories(JMI)
  target_sources(${PROJECT_NAME} PRIVATE
    stun_test.cpp
    stun_jni.cpp
    curl_websocket_jni.cpp
    quic_websocket_jni.cpp
    curl_http_jni.cpp
    jmi.cpp
  )
  if(EXISTS ${LIBS_DIR}/include)
    include_directories(${LIBS_DIR}/include)
    target_link_directories(${PROJECT_NAME} PRIVATE ${LIBS_DIR}/${CMAKE_ANDROID_ARCH_ABI})
    target_link_libraries(${PROJECT_NAME} PRIVATE curl ssl crypto ngtcp2 ngtcp2_crypto_boringssl)
  endif()
endif()
if(IOS)
  set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../libs)
  message(STATUS "LIBS_DIR: ${LIBS_DIR}")
  find_library(OPENSSL NAMES openssl PATHS "${LIBS_DIR}" NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
  find_library(NGTCP2 NAMES ngtcp2 PATHS "${LIBS_DIR}" NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
  find_library(CURL NAMES curl PATHS "${LIBS_DIR}" NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
  find_xcframework(OPENSSL_XCFW "${OPENSSL}")
  find_xcframework(NGTCP2_XCFW "${NGTCP2}")
  find_xcframework(CURL_XCFW "${CURL}")
  target_compile_options(quic PRIVATE "${OPENSSL_XCFW_CFLAGS}" "${NGTCP2_XCFW_CFLAGS}" "${CURL_XCFW_CFLAGS}")
  target_compile_options(${PROJECT_NAME} PRIVATE "${CURL_XCFW_CFLAGS}" "${OPENSSL_XCFW_CFLAGS}")
  target_link_libraries(quic PUBLIC "${OPENSSL_XCFW_LFLAGS}" "${NGTCP2_XCFW_LFLAGS}" "${CURL_XCFW_LFLAGS}")
  target_link_libraries(${PROJECT_NAME} PRIVATE "${CURL_XCFW_LFLAGS}" "${OPENSSL_XCFW_LFLAGS}")
endif()