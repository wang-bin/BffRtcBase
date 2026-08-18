#if (__ANDROID__ + 0)
#pragma once
/*
package com.jspp.avrtcsdk.impl;
public abstract class CurlWebSocketClient {
    void dispatchOpen();
    void dispatchMessage(byte[] data, boolean binary);
    void dispatchClose(int code, String reason, boolean remote);
    void dispatchError(int code, int httpCode, String message);
}
*/
#include "jmi.h"

#include <string>
#include <vector>

namespace jmi {

class CurlWebSocketClient : public jmi::JObject<CurlWebSocketClient> {
public:
    using Base = jmi::JObject<CurlWebSocketClient>;
    using Base::Base;
    static constexpr auto name() { return JMISTR("com/jspp/avrtcsdk/impl/CurlWebSocketClient"); }

    void dispatchOpen();
    void dispatchMessage(const std::vector<jbyte> &data, jboolean binary);
    void dispatchClose(jint code, const std::string &reason, jboolean remote);
    void dispatchError(jint code, jint httpCode, const std::string &message);
};

} // namespace jmi
#endif // __ANDROID__
