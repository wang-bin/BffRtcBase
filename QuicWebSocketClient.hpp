#if (__ANDROID__ + 0)
#pragma once
/*
package com.jspp.avrtcsdk.impl;
public abstract class QuicWebSocketClient {
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

class QuicWebSocketClient : public jmi::JObject<QuicWebSocketClient> {
public:
    using Base = jmi::JObject<QuicWebSocketClient>;
    using Base::Base;
    static constexpr auto name() { return JMISTR("com/jspp/avrtcsdk/impl/QuicWebSocketClient"); }

    void dispatchOpen();
    void dispatchMessage(const std::vector<jbyte> &data, jboolean binary);
    void dispatchClose(jint code, const std::string &reason, jboolean remote);
    void dispatchError(jint code, jint httpCode, const std::string &message);
};

} // namespace jmi
#endif // __ANDROID__
