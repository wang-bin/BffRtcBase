#if (__ANDROID__ + 0)
#include <jni.h>

#include <string>

#include "defs.h"
#include "jmi.h"

#define JSPPRTC_JNI_FUNC(Name) Java_com_jspp_avrtcsdk_impl_##Name
#define JSPPRTC_JNI_S(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name)(JNIEnv* env, jclass clazz, ##__VA_ARGS__)

namespace {

bff::SignalImplementation ToNativeSignalImpl(jint impl)
{
    // Java: NATIVE=0, CURL=1, QUIC=2, MIXED=3
    // C++: Curl=0, Quic=1, Mixed=2 (no Native)
    switch (impl) {
    case 1:
        return bff::SignalImplementation::Curl;
    case 2:
        return bff::SignalImplementation::Quic;
    case 3:
        return bff::SignalImplementation::Mixed;
    case 0:
    default:
        return bff::SignalImplementation::Curl;
    }
}

} // namespace

extern "C" {

JSPPRTC_JNI_S(void,
              StunUtil_nativeApplyConfig,
              jstring role,
              jobjectArray hostKeys,
              jobjectArray hostValues,
              jboolean sni,
              jboolean compression,
              jint icePolicy,
              jstring server,
              jlong serverRecheck,
              jint serversSortTimeout,
              jstring signalServer,
              jboolean signalJson,
              jint signalImplementation,
              jint mixedDelay,
              jint connectTimeout,
              jint pingInterval,
              jint pingTimeout,
              jint reconnectInterval,
              jint reconnectMaxTimes,
              jint responseTimeout,
              jboolean autoSubscribe)
{
    auto& c = bff::Config::Shared();

    const std::string roleStr = jmi::to_string(role, env);
    if (!roleStr.empty()) {
        c.role = roleStr;
    } else {
        c.role.reset();
    }

    c.hosts.clear();
    if (hostKeys && hostValues) {
        const jsize n = env->GetArrayLength(hostKeys);
        const jsize m = env->GetArrayLength(hostValues);
        const jsize count = n < m ? n : m;
        for (jsize i = 0; i < count; ++i) {
            const std::string k = jmi::to_string(static_cast<jstring>(env->GetObjectArrayElement(hostKeys, i)), env);
            const std::string v = jmi::to_string(static_cast<jstring>(env->GetObjectArrayElement(hostValues, i)), env);
            if (!k.empty() && !v.empty()) {
                c.hosts[k] = v;
            }
        }
    }

    c.sni = sni == JNI_TRUE;
    c.compression = compression == JNI_TRUE;
    c.icePolicy = static_cast<bff::RtcIcePolicy>(icePolicy);

    const std::string serverStr = jmi::to_string(server, env);
    if (!serverStr.empty()) {
        c.server = serverStr;
    } else {
        c.server.reset();
    }
    c.serverRecheck = static_cast<int>(serverRecheck);
    c.serversSortTimeout = serversSortTimeout;

    const std::string signalServerStr = jmi::to_string(signalServer, env);
    if (!signalServerStr.empty()) {
        c.signal.server = signalServerStr;
    } else {
        c.signal.server.reset();
    }
    c.signal.json = signalJson == JNI_TRUE;
    c.signal.implementation = ToNativeSignalImpl(signalImplementation);
    c.signal.mixedDelay = mixedDelay;
    c.signal.connectTimeout = connectTimeout;
    c.signal.pingInterval = pingInterval;
    c.signal.pingTimeout = pingTimeout;
    c.signal.reconnectInterval = reconnectInterval;
    c.signal.reconnectMaxTimes = reconnectMaxTimes;
    c.signal.responseTimeout = responseTimeout;
    c.signal.autoSubscribe = autoSubscribe == JNI_TRUE;
}

} // extern "C"
#endif
