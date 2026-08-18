#if (__ANDROID__ + 0)
#include <jni.h>
#include <mutex>
#include <string>
#include <set>
#include <vector>
#include <android/log.h>
#include "stun_test.h"
#include "Log.hpp"
#include "jmi.h"
#include "android.util.Pair.hpp"
#include "FileLogger.hpp"
#include "java.lang.Integer.hpp"

using namespace std;

#define JSPPRTC_JNI_FUNC(Name) Java_com_jspp_avrtcsdk_impl_##Name
#define JSPPRTC_JNI(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jobject thiz, ##__VA_ARGS__)
#define JSPPRTC_JNI_S(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jclass clazz, ##__VA_ARGS__)

namespace {

set<string> to_servers(JNIEnv *env, jobjectArray jservers) {
    set<string> servers;
    if (!jservers) {
        return servers;
    }
    const jsize len = env->GetArrayLength(jservers);
    for (jsize i = 0; i < len; ++i) {
        servers.insert(jmi::to_string(static_cast<jstring>(env->GetObjectArrayElement(jservers, i)), env));
    }
    return servers;
}

void to_rtts(vector<pair<string, int>> &p, JNIEnv *env, jobjectArray ja) {
    p.clear();
    if (!ja) {
        return;
    }
    const jsize n = env->GetArrayLength(ja);
    p.reserve(static_cast<size_t>(n));
    for (jsize i = 0; i < n; ++i) {
        jmi::android::util::Pair row(env->GetObjectArrayElement(ja, i));
        if (!row) {
            continue;
        }
        const auto second = row.second();
        if (!second || !env->IsInstanceOf(second.id(), jmi::java::lang::Integer())) {
            continue;
        }
        jmi::java::lang::Integer rtt(second.id(), false);
        p.emplace_back(row.first().toString(), rtt.intValue());
    }
}

} // namespace

extern "C" {

jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_4) != JNI_OK || !env) {
        return -1;
    }
    jmi::javaVM(vm);
    return JNI_VERSION_1_4;
}

JSPPRTC_JNI_S(jstring, StunUtil_nativeGetIpFromStun, jstring server, jint timeoutMs) {
    set<string> servers{jmi::to_string(server, env)};
    string clientIp;
    auto sorted = SortStun(servers, timeoutMs, &clientIp);
    if (sorted.empty()) {
        __android_log_print(ANDROID_LOG_WARN, "JsppPeerconnect", "no stun server is reachable");
        return nullptr;
    }
    return jmi::from_string(clientIp, env);
}

JSPPRTC_JNI_S(jstring, StunUtil_nativeFindBestStunServer, jobjectArray jservers, jint timeoutMs) {
    string clientIp;
    string res = QueryFastestStun(to_servers(env, jservers), timeoutMs, &clientIp);
    if (res.empty()) {
        return nullptr;
    }
    return jmi::from_string(res, env);
}

JSPPRTC_JNI_S(jobjectArray, StunUtil_nativeSortStunServers, jobjectArray jservers, jint timeoutMs) {
    string clientIp;
    auto sorted = SortStun(to_servers(env, jservers), timeoutMs, &clientIp);
    if (sorted.empty()) {
        __android_log_print(ANDROID_LOG_WARN, "JsppPeerconnect", "no stun server is reachable");
        return nullptr;
    }
    vector<jmi::android::util::Pair> rows;
    rows.reserve(sorted.size());
    for (const auto &item : sorted) {
        rows.push_back(jmi::android::util::Pair::of(item.first, item.second));
    }
    return static_cast<jobjectArray>(jmi::detail::to_jarray(env, rows));
}

JSPPRTC_JNI_S(jstring, StunUtil_nativeFindBestNode, jobjectArray jRtts1, jobjectArray jRtts2) {
    vector<pair<string, int>> rtts1, rtts2;
    to_rtts(rtts1, env, jRtts1);
    to_rtts(rtts2, env, jRtts2);
    return jmi::from_string(FindBestNode(rtts1, rtts2), env);
}

JSPPRTC_JNI_S(void, StunUtil_nativeSetLogger, jobject obj)
{
    static mutex mtx;
    static jmi::FileLogger gLogger;

    {
        [[maybe_unused]] const scoped_lock __(mtx);
        gLogger.reset(obj, env);
        if (gLogger) {
            // FindClass must run on this JNI thread, not a later attached native logger thread.
            (void)jclass(gLogger);
        }
    }

    if (!obj) {
        bff::SetLogger(nullptr);
        return;
    }

    bff::SetLogger([](bff::LogLevel level, const char *tag, const char *msg) {
        [[maybe_unused]] const scoped_lock __(mtx);
        if (!gLogger || !jmi::getEnv()) {
            return;
        }
        gLogger.onLog(msg ? msg : "", static_cast<jint>(level), tag ? tag : "");
    });
}
} // extern "C"
#endif // __ANDROID__
