#if (__ANDROID__ + 0)
#include <jni.h>
#include <string>
#include <set>
#include <vector>
#include <android/log.h>
#include "stun_test.h"
#include "jmi.h"

using  namespace std;

#define JSPPRTC_JNI_FUNC(Name) Java_com_jspp_avrtcsdk_impl_##Name
#define JSPPRTC_JNI(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jobject thiz, ##__VA_ARGS__)
#define JSPPRTC_JNI_S(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jclass clazz, ##__VA_ARGS__)

extern "C" {

jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**) &env, JNI_VERSION_1_4) != JNI_OK || !env) {
        return -1;
    }
    jmi::javaVM(vm);
    return JNI_VERSION_1_4;
}

JSPPRTC_JNI_S(jstring, StunUtil_nativeGetIpFromStun, jstring server, jint timeoutMs) {
    const char *cstr = env->GetStringUTFChars(server, nullptr);
    set<string> servers{cstr};
    env->ReleaseStringUTFChars(server, cstr);
    string clientIp;
    auto sorted = SortStun(servers, timeoutMs, &clientIp);
    if (sorted.empty()) {
        __android_log_print(ANDROID_LOG_WARN, "JsppPeerconnect", "no stun server is reachable");
        return nullptr;
    }
    return env->NewStringUTF(clientIp.c_str());
}

JSPPRTC_JNI_S(jstring, StunUtil_nativeFindBestStunServer, jobjectArray jservers, jint timeoutMs) {
    jsize len = env->GetArrayLength(jservers);
    set<string> servers;
    for (jsize i = 0; i < len; ++i) {
        const auto node = (jstring)env->GetObjectArrayElement(jservers, i);
        const char* cstr = env->GetStringUTFChars(node, nullptr);
        servers.insert(cstr);
        env->ReleaseStringUTFChars(node, cstr);
        env->DeleteLocalRef(node);
    }
    string clientIp;
    string res = QueryFastestStun(servers, timeoutMs, &clientIp);
    if (res.empty()) {
        return nullptr;
    }
    return env->NewStringUTF(res.c_str());
}

JSPPRTC_JNI_S(jobjectArray, StunUtil_nativeSortStunServers, jobjectArray jservers, jint timeoutMs) {
    jsize len = env->GetArrayLength(jservers);
    set<string> servers;
    for (jsize i = 0; i < len; ++i) {
        const auto node = (jstring) env->GetObjectArrayElement(jservers, i);
        const char *cstr = env->GetStringUTFChars(node, nullptr);
        servers.emplace(cstr);
        env->ReleaseStringUTFChars(node, cstr);
        env->DeleteLocalRef(node);
    }
    string clientIp;
    auto sorted = SortStun(servers, timeoutMs, &clientIp);
    if (sorted.empty()) {
        __android_log_print(ANDROID_LOG_WARN, "JsppPeerconnect", "no stun server is reachable");
        return nullptr;
    }
    // return Pair<String, Integer>[]
    jclass pairCls = env->FindClass("android/util/Pair");
    jmethodID pairCtor = env->GetMethodID(pairCls, "<init>",
                                          "(Ljava/lang/Object;Ljava/lang/Object;)V");
    jclass integerCls = env->FindClass("java/lang/Integer");
    jmethodID integerCtor = env->GetMethodID(integerCls, "<init>", "(I)V");
    jobjectArray jres = env->NewObjectArray(sorted.size(), pairCls, nullptr);
    for (size_t i = 0; i < sorted.size(); ++i) {
        jstring node = env->NewStringUTF(sorted[i].first.c_str());
        jobject rtt = env->NewObject(integerCls, integerCtor, sorted[i].second);
        jobject ret = env->NewObject(pairCls, pairCtor, node, rtt);
        env->SetObjectArrayElement(jres, i, ret);
        env->DeleteLocalRef(node);
        env->DeleteLocalRef(rtt);
        env->DeleteLocalRef(ret);
    }

    return jres;
}

static void to(vector<pair<string, int>>& p, JNIEnv *env, jobjectArray ja)
{
    p.clear();
    jclass pairCls = env->FindClass("android/util/Pair");
    jfieldID firstField = env->GetFieldID(pairCls, "first", "Ljava/lang/Object;");
    jfieldID secondField = env->GetFieldID(pairCls, "second", "Ljava/lang/Object;");
    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID intValue = env->GetMethodID(integerClass, "intValue", "()I");
    for (jsize i = 0; i < env->GetArrayLength(ja); ++i) {
        jobject jpair = env->GetObjectArrayElement(ja, i);
        jstring node = (jstring) env->GetObjectField(jpair, firstField);
        jobject jRtt = env->GetObjectField(jpair, secondField);
        jclass objClass = env->GetObjectClass(jRtt);
        if (!env->IsSameObject(objClass, integerClass)) {
            continue;
        }
        env->DeleteLocalRef(objClass);
        jint rtt = env->CallIntMethod(jRtt, intValue);
        const char *cstr = env->GetStringUTFChars(node, nullptr);
        p.emplace_back(cstr, rtt);
        env->ReleaseStringUTFChars(node, cstr);
    }
    env->DeleteLocalRef(integerClass);
    env->DeleteLocalRef(pairCls);
}

JSPPRTC_JNI_S(jstring, StunUtil_nativeFindBestNode, jobjectArray jRtts1, jobjectArray jRtts2) {
    // TODO: implement nativeFindBestNode()
    // jRtts1 and jRtts2 are Pair<String, Integer>[], convert to vector<pair<string, int>>
    vector<pair<string, int>> rtts1, rtts2;
    to(rtts1, env, jRtts1);
    to(rtts2, env, jRtts2);
    const auto node = FindBestNode(rtts1, rtts2);
    return env->NewStringUTF(node.c_str());
}

JSPPRTC_JNI_S(void, StunUtil_nativeSetLogger, jobject obj)
{
    static mutex mtx;
    static jobject gObj = nullptr;

    jmethodID onLogMethod = nullptr;
    {
        [[maybe_unused]] const scoped_lock __(mtx);
        if (gObj) {
            env->DeleteGlobalRef(gObj);
            gObj = nullptr;
        }
        if (obj) {
            jmi::LocalRef k = env->GetObjectClass(obj);
            onLogMethod = env->GetMethodID(k.get<jclass>(), "onLog", "(Ljava/lang/String;ILjava/lang/String;)V");
            gObj = env->NewGlobalRef(obj);
        }
    }

    if (!obj) {
        SetLogger(nullptr);
        return;
    }

    SetLogger([onLogMethod](const char* msg) {
        [[maybe_unused]] const scoped_lock __(mtx);
        if (!gObj) {
            return;
        }
        auto env = jmi::getEnv();
        jmi::LocalRef message = jmi::from_string(msg, env);
        jmi::LocalRef tag = jmi::from_string("rtc.stun", env);
        env->CallVoidMethod(gObj, onLogMethod, message.get<jstring>(), ANDROID_LOG_DEBUG, tag.get<jstring>());
    });
}
} // extern "C"
#endif // __ANDROID__