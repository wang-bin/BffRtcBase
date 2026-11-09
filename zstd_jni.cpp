#if (__ANDROID__ + 0)
#include <jni.h>

#include <vector>

#include "ZstdCodec.hpp"
#include "jmi.h"

using namespace std;

#define JSPPRTC_JNI_FUNC(Name) Java_com_jspp_avrtcsdk_impl_##Name
#define JSPPRTC_JNI(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jobject thiz, ##__VA_ARGS__)
#define JSPPRTC_JNI_S(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jclass clazz, ##__VA_ARGS__)

extern "C" {

JSPPRTC_JNI(jboolean, ZstdCodec_nativeSetDict, jbyteArray dict)
{
    if (!dict) {
        bff::Zstd::shared().clearDict();
        return JNI_TRUE;
    }
    const auto len = env->GetArrayLength(dict);
    if (len <= 0) {
        bff::Zstd::shared().clearDict();
        return JNI_TRUE;
    }
    vector<uint8_t> bytes(static_cast<size_t>(len));
    env->GetByteArrayRegion(dict, 0, len, reinterpret_cast<jbyte*>(bytes.data()));
    return bff::Zstd::shared().setDict(bytes) ? JNI_TRUE : JNI_FALSE;
}

JSPPRTC_JNI(void, ZstdCodec_nativeClearDict)
{
    bff::Zstd::shared().clearDict();
}

JSPPRTC_JNI(jstring, ZstdCodec_nativeDictMd5)
{
    const auto md5 = bff::Zstd::shared().dictMd5();
    return env->NewStringUTF(md5.c_str());
}

JSPPRTC_JNI(jboolean, ZstdCodec_nativeHasDict)
{
    return bff::Zstd::shared().hasDict() ? JNI_TRUE : JNI_FALSE;
}

JSPPRTC_JNI(void, ZstdCodec_nativeSetCacheDir, jstring dir)
{
    if (!dir) {
        bff::Zstd::shared().setCacheDir({});
        return;
    }
    const char* utf = env->GetStringUTFChars(dir, nullptr);
    bff::Zstd::shared().setCacheDir(utf ? utf : "");
    if (utf) {
        env->ReleaseStringUTFChars(dir, utf);
    }
}

JSPPRTC_JNI(jboolean, ZstdCodec_nativeLoadCachedDict)
{
    return bff::Zstd::shared().loadCachedDict() ? JNI_TRUE : JNI_FALSE;
}

JSPPRTC_JNI(jboolean, ZstdCodec_nativeSaveCachedDict)
{
    return bff::Zstd::shared().saveCachedDict() ? JNI_TRUE : JNI_FALSE;
}

JSPPRTC_JNI(jbyteArray, ZstdCodec_nativeEncode, jbyteArray input, jboolean useDict)
{
    if (!input) {
        return nullptr;
    }
    const auto len = env->GetArrayLength(input);
    if (len <= 0) {
        return env->NewByteArray(0);
    }
    vector<uint8_t> bytes(static_cast<size_t>(len));
    env->GetByteArrayRegion(input, 0, len, reinterpret_cast<jbyte*>(bytes.data()));
    const auto out = bff::Zstd::shared().encode(bytes, useDict == JNI_TRUE);
    auto arr = env->NewByteArray(static_cast<jsize>(out.size()));
    if (!arr || out.empty()) {
        return arr;
    }
    env->SetByteArrayRegion(arr, 0, static_cast<jsize>(out.size()), reinterpret_cast<const jbyte*>(out.data()));
    return arr;
}

JSPPRTC_JNI(jstring, ZstdCodec_nativeDecode, jbyteArray input)
{
    if (!input) {
        return env->NewStringUTF("");
    }
    const auto len = env->GetArrayLength(input);
    if (len <= 0) {
        return env->NewStringUTF("");
    }
    vector<uint8_t> bytes(static_cast<size_t>(len));
    env->GetByteArrayRegion(input, 0, len, reinterpret_cast<jbyte*>(bytes.data()));
    const auto out = bff::Zstd::shared().decode(bytes);
    return env->NewStringUTF(out.c_str());
}

} // extern "C"
#endif // __ANDROID__
