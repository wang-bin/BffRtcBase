//
//  clock_offset_jni.cpp
//  rtcbase
//
//  Copyright © 2026 jspp.com. All rights reserved.
//  AI participated
//
#if (__ANDROID__ + 0)
#include <jni.h>

#include <limits>

#include "ClockOffsetStore.h"

#define JSPPRTC_JNI_FUNC(Name) Java_com_jspp_avrtcsdk_impl_##Name
#define JSPPRTC_JNI_S(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jclass clazz, ##__VA_ARGS__)

extern "C" {

JSPPRTC_JNI_S(void, ClockOffsetStore_nativeSave, jlong offsetMs, jlong wallMs, jlong monoMs)
{
    bff::ClockOffsetStore::save(offsetMs, {.wallMs = wallMs, .monoMs = monoMs});
}

// 有效时返回 offset；无效返回 JNI 哨兵 Long.MIN_VALUE（与 Java 侧约定）。
JSPPRTC_JNI_S(jlong, ClockOffsetStore_nativeLoadValid)
{
    const auto offset = bff::ClockOffsetStore::loadValid();
    if (!offset) {
        return std::numeric_limits<jlong>::min();
    }
    return static_cast<jlong>(*offset);
}

} // extern "C"
#endif // __ANDROID__
