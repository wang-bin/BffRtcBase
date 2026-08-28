#if (__ANDROID__ + 0)
#include <jni.h>
#include <string>
#include <vector>

#include "FileLogger.hpp"
#include "Log.hpp"
#include "jmi.h"

using namespace std;

#define JSPPRTC_JNI_FUNC(Name) Java_com_jspp_avrtcsdk_impl_##Name
#define JSPPRTC_JNI(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jobject thiz, ##__VA_ARGS__)
#define JSPPRTC_JNI_S(Return, Name, ...) \
    JNIEXPORT Return JNICALL JSPPRTC_JNI_FUNC(Name) (JNIEnv *env, jclass clazz, ##__VA_ARGS__)

namespace {

bff::LogLevel ToLogLevel(jint level)
{
    // android.util.Log priorities: VERBOSE=2 DEBUG=3 INFO=4 WARN=5 ERROR=6
    switch (level) {
    case 6: return bff::LogLevel::Error;
    case 5: return bff::LogLevel::Warn;
    case 4: return bff::LogLevel::Info;
    case 3: return bff::LogLevel::Debug;
    default: return bff::LogLevel::Verbose;
    }
}

} // namespace

extern "C" {

JSPPRTC_JNI(void, FileLogger_nativeLog, jstring message, jint level, jstring tag)
{
    bff::FileLogger::shared().log(ToLogLevel(level),
                                  jmi::to_string(tag, env),
                                  jmi::to_string(message, env));
}

JSPPRTC_JNI(jboolean, FileLogger_nativeNewLog, jstring userId, jstring logDir)
{
    return bff::FileLogger::shared().newLog(jmi::to_string(userId, env),
                                            jmi::to_string(logDir, env))
               ? JNI_TRUE
               : JNI_FALSE;
}

JSPPRTC_JNI(void, FileLogger_nativeStop)
{
    bff::FileLogger::shared().stop();
}

JSPPRTC_JNI(void, FileLogger_nativeSetUploadServer, jstring server)
{
    bff::FileLogger::shared().setUploadServer(jmi::to_string(server, env));
}

JSPPRTC_JNI(void, FileLogger_nativeSetRoom, jstring room)
{
    bff::FileLogger::shared().setRoom(jmi::to_string(room, env));
}

JSPPRTC_JNI(jobjectArray, FileLogger_nativeFiles)
{
    const auto paths = bff::FileLogger::shared().files();
    return static_cast<jobjectArray>(jmi::detail::to_jarray(env, paths));
}

JSPPRTC_JNI(void, FileLogger_nativeRemove, jstring path)
{
    bff::FileLogger::shared().remove(jmi::to_string(path, env));
}

} // extern "C"
#endif // __ANDROID__
