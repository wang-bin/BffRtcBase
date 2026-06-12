#if (__ANDROID__ + 0)

#include <jni.h>

#include <android/log.h>
#include <condition_variable>
#include <mutex>
#include <string>
#include <utility>

#include "HttpClient.h"
#include "jmi.h"

namespace {

constexpr const char *kTag = "CurlHttpClient";

#define CURLHTTP_JNI(Return, Name, ...) \
    JNIEXPORT Return JNICALL Java_com_jspp_avrtcsdk_impl_CurlHttpClient_##Name( \
        JNIEnv *env, jclass clazz, ##__VA_ARGS__)

struct NativeHttpClient {
    std::unique_ptr<HttpClient> client = std::make_unique<HttpClient>();
};

NativeHttpClient *fromHandle(jlong handle) {
    return reinterpret_cast<NativeHttpClient *>(handle);
}

jobject makeResult(JNIEnv *env, const HttpClient::Result &result) {
    jclass cls = env->FindClass("com/jspp/avrtcsdk/impl/CurlHttpClient$Result");
    jmethodID ctor = env->GetMethodID(cls, "<init>", "(IILjava/lang/String;Ljava/lang/String;I)V");
    jmi::LocalRef body(result.responseBody.empty() ? nullptr : jmi::from_string(result.responseBody, env), env);
    jmi::LocalRef error(result.error.empty() ? nullptr : jmi::from_string(result.error, env), env);
    jobject ret = env->NewObject(cls, ctor, result.httpCode, result.bytesSent, body.get<jstring>(),
                                 error.get<jstring>(), result.curlCode);
    env->DeleteLocalRef(cls);
    return ret;
}

} // namespace

extern "C" {

CURLHTTP_JNI(jlong, nativeCreate) {
    return reinterpret_cast<jlong>(new NativeHttpClient());
}

CURLHTTP_JNI(void, nativeDestroy, jlong handle) {
    delete fromHandle(handle);
}

CURLHTTP_JNI(void, nativeHeader, jlong handle, jstring name, jstring value) {
    auto *native = fromHandle(handle);
    if (!native || !native->client) {
        return;
    }
    native->client->header(jmi::to_string(name, env), jmi::to_string(value, env));
}

CURLHTTP_JNI(void, nativeSni, jlong handle, jstring host) {
    auto *native = fromHandle(handle);
    if (!native || !native->client) {
        return;
    }
    native->client->sni(jmi::to_string(host, env));
}

CURLHTTP_JNI(jobject, nativeRequest, jlong handle, jstring url, jstring method, jbyteArray body) {
    auto *native = fromHandle(handle);
    if (!native || !native->client) {
        return nullptr;
    }

    const std::string url_text = jmi::to_string(url, env);
    const std::string method_text = jmi::to_string(method, env);
    std::string body_text;
    if (body) {
        const jsize len = env->GetArrayLength(body);
        body_text.resize(static_cast<size_t>(len));
        if (len > 0) {
            env->GetByteArrayRegion(body, 0, len, reinterpret_cast<jbyte *>(body_text.data()));
        }
    }

    HttpClient::Result result;
    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;

    native->client->request(url_text, method_text, std::move(body_text),
                            [&](const HttpClient::Result &r) {
                                result = r;
                                std::lock_guard<std::mutex> lock(mtx);
                                done = true;
                                cv.notify_one();
                            });

    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&] { return done; });
    }

    return makeResult(env, result);
}

CURLHTTP_JNI(jboolean, nativeIsSecError, jint curlCode) {
    HttpClient::Result result;
    result.curlCode = curlCode;
    return result.isSecError() ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"

#endif // __ANDROID__
