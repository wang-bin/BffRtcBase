#if (__ANDROID__ + 0)

#include <jni.h>

#include <android/log.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "WebSocket.h"
#include "jmi.h"

namespace {

constexpr const char *kTag = "CurlWebSocket";

#define CURLWS_JNI(Return, Name, ...) \
    JNIEXPORT Return JNICALL Java_com_jspp_avrtcsdk_impl_CurlWebSocket_##Name( \
        JNIEnv *env, jclass clazz, ##__VA_ARGS__)

struct NativeWebSocket {
    std::unique_ptr<bff::WebSocket> ws;
    JavaVM *vm = nullptr;
    jobject java_client = nullptr;
    jmethodID mid_open = nullptr;
    jmethodID mid_message = nullptr;
    jmethodID mid_close = nullptr;
    jmethodID mid_error = nullptr;
};

std::mutex g_mutex;
std::vector<NativeWebSocket *> g_live;

void cacheMethodIds(JNIEnv *env, NativeWebSocket *native_ws) {
    jclass cls = env->GetObjectClass(native_ws->java_client);
    native_ws->mid_open = env->GetMethodID(cls, "dispatchOpen", "()V");
    native_ws->mid_message = env->GetMethodID(cls, "dispatchMessage", "([BZ)V");
    native_ws->mid_close = env->GetMethodID(cls, "dispatchClose", "(ILjava/lang/String;Z)V");
    native_ws->mid_error = env->GetMethodID(cls, "dispatchError", "(ILjava/lang/String;)V");
    env->DeleteLocalRef(cls);
}

void callOnNativeThread(NativeWebSocket *native_ws, const std::function<void(JNIEnv *)> &fn) {
    if (!native_ws || !native_ws->java_client || !native_ws->vm) {
        return;
    }
    JNIEnv *env = nullptr;
    const bool attached = native_ws->vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_4) == JNI_EDETACHED;
    if (attached) {
        native_ws->vm->AttachCurrentThread(&env, nullptr);
    }
    if (env) {
        fn(env);
    }
    if (attached) {
        native_ws->vm->DetachCurrentThread();
    }
}

void wireCallbacks(NativeWebSocket *native_ws) {
    native_ws->ws->setOnOpen([native_ws]() {
        callOnNativeThread(native_ws, [native_ws](JNIEnv *env) {
            env->CallVoidMethod(native_ws->java_client, native_ws->mid_open);
        });
    });

    native_ws->ws->setOnRecv([native_ws](std::string data, bool binary) {
        callOnNativeThread(native_ws, [native_ws, payload = std::move(data), binary](JNIEnv *env) mutable {
            jbyteArray array = env->NewByteArray(static_cast<jsize>(payload.size()));
            if (!payload.empty()) {
                env->SetByteArrayRegion(array, 0, static_cast<jsize>(payload.size()),
                                        reinterpret_cast<const jbyte *>(payload.data()));
            }
            env->CallVoidMethod(native_ws->java_client, native_ws->mid_message, array, binary ? JNI_TRUE : JNI_FALSE);
            env->DeleteLocalRef(array);
        });
    });

    native_ws->ws->setOnClose([native_ws](int code, std::string reason, bool remote) {
        callOnNativeThread(native_ws, [native_ws, code, reason = std::move(reason), remote](JNIEnv *env) mutable {
            jmi::LocalRef jreason(reason.empty() ? nullptr : jmi::from_string(reason, env), env);
            env->CallVoidMethod(native_ws->java_client, native_ws->mid_close, code,
                                jreason.get<jstring>(), remote ? JNI_TRUE : JNI_FALSE);
        });
    });

    native_ws->ws->setOnError([native_ws](int code, std::string error) {
        callOnNativeThread(native_ws, [native_ws, code, error = std::move(error)](JNIEnv *env) mutable {
            jmi::LocalRef jerror(error.empty() ? nullptr : jmi::from_string(error, env), env);
            env->CallVoidMethod(native_ws->java_client, native_ws->mid_error, code, jerror.get<jstring>());
        });
    });
}

NativeWebSocket *fromHandle(jlong handle) {
    return reinterpret_cast<NativeWebSocket *>(handle);
}

} // namespace

extern "C" {

CURLWS_JNI(jlong, nativeCreate, jobject client) {
    auto *native_ws = new NativeWebSocket();
    native_ws->ws = std::make_unique<bff::WebSocket>();
    env->GetJavaVM(&native_ws->vm);
    native_ws->java_client = env->NewGlobalRef(client);
    cacheMethodIds(env, native_ws);
    wireCallbacks(native_ws);

    std::lock_guard<std::mutex> lock(g_mutex);
    g_live.push_back(native_ws);
    return reinterpret_cast<jlong>(native_ws);
}

CURLWS_JNI(void, nativeDestroy, jlong handle) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws) {
        return;
    }

    if (native_ws->ws) {
        native_ws->ws->setOnOpen(nullptr);
        native_ws->ws->setOnClose(nullptr);
        native_ws->ws->setOnError(nullptr);
        native_ws->ws->setOnRecv(nullptr);
        native_ws->ws->close();
        native_ws->ws.reset();
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto it = g_live.begin(); it != g_live.end(); ++it) {
            if (*it == native_ws) {
                g_live.erase(it);
                break;
            }
        }
    }

    if (native_ws->java_client) {
        env->DeleteGlobalRef(native_ws->java_client);
        native_ws->java_client = nullptr;
    }
    delete native_ws;
}

CURLWS_JNI(jboolean, nativeOpen, jlong handle, jstring url, jobjectArray header_keys,
           jobjectArray header_values, jstring sni_host) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return JNI_FALSE;
    }

    bff::WebSocketOpenOptions options;
    options.url = jmi::to_string(url, env);

    if (header_keys && header_values) {
        const jsize count = env->GetArrayLength(header_keys);
        if (count != env->GetArrayLength(header_values)) {
            __android_log_print(ANDROID_LOG_ERROR, kTag, "header key/value length mismatch");
            return JNI_FALSE;
        }
        options.headers.reserve(static_cast<size_t>(count));
        for (jsize i = 0; i < count; ++i) {
            // to_string() deletes the jstring local ref; do not wrap in LocalRef.
            auto *jkey = static_cast<jstring>(env->GetObjectArrayElement(header_keys, i));
            auto *jvalue = static_cast<jstring>(env->GetObjectArrayElement(header_values, i));
            if (!jkey || !jvalue) {
                if (jkey) {
                    env->DeleteLocalRef(jkey);
                }
                if (jvalue) {
                    env->DeleteLocalRef(jvalue);
                }
                continue;
            }
            options.headers.emplace_back(jmi::to_string(jkey, env), jmi::to_string(jvalue, env));
        }
    }

    if (sni_host) {
        options.sni_host = jmi::to_string(sni_host, env);
    }

    return native_ws->ws->open(options) ? JNI_TRUE : JNI_FALSE;
}

CURLWS_JNI(void, nativeClose, jlong handle, jint code, jstring reason) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return;
    }
    std::string reason_text;
    if (reason) {
        reason_text = jmi::to_string(reason, env);
    }
    native_ws->ws->close(code, reason_text);
}

CURLWS_JNI(jboolean, nativeSend, jlong handle, jbyteArray data, jint offset, jint length,
           jboolean binary) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws || !data || length < 0) {
        return JNI_FALSE;
    }

    std::vector<char> payload(static_cast<size_t>(length));
    env->GetByteArrayRegion(data, offset, length, reinterpret_cast<jbyte *>(payload.data()));
    return native_ws->ws->send(payload.data(), payload.size(), binary == JNI_TRUE) ? JNI_TRUE : JNI_FALSE;
}

CURLWS_JNI(jint, nativeReadyState, jlong handle) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return static_cast<jint>(bff::WebSocketReadyState::Closed);
    }
    return static_cast<jint>(native_ws->ws->readyState());
}

} // extern "C"

#endif // __ANDROID__
