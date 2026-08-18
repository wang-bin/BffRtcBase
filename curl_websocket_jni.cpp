#if (__ANDROID__ + 0)

#include <jni.h>

#include <android/log.h>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "WebSocket.h"
#include "Cert.h"
#include "CurlWebSocketClient.hpp"

namespace {

constexpr const char *kTag = "CurlWebSocket";

#define CURLWS_JNI(Return, Name, ...) \
    JNIEXPORT Return JNICALL Java_com_jspp_avrtcsdk_impl_CurlWebSocket_##Name( \
        JNIEnv *env, jclass clazz, ##__VA_ARGS__)

struct NativeWebSocket {
    std::unique_ptr<bff::WebSocket> ws;
    jmi::CurlWebSocketClient java_client;
};

std::mutex g_mutex;
std::vector<NativeWebSocket *> g_live;

void dispatchBytes(NativeWebSocket *native_ws, const std::string &payload, bool binary) {
    if (!native_ws || !native_ws->java_client || !jmi::getEnv()) {
        return;
    }
    std::vector<jbyte> bytes(payload.begin(), payload.end());
    native_ws->java_client.dispatchMessage(bytes, static_cast<jboolean>(binary));
}

void wireCallbacks(NativeWebSocket *native_ws) {
    native_ws->ws->setOnOpen([native_ws]() {
        if (!native_ws->java_client || !jmi::getEnv()) {
            return;
        }
        native_ws->java_client.dispatchOpen();
    });

    native_ws->ws->setOnRecv([native_ws](std::string data, bool binary) {
        dispatchBytes(native_ws, data, binary);
    });

    native_ws->ws->setOnClose([native_ws](bff::WebSocket::CloseCode code, std::string reason, bool remote) {
        if (!native_ws->java_client || !jmi::getEnv()) {
            return;
        }
        native_ws->java_client.dispatchClose(static_cast<jint>(std::to_underlying(code)), reason,
                                             static_cast<jboolean>(remote));
    });

    native_ws->ws->setOnError([native_ws](bff::WebSocket::Error err) {
        if (!native_ws->java_client || !jmi::getEnv()) {
            return;
        }
        native_ws->java_client.dispatchError(static_cast<jint>(err.curlCode), static_cast<jint>(err.httpCode),
                                             err.detail);
    });

    native_ws->ws->onCertVerify([](void *ssl_ctx) { return AddCertsToSSL(ssl_ctx); });
}

NativeWebSocket *fromHandle(jlong handle) {
    return reinterpret_cast<NativeWebSocket *>(handle);
}

} // namespace

extern "C" {

CURLWS_JNI(jlong, nativeCreate, jobject client) {
    auto *native_ws = new NativeWebSocket();
    native_ws->ws = std::make_unique<bff::WebSocket>();
    native_ws->java_client.reset(client, env);
    // JObject::classId() uses FindClass; that must run here on the JNI thread,
    // not later on an attached native worker (system class loader).
    (void)jclass(native_ws->java_client);
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
        native_ws->ws->onCertVerify(nullptr);
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

    native_ws->java_client.reset(nullptr, env);
    delete native_ws;
}

CURLWS_JNI(void, nativeSetConnectTimeout, jlong handle, jint ms) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return;
    }
    native_ws->ws->setConnectTimeout(ms);
}

CURLWS_JNI(jboolean, nativeOpen, jlong handle, jstring url, jobjectArray header_keys,
           jobjectArray header_values, jstring sni_host) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return JNI_FALSE;
    }

    bff::WebSocket::OpenOptions options;
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

    options.sni_host = jmi::to_string(sni_host, env);

    return native_ws->ws->open(options) ? JNI_TRUE : JNI_FALSE;
}

CURLWS_JNI(void, nativeClose, jlong handle, jint code, jstring reason) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return;
    }
    native_ws->ws->close(static_cast<bff::WebSocket::CloseCode>(code), jmi::to_string(reason, env));
}

CURLWS_JNI(void, nativeCloseAsync, jlong handle, jint code, jstring reason) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return;
    }
    native_ws->ws->closeAsync(static_cast<bff::WebSocket::CloseCode>(code), jmi::to_string(reason, env));
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
        return static_cast<jint>(bff::WebSocket::State::Closed);
    }
    return static_cast<jint>(native_ws->ws->readyState());
}

} // extern "C"

#endif // __ANDROID__
