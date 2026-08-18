#if (__ANDROID__ + 0)

#include <jni.h>

#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "Cert.h"
#include "QuicSocket.h"
#include "QuicWebSocketClient.hpp"

namespace {

#define QUICWS_JNI(Return, Name, ...)                                           \
    JNIEXPORT Return JNICALL Java_com_jspp_avrtcsdk_impl_QuicWebSocket_##Name(  \
        JNIEnv *env, jclass clazz, ##__VA_ARGS__)

constexpr int kWebSocketNormalClose = 1000;
constexpr int kQuicWsResolveHost = 1002;
constexpr int kQuicWsOpenFailed = 1003;
constexpr int kQuicWsSsl = 1008;

struct NativeQuicWebSocket {
    std::unique_ptr<bff::QuicSocket> ws;
    jmi::QuicWebSocketClient java_client;
};

std::mutex g_mutex;
std::vector<NativeQuicWebSocket *> g_live;

int mapErrorCode(bff::QuicSocket::ErrorKind kind) {
    switch (kind) {
        case bff::QuicSocket::ErrorKind::Resolve:
            return kQuicWsResolveHost;
        case bff::QuicSocket::ErrorKind::Ssl:
            return kQuicWsSsl;
        case bff::QuicSocket::ErrorKind::Timeout:
        case bff::QuicSocket::ErrorKind::Connect:
        case bff::QuicSocket::ErrorKind::InvalidUrl:
        case bff::QuicSocket::ErrorKind::Other:
            return kQuicWsOpenFailed;
        case bff::QuicSocket::ErrorKind::Http:
            return 0;
    }
    return kQuicWsOpenFailed;
}

int mapCloseCode(int code, bool remote) {
    if (!remote && code == 0) {
        return kWebSocketNormalClose;
    }
    return code;
}

void dispatchBytes(NativeQuicWebSocket *native_ws, const std::string &payload, bool binary) {
    if (!native_ws || !native_ws->java_client || !jmi::getEnv()) {
        return;
    }
    std::vector<jbyte> bytes(payload.begin(), payload.end());
    native_ws->java_client.dispatchMessage(bytes, static_cast<jboolean>(binary));
}

void wireCallbacks(NativeQuicWebSocket *native_ws) {
    native_ws->ws->setOnOpen([native_ws]() {
        if (!native_ws->java_client || !jmi::getEnv()) {
            return;
        }
        native_ws->java_client.dispatchOpen();
    });

    native_ws->ws->setOnRecv([native_ws](std::string data, bool binary) {
        dispatchBytes(native_ws, data, binary);
    });

    native_ws->ws->setOnClose([native_ws](int code, std::string reason, bool remote) {
        if (!native_ws->java_client || !jmi::getEnv()) {
            return;
        }
        native_ws->java_client.dispatchClose(static_cast<jint>(mapCloseCode(code, remote)),
                                             reason, static_cast<jboolean>(remote));
    });

    native_ws->ws->setOnError([native_ws](bff::QuicSocket::Error err) {
        if (!native_ws->java_client || !jmi::getEnv()) {
            return;
        }
        native_ws->java_client.dispatchError(static_cast<jint>(mapErrorCode(err.kind)),
                                             static_cast<jint>(err.httpCode), err.detail);
    });

    native_ws->ws->onCertVerify([](void *ssl_ctx) { return AddCertsToSSL(ssl_ctx); });
}

NativeQuicWebSocket *fromHandle(jlong handle) {
    return reinterpret_cast<NativeQuicWebSocket *>(handle);
}

} // namespace

extern "C" {

QUICWS_JNI(jlong, nativeCreate, jobject client) {
    auto *native_ws = new NativeQuicWebSocket();
    native_ws->ws = std::make_unique<bff::QuicSocket>();
    native_ws->java_client.reset(client, env);
    // JObject::classId() uses FindClass; that must run here on the JNI thread,
    // not later on an attached native worker (system class loader).
    (void)jclass(native_ws->java_client);
    wireCallbacks(native_ws);

    std::lock_guard<std::mutex> lock(g_mutex);
    g_live.push_back(native_ws);
    return reinterpret_cast<jlong>(native_ws);
}

QUICWS_JNI(void, nativeDestroy, jlong handle) {
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

QUICWS_JNI(void, nativeSetConnectTimeout, jlong handle, jint ms) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return;
    }
    native_ws->ws->setConnectTimeout(ms);
}

QUICWS_JNI(jboolean, nativeOpen, jlong handle, jstring url, jstring sni_host) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return JNI_FALSE;
    }

    bff::QuicSocket::OpenOptions options;
    options.url = jmi::to_string(url, env);
    options.sni_host = jmi::to_string(sni_host, env);
    return native_ws->ws->open(options) ? JNI_TRUE : JNI_FALSE;
}

QUICWS_JNI(void, nativeClose, jlong handle, jint code, jstring reason) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return;
    }
    native_ws->ws->close(code, jmi::to_string(reason, env));
}

QUICWS_JNI(void, nativeCloseAsync, jlong handle, jint code, jstring reason) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return;
    }
    native_ws->ws->closeAsync(code, jmi::to_string(reason, env));
}

QUICWS_JNI(jboolean, nativeSend, jlong handle, jbyteArray data, jint offset, jint length,
           jboolean binary) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws || !data || length < 0) {
        return JNI_FALSE;
    }

    std::vector<char> payload(static_cast<size_t>(length));
    env->GetByteArrayRegion(data, offset, length, reinterpret_cast<jbyte *>(payload.data()));
    return native_ws->ws->send(payload.data(), payload.size(), binary == JNI_TRUE) ? JNI_TRUE
                                                                                   : JNI_FALSE;
}

QUICWS_JNI(jint, nativeReadyState, jlong handle) {
    auto *native_ws = fromHandle(handle);
    if (!native_ws || !native_ws->ws) {
        return static_cast<jint>(bff::QuicSocket::State::Closed);
    }
    return static_cast<jint>(native_ws->ws->readyState());
}

} // extern "C"

#endif // __ANDROID__
