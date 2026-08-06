#if (__ANDROID__ + 0)

#include <jni.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "jmi.h"
#include "Cert.h"
#include "Log.hpp"
#include "quic/socket.hpp"

#define TAG "quic.ws"

namespace {

#define QUICWS_JNI(Return, Name, ...)                                          \
  JNIEXPORT Return JNICALL                                                     \
      Java_com_jspp_avrtcsdk_impl_QuicWebSocket_##Name(JNIEnv *env,            \
                                                       jclass clazz,           \
                                                       ##__VA_ARGS__)

enum class QuicWsError : int {
  InvalidUrl = 1001,
  ResolveHost = 1002,
  OpenFailed = 1003,
  OpenStreamFailed = 1004,
  SendFailed = 1005,
  ProtocolDecode = 1006,
  HandshakeCode = 1007,
  Ssl = 1008,
};

enum class ReadyState : int {
  Connecting = 0,
  Open = 1,
  Closing = 2,
  Closed = 3,
};

constexpr int kWebSocketNormalClose = 1000;
// This status is reported to the callback only; it must not be sent in a
// WebSocket close frame.
constexpr int kWebSocketAbnormalClose = 1006;

int WebSocketCloseCode(const quic::Error &error, bool remote) {
  return !remote && error.kind == quic::ErrKind::None
             ? kWebSocketNormalClose
             : kWebSocketAbnormalClose;
}

size_t PutUVarIntLen(uint64_t n) {
  if (n < 64) {
    return 1;
  }
  if (n < 16384) {
    return 2;
  }
  if (n < 1073741824ULL) {
    return 4;
  }
  return 8;
}

uint8_t *PutUVarInt(uint8_t *p, uint64_t n) {
  if (n < 64) {
    *p++ = static_cast<uint8_t>(n);
    return p;
  }
  if (n < 16384) {
    p[0] = static_cast<uint8_t>(0x40 | ((n >> 8) & 0x3f));
    p[1] = static_cast<uint8_t>(n);
    return p + 2;
  }
  if (n < 1073741824ULL) {
    p[0] = static_cast<uint8_t>(0x80 | ((n >> 24) & 0x3f));
    p[1] = static_cast<uint8_t>((n >> 16) & 0xff);
    p[2] = static_cast<uint8_t>((n >> 8) & 0xff);
    p[3] = static_cast<uint8_t>(n & 0xff);
    return p + 4;
  }
  p[0] = static_cast<uint8_t>(0xc0 | ((n >> 56) & 0x3f));
  p[1] = static_cast<uint8_t>((n >> 48) & 0xff);
  p[2] = static_cast<uint8_t>((n >> 40) & 0xff);
  p[3] = static_cast<uint8_t>((n >> 32) & 0xff);
  p[4] = static_cast<uint8_t>((n >> 24) & 0xff);
  p[5] = static_cast<uint8_t>((n >> 16) & 0xff);
  p[6] = static_cast<uint8_t>((n >> 8) & 0xff);
  p[7] = static_cast<uint8_t>(n & 0xff);
  return p + 8;
}

size_t GetUVarIntLen(uint8_t first) { return size_t{1} << (first >> 6); }

size_t GetUVarInt(uint64_t *dest, std::span<const uint8_t> p) {
  if (p.empty()) {
    return 0;
  }
  const auto len = GetUVarIntLen(p[0]);
  if (p.size() < len) {
    return 0;
  }
  uint64_t n = p[0] & 0x3f;
  for (size_t i = 1; i < len; ++i) {
    n = (n << 8) | p[i];
  }
  *dest = n;
  return len;
}

std::vector<uint8_t> WrapVarIntPayload(std::span<const uint8_t> payload) {
  const auto vlen = PutUVarIntLen(payload.size());
  std::vector<uint8_t> framed(vlen + payload.size());
  auto *p = PutUVarInt(framed.data(), payload.size());
  if (!payload.empty()) {
    std::memcpy(p, payload.data(), payload.size());
  }
  return framed;
}

bool ParseBoolQueryValue(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  std::string lower(value);
  for (auto &ch : lower) {
    if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>(ch - 'A' + 'a');
    }
  }
  return lower == "true" || lower == "1" || lower == "yes";
}

// Minimal URL parse for ws(s)/http(s)://host[:port][/path][?query].
bool ParseUrl(const std::string &url, std::string *host, std::string *port,
              std::string *query, bool *secure, std::string *error) {
  const auto scheme_end = url.find("://");
  if (scheme_end == std::string::npos) {
    *error = "invalid websocket URL";
    return false;
  }
  const auto scheme = url.substr(0, scheme_end);
  *secure = (scheme == "wss" || scheme == "https");
  auto rest = url.substr(scheme_end + 3);
  if (rest.empty()) {
    *error = "invalid websocket URL";
    return false;
  }

  // Strip userinfo if present.
  if (const auto at = rest.find('@'); at != std::string::npos) {
    rest = rest.substr(at + 1);
  }

  std::string authority;
  std::string path_and_query;
  if (!rest.empty() && rest.front() == '[') {
    const auto bracket = rest.find(']');
    if (bracket == std::string::npos) {
      *error = "invalid websocket URL";
      return false;
    }
    authority = rest.substr(0, bracket + 1);
    path_and_query = rest.substr(bracket + 1);
  } else {
    const auto slash = rest.find('/');
    const auto qmark = rest.find('?');
    size_t cut = rest.size();
    if (slash != std::string::npos) {
      cut = slash;
    }
    if (qmark != std::string::npos && qmark < cut) {
      cut = qmark;
    }
    authority = rest.substr(0, cut);
    path_and_query = rest.substr(cut);
  }

  if (authority.empty()) {
    *error = "invalid websocket URL";
    return false;
  }

  if (!authority.empty() && authority.front() == '[') {
    const auto bracket = authority.find(']');
    *host = authority.substr(1, bracket - 1);
    if (bracket + 1 < authority.size() && authority[bracket + 1] == ':') {
      *port = authority.substr(bracket + 2);
    }
  } else {
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos &&
        authority.find(':') == colon /* single colon => host:port */) {
      *host = authority.substr(0, colon);
      *port = authority.substr(colon + 1);
    } else {
      *host = authority;
    }
  }

  if (host->empty()) {
    *error = "invalid websocket URL";
    return false;
  }
  if (port->empty()) {
    *port = *secure ? "443" : "80";
  }

  const auto qpos = path_and_query.find('?');
  if (qpos != std::string::npos) {
    *query = path_and_query.substr(qpos + 1);
  } else {
    query->clear();
  }
  return true;
}

bool QueryHasJsonTrue(const std::string &query) {
  size_t start = 0;
  while (start <= query.size()) {
    const auto amp = query.find('&', start);
    const auto part = query.substr(
        start, amp == std::string::npos ? std::string::npos : amp - start);
    const auto eq = part.find('=');
    const auto key = eq == std::string::npos ? part : part.substr(0, eq);
    const auto value = eq == std::string::npos ? std::string{} : part.substr(eq + 1);
    std::string key_l = key;
    for (auto &ch : key_l) {
      if (ch >= 'A' && ch <= 'Z') {
        ch = static_cast<char>(ch - 'A' + 'a');
      }
    }
    if (key_l == "json") {
      return ParseBoolQueryValue(value);
    }
    if (amp == std::string::npos) {
      break;
    }
    start = amp + 1;
  }
  return false;
}

struct NativeQuicWebSocket {
  std::unique_ptr<quic::Socket> socket;
  JavaVM *vm = nullptr;
  jobject java_client = nullptr;
  jmethodID mid_open = nullptr;
  jmethodID mid_message = nullptr;
  jmethodID mid_close = nullptr;
  jmethodID mid_error = nullptr;

  std::atomic<ReadyState> state{ReadyState::Closed};
  std::atomic<bool> close_notified{false};
  std::atomic<bool> error_notified{false};
  bool connect_started = false;

  std::string host;
  std::string port;
  std::string params;
  bool payload_text = false;
  int64_t stream_id = quic::kInvalidStream;
  bool received_status_code = false;
  std::vector<uint8_t> rx_buffer;
  std::mutex rx_mutex;
};

std::mutex g_mutex;
std::vector<NativeQuicWebSocket *> g_live;

void cacheMethodIds(JNIEnv *env, NativeQuicWebSocket *native_ws) {
  jclass cls = env->GetObjectClass(native_ws->java_client);
  native_ws->mid_open = env->GetMethodID(cls, "dispatchOpen", "()V");
  native_ws->mid_message = env->GetMethodID(cls, "dispatchMessage", "([BZ)V");
  native_ws->mid_close =
      env->GetMethodID(cls, "dispatchClose", "(ILjava/lang/String;Z)V");
  native_ws->mid_error =
      env->GetMethodID(cls, "dispatchError", "(IILjava/lang/String;)V");
  env->DeleteLocalRef(cls);
}

void callOnNativeThread(NativeQuicWebSocket *native_ws,
                        const std::function<void(JNIEnv *)> &fn) {
  if (!native_ws || !native_ws->java_client || !native_ws->vm) {
    return;
  }
  JNIEnv *env = nullptr;
  const bool attached =
      native_ws->vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_4) ==
      JNI_EDETACHED;
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

void notifyOpen(NativeQuicWebSocket *native_ws) {
  native_ws->state.store(ReadyState::Open, std::memory_order_release);
  callOnNativeThread(native_ws, [native_ws](JNIEnv *env) {
    env->CallVoidMethod(native_ws->java_client, native_ws->mid_open);
  });
}

void notifyMessage(NativeQuicWebSocket *native_ws, std::string payload,
                   bool binary) {
  callOnNativeThread(
      native_ws, [native_ws, payload = std::move(payload), binary](JNIEnv *env) mutable {
        jbyteArray array = env->NewByteArray(static_cast<jsize>(payload.size()));
        if (!payload.empty()) {
          env->SetByteArrayRegion(array, 0, static_cast<jsize>(payload.size()),
                                  reinterpret_cast<const jbyte *>(payload.data()));
        }
        env->CallVoidMethod(native_ws->java_client, native_ws->mid_message, array,
                            binary ? JNI_TRUE : JNI_FALSE);
        env->DeleteLocalRef(array);
      });
}

void notifyClose(NativeQuicWebSocket *native_ws, int code, std::string reason,
                 bool remote) {
  DBG("onClose. code=%d, reason=%s, remote=%d", code, reason.c_str(), remote);
  bool expected = false;
  if (!native_ws->close_notified.compare_exchange_strong(expected, true)) {
    return;
  }
  if (reason.empty()) {
    reason = remote ? "remote closed" : "closed";
  }
  native_ws->state.store(ReadyState::Closed, std::memory_order_release);
  callOnNativeThread(
      native_ws,
      [native_ws, code, reason = std::move(reason), remote](JNIEnv *env) mutable {
        jmi::LocalRef jreason(jmi::from_string(reason, env), env);
        env->CallVoidMethod(native_ws->java_client, native_ws->mid_close, code,
                            jreason.get<jstring>(), remote ? JNI_TRUE : JNI_FALSE);
      });
}

void notifyError(NativeQuicWebSocket *native_ws, int code, int http_code,
                 std::string detail) {
  DBG("onError. code=%d http=%d detail=%s", code, http_code, detail.c_str());
  bool expected = false;
  // Error and close are separate notifications. Socket guarantees that an
  // error callback precedes the close callback, so do not consume the close
  // notification here.
  if (!native_ws->error_notified.compare_exchange_strong(expected, true)) {
    return;
  }
  native_ws->state.store(ReadyState::Closed, std::memory_order_release);
  callOnNativeThread(
      native_ws, [native_ws, code, http_code,
                  detail = std::move(detail)](JNIEnv *env) mutable {
        jmi::LocalRef jerror(
            detail.empty() ? nullptr : jmi::from_string(detail, env), env);
        env->CallVoidMethod(native_ws->java_client, native_ws->mid_error, code,
                            http_code, jerror.get<jstring>());
      });
}

void fail(NativeQuicWebSocket *native_ws, QuicWsError code, std::string detail,
          int http_code = 0, bool close_socket = false) {
  if (close_socket && native_ws->socket) {
    native_ws->socket->close();
  }
  notifyError(native_ws, static_cast<int>(code), http_code, std::move(detail));
}

void handleDataFramesLocked(NativeQuicWebSocket *native_ws) {
  if (!native_ws->received_status_code) {
    uint64_t code = 0;
    const auto consumed = GetUVarInt(
        &code, std::span<const uint8_t>(native_ws->rx_buffer.data(),
                                        native_ws->rx_buffer.size()));
    if (consumed == 0) {
      return;
    }
    native_ws->rx_buffer.erase(
        native_ws->rx_buffer.begin(),
        native_ws->rx_buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
    native_ws->received_status_code = true;
    if (code != 200) {
      fail(native_ws, QuicWsError::HandshakeCode,
           "quic handshake status code: " + std::to_string(code),
           static_cast<int>(code), true);
      return;
    }
    notifyOpen(native_ws);
  }

  while (!native_ws->rx_buffer.empty()) {
    uint64_t payload_len = 0;
    const auto vlen = GetUVarInt(
        &payload_len, std::span<const uint8_t>(native_ws->rx_buffer.data(),
                                               native_ws->rx_buffer.size()));
    if (vlen == 0) {
      return;
    }
    if (native_ws->rx_buffer.size() < vlen + payload_len) {
      return;
    }
    const auto payload_offset = vlen;
    std::string payload;
    if (payload_len > 0) {
      payload.assign(
          reinterpret_cast<const char *>(native_ws->rx_buffer.data() +
                                         payload_offset),
          static_cast<size_t>(payload_len));
    }
    notifyMessage(native_ws, std::move(payload), !native_ws->payload_text);

    const auto consumed = vlen + payload_len;
    native_ws->rx_buffer.erase(
        native_ws->rx_buffer.begin(),
        native_ws->rx_buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
  }
}

bool sendRaw(NativeQuicWebSocket *native_ws, std::span<const uint8_t> bytes);
bool sendFramed(NativeQuicWebSocket *native_ws,
                std::span<const uint8_t> payload);

void wireCallbacks(NativeQuicWebSocket *native_ws) {
  native_ws->socket->onOpenStream(
      [native_ws](uint64_t /*conn_id*/, int64_t stream_id, quic::Dir /*dir*/,
                  bool remote) {
        // This WebSocket transport only uses its client-created stream.
        // Returning false asks Socket to reset an unexpected peer-created one.
        if (remote) {
          return false;
        }
        if (native_ws->stream_id != quic::kInvalidStream) {
          return true;
        }
        native_ws->stream_id = stream_id;
        const uint8_t marker = 0x35;
        if (!sendRaw(native_ws, std::span<const uint8_t>(&marker, 1))) {
          fail(native_ws, QuicWsError::SendFailed, "quic send failed", 0, true);
          return false;
        }
        const auto params_bytes = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(native_ws->params.data()),
            native_ws->params.size());
        if (!sendFramed(native_ws, params_bytes)) {
          fail(native_ws, QuicWsError::SendFailed, "quic send failed", 0, true);
          return false;
        }
        return true;
      });

  native_ws->socket->onRecv(
      [native_ws](uint64_t /*conn_id*/, int64_t /*stream_id*/,
                  std::span<const uint8_t> data, bool /*fin*/) {
        std::lock_guard lock(native_ws->rx_mutex);
        native_ws->rx_buffer.insert(native_ws->rx_buffer.end(), data.begin(),
                                    data.end());
        handleDataFramesLocked(native_ws);
      });

  native_ws->socket->onError([native_ws](uint64_t /*conn_id*/, quic::Error error) {
    int http_code = 0;
    std::string reason = error.reason;
    if (reason.empty()) {
      reason = "quic error kind=" +
               std::to_string(static_cast<unsigned>(error.kind)) +
               " code=" + std::to_string(error.code);
    }
    QuicWsError ws_error = QuicWsError::OpenFailed;
    if (error.kind == quic::ErrKind::Ssl) {
      ws_error = QuicWsError::Ssl;
    } else if (error.kind == quic::ErrKind::Application) {
      http_code = static_cast<int>(error.code);
    }
    fail(native_ws, ws_error, std::move(reason), http_code,
         /*close_socket=*/false);
  });

  native_ws->socket->onClose(
      [native_ws](uint64_t /*conn_id*/, quic::Error error, bool remote) {
        std::string reason = error.reason;
        if (reason.empty() && error.kind != quic::ErrKind::None) {
          reason = "quic error kind=" +
                   std::to_string(static_cast<unsigned>(error.kind)) +
                   " code=" + std::to_string(error.code);
        }
        notifyClose(native_ws, WebSocketCloseCode(error, remote),
                    std::move(reason), remote);
      });
}

bool sendRaw(NativeQuicWebSocket *native_ws, std::span<const uint8_t> bytes) {
  if (!native_ws->socket || native_ws->stream_id == quic::kInvalidStream) {
    return false;
  }
  return native_ws->socket->send(bytes, 0, native_ws->stream_id) == quic::Ok;
}

bool sendFramed(NativeQuicWebSocket *native_ws, std::span<const uint8_t> payload) {
  auto framed = WrapVarIntPayload(payload);
  return sendRaw(native_ws, framed);
}

void doClose(NativeQuicWebSocket *native_ws, int code, std::string reason_text) {
  if (!native_ws || !native_ws->socket) {
    return;
  }
  const auto state = native_ws->state.load(std::memory_order_acquire);
  if (state == ReadyState::Closed || state == ReadyState::Closing) {
    return;
  }
  native_ws->state.store(ReadyState::Closing, std::memory_order_release);
  native_ws->socket->close();
  notifyClose(native_ws, code, std::move(reason_text), /*remote=*/false);
}

NativeQuicWebSocket *fromHandle(jlong handle) {
  return reinterpret_cast<NativeQuicWebSocket *>(handle);
}

} // namespace

extern "C" {

QUICWS_JNI(jlong, nativeCreate, jobject client) {
  auto *native_ws = new NativeQuicWebSocket();
  native_ws->socket = std::make_unique<quic::Socket>();
  env->GetJavaVM(&native_ws->vm);
  native_ws->java_client = env->NewGlobalRef(client);
  cacheMethodIds(env, native_ws);

  std::lock_guard lock(g_mutex);
  g_live.push_back(native_ws);
  return reinterpret_cast<jlong>(native_ws);
}

QUICWS_JNI(void, nativeDestroy, jlong handle) {
  auto *native_ws = fromHandle(handle);
  if (!native_ws) {
    return;
  }

  if (native_ws->socket) {
    native_ws->socket->close();
    native_ws->socket.reset(); // joins loop thread + tears down
  }

  {
    std::lock_guard lock(g_mutex);
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

QUICWS_JNI(jboolean, nativeOpen, jlong handle, jstring url,
           jstring sni_host) {
  auto *native_ws = fromHandle(handle);
  if (!native_ws || !native_ws->socket) {
    return JNI_FALSE;
  }
  if (native_ws->connect_started) {
    return JNI_FALSE;
  }
  native_ws->connect_started = true;
  native_ws->close_notified.store(false, std::memory_order_release);
  native_ws->error_notified.store(false, std::memory_order_release);
  native_ws->state.store(ReadyState::Connecting, std::memory_order_release);
  native_ws->stream_id = quic::kInvalidStream;
  native_ws->received_status_code = false;
  {
    std::lock_guard lock(native_ws->rx_mutex);
    native_ws->rx_buffer.clear();
  }

  const std::string url_text = jmi::to_string(url, env);
  std::string error;
  bool secure = false;
  if (!ParseUrl(url_text, &native_ws->host, &native_ws->port, &native_ws->params,
                &secure, &error)) {
    fail(native_ws, QuicWsError::InvalidUrl, error);
    return JNI_FALSE;
  }
  native_ws->payload_text = QueryHasJsonTrue(native_ws->params);
  const bool use_sni = sni_host != nullptr;
  const std::string tls_host = jmi::to_string(sni_host, env);
  DBG("open. sni_host=%s", tls_host.c_str());

  native_ws->socket->onCertVerify([](void *ssl_ctx) { return AddCertsToSSL(ssl_ctx); });
  quic::Options opts;
  opts.verify_peer = true;
  opts.sni = use_sni ? tls_host : std::string{};
  native_ws->socket->options(std::move(opts));

  wireCallbacks(native_ws);

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo *res = nullptr;
  if (getaddrinfo(native_ws->host.c_str(), native_ws->port.c_str(), &hints,
                  &res) != 0 ||
      !res) {
    fail(native_ws, QuicWsError::ResolveHost,
         "resolve host failed: " + native_ws->host + ":" + native_ws->port);
    return JNI_FALSE;
  }

  int rc = quic::Err;
  for (auto *rp = res; rp; rp = rp->ai_next) {
    rc = native_ws->socket->open(rp->ai_addr, rp->ai_addrlen);
    if (rc == quic::Ok) {
      break;
    }
  }
  freeaddrinfo(res);
  if (rc != quic::Ok) {
    fail(native_ws, QuicWsError::OpenFailed, "quic open failed");
    return JNI_FALSE;
  }

  if (native_ws->socket->openStream() != quic::Ok) {
    fail(native_ws, QuicWsError::OpenStreamFailed, "open quic stream failed", 0,
         true);
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

QUICWS_JNI(void, nativeClose, jlong handle, jint code, jstring reason) {
  std::string reason_text;
  if (reason) {
    reason_text = jmi::to_string(reason, env);
  }
  DBG("close. code=%d, reason=%s", code, reason_text.c_str());
  doClose(fromHandle(handle), code, std::move(reason_text));
}

QUICWS_JNI(void, nativeCloseAsync, jlong handle, jint code, jstring reason) {
  std::string reason_text;
  if (reason) {
    reason_text = jmi::to_string(reason, env);
  }
  DBG("closeAsync. code=%d, reason=%s", code, reason_text.c_str());
  // Cooperative close is already non-joining; same as nativeClose.
  doClose(fromHandle(handle), code, std::move(reason_text));
}

QUICWS_JNI(jboolean, nativeSend, jlong handle, jbyteArray data, jint offset,
           jint length, jboolean /*binary*/) {
  auto *native_ws = fromHandle(handle);
  if (!native_ws || !native_ws->socket || !data || length < 0) {
    return JNI_FALSE;
  }
  if (native_ws->state.load(std::memory_order_acquire) != ReadyState::Open) {
    return JNI_FALSE;
  }

  std::vector<uint8_t> payload(static_cast<size_t>(length));
  env->GetByteArrayRegion(data, offset, length,
                          reinterpret_cast<jbyte *>(payload.data()));
  return sendFramed(native_ws, payload) ? JNI_TRUE : JNI_FALSE;
}

QUICWS_JNI(jint, nativeReadyState, jlong handle) {
  auto *native_ws = fromHandle(handle);
  if (!native_ws) {
    return static_cast<jint>(ReadyState::Closed);
  }
  return static_cast<jint>(native_ws->state.load(std::memory_order_acquire));
}

} // extern "C"

#endif // __ANDROID__
