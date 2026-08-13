#include "QuicSocket.h"

#include "Cert.h"
#include "Log.hpp"
#include "quic/socket.hpp"

#include <arpa/inet.h>
#include <netdb.h>

#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#define TAG "quic.sock"

namespace {

constexpr int kAbnormalClose = 1006;

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

bool ParseUrl(const std::string &url, std::string *host, std::string *port,
              std::string *query, std::string *error) {
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        *error = "invalid URL";
        return false;
    }
    const auto scheme = url.substr(0, scheme_end);
    const bool secure = (scheme == "wss" || scheme == "https");
    auto rest = url.substr(scheme_end + 3);
    if (rest.empty()) {
        *error = "invalid URL";
        return false;
    }

    if (const auto at = rest.find('@'); at != std::string::npos) {
        rest = rest.substr(at + 1);
    }

    std::string authority;
    std::string path_and_query;
    if (!rest.empty() && rest.front() == '[') {
        const auto bracket = rest.find(']');
        if (bracket == std::string::npos) {
            *error = "invalid URL";
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
        *error = "invalid URL";
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
            authority.find(':') == colon) {
            *host = authority.substr(0, colon);
            *port = authority.substr(colon + 1);
        } else {
            *host = authority;
        }
    }

    if (host->empty()) {
        *error = "invalid URL";
        return false;
    }
    if (port->empty()) {
        *port = secure ? "443" : "80";
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

bff::QuicSocket::Error MapQuicError(const quic::Error &error) {
    bff::QuicSocket::Error out;
    out.detail = error.reason;
    if (out.detail.empty()) {
        out.detail = "quic error kind=" +
                     std::to_string(static_cast<unsigned>(error.kind)) +
                     " code=" + std::to_string(error.code);
    }
    if (error.kind == quic::ErrKind::Ssl) {
        out.kind = bff::QuicSocket::ErrorKind::Ssl;
    } else if (error.kind == quic::ErrKind::Lib &&
               error.code == static_cast<uint64_t>(ETIMEDOUT)) {
        out.kind = bff::QuicSocket::ErrorKind::Timeout;
    } else if (error.kind == quic::ErrKind::Application) {
        out.kind = bff::QuicSocket::ErrorKind::Http;
        out.httpCode = static_cast<int>(error.code);
    }
    return out;
}

} // namespace

namespace bff {

class QuicSocket::Private {
public:
    on_open_fn_t on_open;
    on_close_fn_t on_close;
    on_error_fn_t on_error;
    on_recv_fn_t on_recv;
    on_cert_verify_fn_t on_cert_verify;

    std::unique_ptr<quic::Socket> socket;
    std::atomic<State> state{State::Closed};
    std::atomic<bool> running{false};
    std::atomic<bool> open_notified{false};
    std::atomic<bool> error_reported{false};
    std::atomic<bool> close_called{false};

    int connect_timeout = 0;
    std::string last_error;
    int last_error_code = 0;

    std::string host;
    std::string port;
    std::string params;
    bool payload_text = false;
    int64_t stream_id = quic::kInvalidStream;
    bool received_status_code = false;
    std::vector<uint8_t> rx_buffer;
    std::mutex rx_mutex;

    bool local_close_requested = false;
    int local_close_code = 0;
    std::string local_close_reason;

    ~Private() {
        resetSocket();
    }

    void resetSocket() {
        if (!socket) {
            return;
        }
        socket->close();
        socket.reset();
    }

    void fireError(Error err) {
        DBG("onError. kind=%d http=%d detail=%s", static_cast<int>(err.kind),
            err.httpCode, err.detail.c_str());
        bool expected = false;
        if (!error_reported.compare_exchange_strong(expected, true)) {
            return;
        }
        // onError and onClose are mutually exclusive.
        close_called.store(true, std::memory_order_release);
        last_error_code = err.httpCode;
        last_error = err.detail;
        state.store(State::Closed, std::memory_order_release);
        running.store(false, std::memory_order_release);
        if (on_error) {
            on_error(std::move(err));
        }
    }

    void fireClose(int code, std::string reason, bool remote) {
        DBG("onClose. code=%d, reason=%s, remote=%d", code, reason.c_str(), remote);
        if (close_called.exchange(true) ||
            error_reported.load(std::memory_order_acquire)) {
            return;
        }
        state.store(State::Closed, std::memory_order_release);
        running.store(false, std::memory_order_release);
        if (on_close) {
            on_close(code, std::move(reason), remote);
        }
    }

    void fail(Error err, bool close_socket) {
        // Report first so a synchronous onClose from socket->close() is suppressed.
        fireError(std::move(err));
        if (close_socket && socket) {
            socket->close();
        }
    }

    bool sendRaw(std::span<const uint8_t> bytes) {
        if (!socket || stream_id == quic::kInvalidStream) {
            return false;
        }
        return socket->send(bytes, 0, stream_id) == quic::Ok;
    }

    bool sendFramed(std::span<const uint8_t> payload) {
        auto framed = WrapVarIntPayload(payload);
        return sendRaw(framed);
    }

    void handleDataFramesLocked() {
        if (!received_status_code) {
            uint64_t code = 0;
            const auto consumed = GetUVarInt(
                &code, std::span<const uint8_t>(rx_buffer.data(), rx_buffer.size()));
            if (consumed == 0) {
                return;
            }
            rx_buffer.erase(rx_buffer.begin(),
                            rx_buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
            received_status_code = true;
            if (code != 200) {
                fail(Error{
                         .kind = ErrorKind::Http,
                         .httpCode = static_cast<int>(code),
                         .detail = "quic handshake status code: " + std::to_string(code),
                     },
                     true);
                return;
            }
            bool expected = false;
            if (open_notified.compare_exchange_strong(expected, true)) {
                DBG("onOpen");
                state.store(State::Open, std::memory_order_release);
                if (on_open) {
                    on_open();
                }
            }
        }

        while (!rx_buffer.empty()) {
            uint64_t payload_len = 0;
            const auto vlen = GetUVarInt(
                &payload_len,
                std::span<const uint8_t>(rx_buffer.data(), rx_buffer.size()));
            if (vlen == 0) {
                return;
            }
            if (rx_buffer.size() < vlen + payload_len) {
                return;
            }
            std::string payload;
            if (payload_len > 0) {
                payload.assign(reinterpret_cast<const char *>(rx_buffer.data() + vlen),
                               static_cast<size_t>(payload_len));
            }
            if (on_recv) {
                on_recv(std::move(payload), !payload_text);
            }
            const auto consumed = vlen + payload_len;
            rx_buffer.erase(rx_buffer.begin(),
                            rx_buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
        }
    }

    void wireCallbacks() {
        socket->onOpen([](const sockaddr *addr, socklen_t len) {
            char hostbuf[NI_MAXHOST] = {};
            char service[NI_MAXSERV] = {};
            const int rc =
                addr ? getnameinfo(addr, len, hostbuf, sizeof(hostbuf), service,
                                   sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV)
                     : EAI_FAIL;
            DBG("onOpen. addr=%s:%s", rc == 0 ? hostbuf : "?", rc == 0 ? service : "?");
            return true;
        });

        socket->onOpenStream([this](uint64_t conn_id, int64_t sid, quic::Dir dir,
                                    bool remote) {
            DBG("onOpenStream. conn_id=%" PRIu64 " stream_id=%" PRId64
                " dir=%d remote=%d",
                conn_id, sid, static_cast<int>(dir), remote);
            if (remote) {
                return false;
            }
            if (stream_id != quic::kInvalidStream) {
                return true;
            }
            stream_id = sid;
            const uint8_t marker = 0x35;
            if (!sendRaw(std::span<const uint8_t>(&marker, 1))) {
                fail(Error{.kind = ErrorKind::Connect, .detail = "quic send failed"},
                     true);
                return false;
            }
            const auto params_bytes = std::span<const uint8_t>(
                reinterpret_cast<const uint8_t *>(params.data()), params.size());
            if (!sendFramed(params_bytes)) {
                fail(Error{.kind = ErrorKind::Connect, .detail = "quic send failed"},
                     true);
                return false;
            }
            return true;
        });

        socket->onRecv([this](uint64_t /*conn_id*/, int64_t /*sid*/,
                              std::span<const uint8_t> data, bool /*fin*/) {
            std::lock_guard lock(rx_mutex);
            rx_buffer.insert(rx_buffer.end(), data.begin(), data.end());
            handleDataFramesLocked();
        });

        socket->onError([this](uint64_t conn_id, quic::Error error) {
            DBG("onError. conn_id=%" PRIu64 " kind=%u code=%" PRIu64 " reason=%s",
                conn_id, static_cast<unsigned>(error.kind), error.code,
                error.reason.c_str());
            fail(MapQuicError(error), /*close_socket=*/false);
        });

        socket->onCloseStream([](uint64_t conn_id, int64_t sid, bool remote) {
            DBG("onCloseStream. conn_id=%" PRIu64 " stream_id=%" PRId64 " remote=%d",
                conn_id, sid, remote);
        });

        socket->onClose([this](uint64_t conn_id, quic::Error error, bool remote) {
            const bool normal = !remote && error.kind == quic::ErrKind::None;
            std::string reason = error.reason;
            if (reason.empty() && !normal) {
                reason = "quic error kind=" +
                         std::to_string(static_cast<unsigned>(error.kind)) +
                         " code=" + std::to_string(error.code);
            }
            const int code = normal ? 0 : kAbnormalClose;
            DBG("onClose. conn_id=%" PRIu64 " kind=%u code=%" PRIu64
                " ws_code=%d reason=%s remote=%d",
                conn_id, static_cast<unsigned>(error.kind), error.code, code,
                reason.c_str(), remote);
            if (local_close_requested) {
                fireClose(local_close_code, local_close_reason, false);
            } else {
                fireClose(code, std::move(reason), remote);
            }
        });
    }

    void requestClose(int code, const std::string &reason) {
        local_close_requested = true;
        local_close_code = code;
        local_close_reason = reason;
        const auto current = state.load(std::memory_order_acquire);
        if (current == State::Closed) {
            return;
        }
        if (current != State::Closing) {
            state.store(State::Closing, std::memory_order_release);
        }
        if (socket) {
            socket->close();
        }
    }
};

QuicSocket::QuicSocket() : d(std::make_unique<Private>()) {}

QuicSocket::~QuicSocket() {
    close();
}

bool QuicSocket::open(const std::string &url) {
    OpenOptions options;
    options.url = url;
    return open(options);
}

bool QuicSocket::open(const OpenOptions &options) {
    const auto current = d->state.load(std::memory_order_acquire);
    if (current == State::Connecting || current == State::Open) {
        return false;
    }

    // Join a previous loop thread before creating a new Socket. Must run off
    // the QUIC loop thread (same contract as quic::Socket::~Socket).
    d->resetSocket();

    d->last_error.clear();
    d->last_error_code = 0;
    d->open_notified.store(false, std::memory_order_release);
    d->error_reported.store(false, std::memory_order_release);
    d->close_called.store(false, std::memory_order_release);
    d->local_close_requested = false;
    d->local_close_code = 0;
    d->local_close_reason.clear();
    d->stream_id = quic::kInvalidStream;
    d->received_status_code = false;
    {
        std::lock_guard lock(d->rx_mutex);
        d->rx_buffer.clear();
    }

    std::string error;
    if (!ParseUrl(options.url, &d->host, &d->port, &d->params, &error)) {
        d->fail(Error{.kind = ErrorKind::InvalidUrl, .detail = error}, false);
        return false;
    }
    d->payload_text = QueryHasJsonTrue(d->params);

    d->running.store(true, std::memory_order_release);
    d->state.store(State::Connecting, std::memory_order_release);

    d->socket = std::make_unique<quic::Socket>();
    d->socket->onCertVerify([this](void *ssl_ctx) {
        if (d->on_cert_verify) {
            return d->on_cert_verify(ssl_ctx);
        }
        return AddCertsToSSL(ssl_ctx);
    });

    quic::Options opts;
    opts.verify_peer = true;
    opts.sni = options.sni_host;
    opts.connect_timeout = d->connect_timeout;
    DBG("open. sni_host=%s connect_timeout=%d", opts.sni.c_str(),
        opts.connect_timeout);
    d->socket->options(std::move(opts));
    d->wireCallbacks();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(d->host.c_str(), d->port.c_str(), &hints, &res) != 0 || !res) {
        d->fail(Error{.kind = ErrorKind::Resolve,
                      .detail = "resolve host failed: " + d->host + ":" + d->port},
                false);
        return false;
    }

    int rc = quic::Err;
    for (auto *rp = res; rp; rp = rp->ai_next) {
        rc = d->socket->open(rp->ai_addr, rp->ai_addrlen);
        if (rc == quic::Ok) {
            break;
        }
    }
    freeaddrinfo(res);
    if (rc != quic::Ok) {
        d->fail(Error{.kind = ErrorKind::Connect, .detail = "quic open failed"},
                false);
        return false;
    }

    if (d->socket->openStream() != quic::Ok) {
        d->fail(Error{.kind = ErrorKind::Connect, .detail = "open quic stream failed"},
                true);
        return false;
    }
    return true;
}

void QuicSocket::close() {
    DBG("close");
    close(0);
}

void QuicSocket::close(int code, const std::string &reason) {
    DBG("close. code=%d, reason=%s", code, reason.c_str());
    if (!d) {
        return;
    }
    d->requestClose(code, reason);
    d->resetSocket();
    if (!d->close_called.load(std::memory_order_acquire) &&
        !d->error_reported.load(std::memory_order_acquire)) {
        d->fireClose(code, reason, false);
    }
    d->state.store(State::Closed, std::memory_order_release);
    d->running.store(false, std::memory_order_release);
}

void QuicSocket::closeAsync(int code, const std::string &reason) {
    DBG("closeAsync. code=%d, reason=%s", code, reason.c_str());
    if (d) {
        d->requestClose(code, reason);
    }
}

bool QuicSocket::send(const void *data, size_t len, bool /*binary*/) {
    if (d->state.load(std::memory_order_acquire) != State::Open) {
        return false;
    }
    if (len == 0) {
        return d->sendFramed({});
    }
    if (!data) {
        return false;
    }
    return d->sendFramed(std::span<const uint8_t>(
        static_cast<const uint8_t *>(data), len));
}

void QuicSocket::setOnOpen(on_open_fn_t &&cb) { d->on_open = std::move(cb); }
void QuicSocket::setOnClose(on_close_fn_t &&cb) { d->on_close = std::move(cb); }
void QuicSocket::setOnError(on_error_fn_t &&cb) { d->on_error = std::move(cb); }
void QuicSocket::setOnRecv(on_recv_fn_t &&cb) { d->on_recv = std::move(cb); }
void QuicSocket::onCertVerify(on_cert_verify_fn_t &&cb) {
    d->on_cert_verify = std::move(cb);
}

bool QuicSocket::isRunning() const noexcept { return d->running.load(); }

QuicSocket::State QuicSocket::readyState() const noexcept {
    return d->state.load();
}

const std::string &QuicSocket::lastError() const noexcept {
    return d->last_error;
}

int QuicSocket::lastErrorCode() const noexcept { return d->last_error_code; }

void QuicSocket::setConnectTimeout(int ms) { d->connect_timeout = ms; }

} // namespace bff
