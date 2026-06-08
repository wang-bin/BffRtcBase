#include "WebSocket.h"
#include "Cert.h"

#if __has_include(<curl/curl.h>)

#include <atomic>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/websockets.h>

#if __has_include(<openssl/ssl.h>)
#include <openssl/ssl.h>
#endif

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

namespace bff {


struct SslUserData {
    std::string sni_host;
};

static CURLcode ssl_ctx_callback(CURL* curl, void* ssl_ctx, void* userdata) {
    if (!AddCertsToSSL(ssl_ctx))
        return CURLE_ABORTED_BY_CALLBACK;
#if __has_include(<openssl/ssl.h>)
    if (userdata) {
        const auto *ud = static_cast<const SslUserData *>(userdata);
        if (!ud->sni_host.empty()) {
            SSL_set_tlsext_host_name(static_cast<SSL *>(ssl_ctx), ud->sni_host.c_str());
        }
    }
#endif
    return CURLE_OK;
}

static void set_options(CURL* easy, const SslUserData& ssl_ud) {
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, ssl_ud.sni_host.empty() ? 0L : 2L);
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);
    curl_easy_setopt(easy, CURLOPT_SSL_CTX_DATA, const_cast<SslUserData *>(&ssl_ud));
}

class WebSocket::Private {
public:
    struct SendItem {
        std::vector<char> payload;
        bool binary = false;
        size_t offset = 0;
        bool frame_started = false;
    };

    struct UserData {
        WebSocket::Private *self;
        CURL *easy;
    };

    std::atomic<bool> abort{false};
    std::atomic<bool> running{false};
    std::atomic<CURL *> easy{nullptr};
    std::atomic<WebSocketReadyState> state{WebSocketReadyState::Closed};
    std::thread thread;

    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    SslUserData ssl_ud;
    std::string last_error;
    int last_error_code = 0;

    // inbound buffering (deliver only complete frames to on_recv)
    std::string rx_buf;
    bool rx_is_binary = false;
    size_t rx_expected_offset = 0;

    // close frame buffering (control frames can interleave with data fragments)
    std::string close_buf;
    size_t close_expected_offset = 0;

    // outbound queue for read callback (libcurl >= 8.16)
    std::mutex send_mutex;
    std::deque<SendItem> sendq;
    std::unique_ptr<SendItem> active_send;

    on_open_fn_t on_open;
    on_close_fn_t on_close;
    on_error_fn_t on_error;
    on_recv_fn_t on_recv;

    bool close_called = false;
    bool local_close_requested = false;

    static int xferinfo_cb(void *clientp,
                           curl_off_t /*dltotal*/, curl_off_t /*dlnow*/,
                           curl_off_t /*ultotal*/, curl_off_t /*ulnow*/) {
        auto *ud = reinterpret_cast<UserData *>(clientp);
        if (!ud || !ud->self) {
            return 0;
        }
        return ud->self->abort.load() ? 1 : 0;
    }

    static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
        const auto bytes = size * nmemb;
        if (!userdata || !bytes) {
            return bytes;
        }

        auto *ud = reinterpret_cast<UserData *>(userdata);
        if (!ud || !ud->self || !ud->easy) {
            return bytes;
        }

        const struct curl_ws_frame *meta = curl_ws_meta(ud->easy);
        if (!meta) {
            return bytes;
        }

        // ignore ping/pong here (autopong by default)
        if ((meta->flags & CURLWS_PING) || (meta->flags & CURLWS_PONG)) {
            return bytes;
        }

        // CLOSE frames: buffer and parse (2-byte code + optional reason).
        if (meta->flags & CURLWS_CLOSE) {
            if (meta->offset == 0) {
                ud->self->close_buf.clear();
                ud->self->close_expected_offset = 0;
            }

            if (meta->offset != static_cast<curl_off_t>(ud->self->close_expected_offset)) {
                ud->self->close_buf.clear();
                ud->self->close_expected_offset = 0;
            }

            ud->self->close_buf.append(ptr, bytes);
            ud->self->close_expected_offset += bytes;

            if (meta->bytesleft == 0) {
                int code = 1005; // "no status received" (RFC 6455)
                std::string reason;
                if (ud->self->close_buf.size() >= 2) {
                    const unsigned char b0 = static_cast<unsigned char>(ud->self->close_buf[0]);
                    const unsigned char b1 = static_cast<unsigned char>(ud->self->close_buf[1]);
                    code = (static_cast<int>(b0) << 8) | static_cast<int>(b1);
                    if (ud->self->close_buf.size() > 2) {
                        reason.assign(ud->self->close_buf.data() + 2,
                                      ud->self->close_buf.data() + ud->self->close_buf.size());
                    }
                }
                ud->self->fireClose(code, reason, true);
                ud->self->abort.store(true); // stop curl_easy_perform promptly
                ud->self->close_buf.clear();
                ud->self->close_expected_offset = 0;
            }

            return bytes;
        }

        // Data frames: buffer until complete frame; call on_recv only when bytesleft == 0.
        const bool is_binary = (meta->flags & CURLWS_BINARY) != 0;
        if (meta->offset == 0) {
            ud->self->rx_buf.clear();
            ud->self->rx_is_binary = is_binary;
            ud->self->rx_expected_offset = 0;
        }

        if (meta->offset != static_cast<curl_off_t>(ud->self->rx_expected_offset)) {
            ud->self->rx_buf.clear();
            ud->self->rx_is_binary = is_binary;
            ud->self->rx_expected_offset = 0;
        }

        ud->self->rx_buf.append(ptr, bytes);
        ud->self->rx_expected_offset += bytes;

        if (meta->bytesleft == 0) {
            if (ud->self->on_recv) {
                ud->self->on_recv(ud->self->rx_buf, ud->self->rx_is_binary);
            }
            ud->self->rx_buf.clear();
            ud->self->rx_expected_offset = 0;
        }

        return bytes;
    }

    static size_t read_cb(char *buffer, size_t size, size_t nitems, void *userdata) {
        const auto cap = size * nitems;
        if (!userdata || !buffer || !cap) {
            return 0;
        }

        auto *ud = reinterpret_cast<UserData *>(userdata);
        if (!ud || !ud->self || !ud->easy) {
            return 0;
        }

        if (ud->self->abort.load()) {
            return CURL_READFUNC_ABORT;
        }

#if LIBCURL_VERSION_NUM < 0x081000
        return CURL_READFUNC_PAUSE;
#else
        SendItem *item = nullptr;
        {
            std::lock_guard<std::mutex> lock(ud->self->send_mutex);
            if (!ud->self->active_send && !ud->self->sendq.empty()) {
                ud->self->active_send = std::make_unique<SendItem>(std::move(ud->self->sendq.front()));
                ud->self->sendq.pop_front();
            }
            item = ud->self->active_send.get();
        }

        if (!item) {
            return CURL_READFUNC_PAUSE;
        }

        if (!item->frame_started) {
            const unsigned int flags = item->binary ? CURLWS_BINARY : CURLWS_TEXT;
            const auto frame_len = static_cast<curl_off_t>(item->payload.size());
            const auto rc = curl_ws_start_frame(ud->easy, flags, frame_len);
            if (rc != CURLE_OK) {
                return CURL_READFUNC_ABORT;
            }
            item->frame_started = true;
        }

        const auto left = item->payload.size() - item->offset;
        if (left == 0) {
            std::lock_guard<std::mutex> lock(ud->self->send_mutex);
            ud->self->active_send.reset();
            return 0;
        }

        const auto n = std::min(cap, left);
        memcpy(buffer, item->payload.data() + item->offset, n);
        item->offset += n;

        if (item->offset >= item->payload.size()) {
            std::lock_guard<std::mutex> lock(ud->self->send_mutex);
            ud->self->active_send.reset();
        }

        return n;
#endif
    }

    void fireError(const int code, const std::string& err) {
        last_error_code = code;
        last_error = err;
        if (on_error) {
            on_error(code, err);
        }
    }

    void fireClose(int code, const std::string& reason, bool remote) {
        if (close_called) {
            return;
        }
        close_called = true;
        if (on_close) {
            on_close(code, reason, remote);
        }
    }

    bool sendDirect(const void *data, size_t len, bool binary) {
        auto *e = easy.load(std::memory_order_acquire);
        if (!e) {
            return false;
        }

        const unsigned int flags = binary ? CURLWS_BINARY : CURLWS_TEXT;
        const unsigned char *p = reinterpret_cast<const unsigned char *>(data);
        size_t offset = 0;

        while (offset < len) {
            size_t sent = 0;
            const auto rc = curl_ws_send(e, p + offset, len - offset, &sent, 0, flags);
            offset += sent;

            if (rc == CURLE_OK) {
                continue;
            }
            if (rc == CURLE_AGAIN) {
                curl_socket_t sockfd = CURL_SOCKET_BAD;
                curl_easy_getinfo(e, CURLINFO_ACTIVESOCKET, &sockfd);
                if (sockfd == CURL_SOCKET_BAD) {
                    return false;
                }

                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(sockfd, &wfds);
                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                (void)select(static_cast<int>(sockfd + 1), nullptr, &wfds, nullptr, &tv);
                continue;
            }

            fireError(static_cast<int>(rc), curl_easy_strerror(rc));
            return false;
        }

        return true;
    }

    bool sendCloseFrame(int code, const std::string& reason) {
        auto *e = easy.load(std::memory_order_acquire);
        if (!e) {
            return false;
        }

        unsigned char payload[2 + 123];
        const int normalized = code >= 1000 ? code : 1000;
        payload[0] = static_cast<unsigned char>((normalized >> 8) & 0xff);
        payload[1] = static_cast<unsigned char>(normalized & 0xff);
        size_t payload_len = 2;
        if (!reason.empty()) {
            const size_t max_reason = sizeof(payload) - 2;
            const size_t n = std::min(reason.size(), max_reason);
            memcpy(payload + 2, reason.data(), n);
            payload_len += n;
        }

        size_t sent = 0;
        const auto rc = curl_ws_send(e, payload, payload_len, &sent, 0, CURLWS_CLOSE);
        return rc == CURLE_OK || rc == CURLE_AGAIN;
    }

    void close(int code, const std::string& reason) {
        if (state.load() == WebSocketReadyState::Closed ||
            state.load() == WebSocketReadyState::Closing) {
            return;
        }
        state.store(WebSocketReadyState::Closing);

        local_close_requested = true;
        if (running.load()) {
            (void)sendCloseFrame(code, reason);
        }
        abort.store(true);

        if (auto *e = easy.load(std::memory_order_acquire)) {
            curl_easy_pause(e, CURLPAUSE_CONT);
        }

        if (thread.joinable()) {
            thread.join();
        }

        {
            std::lock_guard<std::mutex> lock(send_mutex);
            sendq.clear();
            active_send.reset();
        }

        easy.store(nullptr, std::memory_order_release);
        // If the remote did not already close, report a local close now.
        if (running.exchange(false) && !close_called) {
            fireClose(code, reason, false);
        }
        state.store(WebSocketReadyState::Closed);
    }
};

WebSocket::WebSocket()
    : d(std::make_unique<Private>()) {}

WebSocket::~WebSocket() {
    close();
}

bool WebSocket::open(const std::string& url) {
    WebSocketOpenOptions options;
    options.url = url;
    return open(options);
}

bool WebSocket::open(const WebSocketOpenOptions& options) {
    close();

    d->url = options.url;
    d->headers = options.headers;
    d->ssl_ud.sni_host = options.sni_host;
    d->last_error.clear();
    d->last_error_code = 0;
    d->abort.store(false);
    d->close_called = false;
    d->local_close_requested = false;
    d->running.store(true);
    d->state.store(WebSocketReadyState::Connecting);

    d->thread = std::thread([this] {
        CURL *easy = curl_easy_init();
        if (!easy) {
            d->running.store(false);
            d->state.store(WebSocketReadyState::Closed);
            d->fireError(-1, "curl_easy_init failed");
            return;
        }

        Private::UserData ud{d.get(), easy};

        curl_easy_setopt(easy, CURLOPT_URL, d->url.c_str());
        curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &Private::write_cb);
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, &ud);
        curl_easy_setopt(easy, CURLOPT_READFUNCTION, &Private::read_cb);
        curl_easy_setopt(easy, CURLOPT_READDATA, &ud);
        curl_easy_setopt(easy, CURLOPT_UPLOAD, 1L);

        curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(easy, CURLOPT_XFERINFOFUNCTION, &Private::xferinfo_cb);
        curl_easy_setopt(easy, CURLOPT_XFERINFODATA, &ud);

        curl_slist *header_list = nullptr;
        for (const auto& [key, value] : d->headers) {
            const auto line = key + ": " + value;
            header_list = curl_slist_append(header_list, line.c_str());
        }
        if (header_list) {
            curl_easy_setopt(easy, CURLOPT_HTTPHEADER, header_list);
        }

        set_options(easy, d->ssl_ud);

        d->easy.store(easy, std::memory_order_release);

        if (d->on_open) {
            d->on_open();
        }
        d->state.store(WebSocketReadyState::Open);

        const auto rc = curl_easy_perform(easy);

        d->easy.store(nullptr, std::memory_order_release);
        d->running.store(false);

        if (!d->abort.load() && rc != CURLE_OK) {
            d->fireError(static_cast<int>(rc), curl_easy_strerror(rc));
        }

        // Ensure a close callback is always emitted.
        if (!d->close_called) {
            const bool remote = !d->local_close_requested;
            d->fireClose(1000, {}, remote);
        }
        d->state.store(WebSocketReadyState::Closed);

        if (header_list) {
            curl_slist_free_all(header_list);
        }
        curl_easy_cleanup(easy);
    });

    return true;
}

void WebSocket::close() {
    close(1000, {});
}

void WebSocket::close(int code, const std::string& reason) {
    if (d) {
        d->close(code, reason);
    }
}

bool WebSocket::send(const void *data, size_t len, bool binary) {
    if (!data && len) {
        return false;
    }
    if (!d->running.load()) {
        return false;
    }

#if LIBCURL_VERSION_NUM < 0x081000
    return d->sendDirect(data, len, binary);
#else
    {
        std::lock_guard<std::mutex> lock(d->send_mutex);
        Private::SendItem item;
        item.binary = binary;
        item.payload.assign(reinterpret_cast<const char *>(data),
                            reinterpret_cast<const char *>(data) + len);
        d->sendq.push_back(std::move(item));
    }

    if (auto *easy = d->easy.load(std::memory_order_acquire)) {
        curl_easy_pause(easy, CURLPAUSE_CONT);
    }

    return true;
#endif
}

void WebSocket::setOnOpen(on_open_fn_t&& cb) { d->on_open = std::move(cb); }
void WebSocket::setOnClose(on_close_fn_t&& cb) { d->on_close = std::move(cb); }
void WebSocket::setOnError(on_error_fn_t&& cb) { d->on_error = std::move(cb); }
void WebSocket::setOnRecv(on_recv_fn_t&& cb) { d->on_recv = std::move(cb); }

bool WebSocket::isRunning() const noexcept {
    return d->running.load();
}

WebSocketReadyState WebSocket::readyState() const noexcept {
    return d->state.load();
}

const std::string& WebSocket::lastError() const noexcept {
    return d->last_error;
}

int WebSocket::lastErrorCode() const noexcept {
    return d->last_error_code;
}

} // namespace bff

#endif // __has_include(<curl/curl.h>)
