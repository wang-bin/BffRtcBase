#include "WebSocket.h"
#include "Cert.h"
#include "SniUrl.h"

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
#include <curl/multi.h>
#include <curl/websockets.h>

#include <fcntl.h>
#include <unistd.h>

namespace bff {

using namespace std;
class WakePipe {
public:
    WakePipe() {
        if (pipe(pipefd_) != 0) {
            pipefd_[0] = pipefd_[1] = -1;
            return;
        }
        for (int fd : pipefd_) {
            const int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) {
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }
        }
    }

    ~WakePipe() {
        if (pipefd_[0] >= 0) {
            close(pipefd_[0]);
        }
        if (pipefd_[1] >= 0) {
            close(pipefd_[1]);
        }
    }

    bool valid() const { return pipefd_[0] >= 0 && pipefd_[1] >= 0; }

    int readFd() const { return pipefd_[0]; }

    void signal() const {
        if (pipefd_[1] < 0) {
            return;
        }
        const char byte = 0;
        (void)write(pipefd_[1], &byte, 1);
    }

    void drain() const {
        if (pipefd_[0] < 0) {
            return;
        }
        char buf[64];
        while (read(pipefd_[0], buf, sizeof(buf)) > 0) {
        }
    }

private:
    int pipefd_[2] = {-1, -1};
};

static CURLcode ssl_ctx_callback(CURL* curl, void* ssl_ctx, void* userdata) {
    (void)curl;
    (void)userdata;
    if (!AddCertsToSSL(ssl_ctx)) {
        return CURLE_ABORTED_BY_CALLBACK;
    }
    return CURLE_OK;
}

static void set_options(CURL* easy, bool verify_host) {
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, verify_host ? 2L : 0L);
    curl_easy_setopt(easy, CURLOPT_TCP_NODELAY, 1L);
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);
    curl_easy_setopt(easy, CURLOPT_SSL_CTX_DATA, nullptr);
}

class WebSocket::Private {
public:
    struct SendItem {
        std::vector<char> payload;
        bool binary = false;
        bool close_frame = false;
    };

    struct UserData {
        WebSocket::Private *self;
        CURL *easy;
    };

    std::atomic<bool> abort{false};
    std::atomic<bool> running{false};
    std::atomic<CURL *> easy{nullptr};
    std::atomic<CURLM *> multi{nullptr};
    std::atomic<WebSocketReadyState> state{WebSocketReadyState::Closed};
    std::thread thread;

    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
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
    std::mutex lifecycle_mutex;
    std::deque<SendItem> sendq;
    WakePipe wake_pipe;

    on_open_fn_t on_open;
    on_close_fn_t on_close;
    on_error_fn_t on_error;
    on_recv_fn_t on_recv;

    bool close_called = false;
    bool local_close_requested = false;
    std::atomic<bool> open_notified{false};
    std::atomic<bool> error_reported{false};

    void notifyOpen() {
        bool expected = false;
        if (!open_notified.compare_exchange_strong(expected, true)) {
            return;
        }
        state.store(WebSocketReadyState::Open);
        if (on_open) {
            on_open();
        }
    }

    ~Private() {
        std::lock_guard<std::mutex> lock(lifecycle_mutex);
        joinThreadLocked();
    }

    void joinThreadLocked() {
        if (thread.joinable()) {
            thread.join();
        }
    }

    void wakeWorker() {
        wake_pipe.signal();
#if LIBCURL_VERSION_NUM >= 0x074400
        if (auto *m = multi.load(std::memory_order_acquire)) {
            curl_multi_wakeup(m);
        }
#endif
        if (auto *e = easy.load(std::memory_order_acquire)) {
            curl_easy_pause(e, CURLPAUSE_CONT);
        }
    }

    static int xferinfo_cb(void *clientp,
                           curl_off_t /*dltotal*/, curl_off_t /*dlnow*/,
                           curl_off_t /*ultotal*/, curl_off_t /*ulnow*/) {
        auto *ud = reinterpret_cast<UserData *>(clientp);
        if (!ud || !ud->self) {
            return 0;
        }
        if (ud->easy) {
            ud->self->notifyOpen();
            ud->self->flushSendQueue(ud->easy);
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

        ud->self->notifyOpen();

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
                ud->self->abort.store(true);
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
                ud->self->on_recv(std::move(ud->self->rx_buf), ud->self->rx_is_binary);
            } else {
                ud->self->rx_buf.clear();
            }
            ud->self->rx_expected_offset = 0;
        }

        ud->self->flushSendQueue(ud->easy);
        return bytes;
    }

    void fireError(const int code, const std::string& err) {
        bool expected = false;
        if (!error_reported.compare_exchange_strong(expected, true)) {
            return;
        }
        // SRWebSocket: didFailWithError and didCloseWithCode are mutually exclusive.
        close_called = true;
        last_error_code = code;
        last_error = err;
        if (on_error) {
            on_error(code, err);
        }
    }

    void fireClose(int code, const std::string& reason, bool remote) {
        if (close_called || error_reported.load(std::memory_order_acquire)) {
            return;
        }
        close_called = true;
        if (on_close) {
            on_close(code, reason, remote);
        }
    }

    // Returns true when the item is fully sent. On false, *fatal indicates whether
    // the connection should be torn down; transient send failures are retried.
    bool sendDirect(CURL *e, SendItem& item, bool& fatal) {
        fatal = false;
        if (!e) {
            return false;
        }

        const unsigned int flags = item.close_frame
            ? CURLWS_CLOSE
            : (item.binary ? CURLWS_BINARY : CURLWS_TEXT);

        while (!item.payload.empty()) {
            size_t sent = 0;
            const auto rc = curl_ws_send(e, item.payload.data(), item.payload.size(), &sent, 0, flags);
            if (sent > 0) {
                item.payload.erase(item.payload.begin(),
                                   item.payload.begin() + static_cast<std::ptrdiff_t>(sent));
            }

            if (rc == CURLE_OK) {
                continue;
            }
            if (rc == CURLE_AGAIN || rc == CURLE_SEND_ERROR) {
                return false;
            }

            fireError(static_cast<int>(rc), curl_easy_strerror(rc));
            fatal = true;
            return false;
        }

        return true;
    }

    void flushSendQueue(CURL *e) {
        if (!e || !open_notified.load(std::memory_order_acquire)) {
            return;
        }
        while (true) {
            SendItem item;
            {
                std::lock_guard<std::mutex> lock(send_mutex);
                if (sendq.empty()) {
                    break;
                }
                item = std::move(sendq.front());
                sendq.pop_front();
            }
            bool fatal = false;
            if (!sendDirect(e, item, fatal)) {
                std::lock_guard<std::mutex> lock(send_mutex);
                sendq.push_front(std::move(item));
                if (fatal) {
                    abort.store(true);
                }
                wakeWorker();
                break;
            }
        }
    }

    void queueCloseFrame(int code, const std::string& reason) {
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

        SendItem item;
        item.close_frame = true;
        item.payload.assign(reinterpret_cast<char *>(payload),
                            reinterpret_cast<char *>(payload) + payload_len);
        std::lock_guard<std::mutex> lock(send_mutex);
        sendq.push_back(std::move(item));
    }

    void close(int code, const std::string& reason) {
        std::lock_guard<std::mutex> lock(lifecycle_mutex);

        local_close_requested = true;
        const auto current = state.load();
        if (current != WebSocketReadyState::Closed &&
            current != WebSocketReadyState::Closing &&
            thread.joinable()) {
            state.store(WebSocketReadyState::Closing);
            if (running.load()) {
                queueCloseFrame(code, reason);
            }
            wakeWorker();
            abort.store(true);
            wakeWorker();
        } else if (thread.joinable()) {
            // Worker may have already set state to Closed without a join on this side.
            abort.store(true);
            wakeWorker();
        }

        joinThreadLocked();

        {
            std::lock_guard<std::mutex> lock(send_mutex);
            sendq.clear();
        }

        easy.store(nullptr, std::memory_order_release);
        running.store(false);
        // Worker clears running before join returns; local close must still deliver on_close.
        if (!close_called && !error_reported.load(std::memory_order_acquire)) {
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
    d->url = options.url;
    d->headers = options.headers;
    d->last_error.clear();
    d->last_error_code = 0;
    d->abort.store(false);
    d->close_called = false;
    d->local_close_requested = false;
    d->open_notified.store(false);
    d->error_reported.store(false);
    d->running.store(true);
    d->state.store(WebSocketReadyState::Connecting);

    auto sni_host = options.sni_host;
    d->thread = std::thread([this, sni_host] {
        CURL *easy = curl_easy_init();
        if (!easy) {
            d->running.store(false);
            d->state.store(WebSocketReadyState::Closed);
            d->fireError(-1, "curl_easy_init failed");
            return;
        }

        Private::UserData ud{d.get(), easy};

        const auto prepared = prepare_url_for_sni(d->url, sni_host);
        curl_slist *resolve_list = nullptr;
        if (!prepared.resolve.empty()) {
            resolve_list = curl_slist_append(nullptr, prepared.resolve.c_str());
            curl_easy_setopt(easy, CURLOPT_RESOLVE, resolve_list);
        }

        curl_easy_setopt(easy, CURLOPT_URL, prepared.url.c_str());
        curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &Private::write_cb);
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, &ud);

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

        set_options(easy, !sni_host.empty());

        d->easy.store(easy, std::memory_order_release);

        CURLM *multi = curl_multi_init();
        if (!multi) {
            d->running.store(false);
            d->state.store(WebSocketReadyState::Closed);
            d->easy.store(nullptr, std::memory_order_release);
            d->fireError(-1, "curl_multi_init failed");
            curl_easy_cleanup(easy);
            if (header_list) {
                curl_slist_free_all(header_list);
            }
            if (resolve_list) {
                curl_slist_free_all(resolve_list);
            }
            return;
        }
        d->multi.store(multi, std::memory_order_release);

        CURLMcode mc = curl_multi_add_handle(multi, easy);
        if (mc != CURLM_OK) {
            d->multi.store(nullptr, std::memory_order_release);
            curl_multi_cleanup(multi);
            d->running.store(false);
            d->state.store(WebSocketReadyState::Closed);
            d->easy.store(nullptr, std::memory_order_release);
            d->fireError(static_cast<int>(mc), curl_multi_strerror(mc));
            curl_easy_cleanup(easy);
            if (header_list) {
                curl_slist_free_all(header_list);
            }
            if (resolve_list) {
                curl_slist_free_all(resolve_list);
            }
            return;
        }

        CURLcode rc = CURLE_OK;
        int still_running = 1;
        while (!d->abort.load() && still_running) {
            mc = curl_multi_perform(multi, &still_running);
            if (mc != CURLM_OK) {
                d->fireError(static_cast<int>(mc), curl_multi_strerror(mc));
                break;
            }

            d->flushSendQueue(easy);

            int msgs_left = 0;
            while (CURLMsg *msg = curl_multi_info_read(multi, &msgs_left)) {
                if (msg->msg == CURLMSG_DONE && msg->easy_handle == easy) {
                    rc = msg->data.result;
                    still_running = 0;
                    break;
                }
            }

            if (!still_running || d->abort.load()) {
                break;
            }

            long timeout_ms = 1000;
            curl_multi_timeout(multi, &timeout_ms);
            if (timeout_ms < 0) {
                timeout_ms = 100;
            }
            bool pending_send = false;
            {
                std::lock_guard<std::mutex> lock(d->send_mutex);
                pending_send = !d->sendq.empty();
                if (pending_send) {
                    timeout_ms = 0;
                }
            }

            struct curl_waitfd extra {};
            const bool use_wake_pipe = d->wake_pipe.valid();
            if (use_wake_pipe) {
                extra.fd = d->wake_pipe.readFd();
                extra.events = CURL_WAIT_POLLIN;
            }

            int numfds = 0;
            mc = curl_multi_poll(multi, use_wake_pipe ? &extra : nullptr,
                                 use_wake_pipe ? 1u : 0u, timeout_ms, &numfds);
            if (mc != CURLM_OK) {
                d->fireError(static_cast<int>(mc), curl_multi_strerror(mc));
                break;
            }
            if (use_wake_pipe && (extra.revents & CURL_WAIT_POLLIN)) {
                d->wake_pipe.drain();
                d->flushSendQueue(easy);
            }
        }

        d->flushSendQueue(easy);

        curl_multi_remove_handle(multi, easy);
        d->multi.store(nullptr, std::memory_order_release);
        curl_multi_cleanup(multi);

        d->easy.store(nullptr, std::memory_order_release);
        d->running.store(false);

        if (!d->abort.load() && rc != CURLE_OK) {
            d->fireError(static_cast<int>(rc), curl_easy_strerror(rc));
        } else if (!d->close_called && !d->error_reported.load() && !d->local_close_requested) {
            // Peer closed without a WS CLOSE frame; local close is reported by close().
            d->fireClose(1000, {}, true);
        }
        d->state.store(WebSocketReadyState::Closed);

        if (header_list) {
            curl_slist_free_all(header_list);
        }
        if (resolve_list) {
            curl_slist_free_all(resolve_list);
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

    {
        std::lock_guard<std::mutex> lock(d->send_mutex);
        Private::SendItem item;
        item.binary = binary;
        item.payload.assign(reinterpret_cast<const char *>(data),
                            reinterpret_cast<const char *>(data) + len);
        d->sendq.push_back(std::move(item));
    }

    d->wakeWorker();
    return true;
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

#else
namespace bff {

class WebSocket::Private {};

WebSocket::WebSocket()
{
}

WebSocket::~WebSocket()
{
}

bool WebSocket::open(const std::string& url)
{
    return false;
}

bool WebSocket::open(const WebSocketOpenOptions& options)
{
    return false;
}

void WebSocket::close()
{
}

void WebSocket::close(int code, const std::string& reason)
{
}

bool WebSocket::send(const void *data, size_t len, bool binary)
{
    return false;
}

void WebSocket::setOnOpen(on_open_fn_t&& cb)
{
}

void WebSocket::setOnClose(on_close_fn_t&& cb)
{
}

void WebSocket::setOnError(on_error_fn_t&& cb)
{
}

void WebSocket::setOnRecv(on_recv_fn_t&& cb)
{
}

bool WebSocket::isRunning() const noexcept
{
    return false;
}

WebSocketReadyState WebSocket::readyState() const noexcept
{
    return WebSocketReadyState::Closed;
}

const std::string& WebSocket::lastError() const noexcept
{
    return "";
}

int WebSocket::lastErrorCode() const noexcept
{
    return 0;
}
} // namespace bff
#endif // __has_include(<curl/curl.h>)
