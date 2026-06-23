#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace bff {

class WebSocket {
public:
    struct OpenOptions {
        std::string url;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string sni_host;
    };

    enum class State {
        Connecting = 0,
        Open = 1,
        Closing = 2,
        Closed = 3,
    };

    /** RFC 6455 close codes plus application-specific values (negative). */
    enum class CloseCode : int {
        /** Normal closure — purpose fulfilled. */
        Normal = 1000,
        /** Endpoint going away (server down, navigated away). */
        GoingAway = 1001,
        /** Protocol error. */
        ProtocolError = 1002,
        /** Unsupported data type. */
        Refuse = 1003,
        // 1004 reserved
        /** No status code present (must not be sent in a Close frame). */
        NoCode = 1005,
        /** Abnormal close without a Close frame (must not be sent). */
        AbnormalClose = 1006,
        /** Non-UTF-8 data in a text message. */
        NoUtf8 = 1007,
        /** Policy violation. */
        PolicyValidation = 1008,
        /** Message too big to process. */
        TooBig = 1009,
        /** Missing extension (client only). */
        Extension = 1010,
        /** Unexpected server condition. */
        UnexpectedCondition = 1011,
        /** Service restarted; client may reconnect after delay. */
        ServiceRestart = 1012,
        /** Overload; reconnect on user action. */
        TryAgainLater = 1013,
        /** Invalid upstream gateway response. */
        BadGateway = 1014,
        /** TLS handshake failure (must not be sent). */
        TlsError = 1015,

        /** Connection never established. */
        NeverConnected = -1,
        /** Buggy close (should not happen). */
        BuggyClose = -2,
        /** Connection flushed and closed. */
        FlashPolicy = -3,
    };

    using on_open_fn_t = std::function<void()>;
    /*
    Called after the websocket connection has been closed.
Params:
code – See CloseCode
reason – Additional information string
remote – Returns whether or not the closing of the connection was initiated by the remote host.
    */
    using on_close_fn_t = std::function<void(CloseCode code, std::string reason, bool remote)>;
    using on_error_fn_t = std::function<void(int code, std::string error)>;
    using on_recv_fn_t = std::function<void(std::string data, bool binary)>;

    WebSocket();
    ~WebSocket();

    WebSocket(const WebSocket&) = delete;
    WebSocket& operator=(const WebSocket&) = delete;

    void setOnOpen(on_open_fn_t&& cb);
    void setOnClose(on_close_fn_t&& cb);
    void setOnError(on_error_fn_t&& cb);
    void setOnRecv(on_recv_fn_t&& cb);

    void setConnectTimeout(int ms);

    bool open(const std::string& url);
    bool open(const OpenOptions& options);
    void close();
    void close(CloseCode code, const std::string& reason = {});
    // Signal shutdown without joining the worker thread (safe from the worker thread).
    void closeAsync(CloseCode code = CloseCode::Normal, const std::string& reason = {});

    bool send(const std::string& data, bool binary) {
        return send(data.data(), data.size(), binary);
    }
    bool send(const void *data, size_t len, bool binary);

    bool isRunning() const noexcept;
    State readyState() const noexcept;
    const std::string& lastError() const noexcept;
    int lastErrorCode() const noexcept;

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace bff
