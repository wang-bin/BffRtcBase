#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace bff {

enum class WebSocketReadyState {
    Connecting = 0,
    Open = 1,
    Closing = 2,
    Closed = 3,
};

struct WebSocketOpenOptions {
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string sni_host;
};

class WebSocket {
public:
    using on_open_fn_t = std::function<void()>;
    /*
    Called after the websocket connection has been closed.
Params:
code – The codes can be looked up here: CloseFrame
reason – Additional information string
remote – Returns whether or not the closing of the connection was initiated by the remote host.
    */
    using on_close_fn_t = std::function<void(int code, const std::string& reason, bool remote)>;
    using on_error_fn_t = std::function<void(int code, const std::string& error)>;
    using on_recv_fn_t = std::function<void(const std::string& data, bool binary)>;

    WebSocket();
    ~WebSocket();

    WebSocket(const WebSocket&) = delete;
    WebSocket& operator=(const WebSocket&) = delete;

    void setOnOpen(on_open_fn_t&& cb);
    void setOnClose(on_close_fn_t&& cb);
    void setOnError(on_error_fn_t&& cb);
    void setOnRecv(on_recv_fn_t&& cb);

    bool open(const std::string& url);
    bool open(const WebSocketOpenOptions& options);
    void close();
    void close(int code, const std::string& reason = {});

    bool send(const std::string& data, bool binary) {
        return send(data.data(), data.size(), binary);
    }
    bool send(const void *data, size_t len, bool binary);

    bool isRunning() const noexcept;
    WebSocketReadyState readyState() const noexcept;
    const std::string& lastError() const noexcept;
    int lastErrorCode() const noexcept;

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace bff

