#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

namespace bff {

// Laser-framed signaling transport over quic::Socket.
class QuicSocket {
public:
    struct OpenOptions {
        std::string url;
        std::string sni_host;
    };

    enum class State {
        Connecting = 0,
        Open = 1,
        Closing = 2,
        Closed = 3,
    };

    enum class ErrorKind {
        Ssl,
        Timeout,
        Resolve,
        Connect,
        Http,
        InvalidUrl,
        Other,
    };

    struct Error {
        ErrorKind kind = ErrorKind::Other;
        int httpCode = 0;
        std::string detail;
    };

    using on_open_fn_t = std::function<void()>;
    using on_close_fn_t = std::function<void(int code, std::string reason, bool remote)>;
    using on_error_fn_t = std::function<void(Error error)>;
    using on_recv_fn_t = std::function<void(std::string data, bool binary)>;
    using on_cert_verify_fn_t = std::function<bool(void *ssl_ctx)>;

    QuicSocket();
    ~QuicSocket();

    QuicSocket(const QuicSocket&) = delete;
    QuicSocket& operator=(const QuicSocket&) = delete;

    void setOnOpen(on_open_fn_t&& cb);
    void setOnClose(on_close_fn_t&& cb);
    void setOnError(on_error_fn_t&& cb);
    void setOnRecv(on_recv_fn_t&& cb);
    void onCertVerify(on_cert_verify_fn_t&& cb);

    // Handshake deadline in milliseconds. <=0 disables (quic::Options default).
    void setConnectTimeout(int ms);

    bool open(const std::string& url);
    bool open(const OpenOptions& options);
    void close();
    void close(int code, const std::string& reason = {});
    // Cooperative shutdown without joining the QUIC loop thread (safe from
    // that thread). ~QuicSocket / a later open() joins.
    void closeAsync(int code = 0, const std::string& reason = {});

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
