#pragma once
#include <optional>
#include <string>
#include <unordered_map>

namespace bff {

// Signaling errors used by bff::Signal. Values match JsppRTCError ordinals for bridge mapping.
enum class RtcError : int {
    SignalFailed = 0,
    SSL = 6,
    Token = 11,
};

// Mirrors JsppRTCLogLevel (JsppDefs.h).
enum class RtcLogLevel : int {
    Error = 0,
    Warn,
    Info,
    Debug,
};

// Parsed from SignalResponse.candidate JSON (see JsppWebSocket receiveCandidate).
struct IceCandidate {
    std::string sdp;
    std::string sdpMid;
    int sdpMLineIndex = 0;
};

enum class RtcIcePolicy : int {
    None = 0,
    All,
    NoHost,
    Relay,
    UDP,
    TCP,
    TLS,
};

enum class SignalImplementation : int {
    Curl = 0,
    Quic,
    // Happy Eyeballs: Quic first, then TCP (Curl) after mixedDelay; first open wins.
    Mixed,
};

struct SignalOptions {
    std::optional<std::string> server;
    bool json = false;
    SignalImplementation implementation = SignalImplementation::Mixed;
    // Mixed: ms to wait after starting Quic before starting TCP. <=0 starts TCP immediately.
    int mixedDelay = 250;
    // Handshake deadline in milliseconds.
    int connectTimeout = 10000;
    int pingInterval = 1000;
    int pingTimeout = 2000;
    int reconnectInterval = 1000;
    int reconnectMaxTimes = 9999;
    int responseTimeout = 2000;
    bool autoSubscribe = true;
    bool compression = false;
};

class Config {
public:
    static Config& Shared() {
        static Config instance;
        return instance;
    }

    std::optional<std::string> role;
    // ip -> host mapping for SNI and cert validation.
    std::unordered_map<std::string, std::string> hosts;
    bool sni = false;

    // Sent on join (signaling); not WebRTC PeerConnection config.
    RtcIcePolicy icePolicy = RtcIcePolicy::All;

    // Forced media/stun node; empty means negotiate via nodelist + STUN.
    std::optional<std::string> server;
    // 2 hours, seconds.
    int serverRecheck = 2 * 60 * 60;
    // ms
    int serversSortTimeout = 200;

    SignalOptions signal;

private:
    Config() = default;
};

} // namespace bff
