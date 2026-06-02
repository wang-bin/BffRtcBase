#pragma once
#include <string>
#include <unordered_map>
#include <vector>

namespace bff {

// Mirrors JsppRTCError (JsppDefs.h) for ObjC bridge mapping.
enum class RtcError : int {
    SignalFailed = 0,
    ConnectionFailed,
    PeerConnectionFailed,
    CameraPermission,
    MicPermission,
    SDP,
    SSL,
    HostDown,
    AudioSessionSetCategory,
    AudioSessionSetActive,
    AudioUnitStart,
    Token,
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

enum class RtcVideoResolution : int {
    R1080 = 0,
    R720,
    R540,
    R360,
    R240,
};

enum class RtcMode : int {
    Sfu = 0,
    Mesh,
    Mixed,
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

struct VideoOptions {
    int fps = 20;
    int muteFps = 10;
    // has* mirrors ObjC nil semantics for NSNumber fields.
    bool hasBitrate = false;
    int bitrate = 0;
    bool hasMinBitrate = false;
    int minBitrate = 0;
    RtcVideoResolution resolution = RtcVideoResolution::R360;
    std::vector<std::string> codecs;
    int h265QpMin = 29;
    int h265QpMax = 41;
};

struct AudioOptions {
    bool noiseSuppression = true;
    bool highPassFilter = true;
};

struct SignalOptions {
    bool hasServer = false;
    std::string server;
    bool json = false;
    int pingInterval = 1000;
    int pingTimeout = 2000;
    int reconnectInterval = 1000;
    int reconnectMaxTimes = 9999;
    int responseTimeout = 2000;
    bool autoSubscribe = true;
};

struct DataChannelOptions {
    int pingInterval = 1000;
    int pingTimeout = 2000;
    int vadInterval = 300;
};

class Config {
public:
    static Config& Shared() {
        static Config instance;
        return instance;
    }

    bool hasRole = false;
    std::string role;
    // ip -> host mapping for SNI and cert validation.
    std::unordered_map<std::string, std::string> hosts;
    bool sni = false;

    RtcMode mode = RtcMode::Sfu;
    RtcIcePolicy icePolicy = RtcIcePolicy::All;
    bool autoPublish = true;
    bool publishAudio = true;
    bool publishVideo = true;
    bool bFrames = false;
    bool fullyReconnect = true;
    RtcLogLevel webrtcLogLevel = RtcLogLevel::Error;
    bool webrtcLogRedirect = true;

    bool hasServer = false;
    std::string server;
    // 2 hours, seconds.
    int serverRecheck = 2 * 60 * 60;
    // ms
    int serversSortTimeout = 200;
    // -1 means disabled.
    int connectingTimeout = -1;

    VideoOptions video;
    AudioOptions audio;
    SignalOptions signal;
    DataChannelOptions dataChannel;
    bool anchorCerts = true;

private:
    Config() = default;
};

} // namespace bff