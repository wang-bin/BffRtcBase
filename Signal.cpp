#include "Signal.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>

#include "NodeSelector.h"
#include "PbCJson.h"
#include "HttpClient.h"
#include "QuicSocket.h"
#include "SniUrl.h"
#include "WebSocket.h"
#include "json.hpp"
#include "Log.hpp"
#define TAG "Signal"

using namespace std;
using namespace std::chrono;
using namespace std::chrono_literals;

#if __has_include(<curl/curl.h>)
#include <curl/curl.h>
#endif


namespace {

// Extract host part from a URL or "host:port" string.
static std::string hostFromUrl(const std::string& url) {
    auto s = url;
    auto scheme = s.find("://");
    if (scheme != std::string::npos) {
        s = s.substr(scheme + 3);
    }
    auto slash = s.find('/');
    if (slash != std::string::npos) {
        s = s.substr(0, slash);
    }
    if (!s.empty() && s.front() == '[') {
        auto rb = s.find(']');
        if (rb != std::string::npos) {
            return s.substr(1, rb - 1);
        }
        return s;
    }
    auto colon = s.find(':');
    if (colon != std::string::npos) {
        return s.substr(0, colon);
    }
    return s;
}

// Extract port from a URL, defaulting to 443 if absent.
static uint32_t portFromUrl(const std::string& url) {
    auto s = url;
    auto scheme = s.find("://");
    if (scheme != std::string::npos) {
        s = s.substr(scheme + 3);
    }
    auto slash = s.find('/');
    if (slash != std::string::npos) {
        s = s.substr(0, slash);
    }
    if (!s.empty() && s.front() == '[') {
        auto rb = s.find(']');
        if (rb == std::string::npos) return 443;
        auto colon = s.find(':', rb);
        if (colon == std::string::npos) return 443;
        return static_cast<uint32_t>(std::stoul(s.substr(colon + 1)));
    }
    auto colon = s.rfind(':');
    if (colon == std::string::npos) return 443;
    // Make sure it's not an IPv6 separator (no '[' implies IPv4 or hostname).
    if (s.find(':') == colon) {
        return static_cast<uint32_t>(std::stoul(s.substr(colon + 1)));
    }
    return 443;
}

static std::string sniHostForUrl(const std::string& url,
                                 const bff::NodeSelector::Hosts& hosts) {
    if (!bff::Config::Shared().sni) {
        return {};
    }
    const auto host = hostFromUrl(url);
    if (host.empty()) {
        return {};
    }

    if (const auto it = hosts.find(host); it != hosts.end()) {
        return it->second;
    }

    const auto hostWithPort = host + ":" + std::to_string(portFromUrl(url));
    if (const auto it = hosts.find(hostWithPort); it != hosts.end()) {
        return it->second;
    }

    return {};
}

static std::map<std::string, int> nodeRttsByIp(const bff::NodeSelector::Rtts& rtts) {
    std::map<std::string, int> byIp;
    for (const auto& kv : rtts) {
        byIp[kv.first] = kv.second;
    }
    return byIp;
}

static int64_t steadyNowMs() {
    return steady_clock::now().time_since_epoch() / 1ms;
}

static bool packSignalRequest(const Rtc__SignalRequest& req, string* out) {
    const size_t n = rtc__signal_request__get_packed_size(&req);
    if (n == 0) {
        return false;
    }
    out->assign(n, '\0');
    return rtc__signal_request__pack(&req, reinterpret_cast<uint8_t*>(out->data())) == n;
}

static Rtc__IcePolicy toPbIcePolicy(bff::RtcIcePolicy p) {
    switch (p) {
        case bff::RtcIcePolicy::None: return RTC__ICE_POLICY__ICE_POLICY_NONE;
        case bff::RtcIcePolicy::All: return RTC__ICE_POLICY__ICE_POLICY_ALL;
        case bff::RtcIcePolicy::NoHost: return RTC__ICE_POLICY__ICE_POLICY_NO_HOST;
        case bff::RtcIcePolicy::Relay: return RTC__ICE_POLICY__ICE_POLICY_RELAY;
        case bff::RtcIcePolicy::UDP: return RTC__ICE_POLICY__ICE_POLICY_RELAY_UDP;
        case bff::RtcIcePolicy::TCP: return RTC__ICE_POLICY__ICE_POLICY_RELAY_TCP;
        case bff::RtcIcePolicy::TLS: return RTC__ICE_POLICY__ICE_POLICY_RELAY_TLS;
    }
    return RTC__ICE_POLICY__ICE_POLICY_ALL;
}

} // anonymous namespace

namespace bff {

class Signal::Private : public std::enable_shared_from_this<Private> {
public:
    enum class Leg { Curl, Quic };

    explicit Private(Signal* owner_ptr) : owner(owner_ptr) {
        websocket.setOnOpen([this] { onTransportOpen(Leg::Curl); });
        websocket.setOnClose([this](WebSocket::CloseCode code, std::string, bool remote) {
            onTransportClose(Leg::Curl, static_cast<int>(code), remote);
        });
        websocket.setOnError([this](WebSocket::Error err) { onCurlError(err); });
        websocket.setOnRecv([this](std::string data, bool binary) {
            onTransportRecv(Leg::Curl, std::move(data), binary);
        });

        quic.setOnOpen([this] { onTransportOpen(Leg::Quic); });
        quic.setOnClose([this](int code, std::string, bool remote) {
            onTransportClose(Leg::Quic, code, remote);
        });
        quic.setOnError([this](QuicSocket::Error err) { onQuicError(err); });
        quic.setOnRecv([this](std::string data, bool binary) {
            onTransportRecv(Leg::Quic, std::move(data), binary);
        });
    }

    static bool mixedMode() {
        return Config::Shared().signal.implementation == SignalImplementation::Mixed;
    }

    static bool isTokenCode(int code) { return code == 602 || code == 603; }

    bool isAlt(Leg leg) const {
        return has_alt && leg == Leg::Curl && primary_leg == Leg::Quic;
    }

    bool isCandidate(Leg leg) const {
        return leg == primary_leg || isAlt(leg);
    }

    void cancelMixedDelayOnly() {
        mixed_delay_gen.fetch_add(1, memory_order::relaxed);
        mixed_delay_pending = false;
    }

    // join=true only from the app thread (close() joins the worker / QUIC loop).
    void cancelMixedRace(bool join) {
        bool close_alt = false;
        {
            std::lock_guard lock(race_mtx);
            cancelMixedDelayOnly();
            if (has_alt) {
                has_alt = false;
                close_alt = true;
            }
        }
        if (!close_alt) {
            return;
        }
        if (join) {
            websocket.close();
        } else {
            websocket.closeAsync();
        }
    }

    bool isMixedRacing() const { return has_alt || mixed_delay_pending; }

    void notifyOnQuic(bool quic) {
        if (!owner) {
            return;
        }
        owner->enumerateListeners([quic](int, SignalListener* listener) {
            listener->onQuic(quic);
        });
    }

    void closeLoserAsync(Leg loser) {
        if (loser == Leg::Curl) {
            websocket.closeAsync();
        } else {
            quic.closeAsync();
        }
    }

    void mixedDeclareWinner(Leg winner) {
        Leg loser;
        const char* name = nullptr;
        {
            std::lock_guard lock(race_mtx);
            cancelMixedDelayOnly();
            if (winner == primary_leg) {
                if (!has_alt) {
                    return;
                }
                loser = Leg::Curl;
                has_alt = false;
                name = (winner == Leg::Quic) ? "Quic" : "TCP";
            } else if (isAlt(winner)) {
                loser = primary_leg;
                primary_leg = winner;
                has_alt = false;
                name = "TCP";
            } else {
                return;
            }
        }
        LOGI("mixed: %s won", name);
        closeLoserAsync(loser);
    }

    void scheduleMixedTcpFallback() {
        const int delayMs = Config::Shared().signal.mixedDelay;
        if (delayMs <= 0) {
            startMixedTcpFallback();
            return;
        }
        uint64_t gen = 0;
        {
            std::lock_guard lock(race_mtx);
            cancelMixedDelayOnly();
            mixed_delay_pending = true;
            gen = mixed_delay_gen.load(memory_order::relaxed);
        }
        std::weak_ptr<Private> weak = shared_from_this();
        std::thread([weak, gen, delayMs] {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            auto self = weak.lock();
            if (!self) {
                return;
            }
            {
                std::lock_guard lock(self->race_mtx);
                if (self->mixed_delay_gen.load(memory_order::relaxed) != gen) {
                    return;
                }
                self->mixed_delay_pending = false;
            }
            self->startMixedTcpFallback();
        }).detach();
    }

    void startMixedTcpFallback() {
        std::string url;
        std::string sni;
        int timeout = 0;
        {
            std::lock_guard lock(race_mtx);
            if (user_closed.load() || session_open || has_alt) {
                return;
            }
            cancelMixedDelayOnly();
            if (quic.readyState() == QuicSocket::State::Open) {
                return;
            }
            if (pending_url.empty()) {
                return;
            }
            url = pending_url;
            sni = pending_sni;
            timeout = Config::Shared().signal.connectTimeout;
        }
        LOGI("mixed: starting TCP fallback");
        websocket.setConnectTimeout(timeout);
        WebSocket::OpenOptions options{
            .url = url,
            .sni_host = sni,
        };
        if (!websocket.open(options)) {
            return;
        }
        std::lock_guard lock(race_mtx);
        if (user_closed.load() || session_open) {
            websocket.closeAsync();
            return;
        }
        has_alt = true;
    }

    // Returns true if the caller must not reconnect / fan out onError.
    bool handleMixedTransportFailure(Leg leg, bool allowQuicFallback) {
        bool start_tcp = false;
        {
            std::lock_guard lock(race_mtx);
            if (!session_open && mixedMode() && allowQuicFallback && leg == Leg::Quic) {
                cancelMixedDelayOnly();
                if (has_alt) {
                    if (leg == primary_leg) {
                        primary_leg = Leg::Curl;
                    }
                    has_alt = false;
                    return true;
                }
                start_tcp = true;
            } else if (!session_open && mixedMode() && isAlt(leg)) {
                has_alt = false;
                const auto st = quic.readyState();
                if (st == QuicSocket::State::Connecting || st == QuicSocket::State::Open) {
                    return true;
                }
            }
        }
        if (!start_tcp) {
            return false;
        }
        startMixedTcpFallback();
        std::lock_guard lock(race_mtx);
        if (has_alt) {
            primary_leg = Leg::Curl;
            has_alt = false;
            return true;
        }
        return false;
    }

    void onTransportOpen(Leg leg) {
        bool discard_alt = false;
        bool racing = false;
        {
            std::lock_guard lock(race_mtx);
            if (!isCandidate(leg)) {
                LOGW("ignore non-candidate open");
                return;
            }
            if (session_open && isAlt(leg)) {
                has_alt = false;
                discard_alt = true;
            } else {
                racing = isMixedRacing() || isAlt(leg);
                session_open = true;
                if (!racing) {
                    cancelMixedDelayOnly();
                }
            }
        }
        if (discard_alt) {
            websocket.closeAsync();
            return;
        }
        if (racing) {
            mixedDeclareWinner(leg);
        }
        bool quic = false;
        {
            std::lock_guard lock(race_mtx);
            quic = primary_leg == Leg::Quic;
        }
        notifyOnQuic(quic);
        last_code = 0;
        state_string = "open";
        startKeepalive();
    }

    void onTransportClose(Leg leg, int code, bool remote) {
        {
            std::lock_guard lock(race_mtx);
            if (!isCandidate(leg)) {
                return;
            }
        }
        if (isTokenCode(code)) {
            failFatal(RtcError::Token);
            return;
        }
        if (handleMixedTransportFailure(leg, /*allowQuicFallback=*/remote && !user_closed.load())) {
            return;
        }
        {
            std::lock_guard lock(race_mtx);
            session_open = false;
        }
        state_string = "closed";
        // Match ObjC: any non-user close reconnects (not only remote/wasClean).
        scheduleReconnect(Config::Shared().signal.reconnectInterval);
    }

    void onCurlError(const WebSocket::Error& err) {
        {
            std::lock_guard lock(race_mtx);
            if (!isCandidate(Leg::Curl) || !owner) {
                return;
            }
        }
        if (isTokenCode(err.httpCode)) {
            failFatal(RtcError::Token);
            return;
        }
        if (IsCurlSecError(err.curlCode)) {
            failFatal(RtcError::SSL);
            return;
        }
        if (handleMixedTransportFailure(Leg::Curl, true)) {
            return;
        }
#if defined(LIBCURL_VERSION_MAJOR)
        if (err.curlCode == CURLE_OPERATION_TIMEDOUT) {
            failFatal(RtcError::SignalFailed);
            return;
        }
#endif
        if (err.curlCode == to_underlying(WebSocket::CloseCode::NeverConnected)) {
            failFatal(RtcError::SignalFailed);
            return;
        }
        {
            std::lock_guard lock(race_mtx);
            session_open = false;
        }
        // Connect/resolve (EHOSTDOWN) and other transport errors: reconnect, no onError.
        scheduleReconnect(Config::Shared().signal.reconnectInterval);
    }

    void onQuicError(const QuicSocket::Error& err) {
        {
            std::lock_guard lock(race_mtx);
            if (!isCandidate(Leg::Quic) || !owner) {
                return;
            }
        }
        if (err.kind == QuicSocket::ErrorKind::Http && isTokenCode(err.httpCode)) {
            failFatal(RtcError::Token);
            return;
        }
        if (err.kind == QuicSocket::ErrorKind::Ssl) {
            failFatal(RtcError::SSL);
            return;
        }
        if (handleMixedTransportFailure(Leg::Quic, true)) {
            return;
        }
        if (err.kind == QuicSocket::ErrorKind::Timeout ||
            err.kind == QuicSocket::ErrorKind::InvalidUrl) {
            failFatal(RtcError::SignalFailed);
            return;
        }
        {
            std::lock_guard lock(race_mtx);
            session_open = false;
        }
        scheduleReconnect(Config::Shared().signal.reconnectInterval);
    }

    void onTransportRecv(Leg leg, std::string data, bool binary) {
        {
            std::lock_guard lock(race_mtx);
            if (leg != primary_leg || !session_open) {
                return;
            }
        }
        Rtc__SignalResponse* response = nullptr;
        if (binary) {
            response = rtc__signal_response__unpack(
                nullptr,
                data.size(),
                reinterpret_cast<const uint8_t*>(data.data()));
        } else {
            auto* msg = messageFromJsonString(&rtc__signal_response__descriptor, data);
            response = reinterpret_cast<Rtc__SignalResponse*>(msg);
        }
        if (!response) {
            LOGW("signal response unpack failed (binary=%d len=%zu)",
                 binary ? 1 : 0, data.size());
            return;
        }
        if (owner) {
            owner->handleReceiveSignalResponse(response);
        }
        rtc__signal_response__free_unpacked(response, nullptr);
    }

    void closeAllTransports(bool join) {
        cancelMixedRace(join);
        if (join) {
            websocket.close();
            quic.close();
        } else {
            websocket.closeAsync();
            quic.closeAsync();
        }
        std::lock_guard lock(race_mtx);
        session_open = false;
        has_alt = false;
    }

    bool sendOnPrimary(const std::string& payload, bool binary) {
        std::lock_guard lock(race_mtx);
        if (primary_leg == Leg::Quic) {
            return quic.send(payload, binary);
        }
        return websocket.send(payload, binary);
    }

    bool primaryRunning() const {
        std::lock_guard lock(race_mtx);
        return primary_leg == Leg::Quic ? quic.isRunning() : websocket.isRunning();
    }

    // App thread only: join previous workers, then open per SignalOptions.implementation.
    bool beginConnect(const std::string& url) {
        reconnect_gen.fetch_add(1, memory_order::relaxed);
        stopKeepalive();
        if (!token.empty()) {
            HttpClient::setAuthToken(token);
        }
        suppress_reconnect.store(true, memory_order::relaxed);
        closeAllTransports(/*join=*/true);
        suppress_reconnect.store(false, memory_order::relaxed);
        user_closed.store(false);

        const auto& opt = Config::Shared().signal;
        const string tokenUrl = HttpClient::urlWithAuthToken(url);
        const string sni = sniHostForUrl(url, hosts_);
        websocket.setConnectTimeout(opt.connectTimeout);
        quic.setConnectTimeout(opt.connectTimeout);

        {
            std::lock_guard lock(race_mtx);
            pending_url = tokenUrl;
            pending_sni = sni;
            session_open = false;
            has_alt = false;
            if (opt.implementation == SignalImplementation::Curl) {
                primary_leg = Leg::Curl;
            } else {
                primary_leg = Leg::Quic;
            }
        }

        if (opt.implementation == SignalImplementation::Curl) {
            return websocket.open(WebSocket::OpenOptions{
                .url = tokenUrl,
                .sni_host = sni,
            });
        }

        QuicSocket::OpenOptions options{
            .url = tokenUrl,
            .sni_host = sni,
        };
        if (!quic.open(options)) {
            return false;
        }
        if (opt.implementation == SignalImplementation::Mixed) {
            scheduleMixedTcpFallback();
        }
        return true;
    }

    void stopKeepalive() {
        keepalive_gen.fetch_add(1, memory_order::relaxed);
        last_recv_ms.store(-1, memory_order::relaxed);
    }

    void resetPingTimeout() {
        last_recv_ms.store(steadyNowMs(), memory_order::relaxed);
    }

    // Fire ping immediately, then every pingInterval. pingTimeout starts after the first
    // SignalResponse (same as ObjC resetTimeout).
    void startKeepalive() {
        const int interval = Config::Shared().signal.pingInterval;
        const int timeout = Config::Shared().signal.pingTimeout;
        const uint64_t gen = keepalive_gen.fetch_add(1, memory_order::relaxed) + 1;
        last_recv_ms.store(-1, memory_order::relaxed);
        weak_ptr weak = shared_from_this();
        thread([weak, gen, interval, timeout] {
            auto stillAlive = [&]() -> shared_ptr<Private> {
                auto self = weak.lock();
                if (!self || self->keepalive_gen.load(memory_order::relaxed) != gen ||
                    self->user_closed.load() || !self->owner) {
                    return nullptr;
                }
                return self;
            };
            if (auto self = stillAlive()) {
                self->owner->sendPing();
            } else {
                return;
            }
            auto lastPing = steady_clock::now();
            while (true) {
                this_thread::sleep_for(50ms);
                auto self = stillAlive();
                if (!self) {
                    return;
                }
                const auto now = steady_clock::now();
                if (interval > 0 && now - lastPing >= interval * 1ms) {
                    self.reset();
                    if (auto live = stillAlive()) {
                        live->owner->sendPing();
                        lastPing = now;
                    } else {
                        return;
                    }
                    continue;
                }
                if (timeout > 0) {
                    const auto recvAt = self->last_recv_ms.load(memory_order::relaxed);
                    if (recvAt >= 0 && steadyNowMs() - recvAt >= timeout) {
                        LOGW("ping timeout, reconnect");
                        self->scheduleReconnect(0);
                        return;
                    }
                }
            }
        }).detach();
    }

    void failFatal(RtcError err) {
        stopKeepalive();
        cancelMixedRace(false);
        {
            std::lock_guard lock(race_mtx);
            session_open = false;
        }
        if (owner) {
            owner->onError(err);
        }
    }

    // Notify listeners, then beginConnect after delayMs on a worker thread (never join
    // transports from a curl/quic callback).
    void scheduleReconnect(int delayMs) {
        if (user_closed.load() || suppress_reconnect.load(memory_order::relaxed)) {
            return;
        }
        const int maxTimes = Config::Shared().signal.reconnectMaxTimes;
        if (reconnect_count.load(memory_order::relaxed) >= maxTimes) {
            LOGW("reconnections has reached %d times, close client", maxTimes);
            stopKeepalive();
            suppress_reconnect.store(true, memory_order::relaxed);
            closeAllTransports(/*join=*/false);
            {
                std::lock_guard lock(race_mtx);
                session_open = false;
            }
            state_string = "closed";
            if (owner) {
                owner->onError(RtcError::SignalFailed);
            }
            return;
        }
        const int n = reconnect_count.fetch_add(1, memory_order::relaxed) + 1;
        LOGI("reconnect %d/%d", n, maxTimes);
        if (owner) {
            owner->enumerateListeners([](int, SignalListener* listener) {
                listener->onReconnect();
            });
        }
        stopKeepalive();
        cancelMixedRace(false);
        {
            std::lock_guard lock(race_mtx);
            session_open = false;
        }
        if (user_closed.load()) {
            LOGI("signal closed, skip reconnect");
            return;
        }

        const uint64_t gen = reconnect_gen.fetch_add(1, memory_order::relaxed) + 1;
        const string url = server_url_;
        const int delay = delayMs < 0 ? 0 : delayMs;
        weak_ptr weak = shared_from_this();
        thread([weak, gen, delay, url] {
            if (delay > 0) {
                this_thread::sleep_for(delay * 1ms);
            }
            auto self = weak.lock();
            if (!self || self->reconnect_gen.load(memory_order::relaxed) != gen ||
                self->user_closed.load()) {
                LOGI("signal closed, skip reconnect");
                return;
            }
            if (url.empty() || !self->owner) {
                return;
            }
            self->state_string = "connecting";
            self->beginConnect(url);
        }).detach();
    }

    Signal* owner = nullptr;
    mutable std::mutex listeners_mtx;
    std::unordered_map<int, SignalListener*> listeners;
    std::unordered_map<int, uint32_t> rtts;

    std::atomic<uint32_t> msg_id{1};
    std::unordered_map<uint32_t, bool> important_reqs;
    mutex pending_mtx;
    vector<string> pending_reqs;

    Signal::SendRequestFn send_request_fn;
    bff::WebSocket websocket;
    bff::QuicSocket quic;
    mutable std::mutex race_mtx;
    Leg primary_leg = Leg::Curl;
    bool has_alt = false;
    bool session_open = false;
    std::atomic<bool> user_closed{false};
    atomic<bool> suppress_reconnect{false};
    atomic<uint64_t> mixed_delay_gen{0};
    atomic<uint64_t> keepalive_gen{0};
    atomic<uint64_t> reconnect_gen{0};
    atomic<int64_t> last_recv_ms{-1};
    bool mixed_delay_pending = false;
    std::string pending_url;
    std::string pending_sni;
    std::string client_ip;
    std::string token;
    std::string last_offer;
    std::vector<std::string> vcodecs;
    std::string state_string;
    std::string host;
    uint32_t port = 0;
    atomic<int> reconnect_count{0};
    int last_code = 0;
    NodeSelector::Hosts hosts_;
    std::string server_url_;
    bool orientation = false;
    bool use_json = false;
    struct Location {
        float latitude = 0.f;
        float longitude = 0.f;
    };
    std::optional<Location> location;
    bool auto_media_join = true;
    bool join_requested = false;
    bool recreating = false;
    bool subscribing = false;
    std::atomic<bool> join_all_requested{false};

    // Stack-backed Options for join/recreate; pointers are valid until sendRequest returns.
    struct ReqOptions {
        Rtc__Options opts = RTC__OPTIONS__INIT;
        Rtc__Location loc = RTC__LOCATION__INIT;
        std::vector<std::string> codecs;
        std::vector<char*> codec_ptrs;

        ReqOptions(Private& d, bool recreatingFlag) {
            if (d.vcodecs.empty()) {
                codecs.emplace_back("h264");
            } else {
                codecs = d.vcodecs;
            }
            codecs.emplace_back("opus");
            codec_ptrs.reserve(codecs.size());
            for (auto& c : codecs) {
                codec_ptrs.push_back(c.data());
            }
            opts.n_codecs = codec_ptrs.size();
            opts.codecs = codec_ptrs.data();
            opts.auto_subscribe = (Config::Shared().signal.autoSubscribe || d.subscribing) ? 1 : 0;
            opts.publishing_audio = 1;
            opts.publishing_video = 1;
            opts.recreating = recreatingFlag ? 1 : 0;
            opts.ip = const_cast<char*>(d.node_selector.bestNodeNegotiated().c_str());
            opts.ice_policy = toPbIcePolicy(Config::Shared().icePolicy);
            opts.video_orientation = d.orientation ? 1 : 0;
            // TODO: location
            if (d.location) {
                loc.latitude = d.location->latitude;
                loc.longitude = d.location->longitude;
                opts.location = &loc;
            }
        }
    };
    std::mutex node_rtts_mtx;
    NodeSelector::Rtts node_rtts;
    std::set<int> node_rtts_sent_channels;
    std::set<int> legacy_node_rtts_channels;
    NodeSelector node_selector;
};

Signal::Signal() : d(std::make_shared<Private>(this)) {
    d->node_selector.setUpdateRttsCallback([d = d](const NodeSelector::Rtts& result) {
        if (!d->owner) return;
        d->owner->sendNodeRttsToFirstChannel(result);
    });
}

Signal::~Signal() {
    d->user_closed.store(true);
    d->reconnect_gen.fetch_add(1, memory_order::relaxed);
    d->stopKeepalive();
    d->cancelMixedDelayOnly();
    d->owner = nullptr;
}

void Signal::setSendRequestFn(SendRequestFn sendFn) {
    d->send_request_fn = std::move(sendFn);
}

bool Signal::connect(const std::string& url) {
    d->server_url_ = url;
    d->state_string = "connecting";
    return d->beginConnect(url);
}

void Signal::disconnect() {
    d->user_closed.store(true);
    d->reconnect_gen.fetch_add(1, memory_order::relaxed);
    d->stopKeepalive();
    d->state_string = "closing";
    sendLeave();
    d->closeAllTransports(/*join=*/true);
    lock_guard lock(d->pending_mtx);
    d->pending_reqs.clear();
}

bool Signal::isConnected() const {
    return d->primaryRunning();
}

void Signal::setListener(int channel, SignalListener* listener) {
    std::lock_guard<std::mutex> lock(d->listeners_mtx);
    if (listener) {
        d->listeners[channel] = listener;
    } else {
        d->listeners.erase(channel);
    }
}

void Signal::removeListener(SignalListener* listener) {
    if (!listener) return;
    std::lock_guard<std::mutex> lock(d->listeners_mtx);
    for (auto it = d->listeners.begin(); it != d->listeners.end(); ++it) {
        if (it->second == listener) {
            d->listeners.erase(it);
            return;
        }
    }
}

uint32_t Signal::rttForChannel(int channel) const {
    auto it = d->rtts.find(channel);
    return it == d->rtts.end() ? 0 : it->second;
}

void Signal::setStateString(std::string state) {
    d->state_string = std::move(state);
}

const std::string& Signal::stateString() const {
    return d->state_string;
}

void Signal::setHostPort(std::string host, uint32_t port) {
    d->host = std::move(host);
    d->port = port;
}

const std::string& Signal::host() const {
    return d->host;
}

uint32_t Signal::port() const {
    return d->port;
}

void Signal::setVcodecs(std::vector<std::string> vcodecs) {
    d->vcodecs = std::move(vcodecs);
}

const std::vector<std::string>& Signal::vcodecs() const {
    return d->vcodecs;
}

void Signal::setOrientation(bool orientation) {
    d->orientation = orientation;
}

bool Signal::orientation() const {
    return d->orientation;
}

void Signal::setLocation(float latitude, float longitude) {
    d->location = {.latitude = latitude, .longitude = longitude};
}

void Signal::clearLocation() {
    d->location.reset();
}

void Signal::setUseJson(bool useJson) {
    d->use_json = useJson;
}

bool Signal::useJson() const {
    return d->use_json;
}

void Signal::updateNodes(const std::vector<std::string>& servers,
                         const std::string* token,
                         NodeSelector::CompletionCallback completionHandler) {
    d->node_selector.updateNodes(servers, token, std::move(completionHandler));
}

void Signal::updateNodes(const std::string& server,
                         NodeSelector::CompletionCallback completionHandler) {
    d->node_selector.updateNodes(server, std::move(completionHandler));
}

void Signal::connectBestUrl(const std::string& serverUrl,
                            NodeSelector::BestUrlCallback completionHandler) {
    d->node_selector.getBestUrl(serverUrl,
        [d = d, completionHandler = std::move(completionHandler)](const std::string& bestUrl, const NodeSelector::Hosts* hosts) mutable {
            if (!d->owner) return;
            d->hosts_.clear();
            if (hosts) {
                d->hosts_ = *hosts;
            }
            d->server_url_ = bestUrl;
            d->host = hostFromUrl(bestUrl);
            d->port = portFromUrl(bestUrl);

            // Reset connection state, mirroring JsppWebSocket connectServerUrl.
            d->important_reqs.clear();
            d->rtts.clear();
            {
                std::lock_guard<std::mutex> lock(d->node_rtts_mtx);
                d->node_rtts.clear();
                d->node_rtts_sent_channels.clear();
                d->legacy_node_rtts_channels.clear();
            }
            d->last_offer.clear();
            d->auto_media_join = true;
            d->subscribing = false;
            d->join_all_requested.store(false);
            d->reconnect_count.store(0);
            d->last_code = 0;

            d->state_string = "connecting";
            d->beginConnect(bestUrl);

            if (completionHandler) {
                completionHandler(bestUrl, hosts);
            }
        });
}

void Signal::sendNodeRttsToFirstChannel(const NodeSelector::Rtts& result) {
    std::vector<int> legacyChannels;
    {
        std::lock_guard<std::mutex> lock(d->node_rtts_mtx);
        if (nodeRttsByIp(d->node_rtts) == nodeRttsByIp(result)) {
            LOGD("nodeRtts not changed");
            return;
        }
        d->node_rtts = result;
        d->node_rtts_sent_channels.clear();
        legacyChannels.assign(d->legacy_node_rtts_channels.begin(), d->legacy_node_rtts_channels.end());
    }

    // rtts are connection-level; sending on a single channel is enough for the server.
    int channel = -1;
    {
        std::lock_guard<std::mutex> lock(d->listeners_mtx);
        if (!d->listeners.empty()) {
            channel = d->listeners.begin()->first;
        }
    }
    if (channel >= 0) {
        sendCachedNodeRttsIfNeededForChannel(channel);
    }
    for (int legacyChannel : legacyChannels) {
        sendCachedNodeRttsIfNeededForChannel(legacyChannel);
    }
}

void Signal::applyNodeRtts(const std::vector<std::pair<std::string, int>>& rtts, bool isSelf) {
    d->node_selector.applyNodeRtts(rtts, isSelf);
}

void Signal::sendNodeRttsForLegacyPeer() {
    std::vector<int> channels;
    {
        std::lock_guard<std::mutex> lock(d->listeners_mtx);
        channels.reserve(d->listeners.size());
        for (const auto& kv : d->listeners) {
            channels.push_back(kv.first);
        }
    }
    {
        std::lock_guard<std::mutex> lock(d->node_rtts_mtx);
        for (int channel : channels) {
            d->legacy_node_rtts_channels.insert(channel);
        }
    }
    for (int channel : channels) {
        sendCachedNodeRttsIfNeededForChannel(channel);
    }
}

bool Signal::nodeSelected() const {
    return !d->node_selector.bestNodeNegotiated().empty();
}

void Signal::join(int channel) {
    if (channel < 0) {
        joinAllChannelsIfNeeded();
    } else {
        sendJoin(channel);
    }
}

bool Signal::joinAllChannelsIfNeeded() {
    bool expected = false;
    if (!d->join_all_requested.compare_exchange_strong(expected, true)) {
        return false;
    }
    std::vector<int> channels;
    {
        std::lock_guard<std::mutex> lock(d->listeners_mtx);
        channels.reserve(d->listeners.size());
        for (const auto& kv : d->listeners) {
            channels.push_back(kv.first);
        }
    }
    for (int ch : channels) {
        sendJoin(ch);
    }
    return true;
}

void Signal::sendJoin(int channel) {
    d->join_requested = true;

    Private::ReqOptions join(*d, d->recreating);
    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_JOIN;
    req.join = &join.opts;
    sendRequest(req, true);
}

void Signal::sendCachedNodeRttsIfNeededForChannel(int channel) {
    NodeSelector::Rtts rtts;
    {
        std::lock_guard<std::mutex> lock(d->node_rtts_mtx);
        if (d->node_rtts.empty() || d->node_rtts_sent_channels.find(channel) != d->node_rtts_sent_channels.end()) {
            return;
        }
        rtts = d->node_rtts;
        d->node_rtts_sent_channels.insert(channel);
    }
    nodeRtts(rtts, channel);
}

void Signal::srtpKey(const std::string& key, Rtc__SrtpProfile profile, int channel) {
    Rtc__SrtpKey srtpKey = RTC__SRTP_KEY__INIT;
    srtpKey.profile = profile;
    srtpKey.key.len = key.size();
    srtpKey.key.data = reinterpret_cast<uint8_t*>(const_cast<char*>(key.data()));

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_SRTP_KEY;
    req.srtp_key = &srtpKey;
    sendRequest(req);
}

void Signal::recreate(int channel) {
    Private::ReqOptions recreate(*d, /*recreatingFlag=*/true);
    d->recreating = true;

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_RECREATE;
    req.recreate = &recreate.opts;
    sendRequest(req);
}

void Signal::offer(const std::string& sdp, int channel) {
    Rtc__SessionDescription offer = RTC__SESSION_DESCRIPTION__INIT;
    offer.type = RTC__SDP_TYPE__SDP_TYPE_OFFER;
    offer.sdp = const_cast<char*>(sdp.c_str());

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_OFFER;
    req.offer = &offer;
    // Mesh publish/subscribe may offer before the peer has joined (814 no selected node).
    sendRequest(req);
}

void Signal::answer(const std::string& sdp, int channel) {
    Rtc__SessionDescription answer = RTC__SESSION_DESCRIPTION__INIT;
    answer.type = RTC__SDP_TYPE__SDP_TYPE_ANSWER;
    answer.sdp = const_cast<char*>(sdp.c_str());

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_ANSWER;
    req.answer = &answer;
    sendRequest(req, true);
}

void Signal::negotiation(bool negotiation, int channel) {
    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_NEGOTIATION;
    req.negotiation = negotiation ? 1 : 0;
    requestOrAgain(req);
}

void Signal::subscribe(bool audio, bool video, int channel) {
    Rtc__Subscribe subscribe = RTC__SUBSCRIBE__INIT;
    Rtc__Subscribe__Media audioMedia = RTC__SUBSCRIBE__MEDIA__INIT;
    Rtc__Subscribe__Media videoMedia = RTC__SUBSCRIBE__MEDIA__INIT;
    audioMedia.subscribe = audio ? 1 : 0;
    videoMedia.subscribe = video ? 1 : 0;
    subscribe.audio = &audioMedia;
    subscribe.video = &videoMedia;

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_SUBSCRIBE;
    req.subscribe = &subscribe;
    sendRequest(req);
    // ws 可能未连接，则 join 时用 autoSubscribe 补上.
    d->subscribing = audio || video;
}

void Signal::candidate(const std::string& candidate, int channel) {
    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_CANDIDATE;
    req.candidate = const_cast<char*>(candidate.c_str());
    sendRequest(req);
}

void Signal::nodeRtts(const std::vector<std::pair<std::string, int>>& rtts, int channel) {
    Rtc__NodeRtts nodeRtts = RTC__NODE_RTTS__INIT;
    std::vector<Rtc__NodeRtt> nodeRttValues(rtts.size(), RTC__NODE_RTT__INIT);
    std::vector<Rtc__NodeRtt*> nodeRttPtrs;
    std::vector<std::string> ips;

    nodeRttPtrs.reserve(rtts.size());
    ips.reserve(rtts.size());
    for (size_t i = 0; i < rtts.size(); ++i) {
        ips.push_back(rtts[i].first);
        nodeRttValues[i].ip = const_cast<char*>(ips.back().c_str());
        nodeRttValues[i].rtt = static_cast<uint32_t>(rtts[i].second < 0 ? 0 : rtts[i].second);
        nodeRttPtrs.push_back(&nodeRttValues[i]);
    }
    nodeRtts.n_node_rtts = nodeRttPtrs.size();
    nodeRtts.node_rtts = nodeRttPtrs.empty() ? nullptr : nodeRttPtrs.data();

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_NODE_RTTS;
    req.node_rtts = &nodeRtts;
    sendRequest(req);
}

void Signal::mute(bool on, uint32_t rtpTime, bool video, int channel) {
    Rtc__Mute mute = RTC__MUTE__INIT;
    Rtc__Mute__Media media = RTC__MUTE__MEDIA__INIT;
    media.mute = on ? 1 : 0;
    media.timestamp = rtpTime;
    if (video) {
        mute.video = &media;
    } else {
        mute.audio = &media;
    }

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_MUTE;
    req.mute = &mute;
    // recreate 重连会在 publish 里发送 mute
    requestOrAgain(req);
}

void Signal::selectChannel(int select, int channel) {
    Rtc__SelectChannel selectChannel = RTC__SELECT_CHANNEL__INIT;
    selectChannel.channel = select == 1 ? RTC__CHANNEL__CHANNEL_MESH : RTC__CHANNEL__CHANNEL_SFU;

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_SELECT_CHANNEL;
    req.select_channel = &selectChannel;
    requestOrAgain(req);
}

void Signal::report(const Rtc__Stats* stats, int64_t /*startTimeSinceEpoch*/, int channel) {
    if (!stats) return;
    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_ADD_STATS;
    req.add_stats = const_cast<Rtc__Stats*>(stats);
    sendRequest(req);
}

void Signal::handleReceiveSignalResponse(const Rtc__SignalResponse* signalResponse) {
    if (!signalResponse) return;
    d->resetPingTimeout();

    bool resetReconn = true;
    SignalListener* listener = listenerForChannel(static_cast<int>(signalResponse->channel));

    switch (signalResponse->message_case) {
        case RTC__SIGNAL_RESPONSE__MESSAGE_JOINED: {
            if (!d->join_requested) {
                d->auto_media_join = false;
            }
            if (listener && signalResponse->joined) {
                listener->onJoined(signalResponse->joined, d->auto_media_join);
            }
            flushPendingReqs();
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_CONFIG:
            if (listener && signalResponse->config) {
                listener->onConfig(signalResponse->config);
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_SUBSCRIBE: {
            bool audio = false;
            bool video = false;
            if (signalResponse->subscribe) {
                if (signalResponse->subscribe->audio) {
                    audio = signalResponse->subscribe->audio->subscribe;
                }
                if (signalResponse->subscribe->video) {
                    video = signalResponse->subscribe->video->subscribe;
                }
            }
            if (listener) {
                listener->onSubscribe(audio, video);
            }
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_ADDR: {
            d->client_ip = signalResponse->addr ? signalResponse->addr : "";
            enumerateListeners([&](int, SignalListener* l) {
                l->onChangedAddress(d->client_ip);
            });
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_OFFER: {
            const std::string sdp = (signalResponse->offer && signalResponse->offer->sdp)
                ? signalResponse->offer->sdp : "";
            if (sdp == d->last_offer) {
                LOGW("offer sdp not changed, ignore");
            } else {
                if (listener) {
                    listener->onOffer(sdp);
                }
                d->last_offer = sdp;
            }
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_ANSWER:
            if (listener && signalResponse->answer && signalResponse->answer->sdp) {
                listener->onAnswer(signalResponse->answer->sdp);
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_CANDIDATE: {
            if (listener && signalResponse->candidate) {
                IceCandidate c;
                if (parseIceCandidateJson(signalResponse->candidate, &c)) {
                    listener->onCandidate(c);
                }
            }
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_NODE_LIST: {
            if (signalResponse->node_list) {
                std::vector<std::string> nodes;
                nodes.reserve(signalResponse->node_list->n_ips);
                for (size_t i = 0; i < signalResponse->node_list->n_ips; ++i) {
                    if (signalResponse->node_list->ips[i]) {
                        nodes.emplace_back(signalResponse->node_list->ips[i]);
                    }
                }
                std::string clientIpOwned;
                if (signalResponse->node_list->client_ip && signalResponse->node_list->client_ip[0]) {
                    clientIpOwned = signalResponse->node_list->client_ip;
                    d->client_ip = clientIpOwned;
                } else if (!d->client_ip.empty()) {
                    clientIpOwned = d->client_ip;
                }
                const std::string* clientIp = clientIpOwned.empty() ? nullptr : &clientIpOwned;
                // NodeSelector stores the selected node internally for all channels.
                d->node_selector.onNodeList(nodes,
                                             static_cast<uint16_t>(signalResponse->node_list->stun_port),
                                             clientIp);
            }
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_PONG:
            if (signalResponse->pong) {
                d->rtts[static_cast<int>(signalResponse->channel)] = timestampMs32() - signalResponse->pong->timestamp;
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_ADD_TRACK:
            if (listener && signalResponse->add_track) {
                listener->onAddTrack(signalResponse->add_track);
                for (size_t i = 0; i < signalResponse->add_track->n_tracks; ++i) {
                    auto* track = signalResponse->add_track->tracks[i];
                    if (track) {
                        listener->onAddStream(track);
                    }
                }
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_REMOVE_TRACK:
            if (listener && signalResponse->remove_track) {
                listener->onRemoveTracks(signalResponse->remove_track);
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_LEAVED:
            if (listener && signalResponse->leaved) {
                listener->onLeaved(signalResponse->leaved);
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_STATE:
            if (listener) {
                listener->onChangedPeerState(signalResponse->state);
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_RESPONSE:
            if (signalResponse->response) {
                d->last_code = static_cast<int>(signalResponse->response->code);
                if (d->last_code != 200) {
                    // Match ObjC: notify only this channel's listener (not fan-out).
                    if (d->last_code == 602 || d->last_code == 603) {
                        d->closeAllTransports(/*join=*/false);
                        if (listener) {
                            listener->onError(RtcError::Token);
                        }
                        return;
                    }
                    if (d->important_reqs.erase(signalResponse->id) > 0) {
                        d->closeAllTransports(/*join=*/false);
                        if (listener) {
                            listener->onError(RtcError::SignalFailed);
                        }
                        return;
                    }
                    resetReconn = false;
                }
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_NEGOTIATION:
            if (listener) {
                listener->onNegotiation(signalResponse->negotiation != 0);
            }
            break;
        case RTC__SIGNAL_RESPONSE__MESSAGE_TOKEN:
            // Match ObjC: store token and push to HTTP client for subsequent requests.
            d->token = signalResponse->token ? signalResponse->token : "";
            HttpClient::setAuthToken(d->token);
            break;
        default:
            break;
    }

    d->important_reqs.erase(signalResponse->id);
    if (resetReconn) {
        d->reconnect_count.store(0);
    }
}

void Signal::onReconnect() {
    d->scheduleReconnect(Config::Shared().signal.reconnectInterval);
}

void Signal::sendPing() {
    vector<int> channels;
    {
        lock_guard lock(d->listeners_mtx);
        channels.reserve(d->listeners.size());
        for (const auto& kv : d->listeners) {
            channels.push_back(kv.first);
        }
    }
    for (int channel : channels) {
        Rtc__Ping ping = RTC__PING__INIT;
        ping.timestamp = timestampMs32();
        ping.rtt = rttForChannel(channel);

        Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
        req.channel = static_cast<uint32_t>(channel);
        req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_PING;
        req.ping = &ping;
        sendRequest(req);
    }
}

void Signal::onError(RtcError error) {
    // Connection-level errors: fan-out to all channels.
    enumerateListeners([&](int, SignalListener* listener) {
        listener->onError(error);
    });
}

SignalListener* Signal::listenerForChannel(int channel) const {
    std::lock_guard<std::mutex> lock(d->listeners_mtx);
    auto it = d->listeners.find(channel);
    return it == d->listeners.end() ? nullptr : it->second;
}

void Signal::enumerateListeners(const std::function<void(int channel, SignalListener*)>& fn) const {
    std::vector<std::pair<int, SignalListener*>> snapshot;
    {
        std::lock_guard<std::mutex> lock(d->listeners_mtx);
        snapshot.reserve(d->listeners.size());
        for (const auto& kv : d->listeners) {
            if (kv.second) {
                snapshot.push_back(kv);
            }
        }
    }
    for (const auto& kv : snapshot) {
        fn(kv.first, kv.second);
    }
}

bool Signal::sendRequest(Rtc__SignalRequest& req, bool important) {
    if (req.id == 0) {
        req.id = d->msg_id.fetch_add(1);
    }

    bool ok = false;
    if (d->primaryRunning()) {
        if (d->use_json) {
            string payload;
            if (!messageToJsonString(&req.base, &payload)) {
                LOGW("signal request toJson failed id=%u channel=%u", req.id, req.channel);
                return false;
            }
            ok = d->sendOnPrimary(payload, /*binary=*/false);
        } else {
            string payload;
            if (!packSignalRequest(req, &payload)) {
                return false;
            }
            ok = d->sendOnPrimary(payload, /*binary=*/true);
        }
    } else if (d->send_request_fn) {
        ok = d->send_request_fn(req);
    }

    if (ok && important) {
        d->important_reqs[req.id] = true;
    }

    // Match ObjC: recreating stays set if Join/Recreate failed to send, so a later join still carries it.
    if (ok && d->recreating &&
        (req.message_case == RTC__SIGNAL_REQUEST__MESSAGE_JOIN ||
         req.message_case == RTC__SIGNAL_REQUEST__MESSAGE_RECREATE)) {
        d->recreating = false;
    }
    return ok;
}

bool Signal::requestOrAgain(Rtc__SignalRequest& req) {
    if (sendRequest(req)) {
        return true;
    }
    LOGW("Failed to send (%u:%u), try again later", req.id, req.channel);
    string packed;
    if (!packSignalRequest(req, &packed)) {
        return false;
    }
    lock_guard lock(d->pending_mtx);
    d->pending_reqs.push_back(std::move(packed));
    return false;
}

void Signal::sendLeave() {
    Rtc__Leave leave = RTC__LEAVE__INIT;
    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = 0;
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_LEAVE;
    req.leave = &leave;
    sendRequest(req);
}

void Signal::flushPendingReqs() {
    vector<string> pending;
    {
        lock_guard lock(d->pending_mtx);
        pending.swap(d->pending_reqs);
    }
    for (const auto& bytes : pending) {
        auto* req = rtc__signal_request__unpack(
            nullptr,
            bytes.size(),
            reinterpret_cast<const uint8_t*>(bytes.data()));
        if (!req) {
            continue;
        }
        LOGD("resend request <= (%u:%u)", req->id, req->channel);
        requestOrAgain(*req);
        rtc__signal_request__free_unpacked(req, nullptr);
    }
}

uint32_t Signal::timestampMs32() {
    return static_cast<uint32_t>(system_clock::now().time_since_epoch() / 1ms);
}

bool Signal::parseIceCandidateJson(const std::string& json, IceCandidate* out) {
    if (!out) return false;
    const auto j = nlohmann::json::parse(json, nullptr, false);
    if (j.is_discarded()) {
        return false;
    }
    if (!j.contains("candidate") || !j.contains("sdpMid") || !j.contains("sdpMLineIndex")) {
        return false;
    }
    if (!j["candidate"].is_string() || !j["sdpMid"].is_string() || !j["sdpMLineIndex"].is_number_integer()) {
        return false;
    }

    IceCandidate c;
    c.sdp = j["candidate"].get<std::string>();
    c.sdpMid = j["sdpMid"].get<std::string>();
    c.sdpMLineIndex = j["sdpMLineIndex"].get<int>();
    *out = std::move(c);
    return true;
}

} // namespace bff
