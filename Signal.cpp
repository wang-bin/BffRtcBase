#include "Signal.hpp"

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <unordered_map>

#include "NodeSelector.h"
#include "PbCJson.h"
#include "HttpClient.h"
#include "SniUrl.h"
#include "WebSocket.h"
#include "json.hpp"
#include "Log.hpp"
#define TAG "Signal"

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

} // anonymous namespace

namespace bff {

class Signal::Private {
public:
    explicit Private(Signal* owner_ptr) : owner(owner_ptr) {
        websocket.setOnOpen([this]() {
            state_string = "open";
        });
        websocket.setOnClose([this](WebSocket::CloseCode code, std::string, bool remote) {
            state_string = "closed";
            if (!owner) {
                return;
            }
            // Match JsppWebSocket didCloseWithCode: 602/603 → Token (all channels), no reconnect.
            const int closeCode = static_cast<int>(code);
            if (closeCode == 602 || closeCode == 603) {
                owner->onError(RtcError::Token);
                return;
            }
            if (remote) {
                owner->onReconnect();
            }
        });
        websocket.setOnError([this](WebSocket::Error err) {
            if (!owner) {
                return;
            }
            // Match JsppWebSocket didFailWithError (+ SRWebSocketCurl curl→NSError mapping):
            // timeout / bad URL → SignalFailed (fan-out); SSL → SSL (fan-out);
            // connect/resolve (EHOSTDOWN) and other errors → no onError (ObjC reconnects).
            if (IsCurlSecError(err.curlCode)) {
                owner->onError(RtcError::SSL);
                return;
            }
#if defined(LIBCURL_VERSION_MAJOR)
            if (err.curlCode == CURLE_OPERATION_TIMEDOUT) {
                owner->onError(RtcError::SignalFailed);
                return;
            }
            if (err.curlCode == CURLE_COULDNT_CONNECT || err.curlCode == CURLE_COULDNT_RESOLVE_HOST) {
                return;
            }
#endif
            if (err.curlCode == static_cast<int>(WebSocket::CloseCode::NeverConnected)) {
                owner->onError(RtcError::SignalFailed);
                return;
            }
            // Generic transport failure: ObjC reconnects without onError.
        });
        websocket.setOnRecv([this](std::string data, bool binary) {
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
        });
    }

    Signal* owner = nullptr;
    mutable std::mutex listeners_mtx;
    std::unordered_map<int, SignalListener*> listeners;
    std::unordered_map<int, uint32_t> rtts;

    std::atomic<uint32_t> msg_id{1};
    std::unordered_map<uint32_t, bool> important_reqs;

    Signal::SendRequestFn send_request_fn;
    bff::WebSocket websocket;
    std::string client_ip;
    std::string token;
    std::string last_offer;
    std::vector<std::string> vcodecs;
    std::string state_string;
    std::string host;
    uint32_t port = 0;
    int reconnect_count = 0;
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
    std::atomic_bool join_all_requested{false};
    std::mutex node_rtts_mtx;
    NodeSelector::Rtts node_rtts;
    std::set<int> node_rtts_sent_channels;
    std::set<int> legacy_node_rtts_channels;
    NodeSelector node_selector;
};

Signal::Signal() : d_(std::make_shared<Private>(this)) {
    auto d = d_;
    d->node_selector.setUpdateRttsCallback([d](const NodeSelector::Rtts& result) {
        if (!d->owner) return;
        d->owner->sendNodeRttsToFirstChannel(result);
    });
}

Signal::~Signal() {
    d_->owner = nullptr;
}

void Signal::setSendRequestFn(SendRequestFn sendFn) {
    d_->send_request_fn = std::move(sendFn);
}

bool Signal::connect(const std::string& url) {
    d_->server_url_ = url;
    d_->state_string = "connecting";
    // Match JsppWebSocket connect: rewrite token= query with refreshed token.
    if (!d_->token.empty()) {
        HttpClient::setAuthToken(d_->token);
    }

    WebSocket::OpenOptions options;
    options.url = HttpClient::urlWithAuthToken(url);
    options.sni_host = sniHostForUrl(url, d_->hosts_);
    return d_->websocket.open(options);
}

void Signal::disconnect() {
    d_->state_string = "closing";
    d_->websocket.close();
}

bool Signal::isConnected() const {
    return d_->websocket.isRunning();
}

void Signal::setListener(int channel, SignalListener* listener) {
    std::lock_guard<std::mutex> lock(d_->listeners_mtx);
    if (listener) {
        d_->listeners[channel] = listener;
    } else {
        d_->listeners.erase(channel);
    }
}

void Signal::removeListener(SignalListener* listener) {
    if (!listener) return;
    std::lock_guard<std::mutex> lock(d_->listeners_mtx);
    for (auto it = d_->listeners.begin(); it != d_->listeners.end(); ++it) {
        if (it->second == listener) {
            d_->listeners.erase(it);
            return;
        }
    }
}

uint32_t Signal::rttForChannel(int channel) const {
    auto it = d_->rtts.find(channel);
    return it == d_->rtts.end() ? 0 : it->second;
}

void Signal::setStateString(std::string state) {
    d_->state_string = std::move(state);
}

const std::string& Signal::stateString() const {
    return d_->state_string;
}

void Signal::setHostPort(std::string host, uint32_t port) {
    d_->host = std::move(host);
    d_->port = port;
}

const std::string& Signal::host() const {
    return d_->host;
}

uint32_t Signal::port() const {
    return d_->port;
}

void Signal::setVcodecs(std::vector<std::string> vcodecs) {
    d_->vcodecs = std::move(vcodecs);
}

const std::vector<std::string>& Signal::vcodecs() const {
    return d_->vcodecs;
}

void Signal::setOrientation(bool orientation) {
    d_->orientation = orientation;
}

bool Signal::orientation() const {
    return d_->orientation;
}

void Signal::setLocation(float latitude, float longitude) {
    d_->location = {latitude, longitude};
}

void Signal::clearLocation() {
    d_->location.reset();
}

void Signal::setUseJson(bool useJson) {
    d_->use_json = useJson;
}

bool Signal::useJson() const {
    return d_->use_json;
}

void Signal::updateNodes(const std::vector<std::string>& servers,
                         const std::string* token,
                         NodeSelector::CompletionCallback completionHandler) {
    d_->node_selector.updateNodes(servers, token, std::move(completionHandler));
}

void Signal::updateNodes(const std::string& server,
                         NodeSelector::CompletionCallback completionHandler) {
    d_->node_selector.updateNodes(server, std::move(completionHandler));
}

void Signal::connectBestUrl(const std::string& serverUrl,
                            NodeSelector::BestUrlCallback completionHandler) {
    auto d = d_;
    d->node_selector.getBestUrl(serverUrl,
        [d, completionHandler = std::move(completionHandler)](const std::string& bestUrl, const NodeSelector::Hosts* hosts) mutable {
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
            d->join_all_requested.store(false);
            d->reconnect_count = 0;
            d->last_code = 0;

            d->state_string = "connecting";
            WebSocket::OpenOptions options;
            options.url = bestUrl;
            options.sni_host = sniHostForUrl(bestUrl, d->hosts_);
            d->websocket.open(options);

            if (completionHandler) {
                completionHandler(bestUrl, hosts);
            }
        });
}

void Signal::sendNodeRttsToFirstChannel(const NodeSelector::Rtts& result) {
    std::vector<int> legacyChannels;
    {
        std::lock_guard<std::mutex> lock(d_->node_rtts_mtx);
        if (nodeRttsByIp(d_->node_rtts) == nodeRttsByIp(result)) {
            LOGD("nodeRtts not changed");
            return;
        }
        d_->node_rtts = result;
        d_->node_rtts_sent_channels.clear();
        legacyChannels.assign(d_->legacy_node_rtts_channels.begin(), d_->legacy_node_rtts_channels.end());
    }

    // rtts are connection-level; sending on a single channel is enough for the server.
    int channel = -1;
    {
        std::lock_guard<std::mutex> lock(d_->listeners_mtx);
        if (!d_->listeners.empty()) {
            channel = d_->listeners.begin()->first;
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
    d_->node_selector.applyNodeRtts(rtts, isSelf);
}

void Signal::sendNodeRttsForLegacyPeer() {
    std::vector<int> channels;
    {
        std::lock_guard<std::mutex> lock(d_->listeners_mtx);
        channels.reserve(d_->listeners.size());
        for (const auto& kv : d_->listeners) {
            channels.push_back(kv.first);
        }
    }
    {
        std::lock_guard<std::mutex> lock(d_->node_rtts_mtx);
        for (int channel : channels) {
            d_->legacy_node_rtts_channels.insert(channel);
        }
    }
    for (int channel : channels) {
        sendCachedNodeRttsIfNeededForChannel(channel);
    }
}

bool Signal::nodeSelected() const {
    return !d_->node_selector.bestNodeNegotiated().empty();
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
    if (!d_->join_all_requested.compare_exchange_strong(expected, true)) {
        return false;
    }
    std::vector<int> channels;
    {
        std::lock_guard<std::mutex> lock(d_->listeners_mtx);
        channels.reserve(d_->listeners.size());
        for (const auto& kv : d_->listeners) {
            channels.push_back(kv.first);
        }
    }
    for (int ch : channels) {
        sendJoin(ch);
    }
    return true;
}

void Signal::sendJoin(int channel) {
    d_->join_requested = true;

    // The media node is owned/selected by NodeSelector and shared by all channels.
    const std::string& node = d_->node_selector.bestNodeNegotiated();
    Rtc__Options join = RTC__OPTIONS__INIT;
    join.ip = const_cast<char*>(node.c_str());
    join.video_orientation = d_->orientation;

    Rtc__Location loc = RTC__LOCATION__INIT;
    if (d_->location) {
        loc.latitude = d_->location->latitude;
        loc.longitude = d_->location->longitude;
        join.location = &loc;
    }

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_JOIN;
    req.join = &join;
    sendRequest(req, true);
}

void Signal::sendCachedNodeRttsIfNeededForChannel(int channel) {
    NodeSelector::Rtts rtts;
    {
        std::lock_guard<std::mutex> lock(d_->node_rtts_mtx);
        if (d_->node_rtts.empty() || d_->node_rtts_sent_channels.find(channel) != d_->node_rtts_sent_channels.end()) {
            return;
        }
        rtts = d_->node_rtts;
        d_->node_rtts_sent_channels.insert(channel);
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
    Rtc__Options recreate = RTC__OPTIONS__INIT;
    recreate.recreating = 1;

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_RECREATE;
    req.recreate = &recreate;
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
    sendRequest(req, true);
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
    sendRequest(req);
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
    sendRequest(req);
}

void Signal::selectChannel(int select, int channel) {
    Rtc__SelectChannel selectChannel = RTC__SELECT_CHANNEL__INIT;
    selectChannel.channel = select == 1 ? RTC__CHANNEL__CHANNEL_MESH : RTC__CHANNEL__CHANNEL_SFU;

    Rtc__SignalRequest req = RTC__SIGNAL_REQUEST__INIT;
    req.channel = static_cast<uint32_t>(channel);
    req.message_case = RTC__SIGNAL_REQUEST__MESSAGE_SELECT_CHANNEL;
    req.select_channel = &selectChannel;
    sendRequest(req);
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

    bool resetReconn = true;
    SignalListener* listener = listenerForChannel(static_cast<int>(signalResponse->channel));

    switch (signalResponse->message_case) {
        case RTC__SIGNAL_RESPONSE__MESSAGE_JOINED: {
            if (!d_->join_requested) {
                d_->auto_media_join = false;
            }
            if (listener && signalResponse->joined) {
                listener->onJoined(signalResponse->joined, d_->auto_media_join);
            }
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
            d_->client_ip = signalResponse->addr ? signalResponse->addr : "";
            enumerateListeners([&](int, SignalListener* l) {
                l->onChangedAddress(d_->client_ip);
            });
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_OFFER: {
            const std::string sdp = (signalResponse->offer && signalResponse->offer->sdp)
                ? signalResponse->offer->sdp : "";
            if (sdp != d_->last_offer && listener) {
                listener->onOffer(sdp);
            }
            d_->last_offer = sdp;
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
                    d_->client_ip = clientIpOwned;
                } else if (!d_->client_ip.empty()) {
                    clientIpOwned = d_->client_ip;
                }
                const std::string* clientIp = clientIpOwned.empty() ? nullptr : &clientIpOwned;
                // NodeSelector stores the selected node internally for all channels.
                d_->node_selector.onNodeList(nodes,
                                             static_cast<uint16_t>(signalResponse->node_list->stun_port),
                                             clientIp);
            }
            break;
        }
        case RTC__SIGNAL_RESPONSE__MESSAGE_PONG:
            if (signalResponse->pong) {
                d_->rtts[static_cast<int>(signalResponse->channel)] = timestampMs32() - signalResponse->pong->timestamp;
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
                d_->last_code = static_cast<int>(signalResponse->response->code);
                if (d_->last_code != 200) {
                    // Match ObjC: notify only this channel's listener (not fan-out).
                    // Socket close on these errors is deferred (parity backlog).
                    if (d_->last_code == 602 || d_->last_code == 603) {
                        if (listener) {
                            listener->onError(RtcError::Token);
                        }
                        return;
                    }
                    if (d_->important_reqs.erase(signalResponse->id) > 0) {
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
            d_->token = signalResponse->token ? signalResponse->token : "";
            HttpClient::setAuthToken(d_->token);
            break;
        default:
            break;
    }

    d_->important_reqs.erase(signalResponse->id);
    if (resetReconn) {
        d_->reconnect_count = 0;
    }
}

void Signal::onReconnect() {
    d_->reconnect_count++;
    enumerateListeners([&](int, SignalListener* listener) {
        listener->onReconnect();
    });
}

void Signal::onError(RtcError error) {
    // Connection-level errors: fan-out to all channels.
    enumerateListeners([&](int, SignalListener* listener) {
        listener->onError(error);
    });
}

SignalListener* Signal::listenerForChannel(int channel) const {
    std::lock_guard<std::mutex> lock(d_->listeners_mtx);
    auto it = d_->listeners.find(channel);
    return it == d_->listeners.end() ? nullptr : it->second;
}

void Signal::enumerateListeners(const std::function<void(int channel, SignalListener*)>& fn) const {
    std::vector<std::pair<int, SignalListener*>> snapshot;
    {
        std::lock_guard<std::mutex> lock(d_->listeners_mtx);
        snapshot.reserve(d_->listeners.size());
        for (const auto& kv : d_->listeners) {
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
    req.id = d_->msg_id.fetch_add(1);
    if (important) {
        d_->important_reqs[req.id] = true;
    }

    if (d_->websocket.isRunning()) {
        if (d_->use_json) {
            std::string payload;
            if (!messageToJsonString(&req.base, &payload)) {
                LOGW("signal request toJson failed id=%u channel=%u", req.id, req.channel);
                return false;
            }
            return d_->websocket.send(payload, /*binary=*/false);
        }

        const size_t packedSize = rtc__signal_request__get_packed_size(&req);
        if (packedSize == 0) {
            return false;
        }
        std::string payload(packedSize, '\0');
        const size_t wrote = rtc__signal_request__pack(
            &req,
            reinterpret_cast<uint8_t*>(&payload[0]));
        if (wrote != packedSize) {
            return false;
        }
        return d_->websocket.send(payload, /*binary=*/true);
    }

    if (!d_->send_request_fn) {
        return false;
    }
    return d_->send_request_fn(req);
}

uint32_t Signal::timestampMs32() {
    using namespace std::chrono;
    const auto nowMs = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    return static_cast<uint32_t>(nowMs);
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
