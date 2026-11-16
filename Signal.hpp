#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "NodeSelector.h"
#include "defs.h"
#include "rtc.pb-c.h"
#include "SignalListener.h"

namespace bff {

// C++ signaling core mirroring JsppWebSocket channel/delegate behavior.
class Signal {
public:
    using SendRequestFn = std::function<bool(const Rtc__SignalRequest&)>;

    Signal();
    ~Signal();

    Signal(const Signal&) = delete;
    Signal& operator=(const Signal&) = delete;

    void setSendRequestFn(SendRequestFn sendFn);
    bool connect(const std::string& url);
    void disconnect();
    // Invokes completion after the leave response or timeout closes all transports.
    void disconnect(std::function<void()> completionHandler);
    bool isConnected() const;

    void setListener(int channel, SignalListener* listener);
    void removeListener(SignalListener* listener);

    uint32_t rttForChannel(int channel) const;
    void setStateString(std::string state);
    const std::string& stateString() const;
    void setHostPort(std::string host, uint32_t port);
    const std::string& host() const;
    uint32_t port() const;

    void setVcodecs(std::vector<std::string> vcodecs);
    const std::vector<std::string>& vcodecs() const;
    void setOrientation(bool orientation);
    bool orientation() const;

    // Optional client location attached to join Options.location.
    void setLocation(float latitude, float longitude);
    void clearLocation();

    // When true, SignalRequest/Response are sent/received as JSON text frames
    // (URL &json=true / JsppRTCConfig.signal.json). Default false = protobuf binary.
    void setUseJson(bool useJson);
    bool useJson() const;

    // Node selection helpers.
    void updateNodes(const std::vector<std::string>& servers,
                     const std::string* token,
                     NodeSelector::CompletionCallback completionHandler);
    void updateNodes(const std::string& server,
                     NodeSelector::CompletionCallback completionHandler);
    void connectBestUrl(const std::string& serverUrl,
                        NodeSelector::BestUrlCallback completionHandler);

    // Connection-level node selection (shared by all channels), backed by NodeSelector.
    void applyNodeRtts(const std::vector<std::pair<std::string, int>>& rtts, bool isSelf);
    bool nodeSelected() const;

    // Sender-side APIs (channel-scoped). channel < 0 joins all channels.
    void join(int channel);
    bool joinAllChannelsIfNeeded();
    void srtpKey(const std::string& key, Rtc__SrtpProfile profile, int channel);
    void recreate(int channel);
    void offer(const std::string& sdp, int channel);
    void answer(const std::string& sdp, int channel);
    void negotiation(bool negotiation, int channel);
    void subscribe(bool audio, bool video, int channel);
    void candidate(const std::string& candidate, int channel);
    void nodeRtts(const std::vector<std::pair<std::string, int>>& rtts, int channel);
    void mute(bool on, uint32_t rtpTime, bool video, int channel);
    void selectChannel(int select, int channel);
    // TODO: use protobuf binary
    void report(const Rtc__StatsLog* stats, int64_t startTimeSinceEpoch, int channel);
    // 上报通话事件；channel 默认 0。返回是否已交给传输发送。
    bool reportEvent(const Rtc__EventLog* event, int channel = 0);
    // 经信令上传文件（如日志）；content 可为已压缩字节，channel 默认 0（对齐 JS）
    void upload(const std::string& filename, std::span<const uint8_t> content, int channel = 0);

    // Receiver-side APIs.
    void handleReceiveSignalResponse(const Rtc__SignalResponse* signalResponse);
    void onReconnect();
    void onError(RtcError error);

private:
    friend class SignalChannelImpl;
    uint64_t muteStateGeneration() const;

    SignalListener* listenerForChannel(int channel) const;
    void enumerateListeners(const std::function<void(int channel, SignalListener*)>& fn) const;
    bool sendRequest(Rtc__SignalRequest& req, bool important = false);
    // 发送失败则入队重发；返回已分配的 msg id（便于登记 RESP 事件）
    uint32_t requestOrAgain(Rtc__SignalRequest& req);
    void trackRespEvent(uint32_t reqId, Rtc__EventType type);
    void emitRespEventIfAny(uint32_t reqId);
    void sendJoin(int channel);
    uint32_t sendLeave();
    void flushPendingReqs();
    void sendPing();
    void sendNodeRttsToChannels(const NodeSelector::Rtts& rtts);

    static uint32_t timestampMs32();
    static bool parseIceCandidateJson(const std::string& json, IceCandidate* out);

private:
    class Private;
    std::shared_ptr<Private> d;
};

using SignalPtr = std::shared_ptr<Signal>;
} // namespace bff
