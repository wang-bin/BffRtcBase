#pragma once

#include <cstdint>
#include <functional>
#include <memory>
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

    // Node selection helpers.
    void updateNodes(const std::vector<std::string>& servers,
                     const std::string* token,
                     NodeSelector::CompletionCallback completionHandler);
    void updateNodes(const std::string& server,
                     NodeSelector::CompletionCallback completionHandler);
    void connectBestUrl(const std::string& serverUrl,
                        NodeSelector::BestUrlCallback completionHandler);

    // Sender-side APIs (channel-scoped).
    void join(const std::string& node, int channel);
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
    void report(const Rtc__Stats* stats, int64_t startTimeSinceEpoch, int channel);

    // Receiver-side APIs.
    void handleReceiveSignalResponse(const Rtc__SignalResponse* signalResponse);
    void onReconnect();
    void onError(RtcError error);

private:
    SignalListener* listenerForChannel(int channel) const;
    void enumerateListeners(const std::function<void(int channel, SignalListener*)>& fn) const;
    bool sendRequest(Rtc__SignalRequest& req, bool important = false);
    void sendNodeRttsToAllChannels(const NodeSelector::Rtts& rtts);

    static uint32_t timestampMs32();
    static bool parseIceCandidateJson(const std::string& json, IceCandidate* out);

private:
    class Private;
    std::shared_ptr<Private> d_;
};

using SignalPtr = std::shared_ptr<Signal>;
} // namespace bff
