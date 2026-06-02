#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "rtc.pb-c.h"

namespace bff {

class Signal;

enum class SignalChannelType : int {
    Sfu = 0,
    Mesh = 1,
};

struct SignalChannelJoinedUpdate {
    bool canJoin = false;
    bool selfJoined = false;
    bool peersIncreased = false;
    std::vector<std::string> peerIds;
};

using SignalChannelPeerHandler = std::function<void(const Rtc__PeerInfo* peer, bool isSelf, bool isNewPeer)>;

// C++ counterpart of ObjC SignalChannel.
// This class is a channel-scoped facade for signaling APIs.
class SignalChannel {
public:
    virtual ~SignalChannel() = default;
    virtual uint32_t rtt() const = 0;
    virtual const std::string& stateString() const = 0;
    virtual const std::string& host() const = 0;
    virtual uint32_t port() const = 0;

    virtual const std::unordered_set<std::string>& peers() const = 0;
    virtual const std::unordered_set<std::string>& joinedPeers() const = 0;
    virtual bool joined() const = 0;
    virtual void setJoined(bool joined) = 0;
    virtual void removePeer(const std::string& peerId) = 0;
    virtual SignalChannelJoinedUpdate applyJoinedPeers(
        const Rtc__PeerInfo* const* peers,
        size_t nPeers,
        const std::string& userId,
        bool autoMediaJoin,
        const SignalChannelPeerHandler& peerHandler = nullptr) = 0;

    /*!
      join with preferred node
    */
    virtual void join() = 0;
    virtual void srtpKey(const std::string& key, Rtc__SrtpProfile profile) = 0;
    virtual void recreate() = 0;
    virtual void offer(const std::string& sdp) = 0;
    virtual void answer(const std::string& sdp) = 0;
    virtual void negotiation(bool negotiation) = 0;
    virtual void subscribe(bool audio, bool video) = 0;
    virtual void candidate(const std::string& candidate) = 0;
    virtual void nodeRtts(const std::vector<std::pair<std::string, int>>& rtts) = 0;
    virtual void mute(bool on, uint32_t rtpTime, bool video) = 0;
    virtual void selectChannel(int select) = 0;
    virtual void report(const Rtc__Stats* stats, int64_t startTimeSinceEpoch) = 0;
};

using SignalChannelPtr = std::shared_ptr<SignalChannel>;
SignalChannelPtr createSignalChannel(std::shared_ptr<Signal> signal, int channel);
} // namespace bff
