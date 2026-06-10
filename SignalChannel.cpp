#include "SignalChannel.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <unordered_set>

#include "Signal.hpp"
#include "../stun_test.h"
#include "defs.h"

namespace bff {
namespace {

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return s;
}

std::vector<std::string> commonCodecs(
    const std::vector<std::string>& codecs,
    const Rtc__PeerInfo* peer) {
    if (!peer || peer->n_codecs == 0 || !peer->codecs) {
        return codecs;
    }

    std::unordered_set<std::string> cap;
    cap.reserve(peer->n_codecs);
    for (size_t i = 0; i < peer->n_codecs; ++i) {
        if (peer->codecs[i]) {
            cap.insert(toLower(peer->codecs[i]));
        }
    }

    std::vector<std::string> out;
    out.reserve(codecs.size());
    for (const auto& c : codecs) {
        auto lc = toLower(c);
        if (lc != "vp9" && cap.find(lc) != cap.end()) {
            out.push_back(std::move(lc));
        }
    }
    return out;
}

std::vector<std::pair<std::string, int>> toNodeRtts(const Rtc__PeerInfo* peer) {
    std::vector<std::pair<std::string, int>> rtts;
    if (!peer || peer->n_node_rtts == 0 || !peer->node_rtts) {
        return rtts;
    }
    rtts.reserve(peer->n_node_rtts);
    for (size_t i = 0; i < peer->n_node_rtts; ++i) {
        const auto* rtt = peer->node_rtts[i];
        if (!rtt || !rtt->ip) {
            continue;
        }
        rtts.emplace_back(rtt->ip, static_cast<int>(rtt->rtt));
    }
    return rtts;
}

} // namespace

class SignalChannelImpl : public SignalChannel {
public:
    SignalChannelImpl(std::shared_ptr<Signal> signal, int channel)
        : signal_(std::move(signal)), channel_(channel) {}

    uint32_t rtt() const override { return signal_->rttForChannel(channel_); }
    const std::string& stateString() const override { return signal_->stateString(); }
    const std::string& host() const override { return signal_->host(); }
    uint32_t port() const override { return signal_->port(); }

    const std::unordered_set<std::string>& peers() const override { return peers_; }
    const std::unordered_set<std::string>& joinedPeers() const override { return joined_peers_; }
    bool joined() const override { return joined_; }
    void setJoined(bool joined) override { joined_ = joined; }

    void removePeer(const std::string& peerId) override {
        peers_.erase(peerId);
        joined_peers_.erase(peerId);
    }

    SignalChannelJoinedUpdate applyJoinedPeers(
        const Rtc__PeerInfo* const* peers,
        size_t nPeers,
        const std::string& userId,
        bool autoMediaJoin,
        const SignalChannelPeerHandler& peerHandler) override {
        const size_t previousPeerCount = peers_.size();
        SignalChannelJoinedUpdate update;
        update.peerIds.reserve(nPeers);

        std::vector<std::pair<std::string, int>> nodeRtts;
        std::vector<std::pair<std::string, int>> nodeRttsSelf;

        for (size_t i = 0; i < nPeers; ++i) {
            const auto* peer = peers ? peers[i] : nullptr;
            if (!peer || !peer->id) {
                continue;
            }

            std::string peerId(peer->id);
            update.peerIds.push_back(peerId);

            const bool isNewPeer = peers_.insert(peerId).second;
            if (peer->media_node && peer->media_node[0] != '\0') {
                joined_peers_.insert(peerId);
            }

            const bool isSelf = (peerId == userId);
            if (isSelf) {
                update.selfJoined = true;
                if (peer->n_node_rtts > 0) {
                    nodeRttsSelf = toNodeRtts(peer);
                }
            } else if (!autoMediaJoin) {
                if (peer->n_codecs > 0) {
                    signal_->setVcodecs(commonCodecs(signal_->vcodecs(), peer));
                }
                if (peer->n_node_rtts > 0) {
                    nodeRtts = toNodeRtts(peer);
                }
            }

            video_orientation_.emplace(peerId, peer->video_orientation != 0);
            if (peerHandler) {
                peerHandler(peer, isSelf, isNewPeer);
            }
        }

        bool orientation = true;
        for (const auto& kv : video_orientation_) {
            if (!kv.second) {
                orientation = false;
                break;
            }
        }
        signal_->setOrientation(orientation);

        if (!nodeRttsSelf.empty()) {
            node_rtts_self_ = std::move(nodeRttsSelf);
        }
        if (!nodeRtts.empty()) {
            node_rtts_ = std::move(nodeRtts);
        }

        update.peersIncreased = peers_.size() > previousPeerCount;
        update.canJoin = !joined_ && !autoMediaJoin && peers_.size() > 1
            && !node_rtts_self_.empty() && !node_rtts_.empty();

        if (update.canJoin) {
            joined_ = true;
            preferred_node_ = Config::Shared().server.empty() ? FindBestNode(node_rtts_self_, node_rtts_) : Config::Shared().server;
            join();
        }
        return update;
    }

    void join() override {
        signal_->join(preferred_node_, channel_);
    }

    void srtpKey(const std::string& key, Rtc__SrtpProfile profile) override { signal_->srtpKey(key, profile, channel_); }
    void recreate() override { signal_->recreate(channel_); }
    void offer(const std::string& sdp) override { signal_->offer(sdp, channel_); }
    void answer(const std::string& sdp) override { signal_->answer(sdp, channel_); }
    void negotiation(bool negotiation) override { signal_->negotiation(negotiation, channel_); }
    void subscribe(bool audio, bool video) override { signal_->subscribe(audio, video, channel_); }
    void candidate(const std::string& candidate) override { signal_->candidate(candidate, channel_); }
    void nodeRtts(const std::vector<std::pair<std::string, int>>& rtts) override { signal_->nodeRtts(rtts, channel_); }
    void mute(bool on, uint32_t rtpTime, bool video) override { signal_->mute(on, rtpTime, video, channel_); }
    void selectChannel(int select) override { signal_->selectChannel(select, channel_); }
    void report(const Rtc__Stats* stats, int64_t startTimeSinceEpoch) override {
        signal_->report(stats, startTimeSinceEpoch, channel_);
    }

private:
    std::shared_ptr<Signal> signal_;
    int channel_;
    std::unordered_set<std::string> peers_;
    std::unordered_set<std::string> joined_peers_;
    bool joined_ = false;
    std::string preferred_node_;
    std::vector<std::pair<std::string, int>> node_rtts_self_;
    std::vector<std::pair<std::string, int>> node_rtts_;
    std::map<std::string, bool> video_orientation_;
};

SignalChannelPtr createSignalChannel(std::shared_ptr<Signal> signal, int channel) {
    return std::make_shared<SignalChannelImpl>(std::move(signal), channel);
}

} // namespace bff
