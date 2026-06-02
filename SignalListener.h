#pragma once

#include <string>

#include "defs.h"
#include "rtc.pb-c.h"

namespace bff {

// Receive callbacks for SignalResponse dispatch. Default bodies match @optional JsppRecvDelegate.
// Message pointers are owned by the dispatcher; valid only for the duration of the callback.
class SignalListener {
public:
    virtual ~SignalListener() = default;

    virtual void onOffer(const std::string& sdp) {}
    virtual void onAnswer(const std::string& sdp) {}
    virtual void onCandidate(const IceCandidate& candidate) {}

    // AddTrack: batch then per-track (same order as receiveAddTrackSignalWithSignalResponse).
    virtual void onAddTrack(const Rtc__AddTrack* addTrack) {}
    virtual void onAddStream(const Rtc__TrackInfo* track) {}

    virtual void onRemoveTracks(const Rtc__RemoveTrack* removeTrack) {}

    virtual void onJoined(const Rtc__Joined* joined, bool autoMediaJoin) {}
    virtual void onConfig(const Rtc__RtcConfig* config) {}
    virtual void onSubscribe(bool audio, bool video) {}

    virtual void onChangedAddress(const std::string& addr) {}
    virtual void onChangedPeerState(Rtc__PeerState peerState) {}
    virtual void onLeaved(const Rtc__Leaved* leaved) {}
    virtual void onNegotiation(bool iceRestart) {}

    virtual void onLog(const std::string& message, RtcLogLevel level, const std::string& component) {}
    virtual void onError(RtcError error) {}
    virtual void onReconnect() {}
};

} // namespace bff
