#pragma once

#include "rtc.pb-c.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace bff {

// 通话事件上报：校时前进内存队列，发送失败落盘，下次带 room_id 再发。
class EventLogger {
public:
    // 返回 true 表示已交给信令发送；false 则落盘等待后续 flush。
    using SendFn = std::function<bool(const Rtc__EventLog&)>;
    // App 侧事件回调：仅内存队列首次刷出时调用一次，落盘重放不回调。
    using OnEventFn = std::function<void(const Rtc__EventLog&)>;

    static EventLogger& shared();

    void setSendFn(SendFn sendFn);
    void setOnEvent(OnEventFn onEvent);
    void setIdentity(std::string roomId, std::string peerId);
    // 在同一个锁内补齐身份并填入缓存校时，已有校时优先。
    void setIdentity(std::string roomId, std::string peerId, std::optional<int64_t> cachedOffset);
    // 通话结束（flush 之后）调用：清 room/peer 与校时，避免下一通前置事件串旧身份。
    // 同时清 clockOffset，使 invite/INIT 等先入队，等 setIdentity 补空字段后再发。
    void clearSession();
    // nodelist 校时完成后调用；会校正排队事件并 flush。
    void onClockOffset(int64_t offsetMs);
    // 安装当前校时值。调用者在释放外部锁后触发 flush。
    void setClockOffset(int64_t offsetMs);
    std::optional<int64_t> clockOffset();
    void flush();

    void log(Rtc__EventType type,
             int32_t errCode = 0,
             int64_t extNum = 0,
             std::string extJson = {},
             int64_t eventTimeMs = 0);

    void invite();
    void ringing();
    void accept();
    void hangup(Rtc__HangupReason reason);

private:
    EventLogger();
    ~EventLogger();
    EventLogger(const EventLogger&) = delete;
    EventLogger& operator=(const EventLogger&) = delete;

    struct Private;
    std::unique_ptr<Private> d;
};

} // namespace bff
