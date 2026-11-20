#include "EventLogger.h"

#include "FileLogger.hpp"
#include "Log.hpp"
#include "defs.h"

#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <vector>

#define TAG "rtc.event"

using namespace std;
namespace fs = std::filesystem;

namespace bff {

namespace {

constexpr const char* kPendingFileName = "event_log_pending.bin";

int64_t WallNowMs() {
    return chrono::duration_cast<chrono::milliseconds>(
               chrono::system_clock::now().time_since_epoch())
        / 1ms;
}

struct PendingEvent {
    Rtc__EventType type = RTC__EVENT_TYPE__EVENT_UNKNOWN;
    int32_t errCode = 0;
    int64_t extNum = 0;
    string extJson;
    int64_t rawTimeMs = 0; // 未加 clockOffset 的墙钟
    string roomId;
    string peerId;
    // 落盘失败回内存队列时，避免下次 flush 再次 onEvent
    bool notified = false;
};

Rtc__EventLog MakeEventLog(PendingEvent& e, int64_t offset) {
    Rtc__EventLog msg = RTC__EVENT_LOG__INIT;
    msg.source = RTC__SOURCE__SOURCE_CLIENT;
    msg.event_type = e.type;
    msg.event_time = e.rawTimeMs + offset;
    msg.err_code = e.errCode;
    msg.ext_num = e.extNum;
    if (!e.roomId.empty()) {
        msg.room_id = e.roomId.data();
    }
    if (!e.peerId.empty()) {
        msg.peer_id = e.peerId.data();
    }
    if (!e.extJson.empty()) {
        msg.ext_json = e.extJson.data();
    }
    return msg;
}

string PendingPath(const string& dir) {
    if (dir.empty()) {
        return {};
    }
    return (fs::path(dir) / kPendingFileName).string();
}

bool AppendPacked(const string& path, const uint8_t* data, size_t len) {
    if (path.empty() || !data || len == 0) {
        return false;
    }
    error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    ofstream out(path, ios::binary | ios::app);
    if (!out) {
        return false;
    }
    const uint32_t n = static_cast<uint32_t>(len);
    out.write(reinterpret_cast<const char*>(&n), sizeof(n));
    out.write(reinterpret_cast<const char*>(data), static_cast<streamsize>(len));
    out.close();
    return static_cast<bool>(out);
}

vector<vector<uint8_t>> LoadPacked(const string& path) {
    vector<vector<uint8_t>> out;
    if (path.empty() || !fs::exists(path)) {
        return out;
    }
    ifstream in(path, ios::binary);
    if (!in) {
        return out;
    }
    while (in) {
        uint32_t n = 0;
        in.read(reinterpret_cast<char*>(&n), sizeof(n));
        if (!in || n == 0 || n > 1024 * 1024) {
            break;
        }
        vector<uint8_t> buf(n);
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<streamsize>(n));
        if (!in) {
            break;
        }
        out.push_back(std::move(buf));
    }
    return out;
}

bool PackAndAppend(const string& path, const Rtc__EventLog& msg) {
    const size_t sz = rtc__event_log__get_packed_size(&msg);
    vector<uint8_t> buf(sz);
    rtc__event_log__pack(&msg, buf.data());
    return AppendPacked(path, buf.data(), buf.size());
}

// 在同目录原子替换积压文件；写入或重命名失败时保留旧文件。
bool ReplacePendingFile(const string& path, const vector<vector<uint8_t>>& packed) {
    if (path.empty()) {
        return false;
    }
    error_code ec;
    if (packed.empty()) {
        fs::remove(path, ec);
        return !ec;
    }
    const string tmp = path + ".tmp";
    fs::remove(tmp, ec);
    if (ec) {
        return false;
    }
    for (const auto& buf : packed) {
        if (!AppendPacked(tmp, buf.data(), buf.size())) {
            fs::remove(tmp, ec);
            return false; // 旧 pending 未动，下次仍从原文件重试
        }
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

} // namespace

struct EventLogger::Private {
    mutex mtx;
    // 串行化 flush 的发送与落盘，避免并发读同一 pending / 删文件误伤
    mutex flush_mtx;
    SendFn sendFn;
    OnEventFn onEvent;
    string roomId;
    string peerId;
    optional<int64_t> clockOffset; // 未设置前事件只入队不发送
    deque<PendingEvent> queue;
};

EventLogger& EventLogger::shared() {
    static EventLogger inst;
    return inst;
}

EventLogger::EventLogger()
    : d(make_unique<Private>()) {}

EventLogger::~EventLogger() = default;

void EventLogger::setSendFn(SendFn sendFn) {
    const scoped_lock lock(d->mtx);
    d->sendFn = std::move(sendFn);
}

void EventLogger::setOnEvent(OnEventFn onEvent) {
    const scoped_lock lock(d->mtx);
    d->onEvent = std::move(onEvent);
}

void EventLogger::setIdentity(string roomId, string peerId) {
    setIdentity(std::move(roomId), std::move(peerId), nullopt);
}

void EventLogger::setIdentity(string roomId, string peerId, optional<int64_t> cachedOffset) {
    {
        const scoped_lock lock(d->mtx);
        if (!d->clockOffset && cachedOffset) {
            d->clockOffset = cachedOffset;
        }
        d->roomId = std::move(roomId);
        d->peerId = std::move(peerId);
        for (auto& e : d->queue) {
            if (e.roomId.empty()) {
                e.roomId = d->roomId;
            }
            if (e.peerId.empty()) {
                e.peerId = d->peerId;
            }
        }
    }
    flush();
}

void EventLogger::clearSession() {
    const scoped_lock lock(d->mtx);
    d->roomId.clear();
    d->peerId.clear();
    d->clockOffset.reset();
}

void EventLogger::onClockOffset(int64_t offsetMs) {
    setClockOffset(offsetMs);
    flush();
}

void EventLogger::setClockOffset(int64_t offsetMs) {
    const scoped_lock lock(d->mtx);
    d->clockOffset = offsetMs;
}

optional<int64_t> EventLogger::clockOffset() {
    const scoped_lock lock(d->mtx);
    return d->clockOffset;
}

void EventLogger::invite() {
    log(RTC__EVENT_TYPE__EVENT_INVITE);
}

void EventLogger::ringing() {
    log(RTC__EVENT_TYPE__EVENT_RINGING);
}

void EventLogger::accept() {
    log(RTC__EVENT_TYPE__EVENT_ACCEPT);
}

void EventLogger::hangup(Rtc__HangupReason reason) {
    log(RTC__EVENT_TYPE__EVENT_HANGUP, 0, static_cast<int64_t>(reason));
}

void EventLogger::log(Rtc__EventType type,
                      int32_t errCode,
                      int64_t extNum,
                      string extJson,
                      int64_t eventTimeMs) {
    PendingEvent e{
        .type = type,
        .errCode = errCode,
        .extNum = extNum,
        .extJson = std::move(extJson),
        .rawTimeMs = eventTimeMs > 0 ? eventTimeMs : WallNowMs(),
    };
    {
        const scoped_lock lock(d->mtx);
        e.roomId = d->roomId;
        e.peerId = d->peerId;
        d->queue.push_back(std::move(e));
        // 校时未就绪：只入队，等 onClockOffset / 显式 flush
        if (!d->clockOffset) {
            return;
        }
    }
    flush();
}

void EventLogger::flush() {
    // App onEvent 必须在 flush_mtx 外调用：delegateQueue==nil 时同步回调，
    // 若 App 在回调里 report* → setIdentity → flush，非递归锁会死锁。
    deque<PendingEvent> local;
    SendFn sendFn;
    OnEventFn onEvent;
    string storageDir;
    int64_t offset = 0;
    deque<PendingEvent> remain;
    vector<PendingEvent> toNotify;

    {
        const scoped_lock flushLock(d->flush_mtx);
        {
            const scoped_lock lock(d->mtx);
            sendFn = d->sendFn;
            onEvent = d->onEvent;
            storageDir = Config::Shared().cacheDir;
            // 显式 flush（stop/setIdentity）允许在尚未 nodelist 校时时用当前 FileLogger offset
            offset = d->clockOffset.value_or(FileLogger::shared().clockOffset());
            local.swap(d->queue);
        }

        const auto path = PendingPath(storageDir);

        auto trySend = [&](Rtc__EventLog& msg) -> bool {
            if (!sendFn) {
                return false;
            }
            return sendFn(msg);
        };

        // 落盘历史重发；只 SendFn，不再 onEvent（本进程已在首次刷出时通知过）
        if (sendFn && !path.empty()) {
            auto packed = LoadPacked(path);
            if (!packed.empty()) {
                vector<vector<uint8_t>> failed;
                for (auto& buf : packed) {
                    auto* msg = rtc__event_log__unpack(nullptr, buf.size(), buf.data());
                    if (!msg) {
                        failed.push_back(std::move(buf));
                        continue;
                    }
                    const bool ok = trySend(*msg);
                    rtc__event_log__free_unpacked(msg, nullptr);
                    if (!ok) {
                        failed.push_back(std::move(buf));
                    }
                }
                if (!ReplacePendingFile(path, failed)) {
                    // 归属仍在旧 pending 文件；勿再入内存，以免与盘上记录重复发送
                    ERROR("event pending replace failed, keep old file (%zu to retry)", failed.size());
                }
            }
        }

        for (auto& e : local) {
            auto msg = MakeEventLog(e, offset);
            // 先保存通知所需的数据，释放锁后再回调 App。
            if (onEvent && !e.notified) {
                toNotify.push_back(e);
                e.notified = true;
            }
            if (!trySend(msg)) {
                if (!PackAndAppend(path, msg)) {
                    remain.push_back(std::move(e));
                }
            }
        }

        if (!remain.empty()) {
            const scoped_lock lock(d->mtx);
            while (!remain.empty()) {
                d->queue.push_front(std::move(remain.back()));
                remain.pop_back();
            }
        }
    }

    for (auto& event : toNotify) {
        onEvent(MakeEventLog(event, offset));
    }
}

} // namespace bff
