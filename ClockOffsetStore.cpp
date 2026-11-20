//
//  ClockOffsetStore.cpp
//  rtcbase
//
//  Copyright © 2026 jspp.com. All rights reserved.
//  AI participated
//
#include "ClockOffsetStore.h"

#include "Log.hpp"
#include "defs.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#if (__APPLE__ + 0) || (__ANDROID__ + 0)
#include <unistd.h>
#endif

#if (__APPLE__ + 0)
#include <sys/sysctl.h>
#include <sys/time.h>
#include <time.h>
#elif (__ANDROID__ + 0)
#include <time.h>
#endif

#define TAG "clock"

namespace bff {
using namespace std;
using namespace std::chrono;

namespace {

constexpr int64_t kWallMonoSkewMs = 1000;
constexpr const char* kFileName = "clock_offset";

filesystem::path cachePath() {
    const auto& dir = Config::Shared().cacheDir;
    if (dir.empty()) {
        return {};
    }
    return filesystem::path(dir) / kFileName;
}

// 返回 follows 失败原因；成功返回 nullptr。供日志用。
const char* followsFailReason(ClockSample later, ClockSample earlier, double* skewOut) noexcept {
    if (earlier.wallMs <= 0 || earlier.monoMs <= 0) {
        return "earlier sample invalid";
    }
    if (later.monoMs < earlier.monoMs) {
        return "mono regress";
    }
    const auto skew = (static_cast<double>(later.wallMs) - earlier.wallMs)
                    - (static_cast<double>(later.monoMs) - earlier.monoMs);
    if (skewOut) {
        *skewOut = skew;
    }
    if (skew < -kWallMonoSkewMs || skew > kWallMonoSkewMs) {
        return "wall-mono skew";
    }
    return nullptr;
}

} // namespace

static int64_t MonotonicBootMs() noexcept {
#if (__APPLE__ + 0)
    // 含休眠；勿用 CLOCK_UPTIME_RAW / mach_absolute_time。
    return static_cast<int64_t>(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1'000'000ull);
#elif (__ANDROID__ + 0)
    timespec ts{};
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
        return 0;
    }
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1'000'000;
#else
    return steady_clock::now().time_since_epoch() / 1ms;
#endif
}

static string CurrentBootId() {
#if (__ANDROID__ + 0)
    ifstream ifs("/proc/sys/kernel/random/boot_id");
    string id;
    if (ifs && getline(ifs, id)) {
        while (!id.empty() && (id.back() == '\n' || id.back() == '\r' || id.back() == ' ')) {
            id.pop_back();
        }
        return id;
    }
    return {};
#elif (__APPLE__ + 0)
    timeval boottime{};
    size_t size = sizeof(boottime);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib, 2, &boottime, &size, nullptr, 0) != 0 || boottime.tv_sec == 0) {
        return {};
    }
    const int64_t usec = static_cast<int64_t>(boottime.tv_sec) * 1'000'000
                       + static_cast<int64_t>(boottime.tv_usec);
    return to_string(usec);
#else
    return {};
#endif
}

ClockSample ClockSample::now() noexcept {
    return {
        .wallMs = system_clock::now().time_since_epoch() / 1ms,
        .monoMs = MonotonicBootMs(),
    };
}

bool ClockSample::follows(ClockSample earlier) const noexcept {
    return followsFailReason(*this, earlier, nullptr) == nullptr;
}

void ClockOffsetStore::save(int64_t offsetMs, ClockSample sample) noexcept {
#if (__APPLE__ + 0) || (__ANDROID__ + 0)
    const auto path = cachePath();
    if (path.empty()) {
        DBG("clockOffset save skip: cacheDir empty");
        return;
    }
    double skew = 0;
    if (const auto* reason = followsFailReason(ClockSample::now(), sample, &skew)) {
        DBG("clockOffset save skip: %s skew=%.0fms sample wall=%lld mono=%lld",
            reason, skew,
            static_cast<long long>(sample.wallMs),
            static_cast<long long>(sample.monoMs));
        return;
    }
    const auto bootId = CurrentBootId();
    if (bootId.empty()) {
        DBG("clockOffset save skip: CurrentBootId empty");
        return;
    }
    error_code ec;
    filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        DBG("clockOffset save skip: create_directories failed");
        return;
    }
    auto tmp = path.string() + ".XXXXXX";
    const auto fd = mkstemp(tmp.data());
    if (fd < 0) {
        DBG("clockOffset save skip: mkstemp failed");
        return;
    }
    auto* file = fdopen(fd, "w");
    if (!file) {
        close(fd);
        filesystem::remove(tmp, ec);
        DBG("clockOffset save skip: fdopen failed");
        return;
    }
    const auto written = fprintf(file, "v2\n%lld\n%lld\n%lld\n%s\n",
                                 static_cast<long long>(offsetMs),
                                 static_cast<long long>(sample.wallMs),
                                 static_cast<long long>(sample.monoMs), bootId.c_str());
    const auto closed = fclose(file);
    if (written < 0 || closed != 0 || rename(tmp.c_str(), path.c_str()) != 0) {
        filesystem::remove(tmp, ec);
        DBG("clockOffset save skip: write/rename failed");
        return;
    }
    DBG("clockOffset saved: offset=%lldms", static_cast<long long>(offsetMs));
#endif
}

optional<int64_t> ClockOffsetStore::loadValid() noexcept {
    const auto path = cachePath();
    if (path.empty()) {
        DBG("clockOffset cache unused: cacheDir empty");
        return nullopt;
    }
    ifstream ifs(path, ios::binary);
    if (!ifs) {
        DBG("clockOffset cache unused: no file");
        return nullopt;
    }
    string ver;
    int64_t offset = 0;
    int64_t wallSaved = 0;
    int64_t monoSaved = 0;
    string bootSaved;
    // 格式：v2 / offset / wall / mono / boot_id（均无空格）
    if (!(ifs >> ver >> offset >> wallSaved >> monoSaved >> bootSaved) || ver != "v2" || bootSaved.empty()) {
        DBG("clockOffset cache unused: bad format ver=%s", ver.c_str());
        return nullopt;
    }

    const auto bootNow = CurrentBootId();
    if (bootNow.empty()) {
        DBG("clockOffset cache unused: CurrentBootId empty");
        return nullopt;
    }
    if (bootSaved != bootNow) {
        DBG("clockOffset cache unused: bootId mismatch saved=%s now=%s",
            bootSaved.c_str(), bootNow.c_str());
        return nullopt;
    }
    double skew = 0;
    const ClockSample saved{.wallMs = wallSaved, .monoMs = monoSaved};
    if (const auto* reason = followsFailReason(ClockSample::now(), saved, &skew)) {
        DBG("clockOffset cache unused: %s skew=%.0fms saved wall=%lld mono=%lld",
            reason, skew,
            static_cast<long long>(wallSaved),
            static_cast<long long>(monoSaved));
        return nullopt;
    }
    INFO("clockOffset cache used: offset=%lldms", static_cast<long long>(offset));
    return offset;
}

} // namespace bff
