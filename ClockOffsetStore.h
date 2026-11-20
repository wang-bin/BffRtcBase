//
//  ClockOffsetStore.h
//  rtcbase
//
//  Copyright © 2026 jspp.com. All rights reserved.
//  AI participated
//
#pragma once

#include <cstdint>
#include <optional>


namespace bff {

struct ClockSample {
    int64_t wallMs;
    int64_t monoMs; // 含休眠的开机单调时钟

    static ClockSample now() noexcept;
    // 判断 *this 是否可作为 earlier 之后的合法采样：
    // earlier 有效、mono 未倒退，且 (Δwall−Δmono) 在 ±1s 内（墙钟相对开机时钟未明显跳变）。
    bool follows(ClockSample earlier) const noexcept;
};

// nodelist 校时结果持久化到 Config::cacheDir；同 boot 且墙钟未相对 mono 跳变时才可恢复。
struct ClockOffsetStore {
    // cacheDir 空则 no-op。写入 offset + wall + mono + boot_id。
    static void save(int64_t offsetMs, ClockSample sample) noexcept;
    // BootId 不一致 / mono 倒退 / |Δwall-Δmono|>1000 → nullopt。
    static std::optional<int64_t> loadValid() noexcept;
};

} // namespace bff
