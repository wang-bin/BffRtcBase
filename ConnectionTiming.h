#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace bff {
// 两种传输共用递增编号，便于配对并发连接的计时日志。
inline uint64_t NextConnectionAttemptId() noexcept {
    static std::atomic<uint64_t> next{0};
    return next.fetch_add(1, std::memory_order::relaxed) + 1;
}
} // namespace bff
