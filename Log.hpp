#pragma once
#include <functional>
#include <string>

#define DBG(...)  bff::user_log(bff::LogLevel::Debug, TAG, __VA_ARGS__);
#define INFO(...) bff::user_log(bff::LogLevel::Info, TAG, __VA_ARGS__);
#define WARN(...) bff::user_log(bff::LogLevel::Warn, TAG, __VA_ARGS__);
#define ERROR(...) bff::user_log(bff::LogLevel::Error, TAG, __VA_ARGS__);

namespace bff {
enum LogLevel { // values are the same as android_LogPriority
    Unknown = 0,
    Default = 1,
    Verbose = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
    Fatal = 7,
    Silent = 8,
};
void user_log(LogLevel level, const char* tag, const char * __restrict fmt, ...);

void SetLogger(std::function<void(LogLevel, const char* tag, const char* msg)>&& cb);
} // namespace bff
