#include "Log.hpp"
#include <mutex>

namespace bff {

static std::function<void(LogLevel, const char*, const char*)> gLog = nullptr;
static std::mutex gMtx;

void SetLogger(std::function<void(LogLevel, const char*, const char*)>&& cb)
{
    [[maybe_unused]] const std::scoped_lock __(gMtx);
    gLog = std::move(cb);
}

void user_log(LogLevel level, const char* tag, const char * __restrict fmt, ...)
{
    va_list vl;
    va_start(vl, fmt);

    [[maybe_unused]] const std::scoped_lock __(gMtx);
    if (gLog) {
        va_list tmp;
        va_copy(tmp, vl);
        std::string vs(std::vsnprintf(nullptr, 0, fmt, tmp), 0); // +1 for terminating null
        std::vsnprintf(&vs[0], vs.size() + 1, fmt, vl);
        gLog(level, tag, vs.data());
        va_end(tmp); // required
    } else {
        vfprintf(stdout, fmt, vl);
    }
    va_end(vl);
}
} // namespace bff
