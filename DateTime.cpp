#include "DateTime.h"
#include <ctime>

using namespace std;
using namespace std::chrono;

namespace bff {


 // %z: +0800(always local zone), %Z: UTC
static std::string tz_string(const std::tm* t)
{
    // Extract and calculate the offset from tm_gmtoff (stored in seconds)
    long gmtoff_seconds = t->tm_gmtoff;
    char sign = (gmtoff_seconds >= 0) ? '+' : '-';
    long abs_seconds = std::labs(gmtoff_seconds);

    long hours = abs_seconds / 3600;
    long minutes = (abs_seconds % 3600) / 60;
    char z[8];
    std::snprintf(z, sizeof(z), "%c%02ld%02ld", sign, hours, minutes);
    return z;
}

static std::string to_string(const std::tm* t)
{
    char buf[20] = {0};
    std::strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", t); // %z always local zone

    return std::string(buf) + tz_string(t);
}

std::string get_utc_time_posix() {
    std::time_t now = std::time(nullptr);
    std::tm tm_buf;
    ::gmtime_r(&now, &tm_buf);                     // 线程安全的 UTC -> struct tm
    //auto tm_buf = gmtime(&now);
    return to_string(&tm_buf);
}

std::string get_local_time_posix() {
    std::time_t now = std::time(nullptr);
    std::tm tm_buf;
    localtime_r(&now, &tm_buf);
    return to_string(&tm_buf);
}


std::string UTCTimeString() {
    return get_utc_time_posix();
}
std::string LocalTimeString() {
    return get_local_time_posix();
}
} // namespace bff