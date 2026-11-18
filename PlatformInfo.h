#pragma once

#include <string>

#if (__APPLE__ + 0)
#include <sys/sysctl.h>
#include <sys/utsname.h>
#elif (__ANDROID__ + 0)
#include <sys/system_properties.h>
#endif

namespace bff {

// 读取平台 OS / 设备信息；供 FileLogger、NodeSelector 等共用。

#if (__APPLE__ + 0)
inline std::string SysctlByName(const char* name)
{
    size_t size = 0;
    if (sysctlbyname(name, nullptr, &size, nullptr, 0) != 0 || size == 0) {
        return {};
    }
    std::string value(size, '\0');
    if (sysctlbyname(name, value.data(), &size, nullptr, 0) != 0) {
        return {};
    }
    // sysctl may include a trailing NUL in size.
    while (!value.empty() && value.back() == '\0') {
        value.pop_back();
    }
    return value;
}

// 对齐 FileLogger DeviceInfoLine：优先 kern.osproductversion，回退 uname.release。
inline std::string OsProductVersion()
{
    std::string version = SysctlByName("kern.osproductversion");
    if (version.empty()) {
        utsname u{};
        if (uname(&u) == 0 && u.release[0]) {
            version = u.release;
        }
    }
    return version;
}
#endif

#if (__ANDROID__ + 0)
inline std::string SystemProperty(const char* key)
{
    char value[PROP_VALUE_MAX] = {};
    if (__system_property_get(key, value) <= 0) {
        return {};
    }
    return value;
}
#endif

} // namespace bff
