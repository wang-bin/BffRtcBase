#pragma once
/*
package com.jspp.avrtcsdk.impl;
public class FileLogger {
    public void onLog(String log, int level, String module);
}
*/
#include "jmi.h"

#include <string>

namespace jmi {

class FileLogger : public jmi::JObject<FileLogger> {
public:
    using Base = jmi::JObject<FileLogger>;
    using Base::Base;
    static constexpr auto name() { return JMISTR("com/jspp/avrtcsdk/impl/FileLogger"); }

    void onLog(const std::string &message, jint level, const std::string &tag);
};

} // namespace jmi
