#pragma once

#include "Log.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace bff {

class FileLogger {
public:
    static FileLogger& shared();

    bool newLog(const std::string& userId, const std::string& logDir);
    void stop();
    bool write(const std::string& text);
    void log(LogLevel level, const std::string& tag, const std::string& message);

    void setUploadServer(const std::string& server);
    std::string getUploadServer(const std::string& name) const;
    void setRoom(const std::string& room);
    std::string getRoom(const std::string& name) const;

    std::vector<std::string> files();
    void remove(const std::string& path);
    std::string currentLogName() const;

    void setRetentionSeconds(int64_t seconds);

private:
    FileLogger();
    ~FileLogger();
    FileLogger(const FileLogger&) = delete;
    FileLogger& operator=(const FileLogger&) = delete;

    struct Impl;
    Impl* d_ = nullptr;
};

} // namespace bff
