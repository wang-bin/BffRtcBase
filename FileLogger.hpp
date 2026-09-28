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
    // 仅当当前打开的日志仍是 name 时关闭；若已 newLog 轮转到下一通则不操作。
    // 用于通话结束上传：关掉本通话文件，又避免旧 stop 误关新通话日志。
    bool stopIfCurrent(const std::string& name);
    bool write(const std::string& text);
    void log(LogLevel level, const std::string& tag, const std::string& message);

    void setUploadServer(const std::string& server);
    std::string getUploadServer(const std::string& name) const;
    void setRoom(const std::string& room);
    std::string getRoom(const std::string& name) const;

    std::vector<std::string> files();
    std::vector<std::string> closedFiles();
    void remove(const std::string& path);
    std::string currentLogName() const;

    // Clock offset in milliseconds, applied to log timestamps and upload dates.
    void setClockOffset(int64_t milliseconds);
    int64_t clockOffset() const;

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
