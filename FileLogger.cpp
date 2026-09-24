#include "FileLogger.hpp"

#include "DateTime.h"
#include "json.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>

#if (__APPLE__ + 0)
#include <dispatch/dispatch.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#elif (__ANDROID__ + 0)
#include <sys/prctl.h>
#include <sys/system_properties.h>
#endif

#include <cstdlib>

using namespace std;
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace bff {

namespace {
constexpr const char* kMetaFileName = "log_meta.json";
constexpr const char* kLogServers = "log_servers";
constexpr const char* kLogRooms = "log_rooms";
constexpr int64_t kDefaultRetentionSeconds = 48 * 3600;

string LevelName(LogLevel level)
{
    switch (level) {
    case LogLevel::Error: return "E";
    case LogLevel::Warn: return "W";
    case LogLevel::Info: return "I";
    case LogLevel::Debug: return "D";
    default: return "V";
    }
}

constexpr const char* kWorkerThreadName = "rtc.log";

void SetCurrentThreadName(const char* name)
{
    if (!name || !name[0]) {
        return;
    }
#if (__APPLE__ + 0)
    pthread_setname_np(name);
#elif (__ANDROID__ + 0)
    // Linux/Android truncates to 15 chars excluding NUL.
    prctl(PR_SET_NAME, name, 0, 0, 0);
#endif
}

string ThreadName()
{
    char buf[64] = {};
#if (__APPLE__ + 0)
    if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) == 0 && buf[0]) {
        return buf;
    }
    if (const char* label = dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL); label && label[0]) {
        return label;
    }
#elif (__ANDROID__ + 0)
    // prctl works on Android 7.0+; pthread_getname_np requires API 26+.
    if (prctl(PR_GET_NAME, buf, 0, 0, 0) == 0 && buf[0]) {
        return buf;
    }
#endif
    return "?";
}

string LocalTimeWithMs(int64_t clockOffset)
{
    const auto now = chrono::system_clock::now() + chrono::milliseconds(clockOffset);
    const auto tt = chrono::system_clock::to_time_t(now);
    tm tmBuf{};
#if (_WIN32 + 0)
    localtime_s(&tmBuf, &tt);
#else
    localtime_r(&tt, &tmBuf);
#endif
    const auto ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) % 1000;
    char timePart[32] = {};
    strftime(timePart, sizeof(timePart), "%H:%M:%S", &tmBuf);
    char line[48] = {};
    snprintf(line, sizeof(line), "%s.%03d", timePart, static_cast<int>(ms.count()));
    return line;
}

// Match Android/iOS "yyyy-MM-dd Z", e.g. "2026-08-20 +0800".
string LocalDateWithZone(int64_t clockOffset)
{
    const auto now = chrono::system_clock::now() + chrono::milliseconds(clockOffset);
    const auto tt = chrono::system_clock::to_time_t(now);
    tm tmBuf{};
#if (_WIN32 + 0)
    localtime_s(&tmBuf, &tt);
#else
    localtime_r(&tt, &tmBuf);
#endif
    char datePart[16] = {};
    strftime(datePart, sizeof(datePart), "%Y-%m-%d", &tmBuf);
    long gmtoff = tmBuf.tm_gmtoff;
    char sign = (gmtoff >= 0) ? '+' : '-';
    long absSeconds = labs(gmtoff);
    char z[8] = {};
    snprintf(z, sizeof(z), "%c%02ld%02ld", sign, absSeconds / 3600, (absSeconds % 3600) / 60);
    return string(datePart) + " " + z;
}

#if (__APPLE__ + 0)
string SysctlByName(const char* name)
{
    size_t size = 0;
    if (sysctlbyname(name, nullptr, &size, nullptr, 0) != 0 || size == 0) {
        return {};
    }
    string value(size, '\0');
    if (sysctlbyname(name, value.data(), &size, nullptr, 0) != 0) {
        return {};
    }
    // sysctl may include a trailing NUL in size.
    while (!value.empty() && value.back() == '\0') {
        value.pop_back();
    }
    return value;
}
#endif

#if (__ANDROID__ + 0)
string SystemProperty(const char* key)
{
    char value[PROP_VALUE_MAX] = {};
    if (__system_property_get(key, value) <= 0) {
        return {};
    }
    return value;
}
#endif

string DeviceInfoLine()
{
#if (__APPLE__ + 0)
    string model = SysctlByName("hw.machine");
    if (model.empty()) {
        utsname u{};
        if (uname(&u) == 0 && u.machine[0]) {
            model = u.machine;
        }
    }
    string version = SysctlByName("kern.osproductversion");
    if (version.empty()) {
        utsname u{};
        if (uname(&u) == 0 && u.release[0]) {
            version = u.release;
        }
    }
    // UIDevice.systemName is "iOS"; uname.sysname is "Darwin".
    return model + " iOS " + version;
#elif (__ANDROID__ + 0)
    const auto model = SystemProperty("ro.product.model");
    const auto brand = SystemProperty("ro.product.brand");
    const auto manufacturer = SystemProperty("ro.product.manufacturer");
    const auto release = SystemProperty("ro.build.version.release");
    const auto api = SystemProperty("ro.build.version.sdk");
    return "model: " + model
        + ". brand: " + brand
        + ". manufacturer: " + manufacturer
        + ". Android: " + release
        + ". api: " + api;
#else
    return {};
#endif
}

string ReadTextFile(const fs::path& path)
{
    ifstream ifs(path, ios::binary);
    if (!ifs.is_open()) {
        return {};
    }
    return string((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
}
} // namespace

struct FileLogger::Impl {
    mutable mutex mtx;
    condition_variable cv;
    deque<string> queue;
    thread worker;
    bool workerStop = false;
    // File rotation waits for an unlocked worker write to finish before closing its FILE*.
    bool writeInProgress = false;
    FILE* file = nullptr;
    fs::path logDir;
    fs::path logPath;
    fs::path metaPath;
    string logName;
    string pendingLogs;
    int64_t retentionSeconds = kDefaultRetentionSeconds;
    int64_t clockOffset = 0;

    Impl()
    {
        worker = thread([this] { this->WorkerLoop(); });
    }

    ~Impl()
    {
        {
            const scoped_lock lock(mtx);
            workerStop = true;
        }
        cv.notify_all();
        if (worker.joinable()) {
            worker.join();
        }
        if (file) {
            fclose(file);
            file = nullptr;
        }
    }

    void WorkerLoop()
    {
        SetCurrentThreadName(kWorkerThreadName);
        unique_lock lock(mtx);
        for (;;) {
            cv.wait(lock, [&] { return workerStop || !queue.empty(); });
            if (workerStop && queue.empty()) {
                break;
            }
            string msg = std::move(queue.front());
            queue.pop_front();
            FILE* f = file;
            writeInProgress = true;
            lock.unlock();
            if (f && !msg.empty()) {
                fwrite(msg.data(), msg.size(), 1, f);
                fflush(f);
            }
            lock.lock();
            writeInProgress = false;
            cv.notify_all();
        }
    }

    json LoadMetaLocked() const
    {
        if (metaPath.empty()) {
            return json::object();
        }
        const auto raw = ReadTextFile(metaPath);
        if (raw.empty()) {
            return json::object();
        }
        auto j = json::parse(raw, nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            return json::object();
        }
        if (!j.contains(kLogServers) || !j[kLogServers].is_object()) {
            j[kLogServers] = json::object();
        }
        if (!j.contains(kLogRooms) || !j[kLogRooms].is_object()) {
            j[kLogRooms] = json::object();
        }
        return j;
    }

    void SaveMetaLocked(const json& j) const
    {
        if (metaPath.empty()) {
            return;
        }
        error_code ec;
        fs::create_directories(metaPath.parent_path(), ec);
        ofstream ofs(metaPath, ios::binary | ios::trunc);
        if (!ofs.is_open()) {
            return;
        }
        ofs << j.dump();
        ofs.flush();
    }

    string MetaGetLocked(const char* group, const string& name) const
    {
        if (name.empty()) {
            return {};
        }
        auto j = LoadMetaLocked();
        if (!j.contains(group) || !j[group].is_object()) {
            return {};
        }
        const auto it = j[group].find(name);
        if (it == j[group].end() || !it->is_string()) {
            return {};
        }
        return it->get<string>();
    }

    void MetaSetCurrentLocked(const char* group, const string& value)
    {
        if (logName.empty() || value.empty()) {
            return;
        }
        auto j = LoadMetaLocked();
        j[group][logName] = value;
        SaveMetaLocked(j);
    }

    void MetaRemoveLocked(const string& name)
    {
        if (name.empty()) {
            return;
        }
        auto j = LoadMetaLocked();
        if (j.contains(kLogServers) && j[kLogServers].is_object()) {
            j[kLogServers].erase(name);
        }
        if (j.contains(kLogRooms) && j[kLogRooms].is_object()) {
            j[kLogRooms].erase(name);
        }
        SaveMetaLocked(j);
    }
};

FileLogger& FileLogger::shared()
{
    static FileLogger obj;
    return obj;
}

FileLogger::FileLogger() : d_(new Impl()) {}

FileLogger::~FileLogger()
{
    delete d_;
    d_ = nullptr;
}

bool FileLogger::newLog(const string& userId, const string& logDir)
{
    if (userId.empty() || logDir.empty()) {
        return false;
    }
    const auto name = userId + "-" + UTCTimeString() + ".log";
    const auto dir = fs::path(logDir);
    const auto path = dir / name;

    error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        return false;
    }

    string pending;
    {
        unique_lock lock(d_->mtx);
        d_->cv.wait(lock, [this] { return d_->queue.empty() && !d_->writeInProgress; });
        FILE* newFile = fopen(path.string().c_str(), "w+");
        if (!newFile) {
            return false;
        }
        if (d_->file) {
            fclose(d_->file);
            d_->file = nullptr;
        }
        d_->logDir = dir;
        d_->logPath = path;
        d_->metaPath = dir / kMetaFileName;
        d_->logName = name;
        d_->file = newFile;
        pending = std::move(d_->pendingLogs);
        d_->pendingLogs.clear();
        if (!pending.empty()) {
            d_->queue.push_back(std::move(pending));
        }
    }
    d_->cv.notify_one();
    log(LogLevel::Debug, "log", "Date: " + LocalDateWithZone(clockOffset()));
    if (const auto device = DeviceInfoLine(); !device.empty()) {
        log(LogLevel::Debug, "log", device);
    }
    return true;
}

void FileLogger::stop()
{
    unique_lock lock(d_->mtx);
    d_->cv.wait(lock, [this] { return d_->queue.empty() && !d_->writeInProgress; });
    if (d_->file) {
        fflush(d_->file);
        fclose(d_->file);
        d_->file = nullptr;
    }
}

bool FileLogger::write(const string& text)
{
    if (text.empty()) {
        return true;
    }
    {
        const scoped_lock lock(d_->mtx);
        if (!d_->file) {
            return false;
        }
        d_->queue.push_back(string(text));
    }
    d_->cv.notify_one();
    return true;
}

void FileLogger::log(LogLevel level, const string& tag, const string& message)
{
    const auto line = LocalTimeWithMs(clockOffset()) + " " + LevelName(level) + " (" + ThreadName() + ") " + tag + ": " + message + "\n";
    bool queued = false;
    {
        const scoped_lock lock(d_->mtx);
        if (d_->file) {
            d_->queue.push_back(line);
            queued = true;
        } else {
            d_->pendingLogs += line;
        }
    }
    if (queued) {
        d_->cv.notify_one();
    }
}

void FileLogger::setUploadServer(const string& server)
{
    const scoped_lock lock(d_->mtx);
    d_->MetaSetCurrentLocked(kLogServers, server);
}

string FileLogger::getUploadServer(const string& name) const
{
    const scoped_lock lock(d_->mtx);
    return d_->MetaGetLocked(kLogServers, name);
}

void FileLogger::setRoom(const string& room)
{
    const scoped_lock lock(d_->mtx);
    d_->MetaSetCurrentLocked(kLogRooms, room);
}

string FileLogger::getRoom(const string& name) const
{
    const scoped_lock lock(d_->mtx);
    return d_->MetaGetLocked(kLogRooms, name);
}

vector<string> FileLogger::files()
{
    vector<string> paths;
    vector<fs::path> expired;
    fs::path dir;
    int64_t retention = kDefaultRetentionSeconds;
    {
        const scoped_lock lock(d_->mtx);
        dir = d_->logDir;
        retention = d_->retentionSeconds;
    }
    if (dir.empty()) {
        return paths;
    }

    error_code ec;
    const auto nowFt = fs::file_time_type::clock::now();
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto& p = entry.path();
        if (p.filename() == kMetaFileName) {
            continue;
        }
        if (p.extension() != ".log") {
            continue;
        }
        const auto ft = entry.last_write_time(ec);
        if (ec) {
            continue;
        }
        const auto ageSec = chrono::duration_cast<chrono::seconds>(nowFt - ft).count();
        if (ageSec > retention) {
            expired.push_back(p);
            continue;
        }
        paths.push_back(p.string());
    }

    for (const auto& p : expired) {
        remove(p.string());
    }
    return paths;
}

vector<string> FileLogger::closedFiles()
{
    vector<string> paths;
    vector<fs::path> expired;
    {
        const scoped_lock lock(d_->mtx);
        if (d_->logDir.empty()) {
            return paths;
        }

        error_code ec;
        const auto nowFt = fs::file_time_type::clock::now();
        for (const auto& entry : fs::directory_iterator(d_->logDir, ec)) {
            if (ec) {
                break;
            }
            if (!entry.is_regular_file()) {
                continue;
            }
            const auto& p = entry.path();
            if (p.filename() == kMetaFileName || p.extension() != ".log") {
                continue;
            }
            if (d_->file && p == d_->logPath) {
                continue;
            }
            const auto ft = entry.last_write_time(ec);
            if (ec) {
                continue;
            }
            const auto ageSec = chrono::duration_cast<chrono::seconds>(nowFt - ft).count();
            if (ageSec > d_->retentionSeconds) {
                expired.push_back(p);
                continue;
            }
            paths.push_back(p.string());
        }
    }

    for (const auto& p : expired) {
        remove(p.string());
    }
    return paths;
}

void FileLogger::remove(const string& path)
{
    if (path.empty()) {
        return;
    }
    error_code ec;
    fs::path p(path);
    fs::remove(p, ec);
    const auto name = p.filename().string();
    const scoped_lock lock(d_->mtx);
    d_->MetaRemoveLocked(name);
}

string FileLogger::currentLogName() const
{
    const scoped_lock lock(d_->mtx);
    return d_->logName;
}

void FileLogger::setClockOffset(int64_t milliseconds)
{
    const scoped_lock lock(d_->mtx);
    d_->clockOffset = milliseconds;
}

int64_t FileLogger::clockOffset() const
{
    const scoped_lock lock(d_->mtx);
    return d_->clockOffset;
}

void FileLogger::setRetentionSeconds(int64_t seconds)
{
    const scoped_lock lock(d_->mtx);
    d_->retentionSeconds = seconds > 0 ? seconds : kDefaultRetentionSeconds;
}

} // namespace bff
