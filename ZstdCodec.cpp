#include "ZstdCodec.hpp"

#include "Log.hpp"

#include <openssl/md5.h>
#include <zstd.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>

#define TAG "zstd"

using namespace std;
namespace fs = std::filesystem;

namespace bff {

namespace {

constexpr uint8_t kZstdMagic[] = {0x28, 0xb5, 0x2f, 0xfd};
constexpr uint8_t kDictMagic[] = {0x37, 0xa4, 0x30, 0xec};
constexpr const char* kDictFileName = "zstd.dict";

} // namespace

Zstd& Zstd::shared() {
    static Zstd instance;
    return instance;
}

Zstd::Zstd(int level) : level_(level) {
    cctx_ = ZSTD_createCCtx();
    dctx_ = ZSTD_createDCtx();
}

Zstd::~Zstd() {
    if (cctx_) {
        ZSTD_freeCCtx(static_cast<ZSTD_CCtx*>(cctx_));
        cctx_ = nullptr;
    }
    if (dctx_) {
        ZSTD_freeDCtx(static_cast<ZSTD_DCtx*>(dctx_));
        dctx_ = nullptr;
    }
}

bool Zstd::startsWith(span<const uint8_t> data, span<const uint8_t> magic) noexcept {
    return data.size() >= magic.size() && memcmp(data.data(), magic.data(), magic.size()) == 0;
}

string Zstd::md5Hex(span<const uint8_t> data) {
    array<uint8_t, MD5_DIGEST_LENGTH> digest{};
    MD5(data.data(), data.size(), digest.data());
    string out;
    out.resize(MD5_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        snprintf(out.data() + i * 2, 3, "%02x", digest[i]);
    }
    return out;
}

bool Zstd::setDict(span<const uint8_t> dict) {
    if (dict.empty()) {
        clearDict();
        return true;
    }
    if (dict.size() < 4) {
        ERROR("invalid zstd dictionary: too short (%zu)", dict.size());
        return false;
    }

    vector<uint8_t> dict_z;
    vector<uint8_t> raw(dict.begin(), dict.end());

    // 若下发的是压缩字典，先解压再校验 dict magic
    if (startsWith(raw, kZstdMagic)) {
        dict_z = raw;
        auto bound = ZSTD_getFrameContentSize(raw.data(), raw.size());
        if (bound == ZSTD_CONTENTSIZE_ERROR || bound == ZSTD_CONTENTSIZE_UNKNOWN) {
            // 未知大小时用 compressBound 量级的缓冲重试；失败则报错
            bound = ZSTD_compressBound(raw.size()) * 8;
            if (bound < raw.size()) {
                bound = raw.size() * 16;
            }
        }
        vector<uint8_t> decompressed(static_cast<size_t>(bound));
        auto n = ZSTD_decompress(decompressed.data(), decompressed.size(), raw.data(), raw.size());
        if (ZSTD_isError(n)) {
            ERROR("decompress zstd dictionary failed: %s", ZSTD_getErrorName(n));
            return false;
        }
        decompressed.resize(n);
        raw = std::move(decompressed);
    }

    if (raw.size() < 4 || !startsWith(raw, kDictMagic)) {
        ERROR("invalid zstd dictionary: bad magic");
        return false;
    }

    lock_guard lock(mtx_);
    dict_ = std::move(raw);
    dict_z_ = std::move(dict_z);
    dict_hash_ = dict_z_.empty() ? md5Hex(dict_) : md5Hex(dict_z_);
    return true;
}

void Zstd::clearDict() {
    lock_guard lock(mtx_);
    dict_.clear();
    dict_z_.clear();
    dict_hash_.clear();
}

string Zstd::dictMd5() const {
    lock_guard lock(mtx_);
    return dict_hash_;
}

bool Zstd::hasDict() const {
    lock_guard lock(mtx_);
    return !dict_.empty();
}

vector<uint8_t> Zstd::dictData() const {
    lock_guard lock(mtx_);
    return dict_;
}

vector<uint8_t> Zstd::dictZData() const {
    lock_guard lock(mtx_);
    return dict_z_;
}

void Zstd::setCacheDir(string_view dir) {
    lock_guard lock(mtx_);
    cache_dir_.assign(dir);
    while (!cache_dir_.empty() && (cache_dir_.back() == '/' || cache_dir_.back() == '\\')) {
        cache_dir_.pop_back();
    }
}

string Zstd::cacheDir() const {
    lock_guard lock(mtx_);
    return cache_dir_;
}

string Zstd::cachePath() const {
    lock_guard lock(mtx_);
    if (cache_dir_.empty()) {
        return {};
    }
    return (fs::path(cache_dir_) / kDictFileName).string();
}

bool Zstd::writeFileAtomic(const string& path, span<const uint8_t> data) {
    if (path.empty() || data.empty()) {
        return false;
    }
    error_code ec;
    const auto file = fs::path(path);
    fs::create_directories(file.parent_path(), ec);
    if (ec) {
        ERROR("zstd create cache dir failed: %s path=%s", ec.message().c_str(), path.c_str());
        return false;
    }
    const auto tmp = file.string() + ".tmp";
    {
        ofstream ofs(tmp, ios::binary | ios::trunc);
        if (!ofs) {
            ERROR("zstd open temp dict failed path=%s", tmp.c_str());
            return false;
        }
        ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<streamsize>(data.size()));
        if (!ofs) {
            ERROR("zstd write temp dict failed path=%s", tmp.c_str());
            fs::remove(tmp, ec);
            return false;
        }
    }
    fs::rename(tmp, file, ec);
    if (ec) {
        // Windows 上目标存在时 rename 可能失败，先删再试
        fs::remove(file, ec);
        fs::rename(tmp, file, ec);
        if (ec) {
            ERROR("zstd rename dict failed: %s path=%s", ec.message().c_str(), path.c_str());
            fs::remove(tmp, ec);
            return false;
        }
    }
    return true;
}

bool Zstd::loadCachedDict() {
    const auto path = cachePath();
    if (path.empty()) {
        return false;
    }
    error_code ec;
    if (!fs::is_regular_file(path, ec) || ec) {
        return false;
    }
    const auto size = fs::file_size(path, ec);
    if (ec || size == 0 || size > 64 * 1024 * 1024) {
        ERROR("zstd load cached dict bad size path=%s", path.c_str());
        return false;
    }
    ifstream ifs(path, ios::binary);
    if (!ifs) {
        ERROR("zstd load cached dict open failed path=%s", path.c_str());
        return false;
    }
    vector<uint8_t> data(static_cast<size_t>(size));
    ifs.read(reinterpret_cast<char*>(data.data()), static_cast<streamsize>(data.size()));
    if (!ifs || static_cast<size_t>(ifs.gcount()) != data.size()) {
        ERROR("zstd load cached dict truncated path=%s", path.c_str());
        return false;
    }
    if (!setDict(data)) {
        ERROR("zstd load cached dict rejected, size=%zu path=%s", data.size(), path.c_str());
        return false;
    }
    const auto md5 = dictMd5();
    INFO("zstd loaded cached dict, size=%zu md5=%s path=%s", data.size(), md5.c_str(), path.c_str());
    return true;
}

bool Zstd::saveCachedDict() const {
    const auto path = cachePath();
    if (path.empty()) {
        return false;
    }
    vector<uint8_t> bytes;
    {
        lock_guard lock(mtx_);
        // 与 JS 一致：落盘原始下发字节（压缩字典优先）
        bytes = dict_z_.empty() ? dict_ : dict_z_;
    }
    if (bytes.empty()) {
        return false;
    }
    if (!writeFileAtomic(path, bytes)) {
        return false;
    }
    INFO("zstd saved dict, size=%zu path=%s", bytes.size(), path.c_str());
    return true;
}

vector<uint8_t> Zstd::encode(span<const uint8_t> input, bool useDict) const {
    lock_guard lock(mtx_);
    if (!cctx_ || input.empty()) {
        return {};
    }

    auto capacity = ZSTD_compressBound(input.size());
    vector<uint8_t> out(capacity);
    size_t n = 0;
    if (useDict && !dict_.empty()) {
        n = ZSTD_compress_usingDict(static_cast<ZSTD_CCtx*>(cctx_),
                                    out.data(),
                                    out.size(),
                                    input.data(),
                                    input.size(),
                                    dict_.data(),
                                    dict_.size(),
                                    level_);
    } else {
        n = ZSTD_compress(out.data(), out.size(), input.data(), input.size(), level_);
    }
    if (ZSTD_isError(n)) {
        ERROR("zstd encode failed: %s", ZSTD_getErrorName(n));
        return {};
    }
    out.resize(n);
    return out;
}

vector<uint8_t> Zstd::encode(string_view input, bool useDict) const {
    return encode(span<const uint8_t>(reinterpret_cast<const uint8_t*>(input.data()), input.size()), useDict);
}

string Zstd::decode(span<const uint8_t> input) const {
    lock_guard lock(mtx_);
    if (!dctx_ || input.empty()) {
        return {};
    }

    auto bound = ZSTD_getFrameContentSize(input.data(), input.size());
    if (bound == ZSTD_CONTENTSIZE_ERROR) {
        ERROR("zstd decode: invalid frame");
        return {};
    }
    if (bound == ZSTD_CONTENTSIZE_UNKNOWN) {
        bound = input.size() * 16;
        if (bound < 64 * 1024) {
            bound = 64 * 1024;
        }
    }

    vector<uint8_t> out(static_cast<size_t>(bound));
    size_t n = 0;
    if (!dict_.empty()) {
        n = ZSTD_decompress_usingDict(static_cast<ZSTD_DCtx*>(dctx_),
                                      out.data(),
                                      out.size(),
                                      input.data(),
                                      input.size(),
                                      dict_.data(),
                                      dict_.size());
    } else {
        n = ZSTD_decompress(out.data(), out.size(), input.data(), input.size());
    }
    if (ZSTD_isError(n)) {
        ERROR("zstd decode failed: %s", ZSTD_getErrorName(n));
        return {};
    }
    return string(reinterpret_cast<const char*>(out.data()), n);
}

} // namespace bff
