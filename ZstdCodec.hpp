#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bff {

// SDP / signaling zstd codec aligned with client-sdk-js Zstd.ts:
// - dict magic 37 A4 30 EC; optional compressed dict (frame magic 28 B5 2F FD)
// - MD5 is over compressed blob when present, else raw dict
// - level default 3; encode may use dictionary when installed
class Zstd {
public:
    static Zstd& shared();

    explicit Zstd(int level = 3);
    ~Zstd();

    Zstd(const Zstd&) = delete;
    Zstd& operator=(const Zstd&) = delete;

    static constexpr const char* kCodecName = "zstd";
    const char* codecName() const noexcept { return kCodecName; }

    // Install dictionary. Accepts raw zstd dict or zstd-framed compressed dict.
    // Empty input clears the dictionary. Returns false on invalid input (state unchanged).
    bool setDict(std::span<const uint8_t> dict);
    void clearDict();

    std::string dictMd5() const;
    bool hasDict() const;
    std::vector<uint8_t> dictData() const;
    std::vector<uint8_t> dictZData() const;

    // 平台注入可写目录；字典文件名为 zstd.dict。空目录禁用落盘。
    void setCacheDir(std::string_view dir);
    std::string cacheDir() const;
    std::string cachePath() const;

    // 从 cachePath 读取并 setDict。
    bool loadCachedDict();
    // 将当前字典原始字节（优先 dict_z_，否则 dict_）原子写入 cachePath。
    bool saveCachedDict() const;

    // 明文 sdp 优先；否则用 sdp_z 解压。与 JS Signal.ts 对齐。
    static std::string resolveSdp(std::string_view sdp, std::span<const uint8_t> sdp_z);

    std::vector<uint8_t> encode(std::span<const uint8_t> input, bool useDict = true) const;
    std::vector<uint8_t> encode(std::string_view input, bool useDict = true) const;
    std::string decode(std::span<const uint8_t> input) const;

private:
    static bool startsWith(std::span<const uint8_t> data, std::span<const uint8_t> magic) noexcept;
    static std::string md5Hex(std::span<const uint8_t> data);
    static bool writeFileAtomic(const std::string& path, std::span<const uint8_t> data);

    mutable std::mutex mtx_;
    int level_ = 3;
    std::string cache_dir_;
    std::vector<uint8_t> dict_;
    std::vector<uint8_t> dict_z_;
    std::string dict_hash_;
    void* cctx_ = nullptr; // ZSTD_CCtx*
    void* dctx_ = nullptr; // ZSTD_DCtx*
};

} // namespace bff
