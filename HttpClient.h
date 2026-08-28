#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

class HttpClient {
public:
    struct Result {
        int httpCode;
        int bytesSent;
        std::string responseBody;
        std::string error;
        int curlCode;
        std::string responseHeaders; // TODO:

        bool isSecError() const;
    };

    using CompletionCallback = std::function<void(const Result&)>;

    HttpClient();
    ~HttpClient();

    // Shared auth token for HTTP (mirrors JsppHTTPClient.token / Android HttpHelper).
    // When set, request URLs that already contain a `token=` query param are rewritten.
    static void setAuthToken(std::string token);
    static std::string authToken();
    static std::string urlWithAuthToken(const std::string& url);

    HttpClient& header(const std::string& name, const std::string& value);
    HttpClient& sni(const std::string& host);
    HttpClient& setConnectTimeout(int ms);
    void get(const std::string& url, CompletionCallback&& cb = {});
    void post(const std::string& url, CompletionCallback&& cb = {});
    void post(const std::string& url, std::string&& body, CompletionCallback&& cb = {});
    // will compress body with gzip
    void postGz(const std::string& url, std::string&& uncompressedBody, CompletionCallback&& cb = {});

    void request(const std::string& url, const std::string& method, std::string&& body, CompletionCallback&& cb = {});
private:
    class Private;
    std::unique_ptr<Private> d;
};

namespace bff {

struct UploadAllLogsResult {
    size_t total = 0;
    size_t succeeded = 0;
    size_t removed = 0;
    bool secError = false;
};

// GET token URL using Config::Shared() hosts/sni. Callback runs on the curl worker thread.
void generateToken(const std::string& url, HttpClient::CompletionCallback cb);

// POST one log file. `logPathOrName` is a path or basename (`id-yyyyMMddHHmmssZ.log`);
// room/upload-server come from FileLogger meta; gzip is internal (falls back uncompressed).
// Callback runs on the curl worker thread. Caller decides when to FileLogger::remove.
void uploadLog(const std::string& uploadUrl,
               std::string payload,
               const std::string& logPathOrName,
               HttpClient::CompletionCallback cb);

// Flush FileLogger, upload every retained .log, remove on HTTP 200 without JSON error.
// Callback runs on the curl worker thread when all uploads finish (or immediately if none).
void uploadAllLogs(const std::string& uploadUrl,
                   std::function<void(const UploadAllLogsResult&)> cb = {});

} // namespace bff
