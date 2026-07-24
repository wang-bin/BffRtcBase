#pragma once

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
