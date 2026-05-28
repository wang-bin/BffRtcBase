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
        
        bool isSecError() const { return false; }
    };

    using CompletionCallback = std::function<void(const Result&)>;

    HttpClient();
    ~HttpClient();

    HttpClient& header(const std::string& name, const std::string& value);
    HttpClient& sni(const std::string& host);
    void get(const std::string& url, CompletionCallback&& cb = {});
    void post(const std::string& url, CompletionCallback&& cb = {});
    void post(const std::string& url, std::string&& body, CompletionCallback&& cb = {});

private:
    class Private;
    std::unique_ptr<Private> d;
};
