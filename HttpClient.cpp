

#include "HttpClient.h"
#include "Cert.h"
#include "SniUrl.h"
#include "Log.hpp"
#define TAG "curl.http"
#if __has_include(<curl/curl.h>)
#include "restincurl.h"
#endif
#include <mutex>
#include <vector>
#include <zlib.h>

#define TAG "curl.http"
// TODO: HOST header, cert selected, response headers

using namespace std;

namespace {

std::mutex g_auth_token_mtx;
std::string g_auth_token;

// Replace existing token= query value; leave URL unchanged if no token= present.
std::string replaceTokenQuery(const std::string& url, const std::string& token) {
    if (token.empty()) {
        return url;
    }
    const std::string key = "token=";
    size_t pos = std::string::npos;
    for (size_t i = 0; i + key.size() <= url.size(); ++i) {
        if ((url[i] == '?' || url[i] == '&') && url.compare(i + 1, key.size(), key) == 0) {
            pos = i + 1;
            break;
        }
    }
    if (pos == std::string::npos) {
        return url;
    }
    const size_t valueStart = pos + key.size();
    size_t valueEnd = url.find('&', valueStart);
    if (valueEnd == std::string::npos) {
        valueEnd = url.size();
    }
    return url.substr(0, valueStart) + token + url.substr(valueEnd);
}

} // namespace

void HttpClient::setAuthToken(std::string token) {
    std::lock_guard<std::mutex> lock(g_auth_token_mtx);
    g_auth_token = std::move(token);
}

std::string HttpClient::authToken() {
    std::lock_guard<std::mutex> lock(g_auth_token_mtx);
    return g_auth_token;
}

std::string HttpClient::urlWithAuthToken(const std::string& url) {
    std::string token;
    {
        std::lock_guard<std::mutex> lock(g_auth_token_mtx);
        token = g_auth_token;
    }
    return replaceTokenQuery(url, token);
}

#ifdef LIBCURL_VERSION_MAJOR
static CURLcode ssl_ctx_callback(CURL* curl, void* ssl_ctx, void* userdata) {
    (void)curl;
    (void)userdata;
    if (!AddCertsToSSL(ssl_ctx))
        return CURLE_ABORTED_BY_CALLBACK;
    return CURLE_OK;
}

bool HttpClient::Result::isSecError() const
{
    return bff::IsCurlSecError(curlCode);
}

static restincurl::Client& client()
{
    static restincurl::Client c;
    return c;
}

HttpClient::Result from(const restincurl::Result& r)
{
    return {
                .httpCode = (int)r.http_response_code,
                .bytesSent = (int)r.bytes_sent,
                .responseBody = r.body,
                .error = r.msg,
                .curlCode = (int)r.curl_code,
            };
}

class HttpClient::Private
{
public:
    int connectTimeout = -1;

    restincurl::RequestBuilder& setOptions(restincurl::RequestBuilder& b) const {
        for (const auto& h : headers) {
            b.Header(h.data());
        }
        if (connectTimeout > 0) {
            b.ConnectTimeout(connectTimeout);
        }
        return b
            //.Option(CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA)
            .Option(CURLOPT_SSL_VERIFYPEER, 1L)
            .Option(CURLOPT_SSL_VERIFYHOST, 0L) // SSL: no alternative certificate subject name matches target ipv4 address '123.60.148.205'
            //.Option(CURLOPT_SSL_VERIFYHOST, sni.empty() ? 0L : 2L)
            .Option(CURLOPT_VERBOSE, 0L)
            .Option(CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);
    }

    template<typename StartRequest>
    void execute(const string& url, StartRequest&& startRequest, CompletionCallback&& cb) {
        const auto urlAuthed = HttpClient::urlWithAuthToken(url);
        const auto prepared = bff::prepare_url_for_sni(urlAuthed, sni);
        curl_slist *resolve_list = nullptr;
        if (!prepared.resolve.empty()) {
            resolve_list = curl_slist_append(nullptr, prepared.resolve.c_str());
        }

        auto pb = client().Build();
        auto& b = setOptions(startRequest(pb, prepared.url));
        if (resolve_list) {
            b.Option(CURLOPT_RESOLVE, resolve_list);
        }

        b.WithCompletion([cb = std::move(cb), resolve_list](const restincurl::Result& r) mutable {
            if (resolve_list) {
                curl_slist_free_all(resolve_list);
            }
            if (cb) {
                cb(from(r));
            }
        });
        b.Execute();
    }

    string sni;
    vector<string> headers;
};

HttpClient::HttpClient()
    : d(make_unique<Private>())
{
}

HttpClient::~HttpClient() = default;

HttpClient& HttpClient::header(const std::string& name, const std::string& value)
{
    d->headers.emplace_back(name + ": " + value);
    return *this;
}

HttpClient& HttpClient::sni(const std::string& host)
{
    LOGD("sni %s", host.c_str());
    d->sni = host;
    return *this;
}

HttpClient& HttpClient::setConnectTimeout(int ms)
{
    d->connectTimeout = ms;
    return *this;
}

void HttpClient::get(const std::string& url, CompletionCallback&& cb)
{
    LOGD("GET");
    d->execute(url, [](const std::unique_ptr<restincurl::RequestBuilder>& pb, const string& preparedUrl) -> restincurl::RequestBuilder& {
        return pb->Get(preparedUrl);
    }, std::move(cb));
}

void HttpClient::post(const std::string& url, CompletionCallback&& cb)
{
    LOGD("POST");
    d->execute(url, [](const std::unique_ptr<restincurl::RequestBuilder>& pb, const string& preparedUrl) -> restincurl::RequestBuilder& {
        return pb->Post(preparedUrl);
    }, std::move(cb));
}

void HttpClient::post(const std::string& url, std::string&& body, CompletionCallback&& cb)
{
    LOGD("POST with body");
    d->execute(url, [&body](const std::unique_ptr<restincurl::RequestBuilder>& pb, const string& preparedUrl) -> restincurl::RequestBuilder& {
        return pb->Post(preparedUrl).WithJson(std::move(body));
    }, std::move(cb));
}

string gzip(const string& data)
{
    if (data.empty())
        return {};
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};
    string output;
    auto capacity = deflateBound(&stream, data.size());
    output.reserve(capacity);
    output.resize(capacity);
    stream.next_in  = (Bytef *)data.data();
    stream.avail_in = (uInt)data.size();
    stream.next_out  = (Bytef *)output.data();
    stream.avail_out = (uInt)capacity;
    if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&stream);
        return {};
    }
    output.resize(stream.total_out);
    deflateEnd(&stream);
    return output;
}

void HttpClient::postGz(const std::string& url, std::string&& uncompressedBody, CompletionCallback&& cb)
{
    auto data = gzip(uncompressedBody);
    if (data.empty()) {
        if (cb) {
            cb({.httpCode = 0, .bytesSent = 0, .responseBody = {}, .error = "gzip failed", .curlCode = 0});
        }
        return;
    }
    header("Content-Encoding", "gzip");
    post(url, std::move(data), std::move(cb));
}

void HttpClient::request(const std::string& url, const std::string& method, std::string&& body, CompletionCallback&& cb)
{
    if (method == "GET") {
        get(url, std::move(cb));
    } else if (method == "POST") {
        post(url, std::move(body), std::move(cb));
    } else {
        if (cb) {
            cb({.httpCode = 0, .bytesSent = 0, .responseBody = {}, .error = "method not supported", .curlCode = 0});
        }
    }
}

#else

bool HttpClient::Result::isSecError() const
{
    return false;
}

class HttpClient::Private {};

HttpClient::HttpClient()
{
}

HttpClient::~HttpClient()
{
}

HttpClient& HttpClient::header(const std::string& name, const std::string& value)
{
    return *this;
}

HttpClient& HttpClient::sni(const std::string& host)
{
    return *this;
}

HttpClient& HttpClient::setConnectTimeout(int ms)
{
    return *this;
}

void HttpClient::get(const std::string& url, CompletionCallback&& cb)
{
    if (cb) {
        cb({.httpCode = 0, .bytesSent = 0, .responseBody = {}, .error = "not implemented", .curlCode = 0});
    }
}

void HttpClient::post(const std::string& url, CompletionCallback&& cb)
{
    if (cb) {
        cb({.httpCode = 0, .bytesSent = 0, .responseBody = {}, .error = "not implemented", .curlCode = 0});
    }
}

void HttpClient::post(const std::string& url, std::string&& body, CompletionCallback&& cb)
{
    if (cb) {
        cb({.httpCode = 0, .bytesSent = 0, .responseBody = {}, .error = "not implemented", .curlCode = 0});
    }
}

void HttpClient::postGz(const std::string& url, std::string&& uncompressedBody, CompletionCallback&& cb)
{
    if (cb) {
        cb({.httpCode = 0, .bytesSent = 0, .responseBody = {}, .error = "not implemented", .curlCode = 0});
    }
}

void HttpClient::request(const std::string& url, const std::string& method, std::string&& body, CompletionCallback&& cb)
{
    if (cb) {
        cb({.httpCode = 0, .bytesSent = 0, .responseBody = {}, .error = "not implemented", .curlCode = 0});
    }
}
#endif // LIBCURL_VERSION_MAJOR
