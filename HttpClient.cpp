

#include "HttpClient.h"
#include "Cert.h"
#include "FileLogger.hpp"
#include "SniUrl.h"
#include "defs.h"
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

namespace bff {
namespace {

std::string hostFromHttpUrl(const std::string& url)
{
    auto pos = url.find("://");
    if (pos == std::string::npos) {
        return {};
    }
    pos += 3;
    if (pos >= url.size()) {
        return {};
    }
    if (url[pos] == '[') {
        const auto end = url.find(']', pos);
        if (end == std::string::npos) {
            return {};
        }
        return url.substr(pos + 1, end - pos - 1);
    }
    const auto end = url.find_first_of(":/?", pos);
    if (end == std::string::npos) {
        return url.substr(pos);
    }
    return url.substr(pos, end - pos);
}

uint16_t portFromHttpUrl(const std::string& url)
{
    auto pos = url.find("://");
    if (pos == std::string::npos) {
        return 0;
    }
    const std::string scheme = url.substr(0, pos);
    pos += 3;
    std::string::size_type hostEnd = pos;
    if (pos < url.size() && url[pos] == '[') {
        hostEnd = url.find(']', pos);
        if (hostEnd == std::string::npos) {
            return 0;
        }
        ++hostEnd;
    } else {
        hostEnd = url.find_first_of(":/?", pos);
        if (hostEnd == std::string::npos) {
            hostEnd = url.size();
        }
    }
    uint16_t port = 0;
    if (hostEnd < url.size() && url[hostEnd] == ':') {
        const auto portEnd = url.find_first_of("/?", hostEnd + 1);
        const auto portStr = url.substr(hostEnd + 1,
                                        (portEnd == std::string::npos ? url.size() : portEnd) - (hostEnd + 1));
        unsigned long p = 0;
        bool ok = !portStr.empty();
        for (char c : portStr) {
            if (c < '0' || c > '9') {
                ok = false;
                break;
            }
            p = p * 10 + static_cast<unsigned long>(c - '0');
            if (p > 65535) {
                ok = false;
                break;
            }
        }
        if (ok && p > 0) {
            port = static_cast<uint16_t>(p);
        }
    }
    if (port != 0) {
        return port;
    }
    if (scheme == "https" || scheme == "wss") {
        return 443;
    }
    if (scheme == "http" || scheme == "ws") {
        return 80;
    }
    return 0;
}

// Match ObjC/Java HTTP: Config.sni + hosts map, fallback to first value.
std::string resolveSniHost(const std::string& url)
{
    const auto& cfg = Config::Shared();
    if (!cfg.sni || cfg.hosts.empty()) {
        return {};
    }
    const auto host = hostFromHttpUrl(url);
    if (host.empty()) {
        return {};
    }
    if (const auto it = cfg.hosts.find(host); it != cfg.hosts.end()) {
        return it->second;
    }
    const auto port = portFromHttpUrl(url);
    if (port != 0) {
        const auto hostWithPort = host + ":" + std::to_string(port);
        if (const auto it = cfg.hosts.find(hostWithPort); it != cfg.hosts.end()) {
            return it->second;
        }
    }
    WARN("no host for %s, use the first", host.c_str());
    return cfg.hosts.begin()->second;
}

} // namespace

void generateToken(const std::string& url, HttpClient::CompletionCallback cb)
{
    INFO("generateToken %s", url.c_str());
    HttpClient client;
    if (const auto sni = resolveSniHost(url); !sni.empty()) {
        client.sni(sni);
    }
    client.get(url, std::move(cb));
}

std::string basenameFromPath(const std::string& path)
{
    const auto slash = path.find_last_of('/');
    if (slash == std::string::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

// Strip scheme/port like Android HttpHelper.getHost(String).
std::string hostOnly(std::string s)
{
    const auto scheme = s.find("://");
    if (scheme != std::string::npos) {
        s = s.substr(scheme + 3);
    } else {
        const auto firstColon = s.find(':');
        const auto lastColon = s.rfind(':');
        if (firstColon != std::string::npos && lastColon != std::string::npos && lastColon > firstColon) {
            s = s.substr(firstColon + 1);
        }
    }
    if (const auto colon = s.rfind(':'); colon != std::string::npos) {
        s = s.substr(0, colon);
    }
    return s;
}

std::string replaceUrlHost(const std::string& url, const std::string& newHost)
{
    const auto schemePos = url.find("://");
    if (schemePos == std::string::npos || newHost.empty()) {
        return url;
    }
    const auto hostStart = schemePos + 3;
    if (hostStart >= url.size()) {
        return url;
    }
    std::string::size_type hostEnd = hostStart;
    if (url[hostStart] == '[') {
        hostEnd = url.find(']', hostStart);
        if (hostEnd == std::string::npos) {
            return url;
        }
        ++hostEnd;
    } else {
        hostEnd = url.find_first_of(":/?", hostStart);
        if (hostEnd == std::string::npos) {
            hostEnd = url.size();
        }
    }
    return url.substr(0, hostStart) + newHost + url.substr(hostEnd);
}

std::string urlEncodeQueryComponent(const std::string& value)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size() * 3);
    for (unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

// Match iOS/Android: id-yyyyMMddHHmmss±zzzz.log → yyyyMMdd/room/id.log when room is set.
std::string uploadLogName(const std::string& basename, const std::string& room)
{
    if (room.empty()) {
        return basename;
    }
    const auto tz = basename.find_last_of("+-");
    if (tz == std::string::npos || tz <= 14) {
        return basename;
    }
    const auto yyyyMMdd = basename.substr(tz - 14, 8);
    const auto dash = basename.find('-');
    if (dash == std::string::npos || dash == 0) {
        return basename;
    }
    return yyyyMMdd + "/" + room + "/" + basename.substr(0, dash) + ".log";
}

std::string appendNameQuery(const std::string& url, const std::string& encodedName)
{
    if (url.find('?') == std::string::npos) {
        return url + "?name=" + encodedName;
    }
    return url + "&name=" + encodedName;
}

void uploadLog(const std::string& uploadUrl,
               std::string payload,
               const std::string& logPathOrName,
               HttpClient::CompletionCallback cb)
{
    auto name = basenameFromPath(logPathOrName);
    INFO("uploadLog name=%s url=%s size=%zu", name.c_str(), uploadUrl.c_str(), payload.size());

    const auto& logger = FileLogger::shared();
    const auto room = logger.getRoom(name);
    const auto uploadServer = logger.getUploadServer(name);
    name = uploadLogName(name, room);
    const auto encodedName = urlEncodeQueryComponent(name);

    std::string url = uploadUrl;
    if (!uploadServer.empty()) {
        url = replaceUrlHost(url, hostOnly(uploadServer));
    }
    url = appendNameQuery(url, encodedName);

    HttpClient client;
    client.header("Content-Type", "application/json");
    client.header("Accept", "application/json, text/plain, */*");
    if (const auto sni = resolveSniHost(url); !sni.empty()) {
        client.sni(sni);
    }

#ifdef LIBCURL_VERSION_MAJOR
    auto compressed = gzip(payload);
#else
    std::string compressed;
#endif
    const auto payloadSize = payload.size();
    auto onComplete = [cb = std::move(cb), payloadSize, name = encodedName](const HttpClient::Result& r) {
        if (r.curlCode && !r.error.empty()) {
            WARN("uploadLog error after sending %d/%zu bytes, code=%d name=%s: %s", r.bytesSent, payloadSize,
                 r.httpCode, name.c_str(), r.error.c_str());
        } else if (r.httpCode != 200) {
            WARN("uploadLog failed after sending %d/%zu bytes, response code: %d name=%s", r.bytesSent,
                 payloadSize, r.httpCode, name.c_str());
        } else {
            INFO("uploadLog done, sent %d/%zu bytes, response: %s name=%s", r.bytesSent, payloadSize,
                 r.responseBody.c_str(), name.c_str());
            if (r.responseBody.find("\"error\"") != std::string::npos) {
                WARN("uploadLog response contains error name=%s", name.c_str());
            }
        }
        if (cb) {
            cb(r);
        }
    };

    if (!compressed.empty()) {
        INFO("uploadLog gzip %zu => %zu name=%s", payloadSize, compressed.size(), encodedName.c_str());
        client.header("Content-Encoding", "gzip");
        client.post(url, std::move(compressed), std::move(onComplete));
    } else {
        if (!payload.empty()) {
            WARN("uploadLog gzip failed, fallback uncompressed size=%zu name=%s", payloadSize,
                 encodedName.c_str());
        }
        client.post(url, std::move(payload), std::move(onComplete));
    }
}

} // namespace bff
