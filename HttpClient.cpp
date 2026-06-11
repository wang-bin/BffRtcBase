

#include "HttpClient.h"
#include "Cert.h"
#include "SniUrl.h"
#include "Log.hpp"
#define TAG "curl.http"
#if __has_include(<curl/curl.h>)
#include "restincurl.h"
#endif
#include <vector>
#include <zlib.h>

// TODO: HOST header, cert selected, response headers

using namespace std;

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
    switch (curlCode) {
        case CURLE_SSL_CACERT:
        case CURLE_SSL_CACERT_BADFILE:
        case CURLE_SSL_CRL_BADFILE:
        case CURLE_SSL_ISSUER_ERROR:
        case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
        case CURLE_SSL_INVALIDCERTSTATUS:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_ENGINE_NOTFOUND:
        case CURLE_SSL_ENGINE_SETFAILED:
        // all CURLE_SSL_*
            return true;
        default:
            return false;
    }
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
    restincurl::RequestBuilder& setOptions(restincurl::RequestBuilder& b) const {
        for (const auto& h : headers) {
            b.Header(h.data());
        }
        return b
            //.Option(CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA)
            .Option(CURLOPT_SSL_VERIFYPEER, 1L)
            .Option(CURLOPT_SSL_VERIFYHOST, sni.empty() ? 0L : 2L)
            .Option(CURLOPT_VERBOSE, 0L)
            .Option(CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);
    }

    template<typename StartRequest>
    void execute(const string& url, StartRequest&& startRequest, CompletionCallback&& cb) {
        const auto prepared = bff::prepare_url_for_sni(url, sni);
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
    d->sni = host;
    return *this;
}

void HttpClient::get(const std::string& url, CompletionCallback&& cb)
{
    d->execute(url, [](const std::unique_ptr<restincurl::RequestBuilder>& pb, const string& preparedUrl) -> restincurl::RequestBuilder& {
        return pb->Get(preparedUrl);
    }, std::move(cb));
}

void HttpClient::post(const std::string& url, CompletionCallback&& cb)
{
    d->execute(url, [](const std::unique_ptr<restincurl::RequestBuilder>& pb, const string& preparedUrl) -> restincurl::RequestBuilder& {
        return pb->Post(preparedUrl);
    }, std::move(cb));
}

void HttpClient::post(const std::string& url, std::string&& body, CompletionCallback&& cb)
{
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
#endif // LIBCURL_VERSION_MAJOR
