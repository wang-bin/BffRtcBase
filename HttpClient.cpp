

#include "HttpClient.h"
#include "Cert.h"
#if __has_include(<curl/curl.h>)
#include "restincurl.h"
#endif
#include <vector>

// TODO: sni, HOST header, cert selected, response headers

using namespace std;

#ifdef LIBCURL_VERSION_MAJOR
static CURLcode ssl_ctx_callback(CURL* curl, void* ssl_ctx, void* userdata) {
    //SSL_CTX_set_cert_verify_callback((SSL_CTX*)ssl_ctx, my_cert_verify_callback, NULL);
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

class HttpClient::Private
{
public:
    restincurl::RequestBuilder& SetOptions(restincurl::RequestBuilder& b) {
        for (const auto& h : headers) {
            b.Header(h.data());
        }
        if (!sni.empty()) {
            //b.Option(CURLOPT_RESOLVE, )
        } else {
            //b.Option(CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_SNI);
        }
        return b
            //.Option(CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA)
            .Option(CURLOPT_SSL_VERIFYPEER, 1L)
            .Option(CURLOPT_SSL_VERIFYHOST, 0L) // SSL: no alternative certificate subject name matches target ipv4 address '123.60.148.205'
            //.Option(CURLOPT_CAINFO, nullptr)
            //.Option(CURLOPT_CAPATH, nullptr)
            .Option(CURLOPT_VERBOSE, 1L)
            .Option(CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);
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

void HttpClient::get(const std::string& url, CompletionCallback&& cb)
{
    // FIXME: b = ... crash
    auto pb = client().Build();
    auto& b = d->SetOptions(pb->Get(url));
    if (cb) {
        b.WithCompletion([cb](const restincurl::Result& r){
            cb(from(r));
        });
    }
    b.Execute();
}

void HttpClient::post(const std::string& url, CompletionCallback&& cb)
{
    auto pb = client().Build();
    auto& b = d->SetOptions(pb->Post(url));
    if (cb) {
        b.WithCompletion([cb](const restincurl::Result& r){
            cb(from(r));
        });
    }
    b.Execute();
}


void HttpClient::post(const std::string& url, std::string&& body, CompletionCallback&& cb)
{
    auto pb = client().Build();
    auto& b = d->SetOptions(pb->Post(url))
        .WithJson(std::move(body))
    ;
    if (cb) {
        b.WithCompletion([cb](const restincurl::Result& r){
            cb(from(r));
        });
    }
    b.Execute();
}

#endif // LIBCURL_VERSION_MAJOR
