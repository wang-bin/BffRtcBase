

#include "HttpClient.h"
#include "restincurl.h"
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include "ssl_roots.h"
#include <vector>

using namespace std;

extern unsigned char laser_ca_der[];
extern unsigned int laser_ca_der_len;

static string XorCertData(const unsigned char *bytes, unsigned int len)
{
    if (!bytes || len == 0) {
        return {};
    }

    const uint16_t key = 0x0bff;
    string out;
    out.reserve(len);
    out.resize(len);


    for (unsigned int i = 0; i < len; ++i) {
        out[i] = (uint8_t)(((uint16_t)bytes[i]) ^ key);
    }
    return out;
}

static const vector<string>& PinnedCerts()
{
    static const vector<string> certs = []{
        vector<string> certs;
        certs.push_back(XorCertData(laser_ca_der, laser_ca_der_len));
        return certs;
    }();
    return certs;
}

#if 0
static int my_cert_verify_callback(X509_STORE_CTX* store, void* arg) {
    // 获取证书和目标主机名
    SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    const char* target_hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    //SSL_get_app_data


    // 检查失败原因是否是主机名不匹配
    int err = X509_STORE_CTX_get_error(store);
    if (err == X509_V_ERR_HOSTNAME_MISMATCH) {
        // 自定义：允许特定的 IP 地址
        // 比如允许 123.60.148.205
        // 注意：这里不能直接获取目标 IP，需要您自己判断上下文
        // 可以预先设置允许的 IP 列表，或者直接允许所有
        return 1;  // 忽略主机名错误
    }
    return 0;  // 其他错误仍然拒绝

}
#endif

static bool openssl_add_cert_der(SSL_CTX *ctx, const uint8_t* data, size_t len)
{
    // 1. Get a pointer to the existing X509 certificate store (This store already contains the default system CAs loaded by curl)
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        fprintf(stderr, "Failed to get OpenSSL certificate store.\n");
        return false;
    }
    // 2. Load your custom pinned CA from memory or a buffer (You can also use X509_LOOKUP_file if loading from a file path)
#if USE_CA_PEM
    const char *pinned_ca_pem =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIB... Your Custom CA Certificate Data Here ...\n"
        "-----END CERTIFICATE-----\n";

    BIO *bio = BIO_new_mem_buf(pinned_ca_pem, -1);
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
#else
    // Initialize a memory BIO with the DER byte array
    //BIO *bio = BIO_new_mem_buf(pinned_ca_der, pinned_ca_der_len);

    // Read the binary DER data into an X509 structure
    //X509 *cert = d2i_X509_bio(bio, NULL);
    //BIO_free(bio);
    X509* cert = d2i_X509(nullptr, &data, len);
#endif
    if (!cert) {
        fprintf(stderr, "Failed to parse custom pinned CA certificate: %s\n", ERR_reason_error_string(ERR_peek_last_error()));
        return false;
    }

    // 3. Inject the pinned CA into the active store alongside the default CAs
    if (X509_STORE_add_cert(store, cert) != 1) {
        // Note: It might return 0 if the cert is already present, which is fine
        auto err = ERR_peek_last_error();
        if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
            fprintf(stderr, "Failed to add certificate to store: %s\n", ERR_reason_error_string(err));
            X509_free(cert);
            return false;
        }
    }

    // Free the local reference (the store increments the reference internal count)
    X509_free(cert);
    return true;
}


bool LoadBuiltinSSLRootCertificates(SSL_CTX* ctx) {
  int count_of_added_certs = 0;
  for (size_t i = 0; i < std::size(kSSLCertCertificateList); i++) {
    const unsigned char* cert_buffer = kSSLCertCertificateList[i];
    size_t cert_buffer_len = kSSLCertCertificateSizeList[i];
    X509* cert = d2i_X509(nullptr, &cert_buffer, cert_buffer_len);  // NOLINT
    if (cert) {
      int return_value = X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert);
      if (return_value == 0) {
        //RTC_LOG(LS_WARNING) << "Unable to add certificate.";
      } else {
        count_of_added_certs++;
      }
      X509_free(cert);
    }
  }
  return count_of_added_certs > 0;
}

static CURLcode ssl_ctx_callback(CURL* curl, void* ssl_ctx, void* userdata) {
    SSL_CTX *ctx = (SSL_CTX *)ssl_ctx;
    //SSL_CTX_set_cert_verify_callback((SSL_CTX*)ssl_ctx, my_cert_verify_callback, NULL);

    LoadBuiltinSSLRootCertificates(ctx);
    //SSL_CTX_set_default_verify_paths(ctx);
    for (const auto& c : PinnedCerts()) {
        if (!openssl_add_cert_der(ctx, (const uint8_t*)c.data(), c.size()))
            return CURLE_ABORTED_BY_CALLBACK;
    }

    // Return CURLE_OK to allow curl to proceed with the handshake
    return CURLE_OK;
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
                .responseBody = r.body,
                .error = r.msg,
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
