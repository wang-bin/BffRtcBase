#pragma once

#include <string>

namespace bff {

struct PreparedUrl {
    std::string url;
    std::string resolve;
};

bool is_numeric_host(const std::string& host);

// libcurl sets TLS SNI from the URL hostname. When connecting to an IP, rewrite
// the URL to the SNI name and pin the IP with CURLOPT_RESOLVE.
PreparedUrl prepare_url_for_sni(const std::string& url, const std::string& sni_host);

} // namespace bff
