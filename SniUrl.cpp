#include "SniUrl.h"

#if defined(__ANDROID__) || defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#endif

namespace bff {
using namespace std;

bool is_numeric_host(const string& host) {
    if (host.empty()) {
        return false;
    }
    if (host.front() == '[') {
        return true;
    }
#if defined(__ANDROID__) || defined(__linux__) || defined(__APPLE__)
    struct in_addr v4 {};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        return true;
    }
    struct in6_addr v6 {};
    if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
        return true;
    }
#endif
    return false;
}

static int default_port_for_scheme(const string& scheme) {
    if (scheme == "https" || scheme == "wss") {
        return 443;
    }
    if (scheme == "http" || scheme == "ws") {
        return 80;
    }
    return 0;
}

static bool is_supported_scheme(const string& scheme) {
    return scheme == "http" || scheme == "https" || scheme == "ws" || scheme == "wss";
}

PreparedUrl prepare_url_for_sni(const string& url, const string& sni_host) {
    PreparedUrl out{url, {}};
    if (sni_host.empty()) {
        return out;
    }

    const auto scheme_pos = url.find("://");
    if (scheme_pos == string::npos) {
        return out;
    }

    const string scheme = url.substr(0, scheme_pos);
    if (!is_supported_scheme(scheme)) {
        return out;
    }

    const size_t host_start = scheme_pos + 3;
    const size_t path_start = url.find('/', host_start);
    const string authority = path_start == string::npos
        ? url.substr(host_start)
        : url.substr(host_start, path_start - host_start);
    const string path = path_start == string::npos ? "/" : url.substr(path_start);

    string connect_host;
    string port;
    if (!authority.empty() && authority.front() == '[') {
        const auto bracket_end = authority.find(']');
        if (bracket_end == string::npos) {
            return out;
        }
        connect_host = authority.substr(1, bracket_end - 1);
        if (bracket_end + 1 < authority.size() && authority[bracket_end + 1] == ':') {
            port = authority.substr(bracket_end + 2);
        }
    } else {
        const auto colon = authority.rfind(':');
        if (colon != string::npos && authority.find(':') == colon) {
            connect_host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        } else {
            connect_host = authority;
        }
    }

    if (connect_host.empty() || connect_host == sni_host) {
        return out;
    }

    if (port.empty()) {
        port = to_string(default_port_for_scheme(scheme));
    }

    out.url = scheme + "://" + sni_host + ":" + port + path;
    if (is_numeric_host(connect_host)) {
        out.resolve = sni_host + ":" + port + ":" + connect_host;
    }
    return out;
}

} // namespace bff
