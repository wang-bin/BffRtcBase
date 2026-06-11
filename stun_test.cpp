#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <array>
#include <cstring>
#include <chrono>
#include <string>
#include <random>
#include <set>
#include <span>
#include <map>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <ctime>
#include "Log.hpp"
#define TAG "stun"
using namespace std;

constexpr uint16_t kBindingRequest = 0x0001;
constexpr uint16_t kBindingResponse = 0x0101;
constexpr uint16_t kXorMappedAddress = 0x0020;
constexpr uint32_t kMagicCookie = 0x2112A442;

using transaction_idt = array<uint8_t, 12>; // rfc 5389 12 bytes

// https://datatracker.ietf.org/doc/html/rfc5389#section-6
struct __attribute__((packed)) StunRequest {
    StunRequest() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& i : transaction_id) {
            i = dis(gen);
        }
    }
    const int16_t msg_type = htons(kBindingRequest);
    const int16_t msg_len = htons(0x0000);
    const int32_t magic_cookie = htonl(kMagicCookie);
    transaction_idt transaction_id;
};

// https://datatracker.ietf.org/doc/html/rfc5389#section-7
struct __attribute__((packed)) StunResponse {
    int16_t msg_type;
    int16_t msg_len;
    int32_t magic_cookie;
    transaction_idt transaction_id;
    std::array<uint8_t, 1000> attributes;
};

struct IPAndPort {
    std::string ip;
    uint16_t port = 0;
    string host;
};

// Converts a host name into an IP address.
static std::string HostnameToIP(std::string const& hostname) {
    const struct addrinfo hints{
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *svInfo;
    if (auto ret = getaddrinfo(hostname.c_str(), "http", &hints, &svInfo); ret != 0) {
        return {};
    }
    string ip;
    for (auto p = svInfo; p; p = p->ai_next) {
        auto h = (struct sockaddr_in*)p->ai_addr;
        char ipc[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &h->sin_addr, ipc, INET_ADDRSTRLEN);
        ip = ipc;
    }
    freeaddrinfo(svInfo);
    return ip;
}

static string getServerKey(const sockaddr_in& addr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
    return std::string(ip);
}

bool parse(const StunResponse& resp, const transaction_idt& tid, string* clientIp)
{
    if (resp.magic_cookie != htonl(kMagicCookie)) {
        DBG("magic cookie of response does not match");
        return false;
    }
    if (resp.transaction_id != tid) {
        DBG("incorrect transaction id");
        return false;
    }
    if (resp.msg_type != htons(kBindingResponse)) {
        DBG("incorrect message type");
        return false;
    }
    auto const& attrbs = resp.attributes;
    int16_t attrbs_length = std::min<int16_t>(htons(resp.msg_len), resp.attributes.size());
    int i = 0;
    while (i < attrbs_length) {
        auto attrb_type = htons(*(int16_t*)(&attrbs[i]));
        auto attrb_length = htons(*(int16_t*)(&attrbs[i + 2]));
        if (attrb_type == kXorMappedAddress) {
            uint16_t port = ntohs(*(uint16_t*)(&attrbs[i + 6]));
            port ^= (kMagicCookie >> 16);
            std::string ip = std::to_string(attrbs[i + 8] ^ ((kMagicCookie & 0xff000000) >> 24)) + "." +
                             std::to_string(attrbs[i + 9] ^ ((kMagicCookie & 0x00ff0000) >> 16)) + "." +
                             std::to_string(attrbs[i + 10] ^ ((kMagicCookie & 0x0000ff00) >> 8 )) + "." +
                             std::to_string(attrbs[i + 11] ^ ((kMagicCookie & 0x000000ff) >> 0 ));
            if (clientIp) {
                *clientIp = ip;// + ":" + std::to_string(port);
            }
            return true;
        }
        i += (4 + attrb_length);
    }
    return false;
}

vector<std::pair<string, int>> SortStun(const span<IPAndPort>& servers, int timeoutMs, string* clientIp = nullptr, bool fastestOnly = false) {
    if (servers.empty()) {
        DBG("No valid STUN server");
        return {};
    }
    int cfd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//0);
    if (cfd_ < 0) {
        DBG("Open socket failed: %s", strerror(errno));
        return {};
    }
    int flags = fcntl(cfd_, F_GETFL, 0);
    if (flags == -1 || fcntl(cfd_, F_SETFL, flags | O_NONBLOCK) == -1) {
        DBG("Set non-blocking failed: %s", strerror(errno));
        return {};
    }
    const struct sockaddr_in caddr{
        .sin_family = AF_INET,
        .sin_port = htons(0), // any port
        .sin_addr = {.s_addr = INADDR_ANY},
    };
    int err = 0;
    if ((err = ::bind(cfd_, (const struct sockaddr*)&caddr, sizeof(caddr))) < 0) {
        DBG("bind failed: %s", strerror(errno));
        close(cfd_);
        return {};
    }
    unordered_map<string, transaction_idt> transaction_map_;
    unordered_map<string, std::chrono::steady_clock::time_point> time_map_;

    for (const auto& sv : servers) {
        DBG("Sending STUN request to %s:%d %s", sv.ip.c_str(), sv.port, sv.host.c_str());
        const struct sockaddr_in saddr{
            .sin_family = AF_INET,
            .sin_port = htons(sv.port),
            .sin_addr = {.s_addr = inet_addr(sv.ip.c_str())},
        };
        time_map_[getServerKey(saddr)] = std::chrono::steady_clock::now();
        StunRequest req;
        if ((err = sendto(cfd_, &req, sizeof(req), 0, (const struct sockaddr*)&saddr, (socklen_t)sizeof(saddr))) < 0) {
            DBG("sendto %s:%u failed: %s", sv.ip.c_str(), sv.port, strerror(errno));
            continue;
        }
        transaction_map_[getServerKey(saddr)] = req.transaction_id;
    }

    DBG("polling for STUN responses...");
    pollfd pfd{
        .fd = cfd_,
        .events = POLLIN,
    };

    vector<std::pair<string, int>> sorted;
    auto now = std::chrono::steady_clock::now();
    while (true) {
        if (timeoutMs > 0 && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - now).count() > timeoutMs) {
            DBG("timeout reached");
            break;
        }
        auto ret = poll(&pfd, 1, 20);
        if (ret < 0) {
            DBG("poll failed: %s", strerror(errno));
            break;
        } else if (ret == 0) {
            //DBG("poll timeout");
            continue;
        }
        if (!(pfd.revents & POLLIN)) {
            continue;
        }
        StunResponse resp;
        struct sockaddr_in sv{};
        socklen_t svLen = sizeof(sv);
        auto n = recvfrom(cfd_, &resp, sizeof(resp), 0, (struct sockaddr*)&sv, &svLen);
        if (n < 0) {
            DBG("recvfrom failed from %s:%d: %s", inet_ntoa(sv.sin_addr), ntohs(sv.sin_port), strerror(errno));
            break;
        }
        const auto key = getServerKey(sv);
        const auto elapsed = duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - time_map_[key]).count();
        string cip;
        if (!parse(resp, transaction_map_[key], &cip)) {
            DBG("invalid stun response from %s", key.c_str());
            continue;
        }
        if (clientIp)
            *clientIp = cip;
        DBG("client ip from stun %s: %s, elapsed: %lldms", key.data(), cip.c_str(), elapsed);
        sorted.emplace_back(key, elapsed);
        if (sorted.size() == servers.size()) {
            break;
        }
        if (fastestOnly) {
            break;
        }
    }
    close(cfd_);
    return sorted;
}

string QueryFastestStun(const span<IPAndPort>& servers, int timeoutMs, string* clientIp = nullptr)
{
    auto sorted = SortStun(servers, timeoutMs, clientIp, true);
    if (sorted.empty()) {
        return {};
    }
    return sorted[0].first;
}

static vector<IPAndPort> toIpPorts(const set<string>& servers)
{
    vector<IPAndPort> ipPorts;
    ipPorts.reserve(servers.size());
    for (const auto& svr : servers) {
        auto ip = svr;
        string host;
        uint16_t port = 3478;
        if (auto colon = ip.find(':'); colon != string::npos) {
            port = static_cast<uint16_t>(atoi(&ip[colon + 1])); // port
            ip = ip.substr(0, colon);
        }
        if (ip[0] >= '0' && ip[0] <= '9') {
            // IP address
        } else {
            // Hostname
            host = ip;
            string resolvedIp = HostnameToIP(host);
            if (resolvedIp.empty()) {
                DBG("Failed to resolve hostname: %s", host.c_str());
                continue;
            }
            ip = resolvedIp;
        }
        ipPorts.emplace_back(std::move(ip), port, std::move(host));
    }
    return ipPorts;
}

string QueryFastestStun(const set<string>& servers, int timeoutMs, string* clientIp)
{
    auto ipPorts = toIpPorts(servers);
    return QueryFastestStun(ipPorts, timeoutMs, clientIp);
}

vector<std::pair<string, int>> SortStun(const set<string>& servers, int timeoutMs, string* clientIp)
{
    auto ipPorts = toIpPorts(servers);
    return SortStun(ipPorts, timeoutMs, clientIp);
}

static int loss(int rtt1, int rtt2)
{
    return rtt1*rtt1 + rtt2*rtt2;
}

string FindBestNode(const vector<pair<string, int>>& rtts1, vector<pair<string, int>> rtts2)
{
    map<int, string> lossMap;
    for (const auto& [ip, rtt] : rtts1) {
        auto it = std::find_if(rtts2.begin(), rtts2.end(), [&ip](const pair<string, int>& p) {
            return p.first == ip;
        });
        if (it != rtts2.end()) {
            int l = loss(rtt, it->second);
            DBG("Node %s, rtt [%d, %d], loss=%d", ip.c_str(), rtt, it->second, l);
            lossMap[l] = ip;
            rtts2.erase(it);
        }
    }
    if (lossMap.empty()) {
        return {};
    }
    return lossMap.begin()->second;
}

#ifdef BUILD_STUN_TEST
// 121.37.187.30 60.204.147.53 101.245.93.66 113.47.168.94 113.46.192.228 139.9.117.89 139.9.117.89 43.225.140.181 stun.cloudflare.com:3478 stun.l.google.com:19302 stun.chat.bilibili.com:3478 1.94.118.100:3478
int main(int argc, char* argv[]) {
    set<string> servers;
    int timeout = 1000; // 1s
    //servers.reserve(argc - 1);
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-timeout") == 0) {
            timeout = atoi(argv[++i]);
            continue;
        }
        servers.insert(argv[i]);
    }
    if (servers.empty()) {
        DBG("No valid STUN server");
        return 1;
    }
    DBG("Querying %zu STUN servers simultaneously...", servers.size());
    string clientIp;
#if 0
    string fastest = QueryFastestStun(servers, timeout, &clientIp);
    if (fastest.empty()) {
        DBG("No STUN server responded");
        return 2;
    }
    DBG("\nFastest STUN server: %s", fastest.c_str());
#endif
    auto now = std::chrono::steady_clock::now();
    auto sorted = SortStun(servers, timeout, &clientIp);
    DBG("\nSTUN servers sorted by response time:");
    for (const auto& [s, elapsed] : sorted) {
        DBG("%s = %dms", s.c_str(), elapsed);
    }

    if (!clientIp.empty()) {
        DBG("Public IP:Port = %s", clientIp.c_str());
    }
    DBG("Total time: %lld ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - now).count());
    return 0;
}
#endif
