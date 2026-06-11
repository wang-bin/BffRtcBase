#include "NodeSelector.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <set>
#include <thread>

#include "HttpClient.h"
#include "defs.h"
#include "json.hpp"

// Reuse the existing STUN sorting helper used by ObjC NodeSelector.
#include "../stun_test.h"

namespace bff {

using json = nlohmann::json;

static constexpr const char* kComponent = "nodes";

// Minimal, local logging macro as requested (keeps base layer decoupled).
#define NODESEL_LOG(level, msg)                                                        \
    do {                                                                               \
        (void)(level);                                                                 \
        if ((msg) && *(msg)) {                                                         \
            std::fprintf(stderr, "[%s] %s\n", kComponent, (msg));                       \
        }                                                                              \
    } while (0)

struct NodeCache {
    std::mutex mtx;
    std::vector<std::string> nodes; // list without port
    std::string best_node;
    std::time_t nodes_time = 0;
    std::string nodes_info_json;
    std::string ip;
    std::string server_ip;
};

static NodeCache& cache() {
    static NodeCache c;
    return c;
}

static std::string hostFromAddr(const std::string& addr) {
    // Handles: proto://host:port/path, host:port, host
    std::string s = addr;
    const auto scheme = s.find("://");
    if (scheme != std::string::npos) {
        s = s.substr(scheme + 3);
    }
    const auto slash = s.find('/');
    if (slash != std::string::npos) {
        s = s.substr(0, slash);
    }
    // IPv6 "[...]" form: keep inside brackets.
    if (!s.empty() && s.front() == '[') {
        const auto rb = s.find(']');
        if (rb != std::string::npos) {
            return s.substr(1, rb - 1);
        }
        return s;
    }
    const auto colon = s.find(':');
    if (colon != std::string::npos) {
        return s.substr(0, colon);
    }
    return s;
}

static std::string replaceHost(const std::string& url, const std::string& oldHost, const std::string& newHost) {
    if (oldHost.empty()) return url;
    auto out = url;
    auto pos = out.find(oldHost);
    if (pos != std::string::npos) {
        out.replace(pos, oldHost.size(), newHost);
    }
    return out;
}

static std::string rttsToJsonObjectString(const NodeSelector::Rtts& ret) {
    json obj = json::object();
    for (const auto& kv : ret) {
        obj[kv.first] = kv.second;
    }
    return obj.dump();
}

NodeSelector::NodeSelector() {
    SetLogger([](const char* msg) {
        NODESEL_LOG(RtcLogLevel::Debug, msg);
    });
}

NodeSelector::~NodeSelector() {
    cancelConnectOperation();
}

void NodeSelector::setUpdateRttsCallback(UpdateRttsCallback cb) {
    on_update_rtts_ = std::move(cb);
}

void NodeSelector::updateRtts(const Rtts& result) {
    if (on_update_rtts_) {
        on_update_rtts_(result);
    }
}

void NodeSelector::setConnectCancelFlag(std::shared_ptr<std::atomic_bool> cancel) {
    std::lock_guard<std::mutex> lock(connect_cancel_mtx_);
    if (connect_cancel_) {
        connect_cancel_->store(true);
    }
    connect_cancel_ = std::move(cancel);
}

void NodeSelector::cancelConnectOperation() {
    setConnectCancelFlag(nullptr);
}

void NodeSelector::asyncSort(const std::vector<std::string>& nodesWithPort, const std::string* ip) {
    // Run STUN sort off-thread; cache best node.
    std::vector<std::string> nodesCopy = nodesWithPort;
    std::string ipCopy = ip ? *ip : std::string();

    std::thread([this, nodesCopy = std::move(nodesCopy), ipCopy = std::move(ipCopy)]() mutable {
        std::set<std::string> servers;
        for (const auto& s : nodesCopy) {
            servers.insert(s);
        }

        const auto start = std::chrono::steady_clock::now();
        bool save = true;
        auto ret = SortStun(servers, 2000, nullptr);
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - start)
                                    .count();

        if (ret.empty()) {
            save = false;
            // Fake results to ensure we can still join.
            for (const auto& s : servers) {
                ret.emplace_back(s, 0);
            }
        }

        updateRtts(ret);

        if (save) {
            // Persist in process memory (base layer has no NSUserDefaults).
            std::vector<std::string> nodesNoPort;
            nodesNoPort.reserve(nodesCopy.size());
            for (const auto& n : nodesCopy) {
                auto h = n;
                auto pos = h.find(':');
                if (pos != std::string::npos) {
                    h = h.substr(0, pos);
                }
                nodesNoPort.push_back(std::move(h));
            }

            auto info = rttsToJsonObjectString(ret);
            auto best = ret.empty() ? std::string() : ret.front().first;
            {
                std::lock_guard<std::mutex> lk(cache().mtx);
                cache().best_node = best;
                cache().nodes_time = std::time(nullptr);
                cache().nodes = std::move(nodesNoPort);
                cache().nodes_info_json = std::move(info);
                cache().ip = ipCopy;
            }
        }

        {
            std::unique_lock<std::mutex> lock(update_nodes_mtx_);
            update_nodes_count_ = 0;
        }
        update_nodes_cv_.notify_one();

        (void)elapsed_ms;
    }).detach();
}

void NodeSelector::updateNodes(const std::vector<std::string>& servers,
                               const std::string* token,
                               CompletionCallback completionHandler) {
    if (servers.empty()) {
        NODESEL_LOG(RtcLogLevel::Warn, "empty servers");
        if (completionHandler) completionHandler();
        return;
    }

    // ObjC version sorts bootstrap servers quickly (100ms) using STUN on :3478.
    std::vector<std::string> ss;
    ss.reserve(servers.size());
    std::set<std::string> cs;
    for (const auto& s : servers) {
        const auto host = hostFromAddr(s);
        const auto hp = host + ":3478";
        cs.insert(hp);
        ss.push_back(hp);
    }

    std::thread([this, cs = std::move(cs), ss = std::move(ss), tokenStr = token ? *token : std::string(), completionHandler = std::move(completionHandler)]() mutable {
        const auto start = std::chrono::steady_clock::now();
        const auto ret = SortStun(cs, 100);
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - start)
                                    .count();

        std::string svr = ss.empty() ? std::string() : ss.front();
        if (!ret.empty()) {
            svr = ret.front().first;
        }

        (void)elapsed_ms;

        std::string tokenOwned = tokenStr.empty() ? std::string() : tokenStr;
        updateNodesInternal(svr, &ss, tokenStr.empty() ? nullptr : &tokenOwned, std::move(completionHandler));
    }).detach();
}

void NodeSelector::updateNodes(const std::string& server, CompletionCallback completionHandler) {
    updateNodesInternal(server, nullptr, nullptr, std::move(completionHandler));
}

void NodeSelector::updateNodesInternal(const std::string& server,
                                       const std::vector<std::string>* extraServers,
                                       const std::string* token,
                                       CompletionCallback completionHandler) {
    {
        std::unique_lock<std::mutex> lock(update_nodes_mtx_);
        update_nodes_count_ = 2;
    }

    const auto host = hostFromAddr(server);
    const auto url = std::string("https://") + host + ":7202/nodelist";

    HttpClient hc;
    if (token && !token->empty()) {
        hc.header("Authorization", *token);
    }

    hc.get(url, [this, extraServers, completionHandler = std::move(completionHandler)](const HttpClient::Result& r) mutable {
        bool sort = false;
        auto autoDone = [&] {
            if (completionHandler) completionHandler();
            {
                std::unique_lock<std::mutex> lock(update_nodes_mtx_);
                update_nodes_count_ = sort ? 1 : 0;
            }
            update_nodes_cv_.notify_one();
        };

        if (!r.error.empty() || r.httpCode < 200 || r.httpCode >= 300) {
            NODESEL_LOG(RtcLogLevel::Error, "get nodelist failed");
            autoDone();
            return;
        }

        json j = json::parse(r.responseBody, nullptr, false);
        if (j.is_discarded()) {
            NODESEL_LOG(RtcLogLevel::Error, "parse nodelist failed");
            autoDone();
            return;
        }

        if (!j.contains("ips") || !j["ips"].is_array()) {
            NODESEL_LOG(RtcLogLevel::Error, "missing ips");
            autoDone();
            return;
        }

        const int port = j.value("stun_port", 3478);
        std::vector<std::string> ips;
        ips.reserve(j["ips"].size() + (extraServers ? extraServers->size() : 0));

        for (const auto& el : j["ips"]) {
            if (!el.is_string()) continue;
            ips.push_back(el.get<std::string>() + ":" + std::to_string(port));
        }

        if (extraServers) {
            for (const auto& s : *extraServers) {
                if (std::find(ips.begin(), ips.end(), s) == ips.end()) {
                    ips.push_back(s);
                }
            }
        }

        std::string ip;
        if (j.contains("client_ip") && j["client_ip"].is_string()) {
            ip = j["client_ip"].get<std::string>();
        }

        sort = true;
        asyncSort(ips, ip.empty() ? nullptr : &ip);
        autoDone();
    });
}

void NodeSelector::getBestUrl(const std::string& serverUrl, BestUrlCallback completionHandler) {
    Hosts hostsCopy = Config::Shared().hosts;
    const auto oldHost = hostFromAddr(serverUrl);

    if (Config::Shared().signal.hasServer && !Config::Shared().signal.server.empty()) {
        const auto bestUrl = replaceHost(serverUrl, oldHost, Config::Shared().signal.server);
        completionHandler(bestUrl, &hostsCopy);
        return;
    }

    std::thread([this, serverUrl, completionHandler = std::move(completionHandler)]() mutable {
        testBestUrl(serverUrl, std::move(completionHandler));
    }).detach();
}

void NodeSelector::testBestUrl(const std::string& serverUrl, BestUrlCallback completionHandler) {
    Hosts hosts = Config::Shared().hosts;
    const auto oldHost = hostFromAddr(serverUrl);

    const auto start = std::chrono::steady_clock::now();
    {
        std::unique_lock<std::mutex> lock(update_nodes_mtx_);
        update_nodes_cv_.wait_for(lock, std::chrono::milliseconds(2000), [this] {
            return update_nodes_count_ == 0;
        });
    }
    (void)start;

    std::string savedBestIp;
    std::string savedIp;
    std::string savedServerIp;
    std::vector<std::string> savedNodes;
    {
        std::lock_guard<std::mutex> lk(cache().mtx);
        savedBestIp = cache().best_node;
        savedIp = cache().ip;
        savedServerIp = cache().server_ip;
        savedNodes = cache().nodes;
        cache().server_ip = oldHost;
    }

    // If server host isn't part of the saved node list, skip best-node rewrite.
    if (!savedNodes.empty()) {
        const bool contains = std::find(savedNodes.begin(), savedNodes.end(), oldHost) != savedNodes.end();
        if (!contains) {
            // Clear cache on environment change.
            std::lock_guard<std::mutex> lk(cache().mtx);
            cache().best_node.clear();
            cache().nodes.clear();
            completionHandler(serverUrl, &hosts);
            return;
        }
    }

    if (savedBestIp.empty()) {
        completionHandler(serverUrl, &hosts);
        return;
    }

    auto cancel = std::make_shared<std::atomic_bool>(false);
    setConnectCancelFlag(cancel);

    std::thread([serverUrl, oldHost, savedBestIp, savedIp, hosts = std::move(hosts), completionHandler = std::move(completionHandler), cancel]() mutable {
        if (cancel && cancel->load()) {
            return;
        }

        std::string ipNow;
        auto ret = SortStun({savedBestIp}, 1000, &ipNow);
        if (cancel && cancel->load()) {
            return;
        }

        if (ret.empty()) {
            completionHandler(serverUrl, nullptr);
            return;
        }

        // Suggest ip -> host mapping (mimics ObjC behavior).
        if (!hosts.empty()) {
            if (hosts.find(savedBestIp) == hosts.end()) {
                hosts[savedBestIp] = hosts.begin()->second;
            }
        }

        (void)savedIp;
        const auto bestUrl = replaceHost(serverUrl, oldHost, savedBestIp);
        completionHandler(bestUrl, &hosts);
    }).detach();
}

std::string NodeSelector::onNodeList(const std::vector<std::string>& nodes,
                                    uint16_t port,
                                    const std::string* clientIp) {
    std::vector<std::string> nodesWithPort;
    nodesWithPort.reserve(nodes.size());
    for (const auto& n : nodes) {
        nodesWithPort.push_back(n + ":" + std::to_string(port));
    }

    // If user provided preferred node, return it but still refresh RTT cache asynchronously.
    if (Config::Shared().hasServer && !Config::Shared().server.empty()) {
        asyncSort(nodesWithPort, clientIp);
        return Config::Shared().server;
    }

    std::set<std::string> servers;
    for (const auto& ip : nodes) {
        servers.insert(ip);
    }

    std::set<std::string> savedSet;
    std::string savedBest;
    std::string savedIp;
    std::time_t savedTime = 0;
    std::string savedInfo;
    std::vector<std::string> savedNodes;
    {
        std::lock_guard<std::mutex> lk(cache().mtx);
        savedBest = cache().best_node;
        savedIp = cache().ip;
        savedTime = cache().nodes_time;
        savedInfo = cache().nodes_info_json;
        savedNodes = cache().nodes;
    }
    for (const auto& ip : savedNodes) {
        savedSet.insert(ip);
    }

    const bool sameIps = (savedSet == servers);
    const bool sameIp = clientIp && !savedIp.empty() && (*clientIp == savedIp);
    if (sameIps && sameIp) {
        const auto elapsed = std::time(nullptr) - savedTime;
        if (!savedBest.empty() && elapsed < Config::Shared().serverRecheck) {
            // Emit cached RTTs, then refresh asynchronously.
            if (!savedInfo.empty()) {
                json obj = json::parse(savedInfo, nullptr, false);
                if (!obj.is_discarded()) {
                    Rtts rtts;
                    for (auto it = obj.begin(); it != obj.end(); ++it) {
                        if (it.value().is_number_integer()) {
                            rtts.emplace_back(it.key(), it.value().get<int>());
                        }
                    }
                    updateRtts(rtts);
                }
            }
            asyncSort(nodesWithPort, clientIp);
            return savedBest;
        }
    }

    // Sync sort (may be partial); update cache and possibly kick async refresh.
    const auto result = SortStun(servers, Config::Shared().serversSortTimeout, nullptr);
    std::string best = savedBest;
    if (!result.empty()) {
        best = result.front().first;
    }

    if (result.size() < servers.size()) {
        asyncSort(nodesWithPort, clientIp);
    } else {
        updateRtts(result);
    }

    {
        std::lock_guard<std::mutex> lk(cache().mtx);
        cache().nodes = nodes;
        cache().best_node = best;
        cache().nodes_time = std::time(nullptr);
        cache().nodes_info_json = rttsToJsonObjectString(result);
        cache().ip = clientIp ? *clientIp : std::string();
    }

    return best;
}

} // namespace bff

