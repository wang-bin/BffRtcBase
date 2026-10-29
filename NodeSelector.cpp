#include "NodeSelector.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <set>
#include <thread>

#include "HttpClient.h"
#include "FileLogger.hpp"
#include "defs.h"
#include "json.hpp"

// Reuse the existing STUN sorting helper used by ObjC NodeSelector.
#include "stun_test.h"
#include "Log.hpp"

#define TAG "nodes"
namespace bff {

using json = nlohmann::json;

static constexpr const char* kComponent = "nodes";

struct NodeCache {
    std::mutex mtx;
    std::vector<std::string> nodes; // list without port
    std::string best_node;
    int best_rtt = 0;
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

void NodeSelector::applyNodeRtts(const Rtts& rtts, bool isSelf) {
    if (isSelf) {
        node_rtts_self_ = rtts;
    } else {
        node_rtts_ = rtts;
    }
    if (Config::Shared().server) {
        best_node_negotiated_ = *Config::Shared().server;
    }
    // All channels (mesh/sfu) share one connection and must use the same media
    // node, so select it once both self and peer rtts are available and reuse it.
    if (!best_node_negotiated_.empty() || node_rtts_self_.empty() || node_rtts_.empty()) {
        return;
    }
    best_node_negotiated_ = FindBestNode(node_rtts_self_, node_rtts_);
    INFO("best node for peers: %s", best_node_negotiated_.c_str());
}

const std::string& NodeSelector::bestNodeNegotiated() const {
    return best_node_negotiated_;
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

uint64_t NodeSelector::beginUpdate() {
    std::lock_guard<std::mutex> lock(update_nodes_mtx_);
    ++update_generation_;
    update_pending_ = true;
    early_result_.reset();
    recent_best_node_result_.reset();
    return update_generation_;
}

void NodeSelector::finishUpdate(uint64_t generation) {
    {
        std::lock_guard<std::mutex> lock(update_nodes_mtx_);
        if (generation != update_generation_ || !update_pending_) {
            return;
        }
        recent_best_node_result_.reset();
        early_result_.reset();
        update_pending_ = false;
    }
    update_nodes_cv_.notify_all();
}

void NodeSelector::asyncSort(const std::vector<std::string>& nodesWithPort,
                             const std::string* ip,
                             std::optional<uint64_t> updateGeneration) {
    // Run STUN sort off-thread; cache best node.
    std::vector<std::string> nodesCopy = nodesWithPort;
    std::string ipCopy = ip ? *ip : std::string();

    std::thread([this, nodesCopy = std::move(nodesCopy), ipCopy = std::move(ipCopy), updateGeneration]() mutable {
        std::set<std::string> servers;
        for (const auto& s : nodesCopy) {
            servers.insert(s);
        }

        const auto start = std::chrono::steady_clock::now();
        bool save = true;
        auto ret = SortStun(servers, 2000, nullptr, [&](const auto& result) {
            if (!updateGeneration) return;
            std::unique_lock lock(update_nodes_mtx_);
            if (*updateGeneration != update_generation_ || !update_pending_) return;
            EarlyResult early{.node = result.first, .nodes = {}, .ip = ipCopy};
            for (const auto& node : nodesCopy) early.nodes.push_back(hostFromAddr(node));
            early_result_ = std::move(early);
            lock.unlock();
            update_nodes_cv_.notify_all();
        });
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - start)
                                    .count();

        if (ret.empty()) {
            save = false;
            // Fake results to ensure we can still join.
            for (const auto& s : servers) {
                ret.emplace_back(hostFromAddr(s), 0);
            }
        }

        std::vector<std::string> nodesNoPort;
        std::string info;
        if (save) {
            nodesNoPort.reserve(nodesCopy.size());
            for (const auto& n : nodesCopy) {
                auto h = n;
                const auto pos = h.find(':');
                if (pos != std::string::npos) {
                    h = h.substr(0, pos);
                }
                nodesNoPort.push_back(std::move(h));
            }
            info = rttsToJsonObjectString(ret);
        }

        const bool tracked = updateGeneration.has_value();
        std::unique_lock<std::mutex> updateLock(update_nodes_mtx_);
        const bool publish = tracked
                           ? *updateGeneration == update_generation_ && update_pending_
                           : !update_pending_;
        if (publish) {
            if (save) {
                std::lock_guard<std::mutex> cacheLock(cache().mtx);
                cache().best_node = ret.front().first;
                cache().best_rtt = ret.front().second;
                cache().nodes_time = std::time(nullptr);
                cache().nodes = std::move(nodesNoPort);
                cache().nodes_info_json = std::move(info);
                cache().ip = ipCopy;
                recent_best_node_result_ = ret.front().first;
            }
            if (tracked) {
                early_result_.reset();
                update_pending_ = false;
            }
        }
        updateLock.unlock();

        if (tracked && publish) {
            update_nodes_cv_.notify_all();
        }
        if (publish) {
            updateRtts(ret);
        }

        (void)elapsed_ms;
    }).detach();
}

void NodeSelector::updateNodes(const std::vector<std::string>& servers,
                               const std::string* token,
                               CompletionCallback completionHandler) {
    if (servers.empty()) {
        WARN("empty servers");
        if (completionHandler) completionHandler();
        return;
    }
    const auto generation = beginUpdate();

    // Use the cached best node as an extra bootstrap candidate and bound STUN wait to 300ms.
    std::vector<std::string> ss;
    ss.reserve(servers.size());
    std::set<std::string> cs;
    for (const auto& s : servers) {
        const auto host = hostFromAddr(s);
        const auto hp = host + ":3478";
        cs.insert(hp);
        ss.push_back(hp);
    }

    std::string cachedBestNode;
    int cachedBestRtt = 0;
    {
        std::lock_guard<std::mutex> lk(cache().mtx);
        cachedBestNode = cache().best_node;
        cachedBestRtt = cache().best_rtt;
    }
    if (!cachedBestNode.empty()) {
        cs.insert(hostFromAddr(cachedBestNode) + ":3478");
    }
    const auto timeout = static_cast<int>(std::ceil(std::min(
        cachedBestRtt > 0 ? cachedBestRtt * 1.5 : 300.0, 300.0)));

    std::thread([this, cs = std::move(cs), ss = std::move(ss), timeout, generation, tokenStr = token ? *token : std::string(), completionHandler = std::move(completionHandler)]() mutable {
        const auto start = std::chrono::steady_clock::now();
        const auto ret = SortStun(cs, timeout);
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - start)
                                    .count();

        std::string svr = ss.empty() ? std::string() : ss.front();
        if (!ret.empty()) {
            svr = ret.front().first;
        }

        (void)elapsed_ms;

        std::string tokenOwned = tokenStr.empty() ? std::string() : tokenStr;
        updateNodesInternal(svr, &ss, tokenStr.empty() ? nullptr : &tokenOwned, generation, std::move(completionHandler));
    }).detach();
}

void NodeSelector::updateNodes(const std::string& server, CompletionCallback completionHandler) {
    const auto generation = beginUpdate();
    updateNodesInternal(server, nullptr, nullptr, generation, std::move(completionHandler));
}

void NodeSelector::updateNodesInternal(const std::string& server,
                                       const std::vector<std::string>* extraServers,
                                       const std::string* token,
                                       uint64_t generation,
                                       CompletionCallback completionHandler) {
    const auto host = hostFromAddr(server);
    const auto url = std::string("https://") + host + ":7202/nodelist";

    HttpClient hc;
    if (token && !token->empty()) {
        hc.header("Authorization", *token);
    }

    const auto extraServersCopy = extraServers ? *extraServers : std::vector<std::string>{};
    hc.get(url, [this, extraServers = extraServersCopy, generation, completionHandler = std::move(completionHandler)](const HttpClient::Result& r) mutable {
        const auto responseCompleteTime = std::chrono::system_clock::now().time_since_epoch()
                                        / std::chrono::milliseconds{1};
        const auto responseTime = responseCompleteTime - std::max<int64_t>(0, r.responseBodyElapsedMs);
        bool sort = false;
        auto autoDone = [&] {
            if (!sort) finishUpdate(generation);
            if (completionHandler) completionHandler();
        };

        if (!r.error.empty() || r.httpCode < 200 || r.httpCode >= 300) {
            ERROR("get nodelist failed");
            autoDone();
            return;
        }

        json j = json::parse(r.responseBody, nullptr, false);
        if (j.is_discarded()) {
            ERROR("parse nodelist failed");
            autoDone();
            return;
        }

        if (!j.contains("ips") || !j["ips"].is_array()) {
            ERROR("missing ips");
            autoDone();
            return;
        }
        const int port = j.value("stun_port", 3478);
        std::vector<std::string> ips;
        ips.reserve(j["ips"].size() + extraServers.size());

        for (const auto& el : j["ips"]) {
            if (!el.is_string()) continue;
            ips.push_back(el.get<std::string>() + ":" + std::to_string(port));
        }

        for (const auto& s : extraServers) {
            if (std::find(ips.begin(), ips.end(), s) == ips.end()) {
                ips.push_back(s);
            }
        }

        std::string ip;
        if (j.contains("client_ip") && j["client_ip"].is_string()) {
            ip = j["client_ip"].get<std::string>();
        }

        if (j.contains("current_time") && j["current_time"].is_number_integer()) {
            const auto serverTime = j["current_time"].get<int64_t>();
            if (serverTime > 0) {
                // current_time 是服务端生成响应时的时间，responseTime 是客户端收到 nodelist 响应时的本地时间。
                // RTT 从 TLS 握手完成后开始计量，不包含建连耗时。
                // 假设上下行时延近似对称且服务端处理耗时较小，回程时延约为 HTTP RTT / 2。
                // 因而 clockOffset = current_time - responseTime + HTTP RTT / 2；此处不使用 STUN RTT。
                const auto clockOffset = serverTime - static_cast<int64_t>(responseTime)
                                       + std::max<int64_t>(0, r.requestRttMs) / 2;
                FileLogger::shared().setClockOffset(clockOffset);
                INFO("nodelist clock offset: %lldms", static_cast<long long>(clockOffset));
            }
        }

        sort = true;
        asyncSort(ips, ip.empty() ? nullptr : &ip, generation);
        autoDone();
    });
}

void NodeSelector::getBestUrl(const std::string& serverUrl, BestUrlCallback completionHandler) {
    Hosts hostsCopy = Config::Shared().hosts;
    const auto oldHost = hostFromAddr(serverUrl);

    if (Config::Shared().signal.server) {
        const auto bestUrl = replaceHost(serverUrl, oldHost, *Config::Shared().signal.server);
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

    std::optional<std::string> recentBestNode;
    std::string savedBestIp;
    std::string savedIp;
    std::vector<std::string> savedNodes;
    bool contains = false;
    bool timedOut = false;
    {
        std::unique_lock<std::mutex> lock(update_nodes_mtx_);
        update_nodes_cv_.wait_for(lock, std::chrono::milliseconds(2000), [this] {
            return !update_pending_ || early_result_.has_value();
        });
        const bool early = update_pending_ && early_result_.has_value();
        timedOut = update_pending_ && !early;
        if (!timedOut) {
            recentBestNode = recent_best_node_result_;
        }
        std::lock_guard<std::mutex> lk(cache().mtx);
        savedBestIp = cache().best_node;
        savedIp = cache().ip;
        savedNodes = cache().nodes;
        cache().server_ip = oldHost;
        if (early) {
            recentBestNode = early_result_->node;
            savedIp = early_result_->ip;
            savedNodes = early_result_->nodes;
        }

        // Match the wrapper behavior: only reuse a best node when this signal
        // host is present in the cached node list. Snapshot under the update
        // lock so a late result cannot affect this selection after timeout.
        contains = std::find(savedNodes.begin(), savedNodes.end(), oldHost) != savedNodes.end();
        if (!contains && !timedOut && !early) {
            cache().best_node.clear();
            cache().best_rtt = 0;
            cache().nodes.clear();
            recent_best_node_result_.reset();
        }
    }

    if (!contains) {
        completionHandler(serverUrl, &hosts);
        return;
    }
    if (recentBestNode) {
        savedBestIp = *recentBestNode;
    }
    if (savedBestIp.empty()) {
        completionHandler(serverUrl, &hosts);
        return;
    }

    auto cancel = std::make_shared<std::atomic_bool>(false);
    setConnectCancelFlag(cancel);

    std::thread([serverUrl, oldHost, savedBestIp, savedIp, recentBestNode, hosts = std::move(hosts), completionHandler = std::move(completionHandler), cancel]() mutable {
        const bool reuseRecentBestNode = recentBestNode.has_value();
        if (cancel && cancel->load()) {
            return;
        }

        std::string ipNow;
        const auto start = std::chrono::steady_clock::now();
        Rtts ret;
        if (!reuseRecentBestNode) {
            ret = SortStun({savedBestIp}, 1000, &ipNow);
        }
        if (cancel && cancel->load()) {
            return;
        }

        if (!reuseRecentBestNode && ret.empty()) {
            completionHandler(serverUrl, nullptr);
            return;
        }

        if (reuseRecentBestNode) {
            INFO("reuse recently measured best node");
        } else {
            INFO("previous client ip: %s", savedIp.c_str());
            INFO("test node elapsed: %lldms", static_cast<long long>(
                (std::chrono::steady_clock::now() - start) / std::chrono::milliseconds{1}));
            if (ipNow != savedIp) {
                WARN("client ip changed");
            }
        }

        // Suggest ip -> host mapping (mimics ObjC behavior).
        if (!hosts.empty() && hosts.find(savedBestIp) == hosts.end()) {
            hosts[savedBestIp] = hosts.begin()->second;
        }

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
    if (Config::Shared().server) {
        asyncSort(nodesWithPort, clientIp);
        best_node_negotiated_ = *Config::Shared().server;
        return *Config::Shared().server;
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

    const auto needsAsyncSort = result.size() < servers.size();
    if (!needsAsyncSort) {
        updateRtts(result);
    }

    {
        std::lock_guard<std::mutex> lock(update_nodes_mtx_);
        if (!update_pending_) {
            std::lock_guard<std::mutex> cacheLock(cache().mtx);
            const std::set<std::string> currentSavedServers(cache().nodes.begin(), cache().nodes.end());
            const bool canReuseRecent = currentSavedServers == servers
                                      && clientIp && cache().ip == *clientIp;
            cache().nodes = nodes;
            cache().best_node = best;
            if (!result.empty()) {
                cache().best_rtt = result.front().second;
            }
            cache().nodes_time = std::time(nullptr);
            cache().nodes_info_json = rttsToJsonObjectString(result);
            cache().ip = clientIp ? *clientIp : std::string();
            if (result.empty()) {
                if (!canReuseRecent) {
                    recent_best_node_result_.reset();
                }
            } else {
                recent_best_node_result_ = result.front().first;
            }
        }
    }

    if (needsAsyncSort) {
        asyncSort(nodesWithPort, clientIp);
    }

    return best;
}

} // namespace bff
