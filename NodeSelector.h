#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace bff {

// C++ counterpart of ObjC NodeSelector.
// - Fetches `/nodelist` from a bootstrap server via HttpClient
// - Sorts returned STUN nodes using `SortStun` (stun_test.*)
// - Caches last-best node for quick reconnects
class NodeSelector {
public:
    using Rtts = std::vector<std::pair<std::string, int>>;
    using Hosts = std::unordered_map<std::string, std::string>;

    using CompletionCallback = std::function<void()>;
    using UpdateRttsCallback = std::function<void(const Rtts&)>;
    using BestUrlCallback = std::function<void(const std::string& bestUrl, const Hosts* hosts)>;

    NodeSelector();
    ~NodeSelector();

    NodeSelector(const NodeSelector&) = delete;
    NodeSelector& operator=(const NodeSelector&) = delete;

    void setUpdateRttsCallback(UpdateRttsCallback cb);

    void updateNodes(const std::vector<std::string>& servers,
                     const std::string* token,
                     CompletionCallback completionHandler);
    void updateNodes(const std::string& server, CompletionCallback completionHandler);

    void getBestUrl(const std::string& serverUrl, BestUrlCallback completionHandler);
    void cancelConnectOperation();

    // return: preferred node (host / ip). Empty string means "no preference".
    std::string onNodeList(const std::vector<std::string>& nodes,
                           uint16_t port,
                           const std::string* clientIp);

    // The media node shared by all channels on a connection. Self/peer node rtts
    // are stored here and the best node is selected once, then reused by every
    // channel.
    void applyNodeRtts(const Rtts& rtts, bool isSelf);
    const std::string& bestNodeNegotiated() const;

private:
    void updateRtts(const Rtts& result);
    void asyncSort(const std::vector<std::string>& nodesWithPort,
                   const std::string* ip,
                   std::optional<uint64_t> updateGeneration = std::nullopt);
    uint64_t beginUpdate();
    void finishUpdate(uint64_t generation);
    void testBestUrl(const std::string& serverUrl, BestUrlCallback completionHandler);
    void setConnectCancelFlag(std::shared_ptr<std::atomic_bool> cancel);

    void updateNodesInternal(const std::string& server,
                             const std::vector<std::string>* extraServers,
                             const std::string* token,
                             uint64_t generation,
                             CompletionCallback completionHandler);

private:
    UpdateRttsCallback on_update_rtts_;

    std::mutex update_nodes_mtx_;
    std::condition_variable update_nodes_cv_;
    uint64_t update_generation_ = 0;
    bool update_pending_ = false;
    std::optional<std::string> recent_best_node_result_;

    std::mutex connect_cancel_mtx_;
    std::shared_ptr<std::atomic_bool> connect_cancel_;

    Rtts node_rtts_self_;
    Rtts node_rtts_;
    std::string best_node_negotiated_;
};

} // namespace bff

