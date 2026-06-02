#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
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

private:
    void updateRtts(const Rtts& result);
    void asyncSort(const std::vector<std::string>& nodesWithPort, const std::string* ip);
    void testBestUrl(const std::string& serverUrl, BestUrlCallback completionHandler);
    void setConnectCancelFlag(std::shared_ptr<std::atomic_bool> cancel);

    void updateNodesInternal(const std::string& server,
                             const std::vector<std::string>* extraServers,
                             const std::string* token,
                             CompletionCallback completionHandler);

private:
    UpdateRttsCallback on_update_rtts_;

    std::mutex update_nodes_mtx_;
    std::condition_variable update_nodes_cv_;
    int update_nodes_count_ = 0;

    std::mutex connect_cancel_mtx_;
    std::shared_ptr<std::atomic_bool> connect_cancel_;
};

} // namespace bff

