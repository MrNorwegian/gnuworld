/**
 * proxyscan.h
 *
 * Scans connecting clients against configured DNSBL / RBL zones.
 * Sets network GLINEs directly via GNUWorld xServer core when hits occur.
 */

#ifndef __PROXYSCAN_H
#define __PROXYSCAN_H

#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "client.h"
#include "events.h"
#include "iClient.h"
#include "misc.h"
#include "server.h"
#include "StringTokenizer.h"
#include "TimerHandler.h"

namespace gnuworld {

class proxyscan : public xClient {
  public:
    proxyscan(const std::string& configFileName);
    virtual ~proxyscan();

    virtual void OnAttach();
    virtual void BurstChannels();
    virtual void OnPrivateMessage(iClient*, const std::string&, bool secure = false);
    virtual void OnEvent(const eventType&, void* = 0, void* = 0, void* = 0, void* = 0);
    virtual void OnTimer(const xServer::timerID&, void*);

  protected:
    // CIDR ignore representation for IPv4
    struct CidrIgnore {
        uint32_t network;
        uint32_t mask;
        int prefix;
        std::string text;
    };

    // RBL Zone configuration
    struct RblZone {
        std::string name;
        std::string zone;
        std::string defaultReason;
        std::map<std::string, std::string> returnReasons; // e.g. "127.0.0.9" -> "HTTP Proxy"
    };

    // Pending lookup request for background worker
    struct ScanRequest {
        std::string nick;
        std::string user;
        std::string host;
        std::string ip;
        uint32_t ipNum;
        std::string reversedIp;
    };

    // Hit result returned from background worker
    struct ScanResult {
        std::string nick;
        std::string user;
        std::string host;
        std::string ip;
        std::string zoneName;
        std::string zoneDomain;
        std::string returnCode;
        std::string reason;
    };

    // Event handlers
    void handleNewClient(iClient*);

    // Matching and checks
    bool isIgnored(const std::string& ipStr, uint32_t ipNum, const std::string& host);
    static bool parseCidr(const std::string& str, CidrIgnore& out);
    static std::string reverseIpv4(const std::string& ip);

    // Reporting and actions
    void report(const std::string&);
    void applyGline(const ScanResult&);
    void processScanResults();

    // Background thread loop
    void workerLoop();
    void resolveRbl(const ScanRequest& req);

    // Operator commands
    void cmdIgnore(iClient*, const StringTokenizer&, bool add);
    void cmdList(iClient*, const StringTokenizer&);
    void cmdStatus(iClient*);
    void cmdReload(iClient*);
    void sendHelp(iClient*);

    // Config & Ignores
    void loadConfig(const std::string& fileName);
    bool hasAccess(const std::string& accountName) const;

    void loadIgnores();
    void saveIgnores() const;

    // Config options
    std::string adminChanName;
    std::string ignoreFile;
    time_t glineDuration;
    std::string glineDurationStr;
    bool allowOpers;
    std::vector<std::string> permittedUsers;
    bool useColours;
    bool scanOnBurst;
    time_t cacheTime;

    std::vector<RblZone> rblZones;

    // Ignores
    std::vector<CidrIgnore> ignoredCidrs;
    std::set<std::string> ignoredHosts;

    // Cache of recently glined/checked IPs to prevent duplicate GLINEs
    std::map<std::string, time_t> glinedCache;

    // Stats
    uint64_t totalScans;
    uint64_t totalHits;
    uint64_t totalGlines;
    uint64_t totalIgnored;

    // Threading
    std::thread workerThread;
    bool stopWorker;
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::deque<ScanRequest> pendingQueue;
    std::vector<ScanResult> completedResults;

    // Periodic timer ID
    xServer::timerID timerId;
};

} // namespace gnuworld

#endif // __PROXYSCAN_H
