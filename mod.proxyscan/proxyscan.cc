/**
 * proxyscan.cc
 *
 * Scans connecting clients against configured DNSBL / RBL zones.
 * Sets network GLINEs directly via GNUWorld xServer core when hits occur.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include "Channel.h"
#include "EConfig.h"
#include "ELog.h"
#include "Gline.h"
#include "Network.h"
#include "StringTokenizer.h"
#include "client.h"
#include "events.h"
#include "iClient.h"
#include "iServer.h"
#include "ip.h"
#include "misc.h"
#include "proxyscan.h"
#include "server.h"

namespace gnuworld {

using std::string;

extern "C" {
xClient* _gnuwinit(const string& args) { return new proxyscan(args); }
}

namespace {

uint32_t ipv4ToUint(const string& ipStr) {
    struct in_addr addr;
    if (::inet_aton(ipStr.c_str(), &addr) != 0) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

time_t parseDuration(const string& durationStr, time_t fallback) {
    if (durationStr.empty()) return fallback;
    size_t idx = 0;
    long val = 0;
    try {
        val = std::stol(durationStr, &idx);
    } catch (...) {
        return fallback;
    }
    if (idx >= durationStr.size()) return static_cast<time_t>(val);
    char unit = static_cast<char>(::tolower(static_cast<unsigned char>(durationStr[idx])));
    switch (unit) {
    case 's': return static_cast<time_t>(val);
    case 'm': return static_cast<time_t>(val * 60);
    case 'h': return static_cast<time_t>(val * 3600);
    case 'd': return static_cast<time_t>(val * 86400);
    case 'w': return static_cast<time_t>(val * 604800);
    default:  return static_cast<time_t>(val);
    }
}

} // namespace

proxyscan::proxyscan(const string& configFileName)
    : xClient(configFileName),
      glineDuration(3600),
      glineDurationStr("1h"),
      allowOpers(true),
      useColours(true),
      scanOnBurst(false),
      cacheTime(300),
      totalScans(0),
      totalHits(0),
      totalGlines(0),
      totalIgnored(0),
      stopWorker(false),
      timerId(0) {
    loadConfig(configFileName);
    loadIgnores();

    // Start background DNS worker thread
    workerThread = std::thread(&proxyscan::workerLoop, this);
}

proxyscan::~proxyscan() {
    // Stop background worker thread
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        stopWorker = true;
        queueCv.notify_all();
    }
    if (workerThread.joinable()) {
        workerThread.join();
    }
}

void proxyscan::loadConfig(const string& fileName) {
    EConfig conf(fileName);
    adminChanName = conf.Require("adminchan")->second;
    ignoreFile = conf.TryRequire<string>("ignorefile", string("proxyscan.ignores"));
    glineDurationStr = conf.TryRequire<string>("gline_duration", string("1h"));
    glineDuration = parseDuration(glineDurationStr, 3600);
    // Access control: allow_opers and permit_user
    allowOpers = conf.TryRequire<bool>("allow_opers", true);
    permittedUsers.clear();
    for (EConfig::const_iterator it = conf.Find("permit_user"); it != conf.end() && it->first == "permit_user"; ++it) {
        permittedUsers.push_back(it->second);
    }
    useColours = (string_lower(conf.TryRequire<string>("colours", string("yes"))) != "no");
    scanOnBurst = (string_lower(conf.TryRequire<string>("scan_on_burst", string("no"))) == "yes");
    cacheTime = static_cast<time_t>(conf.TryRequire<unsigned int>("cache_time", 300));

    // Parse RBL zones from configuration
    // rbl.<name>.zone = dnsbl.dronebl.org
    // rbl.<name>.default_reason = Listed on DroneBL
    // rbl.<name>.reason.<return_code> = HTTP Proxy
    rblZones.clear();
    std::map<string, size_t> zoneMap;

    for (EConfig::const_iterator it = conf.begin(); it != conf.end(); ++it) {
        const string& key = it->first;
        const string& val = it->second;

        if (key.rfind("rbl.", 0) != 0) continue;

        StringTokenizer st(key, '.');
        if (st.size() < 3) continue;

        const string zoneId = string_lower(st[1]);
        if (zoneMap.find(zoneId) == zoneMap.end()) {
            RblZone z;
            z.name = zoneId;
            z.defaultReason = "Listed in RBL (" + zoneId + ")";
            rblZones.push_back(z);
            zoneMap[zoneId] = rblZones.size() - 1;
        }

        RblZone& cur = rblZones[zoneMap[zoneId]];
        const string attr = string_lower(st[2]);

        if (attr == "zone") {
            cur.zone = val;
        } else if (attr == "default_reason") {
            cur.defaultReason = val;
        } else if (attr == "reason") {
            if (st.size() >= 4) {
                // Return code can be 127.0.0.x or single digit
                // Reassemble return code
                string code;
                for (size_t i = 3; i < st.size(); ++i) {
                    if (i > 3) code += '.';
                    code += st[i];
                }
                cur.returnReasons[code] = val;
            }
        }
    }

    // Default zones if none defined in conf
    if (rblZones.empty()) {
        RblZone dronebl;
        dronebl.name = "dronebl";
        dronebl.zone = "dnsbl.dronebl.org";
        dronebl.defaultReason = "IRC Drone / Proxy";
        dronebl.returnReasons["127.0.0.3"] = "IRC Drone / Botnet Node";
        dronebl.returnReasons["127.0.0.5"] = "Spam / Injection Form";
        dronebl.returnReasons["127.0.0.8"] = "Socks Proxy";
        dronebl.returnReasons["127.0.0.9"] = "HTTP Proxy";
        dronebl.returnReasons["127.0.0.255"] = "Unknown / Blacklisted Drone";
        rblZones.push_back(dronebl);

        RblZone efnet;
        efnet.name = "efnetrbl";
        efnet.zone = "rbl.efnetrbl.org";
        efnet.defaultReason = "EFnet RBL hit";
        efnet.returnReasons["127.0.0.1"] = "Open Proxy";
        efnet.returnReasons["127.0.0.2"] = "Spam / Malicious IRC";
        efnet.returnReasons["127.0.0.3"] = "Tor Exit Node";
        rblZones.push_back(efnet);

        RblZone evilnet;
        evilnet.name = "evilnet";
        evilnet.zone = "rbl.evilnet.org";
        evilnet.defaultReason = "Evilnet RBL hit";
        evilnet.returnReasons["127.0.0.3"] = "JoinPart flood";
        evilnet.returnReasons["127.0.0.5"] = "Compromised HOST/IP";
        evilnet.returnReasons["127.0.0.6"] = "IRC Spam Drone";
        evilnet.returnReasons["127.0.0.7"] = "DDoS Drone";
        evilnet.returnReasons["127.0.0.8"] = "Open Proxy / HTTP Proxy";
        rblZones.push_back(evilnet);
    }
}

void proxyscan::OnAttach() {
    xClient::OnAttach();

    MyUplink->RegisterEvent(EVT_NICK, this);

    // Register 1-second recurring timer with xServer to check worker thread results
    timerId = MyUplink->RegisterTimer(::time(0) + 1, this, 0);
}

void proxyscan::BurstChannels() {
    xClient::BurstChannels();

    if (!adminChanName.empty()) {
        Join(adminChanName, string(), 0, true);
    }
}

void proxyscan::OnEvent(const eventType& whichEvent, void* arg1, void* arg2, void* arg3, void* arg4) {
    if (whichEvent == EVT_NICK) {
        if (arg1) {
            handleNewClient(static_cast<iClient*>(arg1));
        }
    }
    xClient::OnEvent(whichEvent, arg1, arg2, arg3, arg4);
}

void proxyscan::OnTimer(const xServer::timerID&, void*) {
    // Process results queued by background DNS resolver thread
    processScanResults();

    // Expire old GLINE cache entries
    const time_t now = ::time(0);
    for (auto it = glinedCache.begin(); it != glinedCache.end();) {
        if (now >= it->second) {
            it = glinedCache.erase(it);
        } else {
            ++it;
        }
    }

    // Reschedule timer for next second
    MyUplink->RegisterTimer(::time(0) + 1, this, 0);
}

void proxyscan::report(const string& text) {
    if (!adminChanName.empty()) {
        Message(adminChanName, text);
    }
}

string proxyscan::reverseIpv4(const string& ip) {
    StringTokenizer st(ip, '.');
    if (st.size() != 4) return string();
    return st[3] + "." + st[2] + "." + st[1] + "." + st[0];
}

bool proxyscan::parseCidr(const string& str, CidrIgnore& out) {
    string ipPart = str;
    int prefix = 32;

    string::size_type slashPos = str.find('/');
    if (slashPos != string::npos) {
        ipPart = str.substr(0, slashPos);
        string prefStr = str.substr(slashPos + 1);
        try {
            prefix = std::stoi(prefStr);
            if (prefix < 0 || prefix > 32) return false;
        } catch (...) {
            return false;
        }
    }

    uint32_t ipVal = ipv4ToUint(ipPart);
    if (0 == ipVal && ipPart != "0.0.0.0") return false;

    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    out.network = ipVal & mask;
    out.mask = mask;
    out.prefix = prefix;
    out.text = str;
    return true;
}

bool proxyscan::isIgnored(const string& ipStr, uint32_t ipNum, const string& host) {
    // Check CIDR / IP ignores
    for (const auto& cidr : ignoredCidrs) {
        if ((ipNum & cidr.mask) == cidr.network) {
            return true;
        }
    }

    // Check Host ignores (wildcard match)
    const string lowerHost = string_lower(host);
    const string lowerIp = string_lower(ipStr);
    for (const auto& mask : ignoredHosts) {
        if (0 == match(mask, lowerHost) || 0 == match(mask, lowerIp)) {
            return true;
        }
    }

    return false;
}

void proxyscan::handleNewClient(iClient* theClient) {
    if (!theClient) return;

    // Do not scan services / local clients
    if (theClient->isModeK() || theClient->isFake() || Network->findLocalClient(theClient->getIntYYXXX())) return;

    // Skip scanning on network burst if scanOnBurst is false
    if (!scanOnBurst) {
        iServer* srv = theClient->getServer() ? const_cast<iServer*>(theClient->getServer()) : nullptr;
        if (srv && srv->isBursting()) return;
        if (MyUplink->isBursting() || 0 == MyUplink->getBurstEnd()) return;
    }

    // Get client IP
    const string numericIp = xIP(theClient->getIP()).GetNumericIP();
    if (numericIp.empty() || numericIp.find(':') != string::npos) {
        // Skip IPv6 or invalid for IPv4 DNSBL lookups
        return;
    }

    // Skip loopback / private RFC1918
    uint32_t ipNum = ipv4ToUint(numericIp);
    if ((ipNum & 0xFF000000) == 0x7F000000 || // 127.0.0.0/8
        (ipNum & 0xFF000000) == 0x0A000000 || // 10.0.0.0/8
        (ipNum & 0xFFF00000) == 0xAC100000 || // 172.16.0.0/12
        (ipNum & 0xFFFF0000) == 0xC0A80000) { // 192.168.0.0/16
        return;
    }

    const string& realHost = theClient->getRealInsecureHost().empty() ? theClient->getInsecureHost()
                                                                      : theClient->getRealInsecureHost();

    // Check ignore list
    if (isIgnored(numericIp, ipNum, realHost)) {
        ++totalIgnored;
        return;
    }

    // Check if recently glined or scanned
    if (glinedCache.find(numericIp) != glinedCache.end()) {
        return;
    }

    string revIp = reverseIpv4(numericIp);
    if (revIp.empty()) return;

    // Queue request for worker thread
    ScanRequest req;
    req.nick = theClient->getNickName();
    req.user = theClient->getUserName();
    req.host = realHost;
    req.ip = numericIp;
    req.ipNum = ipNum;
    req.reversedIp = revIp;

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        pendingQueue.push_back(req);
        ++totalScans;
    }
    queueCv.notify_one();
}

void proxyscan::workerLoop() {
    while (true) {
        ScanRequest req;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCv.wait(lock, [this] { return stopWorker || !pendingQueue.empty(); });
            if (stopWorker && pendingQueue.empty()) {
                break;
            }
            req = pendingQueue.front();
            pendingQueue.pop_front();
        }

        resolveRbl(req);
    }
}

void proxyscan::resolveRbl(const ScanRequest& req) {
    for (const auto& zone : rblZones) {
        if (zone.zone.empty()) continue;

        string query = req.reversedIp + "." + zone.zone;

        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo* res0 = nullptr;
        int err = ::getaddrinfo(query.c_str(), nullptr, &hints, &res0);

        if (err == 0 && res0 != nullptr) {
            // Found a hit on this RBL
            struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(res0->ai_addr);
            char ipBuf[INET_ADDRSTRLEN];
            const char* returnCode = ::inet_ntop(AF_INET, &(sin->sin_addr), ipBuf, sizeof(ipBuf));
            string retCodeStr = returnCode ? returnCode : "127.0.0.1";
            ::freeaddrinfo(res0);

            string reason = zone.defaultReason;
            auto it = zone.returnReasons.find(retCodeStr);
            if (it != zone.returnReasons.end()) {
                reason = it->second;
            }

            ScanResult result;
            result.nick = req.nick;
            result.user = req.user;
            result.host = req.host;
            result.ip = req.ip;
            result.zoneName = zone.name;
            result.zoneDomain = zone.zone;
            result.returnCode = retCodeStr;
            result.reason = reason;

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                completedResults.push_back(result);
            }
        } else if (res0) {
            ::freeaddrinfo(res0);
        }
    }
}

void proxyscan::processScanResults() {
    std::vector<ScanResult> results;
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        if (completedResults.empty()) return;
        results.swap(completedResults);
    }

    for (const auto& res : results) {
        ++totalHits;

        // Visual format for report
        string alert;
        if (useColours) {
            alert = "\002\00304[PROXYSCAN]\003\002 IP \00307" + res.ip + "\003 (\00311" + res.nick +
                    "!" + res.user + "@" + res.host + "\003) listed on \002" + res.zoneDomain +
                    "\002 (\00303" + res.reason + "\003 - " + res.returnCode + ")";
        } else {
            alert = "[PROXYSCAN] IP " + res.ip + " (" + res.nick + "!" + res.user + "@" + res.host +
                    ") listed on " + res.zoneDomain + " (" + res.reason + " - " + res.returnCode + ")";
        }
        report(alert);

        applyGline(res);
    }
}

void proxyscan::applyGline(const ScanResult& res) {
    const time_t now = ::time(0);

    // Prevent duplicate GLINEs across multiple RBL hits for the same IP
    auto it = glinedCache.find(res.ip);
    if (it != glinedCache.end() && now < it->second) {
        return;
    }

    glinedCache[res.ip] = now + cacheTime;
    ++totalGlines;

    const string userHost = "*@" + res.ip;
    const string glineReason = "RBL hit on " + res.zoneDomain + " (" + res.reason + ")";

    // Set GLINE directly in GNUWorld network via xServer
    MyUplink->setGline(getNickName(), userHost, glineReason, glineDuration, now, this, "*");

    string logMsg;
    if (useColours) {
        logMsg = "\002\00304[GLINE]\003\002 Setting network GLINE on \00307" + userHost +
                 "\003 for \002" + glineDurationStr + "\002: " + glineReason;
    } else {
        logMsg = "[GLINE] Setting network GLINE on " + userHost + " for " + glineDurationStr +
                 ": " + glineReason;
    }
    report(logMsg);
}

/* ------------------------------------------------------------------ */
/* Operator commands                                                  */
/* ------------------------------------------------------------------ */

void proxyscan::OnPrivateMessage(iClient* theClient, const string& message, bool) {
    bool userHasAccess = hasAccess(theClient->getAccount());
    if (!userHasAccess && !theClient->isOper()) {
        return;
    }
    if (!userHasAccess && !allowOpers) {
        return;
    }

    StringTokenizer st(message);
    if (st.empty()) return;

    const string cmd = string_lower(st[0]);
    if ("ignore" == cmd) {
        cmdIgnore(theClient, st, true);
    } else if ("unignore" == cmd) {
        cmdIgnore(theClient, st, false);
    } else if ("list" == cmd || "ignores" == cmd) {
        cmdList(theClient, st);
    } else if ("status" == cmd) {
        cmdStatus(theClient);
    } else if ("reload" == cmd || "rehash" == cmd) {
        cmdReload(theClient);
    } else {
        sendHelp(theClient);
    }
}

void proxyscan::sendHelp(iClient* theClient) {
    Notice(theClient, "=== " + getNickName() + " DNSBL Proxy Scanner ===");
    Notice(theClient, "  IGNORE ADD <ip[/cidr] | hostmask> [reason]");
    Notice(theClient, "  IGNORE DEL <ip[/cidr] | hostmask>");
    Notice(theClient, "  IGNORE LIST");
    Notice(theClient, "  STATUS");
    Notice(theClient, "  RELOAD");
    Notice(theClient, "Examples: /msg " + getNickName() + " IGNORE ADD 81.31.32.42");
    Notice(theClient, "          /msg " + getNickName() + " IGNORE ADD 81.31.32.0/24 ISP Whitelist");
    Notice(theClient, "          /msg " + getNickName() + " IGNORE ADD *.undernet.org");
}

void proxyscan::cmdIgnore(iClient* theClient, const StringTokenizer& st, bool add) {
    // IGNORE ADD <target> or UNIGNORE <target>
    StringTokenizer::size_type targetIdx = 1;
    if ("ignore" == string_lower(st[0]) && st.size() > 1) {
        string sub = string_lower(st[1]);
        if ("add" == sub) {
            add = true;
            targetIdx = 2;
        } else if ("del" == sub || "rem" == sub) {
            add = false;
            targetIdx = 2;
        } else if ("list" == sub) {
            cmdList(theClient, st);
            return;
        }
    }

    if (targetIdx >= st.size()) {
        sendHelp(theClient);
        return;
    }

    string target = st[targetIdx];

    // Check if target is CIDR/IP
    CidrIgnore cidr;
    if (parseCidr(target, cidr)) {
        if (add) {
            for (const auto& existing : ignoredCidrs) {
                if (existing.network == cidr.network && existing.prefix == cidr.prefix) {
                    Notice(theClient, "CIDR/IP " + cidr.text + " is already in the ignore list.");
                    return;
                }
            }
            ignoredCidrs.push_back(cidr);
            saveIgnores();
            Notice(theClient, "Added CIDR/IP ignore: " + cidr.text);
        } else {
            bool found = false;
            for (auto it = ignoredCidrs.begin(); it != ignoredCidrs.end(); ++it) {
                if (it->network == cidr.network && it->prefix == cidr.prefix) {
                    ignoredCidrs.erase(it);
                    found = true;
                    break;
                }
            }
            if (found) {
                saveIgnores();
                Notice(theClient, "Removed CIDR/IP ignore: " + cidr.text);
            } else {
                Notice(theClient, "CIDR/IP " + cidr.text + " not found in ignore list.");
            }
        }
        return;
    }

    // Hostmask ignore
    string hostMask = string_lower(target);
    if (add) {
        if (!ignoredHosts.insert(hostMask).second) {
            Notice(theClient, "Hostmask " + hostMask + " is already in the ignore list.");
            return;
        }
        saveIgnores();
        Notice(theClient, "Added hostmask ignore: " + hostMask);
    } else {
        if (ignoredHosts.erase(hostMask) == 0) {
            Notice(theClient, "Hostmask " + hostMask + " not found in ignore list.");
            return;
        }
        saveIgnores();
        Notice(theClient, "Removed hostmask ignore: " + hostMask);
    }
}

void proxyscan::cmdList(iClient* theClient, const StringTokenizer&) {
    Notice(theClient, "=== Ignored CIDRs / IPs (" + std::to_string(ignoredCidrs.size()) + ") ===");
    for (const auto& c : ignoredCidrs) {
        Notice(theClient, "  " + c.text);
    }
    Notice(theClient, "=== Ignored Hostmasks (" + std::to_string(ignoredHosts.size()) + ") ===");
    for (const auto& h : ignoredHosts) {
        Notice(theClient, "  " + h);
    }
}

void proxyscan::cmdStatus(iClient* theClient) {
    Notice(theClient, "=== " + getNickName() + " Status ===");
    Notice(theClient, "  Active RBL Zones: " + std::to_string(rblZones.size()));
    for (const auto& z : rblZones) {
        Notice(theClient, "    " + z.name + " -> " + z.zone + " (" + z.defaultReason + ")");
    }
    Notice(theClient, "  GLINE Duration: " + glineDurationStr + " (" + std::to_string(glineDuration) + "s)");
    Notice(theClient, "  Admin Channel: " + adminChanName);
    Notice(theClient, "  Total Scanned: " + std::to_string(totalScans));
    Notice(theClient, "  Total Hits: " + std::to_string(totalHits));
    Notice(theClient, "  Total GLINEs set: " + std::to_string(totalGlines));
    Notice(theClient, "  Total Ignored: " + std::to_string(totalIgnored));
    Notice(theClient, "  Pending Scan Queue: " + std::to_string(pendingQueue.size()));
    Notice(theClient, "  GLINE Cache Entries: " + std::to_string(glinedCache.size()));
}

void proxyscan::cmdReload(iClient* theClient) {
    loadConfig(getConfigFileName());
    loadIgnores();
    Notice(theClient, "Reloaded configuration and ignore lists.");
}

/* ------------------------------------------------------------------ */
/* Persistence                                                        */
/* ------------------------------------------------------------------ */

bool proxyscan::hasAccess(const string& accountName) const {
    if (accountName.empty()) return false;
    for (const string& user : permittedUsers) {
        if (!strcasecmp(accountName.c_str(), user.c_str())) {
            return true;
        }
    }
    return false;
}

void proxyscan::loadIgnores() {
    ignoredCidrs.clear();
    ignoredHosts.clear();

    std::ifstream in(ignoreFile.c_str());
    if (!in) return;

    string line;
    while (std::getline(in, line)) {
        StringTokenizer st(line);
        if (st.empty()) continue;
        const string& type = string_lower(st[0]);
        if (type == "cidr" || type == "ip") {
            if (st.size() >= 2) {
                CidrIgnore cidr;
                if (parseCidr(st[1], cidr)) {
                    ignoredCidrs.push_back(cidr);
                }
            }
        } else if (type == "host") {
            if (st.size() >= 2) {
                ignoredHosts.insert(string_lower(st[1]));
            }
        }
    }
}

void proxyscan::saveIgnores() const {
    std::ofstream out(ignoreFile.c_str(), std::ios::trunc);
    if (!out) {
        elog << "proxyscan::saveIgnores> Unable to write " << ignoreFile << std::endl;
        return;
    }
    for (const auto& c : ignoredCidrs) {
        out << "cidr " << c.text << '\n';
    }
    for (const auto& h : ignoredHosts) {
        out << "host " << h << '\n';
    }
}

} // namespace gnuworld
