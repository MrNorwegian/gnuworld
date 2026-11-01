/**
 * spybot.h
 *
 * Reads the P10 traffic seen by this server and reports it to an admin channel.
 * Derived from the layout of mod.scanner.
 */

#ifndef __SPYBOT_H
#define __SPYBOT_H

#include <set>
#include <string>

#include "client.h"
#include "iClient.h"
#include "iServer.h"
#include "StringTokenizer.h"

namespace gnuworld {

class Gline;

class spybot : public xClient {
  public:
    spybot(const std::string& configFileName);
    virtual ~spybot();

    virtual void OnAttach();
    virtual void BurstChannels();
    virtual void OnPrivateMessage(iClient*, const std::string&, bool secure = false);
    virtual void OnEvent(const eventType&, void* = 0, void* = 0, void* = 0, void* = 0);

  protected:
    enum IgnoreType { IGN_SERVER, IGN_CLIENT, IGN_CHANNEL };

    typedef std::set<std::string> maskSetType;

    // Reporting
    void report(const std::string&);
    void debugLine(const char* direction, const std::string& line);
    void handleRawOut(const std::string&);

    // mIRC colours, plain text when colours are disabled
    std::string colour(const std::string& code, const std::string&) const;
    std::string cNick(const std::string& s) const { return colour(colNick, s); }
    std::string cUserHost(const std::string& s) const { return colour(colUserHost, s); }
    std::string cIp(const std::string& s) const { return colour(colIp, s); }
    std::string cChan(const std::string& s) const { return colour(colChannel, s); }
    std::string cServer(const std::string& s) const { return colour(colServer, s); }
    std::string cModes(const std::string& s) const { return colour(colModes, s); }

    // "7", "07" or "4,2" (fg,bg) become a two digit mIRC code; none/empty gives ""
    static std::string parseColour(const std::string& value, const std::string& fallback);

    // Network event handlers
    void handleConnect(iClient*);
    void handleQuit(iClient*, const std::string*);
    void handleKill(void*, iClient*, const std::string*);
    void handleNickChange(iClient*, const std::string*);
    void handleServerLink(iServer*, iServer*);
    void handleServerSplit(iServer*, const std::string*);
    void handleGline(Gline*, bool added);

    // Raw P10 lines: join/part/kick/create/topic and user/channel modes
    void handleRaw(const std::string&);
    void rawJoin(const std::string& src, const StringTokenizer&, bool create);
    void rawPart(const std::string& src, const StringTokenizer&);
    void rawKick(const std::string& src, const StringTokenizer&);
    void rawAccount(const StringTokenizer& st);
    void rawTopic(const std::string& src, const StringTokenizer&);
    void rawMode(const std::string& src, const StringTokenizer&, bool opmode);

    // Current modes after a change, e.g. "+ix" or "+tnsk key"
    std::string userModeSummary(const iClient*) const;
    std::string channelModeSummary(const std::string& channelName) const;

    // Describing and matching
    std::string describeSource(const std::string& numeric) const;
    std::string describeClient(const iClient*) const;
    std::string serverNameOf(const iClient*) const;

    bool isServerIgnored(const std::string& serverName) const;
    bool isClientIgnored(const iClient*) const;
    bool isChannelIgnored(const std::string& channelName) const;
    bool isSourceIgnored(const std::string& numeric) const;

    // Admin commands
    void cmdIgnore(iClient*, const StringTokenizer&, bool add);
    void cmdList(iClient*, const StringTokenizer&);
    void cmdDebug(iClient*, const StringTokenizer&);
    void sendHelp(iClient*);

    maskSetType* setFor(IgnoreType);
    const maskSetType* setFor(IgnoreType) const;
    static bool parseType(const std::string&, IgnoreType&);
    static const char* typeName(IgnoreType);

    void loadIgnores();
    void saveIgnores() const;

    std::string adminChanName;
    std::string ignoreFile;
    std::string debugChanName;
    bool useColours;
    std::string colNick, colUserHost, colIp, colChannel, colServer, colModes;
    bool debugEnabled;

    // P10/P11 command tokens that are left out of the debug channel
    std::set<std::string> debugIgnore;

    // True while spybot itself writes, so its own output is not logged again
    bool writing;

    maskSetType ignoredServers;
    maskSetType ignoredClients;
    maskSetType ignoredChannels;
};

} // namespace gnuworld

#endif // __SPYBOT_H
