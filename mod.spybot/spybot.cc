/**
 * spybot.cc
 *
 * Reports network traffic (connects, quits, kills, nick/mode changes,
 * joins/parts/kicks, server links/splits and glines) to an admin channel.
 * Operators can manage ignore lists with /msg spybot.
 */

#include <cctype>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>

#include "Channel.h"
#include "ELog.h"
#include "EConfig.h"
#include "Gline.h"
#include "Network.h"
#include "StringTokenizer.h"
#include "client.h"
#include "events.h"
#include "iClient.h"
#include "iServer.h"
#include "ip.h"
#include "misc.h"
#include "server.h"
#include "spybot.h"

namespace gnuworld {

using std::string;

extern "C" {
xClient* _gnuwinit(const string& args) { return new spybot(args); }
}

namespace {

string stripColon(const string& s) { return (!s.empty() && ':' == s[0]) ? s.substr(1) : s; }

string tail(const StringTokenizer& st, StringTokenizer::size_type from) {
    return (from < st.size()) ? stripColon(st.assemble(from)) : string();
}

bool isChannelName(const string& s) { return !s.empty() && ('#' == s[0] || '&' == s[0]); }

} // namespace

spybot::spybot(const string& configFileName)
    : xClient(configFileName), useColours(true), debugEnabled(false), writing(false) {
    EConfig conf(configFileName);
    adminChanName = conf.Require("adminchan")->second;
    ignoreFile = conf.TryRequire<string>("ignorefile", string("spybot.ignores"));
    debugChanName = conf.TryRequire<string>("debugchan", string());
    debugEnabled = !debugChanName.empty();
    // Commands to leave out of the debug channel, separated by space or comma
    const string ignoreList = conf.TryRequire<string>("debugignore", string("RI RO Z G"));
    string token;
    for (char ch : ignoreList + " ") {
        if (' ' == ch || ',' == ch) {
            if (!token.empty()) {
                debugIgnore.insert(token);
                token.clear();
            }
        } else {
            token += static_cast<char>(::toupper(static_cast<unsigned char>(ch)));
        }
    }
    useColours = (string_lower(conf.TryRequire<string>("colours", string("yes"))) != "no");
    loadIgnores();
}

spybot::~spybot() {}

void spybot::OnAttach() {
    xClient::OnAttach();

    MyUplink->RegisterEvent(EVT_NICK, this);
    MyUplink->RegisterEvent(EVT_QUIT, this);
    MyUplink->RegisterEvent(EVT_KILL, this);
    MyUplink->RegisterEvent(EVT_CHNICK, this);
    MyUplink->RegisterEvent(EVT_NETJOIN, this);
    MyUplink->RegisterEvent(EVT_NETBREAK, this);
    MyUplink->RegisterEvent(EVT_GLINE, this);
    MyUplink->RegisterEvent(EVT_REMGLINE, this);
    MyUplink->RegisterEvent(EVT_RAW, this);
    MyUplink->RegisterEvent(EVT_RAW_OUT, this);
}

void spybot::BurstChannels() {
    xClient::BurstChannels();

    Join(adminChanName);
    if (!debugChanName.empty() && 0 != strcasecmp(debugChanName.c_str(), adminChanName.c_str())) {
        Join(debugChanName);
    }
}

void spybot::OnEvent(const eventType& whichEvent, void* arg1, void* arg2, void* arg3, void* arg4) {
    switch (whichEvent) {
    case EVT_NICK:
        handleConnect(static_cast<iClient*>(arg1));
        break;
    case EVT_QUIT:
        handleQuit(static_cast<iClient*>(arg1), static_cast<const string*>(arg2));
        break;
    case EVT_KILL:
        handleKill(arg1, static_cast<iClient*>(arg2), static_cast<const string*>(arg3));
        break;
    case EVT_CHNICK:
        handleNickChange(static_cast<iClient*>(arg1), static_cast<const string*>(arg2));
        break;
    case EVT_NETJOIN:
        handleServerLink(static_cast<iServer*>(arg1), static_cast<iServer*>(arg2));
        break;
    case EVT_NETBREAK:
        // arg2 is not the same type at every posting site, so it is not used
        handleServerSplit(static_cast<iServer*>(arg1), static_cast<const string*>(arg3));
        break;
    case EVT_GLINE:
        handleGline(static_cast<Gline*>(arg1), true);
        break;
    case EVT_REMGLINE:
        handleGline(static_cast<Gline*>(arg1), false);
        break;
    case EVT_RAW:
        if (arg1) {
            const string& line = *static_cast<const string*>(arg1);
            debugLine("[Sockread Server] -->", line);
            handleRaw(line);
        }
        break;
    case EVT_RAW_OUT:
        if (arg1) {
            handleRawOut(*static_cast<const string*>(arg1));
        }
        break;
    default:
        break;
    }

    xClient::OnEvent(whichEvent, arg1, arg2, arg3, arg4);
}

string spybot::colour(const char* code, const string& text) const {
    return useColours ? string("\003") + code + text + "\003" : text;
}

void spybot::report(const string& text) {
    const bool was = writing;
    writing = true;
    Message(adminChanName, text);
    writing = was;
}

void spybot::handleRawOut(const string& line) {
    if (!writing) {
        debugLine("[Sockwrite Server] <--", line);
    }
}

// Logs one raw P10/P11 line to the debug channel, split to fit an IRC line
void spybot::debugLine(const char* direction, const string& rawLine) {
    if (!debugEnabled || debugChanName.empty() || writing) {
        return;
    }

    // The command token is second on a line, after an optional P11 @tags token
    {
        string noTags = rawLine;
        if (!noTags.empty() && '@' == noTags[0]) {
            const string::size_type sp = noTags.find(' ');
            noTags = (string::npos == sp) ? string() : noTags.substr(sp + 1);
        }
        StringTokenizer tok(noTags);
        if (tok.size() > 1 && debugIgnore.count(tok[1])) {
            return;
        }
    }

    string line;
    for (char ch : rawLine) {
        if (static_cast<unsigned char>(ch) >= 0x20) {
            line += ch;
        }
    }

    const size_t chunk = 350;
    writing = true;
    size_t pos = 0;
    do {
        Message(debugChanName, string(direction) + " " + line.substr(pos, chunk));
        pos += chunk;
    } while (pos < line.size());
    writing = false;
}

/* ------------------------------------------------------------------ */
/* Describing and matching                                             */
/* ------------------------------------------------------------------ */

string spybot::serverNameOf(const iClient* theClient) const {
    iServer* theServer = Network->findServer(theClient->getIntYY());
    return theServer ? theServer->getName() : string("unknown");
}

string spybot::describeClient(const iClient* theClient) const {
    const string& host = theClient->getRealInsecureHost().empty() ? theClient->getInsecureHost()
                                                                  : theClient->getRealInsecureHost();
    return "User " + orange(theClient->getNickName() + " (" + theClient->getUserName() + "@" + host + ")") +
           " [" + xIP(theClient->getIP()).GetNumericIP() + "]";
}

string spybot::describeSource(const string& numeric) const {
    if (2 == numeric.size()) {
        iServer* theServer = Network->findServer(numeric);
        return "Server " + yellow(theServer ? theServer->getName() : numeric);
    }
    iClient* theClient = Network->findClient(numeric);
    return theClient ? describeClient(theClient) : "Unknown " + numeric;
}

bool spybot::isServerIgnored(const string& serverName) const {
    for (const string& mask : ignoredServers) {
        if (0 == match(mask, serverName)) {
            return true;
        }
    }
    return false;
}

bool spybot::isChannelIgnored(const string& channelName) const {
    for (const string& mask : ignoredChannels) {
        if (0 == match(mask, channelName)) {
            return true;
        }
    }
    return false;
}

bool spybot::isClientIgnored(const iClient* theClient) const {
    if (isServerIgnored(serverNameOf(theClient))) {
        return true;
    }

    const string prefix = theClient->getNickName() + "!" + theClient->getUserName() + "@";
    const string candidates[] = {prefix + theClient->getInsecureHost(),
                                 prefix + theClient->getRealInsecureHost(),
                                 prefix + xIP(theClient->getIP()).GetNumericIP()};
    for (const string& mask : ignoredClients) {
        for (const string& candidate : candidates) {
            if (0 == match(mask, candidate)) {
                return true;
            }
        }
    }
    return false;
}

bool spybot::isSourceIgnored(const string& numeric) const {
    if (2 == numeric.size()) {
        iServer* theServer = Network->findServer(numeric);
        return theServer && isServerIgnored(theServer->getName());
    }
    iClient* theClient = Network->findClient(numeric);
    return theClient && isClientIgnored(theClient);
}

/* ------------------------------------------------------------------ */
/* Network event handlers                                              */
/* ------------------------------------------------------------------ */

void spybot::handleConnect(iClient* theClient) {
    // Users arriving in our own link burst are not new connections
    if (!theClient || MyUplink->isBursting() || isClientIgnored(theClient)) {
        return;
    }

    report(describeClient(theClient) + " * " + theClient->getDescription() + " Connected to " +
           yellow("[" + serverNameOf(theClient) + "]"));
}

void spybot::handleQuit(iClient* theClient, const string* reason) {
    // Quits caused by a netsplit are posted without a reason; the split is reported instead
    if (!theClient || !reason || isClientIgnored(theClient)) {
        return;
    }

    report(describeClient(theClient) + " * " + theClient->getDescription() + " Disconnected from " +
           yellow("[" + serverNameOf(theClient) + "]") + " With reason: " + *reason);
}

void spybot::handleKill(void* source, iClient* target, const string* reason) {
    if (!target) {
        return;
    }

    // Both iClient and iServer derive from NetworkTarget
    NetworkTarget* src = static_cast<NetworkTarget*>(source);
    string who = "Server";
    bool srcIgnored = false;
    if (iClient* srcClient = dynamic_cast<iClient*>(src)) {
        who = describeClient(srcClient);
        srcIgnored = isClientIgnored(srcClient);
    } else if (iServer* srcServer = dynamic_cast<iServer*>(src)) {
        who = "Server " + yellow(srcServer->getName());
        srcIgnored = isServerIgnored(srcServer->getName());
    }

    if (srcIgnored || isClientIgnored(target)) {
        return;
    }

    report(who + " killed " + describeClient(target) + " With reason: " + (reason ? *reason : string()));
}

void spybot::handleNickChange(iClient* theClient, const string* oldNick) {
    if (!theClient || isClientIgnored(theClient)) {
        return;
    }

    report(describeClient(theClient) + " changed nick: " + (oldNick ? *oldNick : string("?")) + " -> " +
           theClient->getNickName());
}

void spybot::handleServerLink(iServer* theServer, iServer* uplink) {
    if (!theServer) {
        return;
    }
    if (!uplink) {
        uplink = Network->findServer(theServer->getUplinkIntYY());
    }
    if (isServerIgnored(theServer->getName())) {
        return;
    }

    report("Server " + yellow(theServer->getName()) + " linked to " +
           yellow(uplink ? uplink->getName() : string("?")) + " (" + theServer->getDescription() + ")");
}

void spybot::handleServerSplit(iServer* theServer, const string* reason) {
    if (!theServer || isServerIgnored(theServer->getName())) {
        return;
    }

    iServer* uplink = Network->findServer(theServer->getUplinkIntYY());
    report("Server " + yellow(theServer->getName()) + " split from " +
           yellow(uplink ? uplink->getName() : string("?")) + " (" + (reason ? *reason : string()) + ")");
}

void spybot::handleGline(Gline* theGline, bool added) {
    if (!theGline) {
        return;
    }

    const string& setBy = theGline->getSetBy();
    string who = setBy;
    if (iServer* theServer = Network->findServerName(setBy)) {
        if (isServerIgnored(theServer->getName())) {
            return;
        }
        who = "Server " + yellow(theServer->getName());
    } else if (iClient* theClient = Network->findNick(setBy)) {
        if (isClientIgnored(theClient)) {
            return;
        }
        who = describeClient(theClient);
    }

    if (!added) {
        report(who + " removed GLINE " + theGline->getUserHost());
        return;
    }

    const time_t expiration = theGline->getExpiration();
    const long remaining = static_cast<long>(expiration - ::time(0));
    char buf[64] = "";
    struct tm tmBuf;
    if (::localtime_r(&expiration, &tmBuf)) {
        ::strftime(buf, sizeof(buf), "%d %b %Y %H:%M:%S", &tmBuf);
    }

    report(who + " set GLINE " + theGline->getUserHost() + " for reason: " + theGline->getReason() +
           " - Time remaining: " + std::to_string(remaining) + " seconds (" + buf + ")");
}

/* ------------------------------------------------------------------ */
/* Raw P10                                                             */
/* ------------------------------------------------------------------ */

void spybot::handleRaw(const string& rawLine) {
    string line(rawLine);
    while (!line.empty() && ('\n' == line.back() || '\r' == line.back())) {
        line.pop_back();
    }

    // P11 lines may begin with a message-tags token
    if (!line.empty() && '@' == line[0]) {
        const string::size_type sp = line.find(' ');
        if (string::npos == sp) {
            return;
        }
        line.erase(0, sp + 1);
    }

    StringTokenizer st(line);
    if (st.size() < 3) {
        return;
    }

    const string& src = st[0];
    const string& token = st[1];
    if (src.empty() || ':' == src[0]) {
        return;
    }

    if ("J" == token) {
        rawJoin(src, st, false);
    } else if ("C" == token) {
        rawJoin(src, st, true);
    } else if ("L" == token) {
        rawPart(src, st);
    } else if ("K" == token) {
        rawKick(src, st);
    } else if ("T" == token) {
        rawTopic(src, st);
    } else if ("M" == token) {
        rawMode(src, st, false);
    } else if ("OM" == token) {
        rawMode(src, st, true);
    }
}

void spybot::rawJoin(const string& src, const StringTokenizer& st, bool create) {
    if (isSourceIgnored(src)) {
        return;
    }

    const string who = describeSource(src);
    if ("0" == st[2]) {
        report(who + " parts all channels");
        return;
    }

    StringTokenizer chans(st[2], ',');
    for (StringTokenizer::size_type i = 0; i < chans.size(); ++i) {
        if (!isChannelIgnored(chans[i])) {
            report(who + (create ? " creates " : " joins ") + chans[i]);
        }
    }
}

void spybot::rawPart(const string& src, const StringTokenizer& st) {
    if (isSourceIgnored(src)) {
        return;
    }

    const string who = describeSource(src);
    const string reason = tail(st, 3);
    StringTokenizer chans(st[2], ',');
    for (StringTokenizer::size_type i = 0; i < chans.size(); ++i) {
        if (!isChannelIgnored(chans[i])) {
            report(who + " parts " + chans[i] + (reason.empty() ? string() : " (" + reason + ")"));
        }
    }
}

void spybot::rawKick(const string& src, const StringTokenizer& st) {
    if (st.size() < 4 || isChannelIgnored(st[2]) || isSourceIgnored(src) || isSourceIgnored(st[3])) {
        return;
    }

    report(describeSource(src) + " kicked " + describeSource(st[3]) + " from " + st[2] + " (" + tail(st, 4) +
           ")");
}

void spybot::rawTopic(const string& src, const StringTokenizer& st) {
    if (isChannelIgnored(st[2]) || isSourceIgnored(src)) {
        return;
    }

    // The topic is the trailing parameter; timestamps may precede it
    string topic;
    for (StringTokenizer::size_type i = 3; i < st.size(); ++i) {
        if (!st[i].empty() && ':' == st[i][0]) {
            topic = tail(st, i);
            break;
        }
    }

    report(describeSource(src) + " sets topic on " + st[2] + ": " + topic);
}

void spybot::rawMode(const string& src, const StringTokenizer& st, bool opmode) {
    if (st.size() < 4 || isSourceIgnored(src)) {
        return;
    }

    const string& target = st[2];
    const string label = opmode ? " uses OPMODE: " : " sets mode: ";

    if (isChannelName(target)) {
        if (isChannelIgnored(target)) {
            return;
        }

        // Show nicks instead of numerics for client arguments
        string modes = stripColon(st[3]);
        for (StringTokenizer::size_type i = 4; i < st.size(); ++i) {
            iClient* argClient = (5 == st[i].size()) ? Network->findClient(st[i]) : 0;
            modes += " " + (argClient ? argClient->getNickName() : st[i]);
        }
        report(describeSource(src) + label + target + " " + modes);
        return;
    }

    iClient* targetClient = Network->findNick(target);
    if (targetClient && isClientIgnored(targetClient)) {
        return;
    }

    const string modes = tail(st, 3);
    const bool self = targetClient && src == targetClient->getCharYYXXX();
    report(describeSource(src) + label + modes + (self ? string() : " (on " + target + ")"));
}

/* ------------------------------------------------------------------ */
/* Admin commands                                                      */
/* ------------------------------------------------------------------ */

void spybot::OnPrivateMessage(iClient* theClient, const string& message, bool) {
    if (!theClient->isOper()) {
        Notice(theClient, string("Access denied"));
        return;
    }

    StringTokenizer st(message);
    if (st.empty()) {
        return;
    }

    const string command = string_lower(st[0]);
    if ("ignore" == command) {
        cmdIgnore(theClient, st, true);
    } else if ("unignore" == command) {
        cmdIgnore(theClient, st, false);
    } else if ("list" == command || "ignores" == command) {
        cmdList(theClient, st);
    } else if ("debug" == command) {
        cmdDebug(theClient, st);
    } else {
        sendHelp(theClient);
    }
}

void spybot::sendHelp(iClient* theClient) {
    Notice(theClient, string("Commands:"));
    Notice(theClient, string("  IGNORE <server|client|channel> <mask>"));
    Notice(theClient, string("  UNIGNORE <server|client|channel> <mask>"));
    Notice(theClient, string("  LIST IGNORES [server|client|channel]"));
    Notice(theClient, string("  DEBUG [ON|OFF]  (raw P10/P11 log to the debug channel)"));
    Notice(theClient, string("Client masks are nick!user@host (host may be an IP); a bare nick or user@host is expanded."));
}

void spybot::cmdDebug(iClient* theClient, const StringTokenizer& st) {
    if (debugChanName.empty()) {
        Notice(theClient, string("No debugchan is set in the config"));
        return;
    }
    if (st.size() > 1) {
        const string arg = string_lower(st[1]);
        if ("on" != arg && "off" != arg) {
            sendHelp(theClient);
            return;
        }
        debugEnabled = ("on" == arg);
    }
    Notice(theClient, string("Raw debug logging to ") + debugChanName + " is " + (debugEnabled ? "ON" : "OFF"));
}

bool spybot::parseType(const string& name, IgnoreType& type) {
    const string lower = string_lower(name);
    if ("server" == lower) {
        type = IGN_SERVER;
    } else if ("client" == lower) {
        type = IGN_CLIENT;
    } else if ("channel" == lower) {
        type = IGN_CHANNEL;
    } else {
        return false;
    }
    return true;
}

const char* spybot::typeName(IgnoreType type) {
    switch (type) {
    case IGN_SERVER:
        return "server";
    case IGN_CLIENT:
        return "client";
    default:
        return "channel";
    }
}

spybot::maskSetType* spybot::setFor(IgnoreType type) {
    switch (type) {
    case IGN_SERVER:
        return &ignoredServers;
    case IGN_CLIENT:
        return &ignoredClients;
    default:
        return &ignoredChannels;
    }
}

const spybot::maskSetType* spybot::setFor(IgnoreType type) const {
    return const_cast<spybot*>(this)->setFor(type);
}

void spybot::cmdIgnore(iClient* theClient, const StringTokenizer& st, bool add) {
    IgnoreType type;
    if (st.size() < 3 || !parseType(st[1], type)) {
        sendHelp(theClient);
        return;
    }

    string mask = string_lower(st[2]);
    if (IGN_CLIENT == type) {
        if (string::npos == mask.find('!')) {
            mask = (string::npos == mask.find('@')) ? mask + "!*@*" : "*!" + mask;
        }
    }

    maskSetType* masks = setFor(type);
    if (add) {
        if (!masks->insert(mask).second) {
            Notice(theClient, "Already ignoring " + string(typeName(type)) + " " + mask);
            return;
        }
        Notice(theClient, "Now ignoring " + string(typeName(type)) + " " + mask);
    } else {
        if (0 == masks->erase(mask)) {
            Notice(theClient, "No " + string(typeName(type)) + " ignore " + mask);
            return;
        }
        Notice(theClient, "No longer ignoring " + string(typeName(type)) + " " + mask);
    }
    saveIgnores();
}

void spybot::cmdList(iClient* theClient, const StringTokenizer& st) {
    // Accept both "LIST IGNORES [type]" and "IGNORES [type]"
    StringTokenizer::size_type next = ("list" == string_lower(st[0])) ? 1 : 0;
    if (next >= st.size() || "ignores" != string_lower(st[next])) {
        sendHelp(theClient);
        return;
    }
    ++next;

    bool all = true;
    IgnoreType only = IGN_SERVER;
    if (next < st.size()) {
        if (!parseType(st[next], only)) {
            sendHelp(theClient);
            return;
        }
        all = false;
    }

    for (int t = IGN_SERVER; t <= IGN_CHANNEL; ++t) {
        const IgnoreType type = static_cast<IgnoreType>(t);
        if (!all && type != only) {
            continue;
        }
        const maskSetType* masks = setFor(type);
        Notice(theClient, string("Ignored ") + typeName(type) + "s (" + std::to_string(masks->size()) + "):");
        for (const string& mask : *masks) {
            Notice(theClient, "  " + mask);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Persistence                                                         */
/* ------------------------------------------------------------------ */

void spybot::loadIgnores() {
    std::ifstream in(ignoreFile.c_str());
    string line;
    while (std::getline(in, line)) {
        StringTokenizer st(line);
        IgnoreType type;
        if (st.size() == 2 && parseType(st[0], type)) {
            setFor(type)->insert(string_lower(st[1]));
        }
    }
}

void spybot::saveIgnores() const {
    std::ofstream out(ignoreFile.c_str(), std::ios::trunc);
    if (!out) {
        elog << "spybot::saveIgnores> Unable to write " << ignoreFile << std::endl;
        return;
    }
    for (int t = IGN_SERVER; t <= IGN_CHANNEL; ++t) {
        const IgnoreType type = static_cast<IgnoreType>(t);
        for (const string& mask : *setFor(type)) {
            out << typeName(type) << ' ' << mask << '\n';
        }
    }
}

} // namespace gnuworld
