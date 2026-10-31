/**
 * server_connection.cc
 * This is the implementation file for the xServer class.
 * This class is the entity which is the GNUWorld server
 * proper.  It manages network I/O, parsing and distributing
 * incoming messages, notifying attached clients of
 * system events, on, and on, and on.
 *
 * Copyright (C) 2002 Daniel Karrels <dan@karrels.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 *
 * $Id: server_connection.cc,v 1.4 2006/12/22 06:41:45 kewlio Exp $
 */

#include <new>
#include <string>
#include <string_view>
// #include	<list>
// #include	<vector>
// #include	<algorithm>
#include <sstream>
// #include	<fstream>
// #include	<stack>
// #include	<iostream>
// #include	<utility>

// #include	<cstdlib>
#include <cstdio>
#include <cstdarg>
// #include	<cstring>
// #include	<cassert>
// #include	<cerrno>
// #include	<csignal>

#include "gnuworld_config.h"
// #include	"misc.h"
// #include	"events.h"
// #include	"ip.h"

#include "server.h"
#include "Network.h"
// #include	"iServer.h"
// #include	"iClient.h"
// #include	"EConfig.h"
// #include	"match.h"
#include "logger.h"
// #include	"StringTokenizer.h"
// #include	"xparameters.h"
// #include	"moduleLoader.h"
// #include	"ServerTimerHandlers.h"
// #include	"LoadClientTimerHandler.h"
// #include	"UnloadClientTimerHandler.h"
#include "misc.h"
#include "ConnectionManager.h"
#include "ConnectionHandler.h"
#include "Connection.h"

/* The logger this file writes to: the link to the uplink.  Core is one binary
 * and not one module, so this stands once per .cc file rather than in a header */
GNUWORLD_CORE_LOGGER(Net);

namespace gnuworld {

// using std::pair ;
// using std::make_pair ;
using std::string;
// using std::vector ;
// using std::list ;
using std::clog;
using std::endl;
using std::stringstream;
// using std::stack ;
// using std::unary_function ;

void xServer::OnConnect(Connection* theConn) {
    // Just connected to our uplink
    serverConnection = theConn;

    // P11 version information, bogus.
    Version = 11;

    // Set ourselves as a service.
    me->setService();

    // Record the protocol version we announce in our SERVER line.
    me->setProtocol(static_cast<unsigned int>(Version));

    // Initialize the connection time variable to current time.
    ConnectionTime = ::time(NULL);

    clog << "*** Connected!" << endl;

    LOG(INFO, "Connected to {}, port {}", serverConnection->getHostname(),
        serverConnection->getRemotePort());

    // Login to the uplink.
    WriteDuringBurst("PASS :{}\n", Password);

    // Send our server information.
    WriteDuringBurst("SERVER {} {} {} {} J{:02} {} +s6 :{}\n", ServerName, 1, StartTime,
                     ConnectionTime, Version, (string(getCharYY()) + "]]]"), ServerDescription);

    // Our capabilities follow once the uplink has said which protocol it
    // speaks: a P10 server must never be sent a CAP.  See msg_Server.
}

void xServer::OnConnectFail(Connection* theConn) {
    LOG(FATAL, "Failed to establish connection to {}:{}", theConn->getHostname(),
        theConn->getRemotePort());

    serverConnection = 0;
    keepRunning = false;
}

/**
 * Handle a disconnect from our uplink.  This method is
 * responsible for deallocating variables mostly.
 */
void xServer::OnDisconnect(Connection* theConn) {
    if (theConn != serverConnection) {
        LOG(WARN, "Unknown connection");
        return;
    }

    // Disconnected from uplink
    // The ConnectionManager will deallocate the memory associated with
    // the Connection object
    serverConnection = 0;

    LOG(INFO, "Disconnected :(");

    keepRunning = false;

    // doShutdown() will be called at the bottom of the main for loop,
    // which will perform a proper shutdown.
    for (xNetwork::localClientIterator cItr = Network->localClient_begin();
         cItr != Network->localClient_end(); ++cItr) {
        cItr->second->OnDisconnect();
    }
}

void xServer::OnRead(Connection* theConn, const string& line) {
    if (theConn != serverConnection) {
        LOG(WARN, "Unknown connection");
        return;
    }

    // Don't process any incoming data on the last iteration of
    // the main control loop.
    if (!keepRunning || lastLoop) {
        // Part of the shutdown process includes flushing any
        // data in the output buffer, and closing connections.
        // This requires calling Poll(), which will also
        // recv() and perform any distribution of messages to
        // handlers, including OnRead().
        // Therefore, only handle data if the server is still
        // in a running state.
        return;
    }

    burstLines++;
    burstBytes += line.size();

    size_t len = line.size() - 1;
    while (('\n' == line[len]) || ('\r' == line[len])) {
        --len;
    }

    if (len + 1 >= sizeof(inputCharBuffer)) {
        LOG(WARN, "Rejecting oversized line ({} bytes, max {})", len + 1,
            sizeof(inputCharBuffer) - 1);
        return;
    }

    memset(inputCharBuffer, 0, sizeof(inputCharBuffer));
    strncpy(inputCharBuffer, line.c_str(), len + 1);

    struct CommandMask {
        std::string command;
        size_t pos;
    };

    /* List of commands containing sensitive information to be redacted in logging.
     * 1. Command in upper case only.
     * 2. The position of the sensitive information in the command.
     */
    static const CommandMask commandMasks[] = {
        {"LOGIN", 2},
        {"LOGIN2", 5},
        {"NEWPASS", 1},
        {"SUSPENDME", 1},
    };

    std::string logLine = line;
    if (line.size() > 10 &&
        ((line[6] == 'P' && line[9] == '@') || (line[3] == 'X' && line[4] == 'Q'))) {
        size_t colonPos = logLine.find(" :");
        if (colonPos != std::string::npos) {
            std::istringstream iss(logLine.substr(colonPos + 2));
            std::string word;
            iss >> word;

            // Find command in mask table
            for (const auto& mask : commandMasks) {
                if (string_upper(word) == mask.command) {
                    std::vector<std::string> fields;
                    fields.push_back(word);
                    while (iss >> word)
                        fields.push_back(word);

                    // Scramble password if position exists
                    if (fields.size() > mask.pos)
                        fields[mask.pos] = gnuworld::mask(fields[mask.pos]);

                    // Reconstruct scrambled message
                    std::ostringstream oss;
                    for (size_t i = 0; i < fields.size(); ++i) {
                        if (i > 0)
                            oss << " ";
                        oss << fields[i];
                    }
                    std::string scrambled = oss.str();

                    // If the original line ended with a newline, add it back
                    if (!logLine.empty() && (line.back() == '\n' || line.back() == '\r'))
                        scrambled += "\n";

                    logLine.replace(colonPos + 2, std::string::npos, scrambled);
                    break;
                }
            }
        }
    }

    if (verbose) {
        clog << "[IN ]: " << logLine;
    }

    if (logSocket) {
        socketFile << ::time(0) << " " << logLine;
        socketFile.flush();
    }

    Process(inputCharBuffer);

    // Post the RAW read event
    PostEvent(EVT_RAW, static_cast<void*>(const_cast<string*>(&line)));
}

/**
 * This method will append a string to the output
 * buffer.
 * Returns false if there is no valid connection,
 * true otherwise.
 */
bool xServer::writeLine(std::string_view text, bool duringBurst) {
    if (!isConnected()) {
        if (duringBurst) {
            LOG(WARN, "Not connected");
        }
        return false;
    }

    // One call is one line.  Callers may or may not supply the line ending.
    while (!text.empty() && ('\n' == text.back() || '\r' == text.back())) {
        text.remove_suffix(1);
    }

    // ircu ends a line at CR as well as at LF, so text with either inside
    // it, a channel description out of the database say, would start a new
    // server-to-server line of somebody else's choosing.  Cut it there.  A
    // NUL ends the line for ircu too.
    const std::string_view::size_type cut = text.find_first_of(std::string_view("\r\n\0", 3));
    if (cut != std::string_view::npos) {
        LOG(WARN, "Dropped {} bytes behind a line break inside: {}", text.size() - cut,
            text.substr(0, cut));
        text = text.substr(0, cut);
    }

    if (text.empty()) {
        return false;
    }

    if (verbose) {
        clog << "[OUT]: " << text << endl;
    }

    // Let listeners see every line sent to the uplink, including held ones
    if (!eventList[EVT_RAW_OUT].empty()) {
        std::string out(text);
        PostEvent(EVT_RAW_OUT, static_cast<void*>(&out));
    }

    std::string line(text);
    line += '\n';

    // Outside of our own burst, output is held back until the burst is done
    if (!duringBurst && useHoldBuffer) {
        burstHoldBuffer += line;
    } else {
        serverConnection->Write(line);
    }
    return true;
}

bool xServer::Write(const string& buf) { return writeLine(buf, false); }

bool xServer::Write(const xParameters::tagListType& tags, const string& line) {
    if (tags.empty() || !(Uplink && Uplink->getProtocol() >= 11)) {
        return Write(line);
    }
    return Write(xParameters::formatTagPrefix(tags) + line);
}

bool xServer::Write(const xParameters::tagListType& tags, const stringstream& line) {
    return Write(tags, string(line.str()));
}

bool xServer::WriteWithTime(const string& line) {
    if (!(Uplink && Uplink->getProtocol() >= 11)) {
        return Write(line);
    }
    xParameters::tagListType tags{MessageTag{"time", formatServerTime()}};
    return Write(tags, line);
}

bool xServer::WriteWithTime(const stringstream& line) { return WriteWithTime(string(line.str())); }

bool xServer::WriteDuringBurst(const string& buf) { return writeLine(buf, true); }

/**
 * Write the contents of a std::stringstream to the uplink connection.
 */
bool xServer::Write(const stringstream& s) { return Write(string(s.str())); }

bool xServer::WriteDuringBurst(const stringstream& s) { return WriteDuringBurst(string(s.str())); }

/**
 * This method appends the variable sized argument
 * list buffer to the output buffer.
 * Returns false if no valid connection available,
 * true otherwise.
 * I despise this function. --dan
 */
void xServer::WriteBurstBuffer() {
    if (!isConnected()) {
        return;
    }

    serverConnection->Write(burstHoldBuffer.data());
    burstHoldBuffer.clear();
}

void xServer::FlushData() {
    if (!isConnected()) {
        return;
    }
    serverConnection->Flush();
}

} // namespace gnuworld
