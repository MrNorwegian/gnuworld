/**
 * MODECommand.cc
 *
 * 01/04/2024 - MrIron <iron@masterbofh.org>
 * Initial Version.
 *
 * Sets modes in a channel.
 *
 * Caveats: None
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
 */

#include <string>
#include <sstream>
#include <iostream>
#include "StringTokenizer.h"
#include "ELog.h"
#include "cservice.h"
#include "levels.h"
#include "responses.h"
#include "Network.h"

namespace gnuworld {
using std::endl;
using std::ends;
using std::string;
using std::stringstream;

bool MODECommand::Exec(iClient* theClient, const string& Message) {
    StringTokenizer st(Message);
    if (st.size() < 3 || (st[2][0] != '-' && st[2][0] != '+')) {
        Usage(theClient);
        return true;
    }

    sqlUser* theUser = bot->isAuthed(theClient, true);
    if (!theUser) {
        return false;
    }

    sqlChannel* theChan = bot->getChannelRecord(st[1]);
    if (!theChan) {
        bot->Notice(theClient, bot->getResponse(theUser, language::chan_not_reg).c_str(),
                    st[1].c_str());
        return false;
    }

    /* Check the bot is in the channel. */
    if (!theChan->getInChan()) {
        bot->Notice(theClient, bot->getResponse(theUser, language::i_am_not_on_chan,
                                                string("I'm not in that channel!")));
        return false;
    }

    int level = bot->getEffectiveAccessLevel(theUser, theChan, true);
    if (level < level::mode) {
        bot->Notice(theClient, bot->getResponse(theUser, language::insuf_access).c_str(),
                    st[1].c_str());
        return false;
    }

    // Cannot set mode, if the bot hasn't joined.
    Channel* tmpChan = Network->findChannel(theChan->getName());
    if (!tmpChan) {
        bot->Notice(theClient, bot->getResponse(theUser, language::chan_is_empty).c_str(),
                    st[1].c_str());
        return false;
    }

    // Done with the checking.

    // Define mode to be any mode, such as +abc-def
    // Define argument to to be any argument to a particular mode: +k <key> or +l <limit>

    // index into the st object, location of next argument
    StringTokenizer::size_type argPos = 3;

    // Store the command to be sent to the network in two strings
    // modeString holds the updated modes
    string modeString = "";

    // argString holds the updated arguments, delimited by space (' ')
    string argString = "";

    // Store the banmasks.
    string banString = "";

    // Will be set to true if a person tries to give or remove ops or voice.
    bool wrongMode = false;

    // Keep track of the polarity of the mode change.
    bool plus = true;

    // We need to put +l at the end of the modeString
    int limitPos = 0;

    // Iterate through the characters of the mode at st[ modePos ]
    for (string::size_type charPos = 0; charPos < st[2].size(); ++charPos) {
        switch (st[2][charPos]) {
        case 'o': // Op
            wrongMode = true;
            break;
        case 'v': // Voice
            wrongMode = true;
            break;
        case 'b': // Ban
            if (argPos >= st.size()) {
                Usage(theClient);
                return true;
            }

            if (!validUserMask(st[argPos]))
                break;

            // Add this mode to the current modeString
            modeString += st[2][charPos];

            // Add this argument to the current argument string
            argString += st[argPos] + ' ';

            // Add ban to banString, to be used in the response.
            if (!banString.empty())
                banString += ", ";
            banString += st[argPos];

            // Move to next argument
            argPos++;

            break;
        case 'k': // Key
            // Each of these modes needs an argument
            if (argPos >= st.size()) {
                Usage(theClient);
                return true;
            }

            if (plus) {
                if (tmpChan->getMode(
                        Channel::MODE_KEY)) /* Do not update key if chan is already +k */
                {
                    argPos++;
                    break;
                }

                if (st[argPos].size() > MAX_KEY_LENGTH) {
                    bot->Notice(
                        theClient,
                        bot->getResponse(theUser, language::mode_keylength,
                                         string("The channel key cannot exceed %i characters."))
                            .c_str(),
                        MAX_KEY_LENGTH);
                    return false;
                }

            } else {
                if (!tmpChan->getMode(Channel::MODE_KEY)) /* Not +k? */
                {
                    argPos++;
                    break;
                }

                // The user needs to provide the correct key in order to -k
                if (tmpChan->getKey() != st[argPos]) {
                    bot->Notice(theClient,
                                bot->getResponse(theUser, language::mode_wrongkey,
                                                 string("You need to provide the existing key in "
                                                        "order to unset the key."))
                                    .c_str());
                    return false;
                }
            }

            // Add this mode to the current modeString
            modeString += st[2][charPos];

            // Add this argument to the current argument string
            argString += st[argPos] + ' ';

            // Move to next argument
            argPos++;

            break;
        case 'l': // Limit
            // Mode -l requires no argument
            if (!plus) {
                // No args needed
                modeString += st[2][charPos];
                break;
            }

            // Else, the user has specified +l, need an
            // argument.
            if (argPos >= st.size() || !IsNumeric(st[argPos])) {
                Usage(theClient);
                return true;
            }

            // Save position of argument
            limitPos = argPos;

            // Move to next argument
            argPos++;

            break;
        case 'i': // Invite?

            modeString += st[2][charPos];
            break;
        case 'p': // Private?

            modeString += st[2][charPos];
            break;
        case 'r': // Moderated for non-authed users?

            modeString += st[2][charPos];
            break;
        case 's': // Secret?

            modeString += st[2][charPos];
            break;
        case 'm': // Moderated?

            modeString += st[2][charPos];
            break;
        case 'n': // No External Messages?

            modeString += st[2][charPos];
            break;
        case 't': // Topic?

            modeString += st[2][charPos];
            break;
        case 'c': // Colours

            modeString += st[2][charPos];
            break;
        case 'C': // CTCP

            modeString += st[2][charPos];
            break;
        case 'u': // No part messages
        case 'M': // Moderated for unauthenticated users
        case 'Z': // TLS only clients
            // P11 has these three modes; a P10 uplink does not know them
            if (bot->getUplink()->getUplink()->getProtocol() < 11)
                break;
            modeString += st[2][charPos];
            break;
        case 'D': // Delayed joins

            modeString += st[2][charPos];
            break;

        case '+':
            if (plus) {
                modeString += st[2][charPos];
                break;
            }
            plus = true;
            modeString += st[2][charPos];
            break;
        case '-':
            if (!plus) {
                // Already minus
                break;
            }
            plus = false;
            modeString += st[2][charPos];
            break;
        default:
            // Not a valid mode, break.
            break;
        } // switch()
    } // for()

    if (modeString.size() > 1 || limitPos > 0) {
        // Add +l to the modeString which would need to be after +k
        if (plus && limitPos > 0) {
            // Add this mode to the current modeString
            modeString += 'l';

            // Add this argument to the current argument string
            argString += st[limitPos];
        }

        bot->Mode(tmpChan, modeString, argString, false);
        bot->Notice(
            theClient,
            bot->getResponse(theUser, language::mode_is, string("Mode for %s is now: %s")).c_str(),
            tmpChan->getName().c_str(), tmpChan->getModeString().c_str());

        if (!banString.empty())
            bot->Notice(
                theClient,
                bot->getResponse(theUser, language::mode_banset, string("Ban-modes set for: %s"))
                    .c_str(),
                banString.c_str());

        // Send action opnotice to channel if OPLOG is enabled
        if (theChan->getFlag(sqlChannel::F_OPLOG))
            bot->NoticeChannelOps(theChan->getName(), "%s (%s) set mode: %s %s",
                                  theClient->getNickName().c_str(), theUser->getUserName().c_str(),
                                  modeString.c_str(), argString.c_str());

        if (wrongMode)
            bot->Notice(theClient,
                        bot->getResponse(theUser, language::mode_opvoice,
                                         string("Please use the OP, DEOP, VOICE and DEVOICE "
                                                "commands to give or remove ops or voice.")));
    } else {
        Usage(theClient);
    }
    return true;
}

} // namespace gnuworld.
