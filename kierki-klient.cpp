#include <iostream>
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "kierki-common.h"

#define HAND 13
#define TRICKS_IN_ROUND 13

// --------------------------- Declarations & Data Structures ---------------------------

static std::map<char, int> map_place = {
    {'N', 1},
    {'E', 2},
    {'S', 3},
    {'W', 4}
};


// ----------------------------------- Initialization -----------------------------------

// Sets variables describing input options.
int set_input_variables(int argc, char** argv, std::string* host, std::string* port, 
                        char* place, bool* ipv4, bool* ipv6, bool* bot) {
    int opt;
    while ((opt = getopt(argc, argv, "h:p:46NEWSa")) != -1) {
        switch (opt) {
            case 'h':
                *host = optarg;
                break;
            case 'p':
                *port = optarg;
                break;
            case '4':
                if (*ipv6 == true) {
                    *ipv6 = false;
                }
                *ipv4 = true;
                break;
            case '6':
                if (*ipv4 == true) {
                    *ipv4 = false;
                }
                *ipv6 = true;
                break;
            case 'N':
                *place = 'N';
                break;
            case 'E':
                *place = 'E';
                break;
            case 'S':
                *place = 'S';
                break;
            case 'W':
                *place = 'W';
                break;
            case 'a':
                *bot = true;
                break;
            default:
                return ERROR;
        }
    }
    return GOOD;
}

// Parses command line arguments.
void parse_arguments(int argc, char** argv, std::string* host, std::string* port, 
                     char* place, bool* ipv4, bool* ipv6, bool* bot)
{
    if (set_input_variables(argc, argv, host, port, place, ipv4, ipv6, bot) == ERROR ||
        (*host).empty() ||
        (*port).empty() ||
        *place == 'X'
    ) {
        throw std::runtime_error(
            "Usage: kierki-klient -h <host> -p <port> <-N | -E | -S | -W> [-4 | -6] [-a]\n"
        );
    }
}

// [TEST FUNCTION] Prints initial settings info.
void print_options_info(std::string host, std::string port, char place,
                        bool ipv4, bool ipv6, bool bot)
{
    std::cout << "Selected program options:\n";
    std::cout << "Host (-h): " << host << "\n";
    std::cout << "Port (-p): " << port << "\n";

    if (ipv4) {
        std::cout << "Protocol: IPv4\n";
    } else if (ipv6) {
        std::cout << "Protocol: IPv6\n";
    } else {
        std::cout << "Protocol: unspecified\n";
    }

    std::cout << "Place (-N/E/S/W): " << place << "\n";

    if (bot) {
        std::cout << "Robot\n";
    } else {
        std::cout << "Player\n";
    }
}

// Gets client IP and port (used in raport).
std::string get_client_ip_and_port(int socket_fd) {
    struct sockaddr_storage client_address;
    socklen_t address_len = sizeof(client_address);
    char ip[INET6_ADDRSTRLEN];
    uint16_t port;

    // Get the local address and port associated with the socket.
    if (getsockname(socket_fd, (struct sockaddr*)&client_address, &address_len) == -1) {
        throw std::runtime_error("getsockname failed");
    }

    // Determine if the socket is using IPv4 or IPv6.
    if (client_address.ss_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)&client_address;
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET6_ADDRSTRLEN);
        port = ntohs(addr_in->sin_port);
    } else if (client_address.ss_family == AF_INET6) {
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)&client_address;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
        port = ntohs(addr_in6->sin6_port);
    } else {
        throw std::runtime_error("Unknown address family");
    }

    return std::string(ip) + ":" + std::to_string(port);
}

// Connects client to server (based on code in man getaddrinfo).
void connect_to_server(std::string port_s, std::string host, bool ipv4,
                       bool ipv6, int* sock, bool* connected, std::string* server_ip_and_port) {

    uint16_t port = read_port(port_s);

    signal(SIGPIPE, SIG_IGN);

    struct addrinfo hints;
    struct addrinfo *address_result, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (ipv4) {
        hints.ai_family = AF_INET;
    } else if (ipv6) {
        hints.ai_family = AF_INET6;
    } else {
        hints.ai_family = AF_UNSPEC;
    }

    // *address_result is a list of possible addresses (struct addrinfo).
    int errcode = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &address_result);
    if (errcode != 0) {
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(errcode)));
    }

    int socket_fd = -1;

    for (p = address_result; p != nullptr; p = p->ai_next) {        
        socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (socket_fd == -1) {
            continue;
        }
        int errcode = connect(socket_fd, p->ai_addr, p->ai_addrlen);
        if (errcode != -1) {
            break;
        }

        close(socket_fd);
    }

    freeaddrinfo(address_result);

    if (p == nullptr) {
        throw std::runtime_error("No valid address found");
    }

    char ip[INET6_ADDRSTRLEN];

    if (p->ai_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)p->ai_addr)->sin_addr, ip, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)p->ai_addr)->sin6_addr, ip, INET6_ADDRSTRLEN);
    }

    *server_ip_and_port = ip;
    *server_ip_and_port += ":" + std::to_string(port);
    *sock = socket_fd;
    *connected = true;
}

// Initializes descriptors' array to use in poll().
void initialize_descriptors(struct pollfd* poll_fds, int socket_fd) {
    poll_fds[0].fd = socket_fd;
    poll_fds[0].events = POLLIN;
    poll_fds[1].fd = STDIN_FILENO;
    poll_fds[1].events = POLLIN;
}

// Disconnects client from server.
// TODO: Special function with manual error handling
void disconnect_from_server(bool* connected, int socket_fd) {
    if (*connected) {
        close(socket_fd);
        *connected = false;
    }   
}


// -------------------------------- Receiving messages ----------------------------------

// Reads from given descriptor until it founds '\n'.
int user_read_to_newline(int descriptor, std::string* result) {
    
    char buf;
    std::string buffer;

    int count = 0;
    while (count < READING_LIMIT) {
        ssize_t read_byte = readn(descriptor, &buf, 1);
        if (read_byte < 0) {
            return (int) read_byte;
        } else if (read_byte == 0) {
            break;
        } else if (read_byte == 1) {
            count++;
            buffer += buf;
            if (buffer.size() >= 1 && buffer.substr(buffer.size() - 1) == "\n") {
                *result = buffer;
                return count;
            }
        } else {
            throw std::runtime_error("weird error in readn");
        }
    }
    // Return number of read bytes:
    return count;
}

// Checks some of poll flags.
void check_poll_flags(struct pollfd* poll_fds) {
    // POLLHUP <=> client disconnected from server - in case of some weird behaviour.
    if (poll_fds[0].fd != -1 && (poll_fds[0].revents & POLLHUP)) {
        std::cerr << "POLLHUP in descriptor of the server - disconnected\n";
        throw std::runtime_error("poll: POLLHUP");
    }
    // POLLERR <=> server's error.
    else if (poll_fds[0].fd != -1 && (poll_fds[0].revents & POLLERR)) {
        std::cerr << "POLLERR in descriptor of the server - disconnected\n";
        throw std::runtime_error("poll: POLLERR");
    }
    // POLLNVAL <=> wrong descriptor.
    else if (poll_fds[0].fd != -1 && (poll_fds[0].revents & POLLNVAL)) {
        std::cerr << "POLLNVAL in descriptor of the server - disconnected\n";
        throw std::runtime_error("poll: POLLNVAL");
    }
}


// ------------------------------------- Parsers ----------------------------------------

// All parsers return 0 if a message is parsed correctly, 1 if it's not.

// Parser for a message of type: BUSY<place list>\r\n.
int parse_busy(const std::string& message, std::vector<char>& busy_places) {

    std::regex pattern(R"(BUSY([NESW]{1,4})\r\n)");
    std::smatch match;

    busy_places.clear();

    if (std::regex_match(message, match, pattern)) {
        std::string places = match[1].str();
        std::set<char> places_set(places.begin(), places.end());
        if (places.size() == places_set.size()) {
            for (char c : places_set) {
                busy_places.push_back(c);
            }
        } else {
            std::cerr << "Wrong message format, ignored\n";
            return ERROR;
        }
        return GOOD;
    } else {
        return ERROR;
    }
}

// Parser for a message of type: DEAL<round type><starting player><card list>\r\n.
int parse_deal(const std::string& message, int* round_type, 
               char* starting_player, Hand& hand) {

    std::regex pattern(R"(DEAL([1-7])([NESW])(.+)\r\n)");
    std::smatch match;

    hand.cards.clear();

    if (std::regex_match(message, match, pattern)) {
        
        *round_type = std::stoi(match[1].str());
        *starting_player = match[2].str()[0];
        
        if (parse_card_set(match[3].str(), hand.cards) == 0) {
            std::set<Card> card_set;
            for (auto& card : hand.cards) {
                card_set.insert(Card(card.value, card.suit));
            }
            
            if (card_set.size() == HAND) {
                return GOOD;
            } else {
                std::cerr << "didn't get 13 unique cards\n";
                return ERROR;
            }
        } else {
            return ERROR;
        }
    } else {
        return ERROR;
    }
}

// Parser for a message of type: TRICK<trick number><card list>\r\n.
int parse_trick(const std::string& message, int* trick_number,
                std::vector<Card>& on_table, bool trick_one) {
    
    std::regex pattern;
    if (trick_one) {
        pattern = R"(TRICK(1)(.*)\r\n)";
    } else {
        pattern = R"(TRICK([2-9]|1[0-3])(.*)\r\n)";
    }
    std::smatch match;

    on_table.clear();

    if (std::regex_match(message, match, pattern)) {

        *trick_number = std::stoi(match[1].str());
        
        if (match[2].str().length() == 0) {
            return GOOD;
        } 
        else if (parse_card_set(match[2].str(), on_table) == 0) {
            std::set<Card> card_set;
            for (auto& card : on_table) {
                card_set.insert(Card(card.value, card.suit));
            }

            if (on_table.size() <= 3 && card_set.size() == on_table.size()) {
                return GOOD;
            } else {
                std::cerr << "didn't get from 0 to 3 unique cards\n";
                return ERROR;
            }
        } else {
            return ERROR;
        }
    } else {
        return ERROR;
    }
}

// Parser for a message of type: WRONG<trick number>\r\n.
int parse_wrong(const std::string& message, int* trick_number) {

    std::regex pattern(R"(WRONG([1-9]|1[0-3])\r\n)");
    std::smatch match;

    if (std::regex_match(message, match, pattern)) {
        *trick_number = std::stoi(match[1].str());
        return GOOD;
    } else {
        return ERROR;
    }
}

// Parser for a message of type: TAKEN<trick number><card list><player taking cards>\r\n.
int parse_taken(const std::string& message, int* trick_number,
                std::vector<Card>& cards, char* taken_by, bool trick_one) {
    
    std::regex pattern;
    if (trick_one) {
        pattern = R"(TAKEN(1)(.+)([NESW])\r\n)";
    } else {
        pattern = R"(TAKEN(1[0-3]|[2-9])(.+)([NESW])\r\n)";
    }
    std::smatch match;

    cards.clear();

    if (std::regex_match(message, match, pattern)) {

        *trick_number = std::stoi(match[1].str());
        std::string card_list = match[2].str();
        *taken_by = match[3].str()[0];

        if (parse_card_set(card_list, cards) == 0) {
            std::set<Card> card_set;
            for (auto& card : cards) {
                card_set.insert(Card(card.value, card.suit));
            }

            if (cards.size() == 4 && cards.size() == card_set.size()) {
                return GOOD;
            } else {
                std::cerr << "didn't get 4 unique cards\n";
                return ERROR;
            }
        } else {
            std::cerr << "parsing error\n";
            return ERROR;
        }
    } else {
        return ERROR;
    }

}

// Parser for a message of type: SCORE<player name><points>[...]\r\n.
int parse_score(const std::string& message, int* scores) {

    std::regex pattern(R"(SCORE(N|E|S|W)(\d+)(N|E|S|W)(\d+)(N|E|S|W)(\d+)(N|E|S|W)(\d+)\r\n)");
    std::smatch match;

    for (int i = 0; i <= 4; i++) {
        scores[i] = -1;
    }

    if (std::regex_match(message, match, pattern)) {
        for (int i = 1; i < (int) match.size(); i += 2) {
            int place = map_place[match[i].str()[0]];
            scores[place] = std::stoi(match[i + 1].str());
        }
        for (int i = 1; i <= 4; i++) {
            if (scores[i] == -1) {
                std::cerr << "Didn't receive points of all players\n";
                return ERROR;
            }
        }
        return GOOD;
    } else {
        return ERROR;
    }
}

// Parser for a message of type: TOTAL<player name><points>[...]\r\n.
int parse_total(const std::string& message, int* scores) {

    std::regex pattern(R"(TOTAL(N|E|S|W)(\d+)(N|E|S|W)(\d+)(N|E|S|W)(\d+)(N|E|S|W)(\d+)\r\n)");
    std::smatch match;

    for (int i = 0; i <= 4; i++) {
        scores[i] = -1;
    }

    if (std::regex_match(message, match, pattern)) {
        for (int i = 1; i < (int) match.size(); i += 2) {
            int place = map_place[match[i].str()[0]];
            scores[place] = std::stoi(match[i + 1].str());
        }
        for (int i = 1; i <= 4; i++) {
            if (scores[i] == -1) {
                std::cerr << "Didn't receive points of all players\n";
                return ERROR;
            }
        }
        return GOOD;
    } else {
        return ERROR;
    }
}


// --------------------------------- User interface -------------------------------------

// BUSY<lista zajętych miejsc przy stole>
void verbose_busy(std::vector<char> busy_places) {
    std::cout << "Place busy, list of busy places received: ";
    for (size_t i = 0; i < busy_places.size(); i++) {
        std::cout << busy_places[i];
        if (i != busy_places.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << ".\n";
}

// DEAL<typ rozdania><miejsce przy stole klienta wychodzącego jako pierwszy w rozdaniu><lista kart>
void verbose_deal(int round_type, char starting_player, std::vector<Card>& card_list) {
    std::cout << "New deal " << round_type << ": staring place " << starting_player << ", your cards: ";
    for (size_t i = 0; i < card_list.size(); i++) {
        std::cout << card_list[i].value << card_list[i].suit;
        if (i != card_list.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << ".\n";
}

// WRONG<numer lewy>
void verbose_wrong(int trick_number) {
    std::cout << "Wrong message received in trick " << trick_number << ".\n";
}

// TAKEN<numer lewy><lista kart><miejsce przy stole klienta biorącego lewę>
void verbose_taken(int trick_number, char winner, std::vector<Card>& card_list) {
    std::cout << "A trick " << trick_number << " is taken by " << winner << ", cards ";
    for (size_t i = 0; i < card_list.size(); i++) {
        std::cout << card_list[i].value << card_list[i].suit;
        if (i != card_list.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << ".\n";
}

// SCORE<miejsce przy stole klienta><liczba punktów>[...]
void verbose_score(int* scores) {
    std::cout << "The scores are:\n";
    std::cout << "N | " << scores[1] << "\n";
    std::cout << "E | " << scores[2] << "\n";
    std::cout << "S | " << scores[3] << "\n";
    std::cout << "W | " << scores[4] << "\n";
}

// TOTAL<miejsce przy stole klienta><liczba punktów>[...]
void verbose_total(int* total_scores) {
    std::cout << "The total scores are:\n";
    std::cout << "N | " << total_scores[1] << "\n";
    std::cout << "E | " << total_scores[2] << "\n";
    std::cout << "S | " << total_scores[3] << "\n";
    std::cout << "W | " << total_scores[4] << "\n";
}

// TRICK<numer lewy><lista kart>
void verbose_trick(int trick_number, std::vector<Card>& cards_on_table, std::vector<Card>& cards_in_hand) {
    std::cout << "Trick: (" << trick_number << ") ";
    for (size_t i = 0; i < cards_on_table.size(); i++) {
        std::cout << cards_on_table[i].value << cards_on_table[i].suit;
        if (i != cards_on_table.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << "\nAvailable: ";
    for (size_t i = 0; i < cards_in_hand.size(); i++) {
        std::cout << cards_in_hand[i].value << cards_in_hand[i].suit;
        if (i != cards_in_hand.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << "\n";
}


// -------------------------------- Sending messages ------------------------------------

// Sends IAM<place> message to the server.
void send_iam(int socket_fd, char place, Logs& logs, std::string from, std::string to) {

    std::string message = "IAM";

    message += std::string(1, place);

    message += "\r\n";

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes < 0) {
        throw std::runtime_error("writen (iam)");
    } else if (written_bytes == 0) {
        throw std::runtime_error("empty writen");
    }

    logs.add(from, to, Clock::now(), message);
}

// Sends TRICK<trick number><card> message to the server.
void send_trick(struct pollfd* poll_fds, Hand& hand, int trick_number, char required_suit,
                Logs& logs, std::string from, std::string to) {

    std::string message = "TRICK";

    message += std::to_string(trick_number);

    // Chosen card:
    std::string value;
    char suit;
    bool found = false;

    for (Card card : hand.cards) {
        if (card.suit == required_suit) {
            suit = card.suit;
            value = card.value;
            found = true;
            break;
        }
    }

    if (!found) {
        suit = hand.cards[0].suit;
        value = hand.cards[0].value;
    }

    message += value;
    message += std::string(1, suit);

    message += "\r\n";

    ssize_t written_bytes = writen(poll_fds[0].fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (trick)");
    }

    logs.add(from, to, Clock::now(), message);

}

// Waits for a card to be chosen by a user and sends TRICK<trick number><card> message to the server.
void send_trick_user(struct pollfd* poll_fds, Hand& hand, Logs& logs, std::vector<Card>& tricks_taken,
                     std::string server_ip_and_port, std::string my_ip_and_port, 
                     bool trick_one, int trick_number) {

    bool sent = false;

    do {
        poll_fds[0].revents = 0; // server
        poll_fds[1].revents = 0; // stdin

        // Client can wait indefinitely:
        int poll_status = poll(poll_fds, 2, -1); 
        check_poll_error(poll_status);

        if (poll_status > 0) {
            // Message from server:
            if (poll_fds[0].revents & POLLIN) {

                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("finished");
                } else {
                    // Server is sending TRICKS in a loop:
                    logs.add(server_ip_and_port, my_ip_and_port, Clock::now(), buffer);
                    int parsed_trick_number;
                    std::vector<Card> on_table;
                    if (parse_trick(buffer, &parsed_trick_number, on_table, trick_one) == GOOD) {
                        verbose_trick(parsed_trick_number, on_table, hand.cards);
                    }
                    else {
                        // Message can't be parsed, waiting:
                        std::cerr << "parsing trick failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                std::string buffer = ""; 
                int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
                if (received_bytes <= 0) {
                    std::cerr << "error in user_read\n";
                } else {
                    if (buffer == "cards\n") {
                        // Show cards in hand:
                        for (size_t i = 0; i < hand.cards.size(); i++) {
                            std::cout << hand.cards[i].value << hand.cards[i].suit;
                            if (i != hand.cards.size() - 1) {
                                std::cout << ", ";
                            }
                        }
                        std::cout << "\n";
                    }
                    else if (buffer == "tricks\n") {
                        // Show all tricks taken in this round:
                        for (size_t i = 0; i < tricks_taken.size(); i++) {
                            std::cout << tricks_taken[i].value << tricks_taken[i].suit;
                            if ((i + 1) % 4 == 0) {
                                std::cout << "\n";
                            } else if (i != tricks_taken.size() - 1) {
                                std::cout << ", ";
                            }
                        }
                    }
                    else if (buffer[0] == '!' && (buffer.length() == 4 || (buffer[1] == '1' && buffer.length() == 5)) && buffer[buffer.length() - 1] == '\n') {
                        // Try parsing card:
                        std::string card_str = buffer.substr(1, buffer.length() - 2);
                        size_t pos = 0;
                        bool fmt_ok;
                        Card card_to_put = parse_card(card_str, pos, &fmt_ok);
                        if (fmt_ok) {
                            // Send TRICK if card's format is correct:
                            std::string message = "TRICK";
                            message += std::to_string(trick_number);
                            message += card_to_put.value;
                            message += std::string(1, card_to_put.suit);
                            message += "\r\n";

                            ssize_t written_bytes = writen(poll_fds[0].fd, message.c_str(), message.length());
                            if (written_bytes <= 0) {
                                throw std::runtime_error("writen (trick)");
                            }

                            sent = true;
                            logs.add(my_ip_and_port, server_ip_and_port, Clock::now(), message);

                        } else {
                            std::cerr << "Wrong card format. Use 'cards' to display your cards.\n";
                        }
                    }
                    else {
                        std::cerr << "Available commands: cards, tricks.\n";
                    }
                }
            } else {
                check_poll_flags(poll_fds);
            }
        }

    } while (!sent);
}


// ------------------------------- Receiving messages -----------------------------------

void handle_user_activity(struct pollfd* poll_fds, Hand& hand, std::vector<Card>& tricks_taken, bool verbose) {
    std::string buffer = ""; 
    int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
    if (received_bytes <= 0) {
        std::cerr << "error in user_read\n";
    } else {
        if (verbose) {
            if (buffer == "cards\n") {
                // Show cards in hand:
                for (size_t i = 0; i < hand.cards.size(); i++) {
                    std::cout << hand.cards[i].value << hand.cards[i].suit;
                    if (i != hand.cards.size() - 1) {
                        std::cout << ", ";
                    }
                }
                std::cout << "\n";
            }
            else if (buffer == "tricks\n") {
                // Show all tricks taken in this round:
                for (size_t i = 0; i < tricks_taken.size(); i++) {
                    std::cout << tricks_taken[i].value << tricks_taken[i].suit;
                    if ((i + 1) % 4 == 0) {
                        std::cout << "\n";
                    } else if (i != tricks_taken.size() - 1) {
                        std::cout << ", ";
                    }
                }
            }
            else {
                std::cerr << "Available commands: cards, tricks.\n";
            }
        } else {
            std::cerr << "User interface not available\n";
        }
    }
}

// Receives first message from the server to determine if server accepted a request.
bool recv_busy_or_deal(struct pollfd* poll_fds, int* round_type, char* starting_player,
                       Hand& hand, int* first_trick, char* first_suit, Logs& logs, std::string from,
                       std::string to, bool verbose, char my_position, std::vector<Card>& tricks_taken) {

    bool received = false;

    do {
        poll_fds[0].revents = 0;
        poll_fds[1].revents = 0;

        int poll_status = poll(poll_fds, 2, -1); 
        check_poll_error(poll_status);

        if (poll_status > 0) {
            // Message from server:
            if (poll_fds[0].revents & POLLIN) {

                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    std::cerr << "couldn't receive the message, disconnecting\n";
                    break;
                } else if (received_bytes == 0) {
                    std::cerr << "server closed the connection\n";
                    break;
                } else {
                    // Try parsing BUSY/DEAL:
                    logs.add(from, to, Clock::now(), buffer);
                    std::vector<char> busy_places;
                    if (parse_deal(buffer, round_type, starting_player, hand) == GOOD) {
                        
                        if (verbose) verbose_deal(*round_type, *starting_player, hand.cards);
                        
                        bool got_trick = false;
                        bool trick_one = true;
                        do {
                            // Try parsing TAKEN/TRICK:
                            buffer = "";
                            received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                            logs.add(from, to, Clock::now(), buffer);
                            // TAKEN:
                            int parsed_trick_number;
                            std::vector<Card> cards_in_taken;
                            std::vector<Card> cards_on_table;
                            char taken_by;
                            if (parse_taken(buffer, &parsed_trick_number, cards_in_taken, &taken_by, trick_one) == GOOD) {
                                if (verbose) verbose_taken(parsed_trick_number, taken_by, cards_in_taken);
                                // Save the trick that was taken:
                                if (taken_by == my_position) {
                                    for (Card card : cards_in_taken) {
                                        tricks_taken.push_back(card);
                                    }
                                }
                                trick_one = false;
                                hand.remove_cards_in_taken(cards_in_taken);
                                (*first_trick)++;
                            }
                            // TRICK:
                            else if (parse_trick(buffer, &parsed_trick_number, cards_on_table, trick_one) == GOOD) {
                                if (verbose) verbose_trick(parsed_trick_number, cards_on_table, hand.cards);
                                if (cards_on_table.size() != 0) {
                                    *first_suit = cards_on_table[0].suit;
                                }
                                if (parsed_trick_number == *first_trick) {
                                    // std::cout << "GOOD! starting from trick " << parsed_trick_number << "\n";
                                }
                                got_trick = true;
                            } else {
                                std::cerr << "couldn't parse message (taken/trick)\n";
                            }

                        } while (!got_trick);

                        received = true;
                        break;
                    }
                    else if (parse_busy(buffer, busy_places) == GOOD) {

                        if (verbose) verbose_busy(busy_places);
                        break;
                    }
                    else {
                        // Message can't be parsed, waiting:
                        std::cerr << "parsing busy/deal failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                handle_user_activity(poll_fds, hand, tricks_taken, verbose);
            }
            else {
                check_poll_flags(poll_fds);
            }
        }

    } while (!received);

    return received;
}


void recv_deal(struct pollfd* poll_fds, int* round_type, char* starting_player, Hand& hand,
               Logs& logs, std::string from, std::string to, bool verbose, std::vector<Card>& tricks_taken) {

    bool received = false;

    do {
        poll_fds[0].revents = 0;
        poll_fds[1].revents = 0;

        // Client can wait indefinitely:
        int poll_status = poll(poll_fds, 2, -1); 
        check_poll_error(poll_status);

        if (poll_status > 0) {
            // Message from server:
            if (poll_fds[0].revents & POLLIN) {

                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("finished");
                } else {
                    // Try parsing DEAL:
                    logs.add(from, to, Clock::now(), buffer);
                    if (parse_deal(buffer, round_type, starting_player, hand) == GOOD) {
                        if (verbose) verbose_deal(*round_type, *starting_player, hand.cards);
                        received = true;
                        break;
                    }
                    else {
                        // Message can't be parsed, waiting:
                        std::cerr << "parsing deal failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                handle_user_activity(poll_fds, hand, tricks_taken, verbose);
            }
            else {
                check_poll_flags(poll_fds);
            }
        }

    } while (!received);
}


void recv_trick_or_score(struct pollfd* poll_fds, char* suit, bool trick_one,  bool* early_finish,
                         int* scores, int* total_scores, Hand& hand, Logs& logs, std::string from, std::string to,
                         bool verbose, std::vector<Card>& tricks_taken) {

    bool received = false;

    do {
        poll_fds[0].revents = 0;
        poll_fds[1].revents = 0;

        // Client can wait indefinitely:
        int poll_status = poll(poll_fds, 2, -1); 
        check_poll_error(poll_status);

        if (poll_status > 0) {
            // Message from server:
            if (poll_fds[0].revents & POLLIN) {

                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("server closed the connection\n");
                } else {
                    int trick_number;
                    std::vector<Card> on_table;
                    logs.add(from, to, Clock::now(), buffer);

                    // TRICK:
                    if (parse_trick(buffer, &trick_number, on_table, trick_one) == GOOD) {
                        if (verbose) verbose_trick(trick_number, on_table, hand.cards);
                        if (on_table.size() != 0) {
                            *suit = on_table[0].suit;
                        }
                        received = true;
                        break;
                    }
                    // SCORE + TOTAL:
                    else if (parse_score(buffer, scores) == GOOD) {
                        if (verbose) verbose_score(scores);
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        logs.add(from, to, Clock::now(), buffer);
                        if (parse_total(buffer, total_scores) == GOOD) {
                            if (verbose) verbose_total(total_scores);
                            received = true;
                            *early_finish = true;
                            break;
                        } else {
                            std::cerr << "error parsing early total\n";
                        }
                    }
                    // TOTAL + SCORE:
                    else if (parse_total(buffer, total_scores) == GOOD) {
                        if (verbose) verbose_total(total_scores);
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        logs.add(from, to, Clock::now(), buffer);
                        if (parse_score(buffer, scores) == GOOD) {
                            if (verbose) verbose_score(scores);
                            received = true;
                            *early_finish = true;
                            break;
                        } else {
                            std::cerr << "error parsing early score\n";
                        }
                    }
                    else {
                        // Message can't be parsed, waiting:
                        std::cerr << "parsing trick failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                handle_user_activity(poll_fds, hand, tricks_taken, verbose);
            }
            else {
                check_poll_flags(poll_fds);
            }
        }

    } while (!received);
}


void recv_trick_response(struct pollfd* poll_fds, bool* accepted, Hand& hand, bool trick_one,
                         Logs& logs, std::string from, std::string to, bool verbose, char my_position,
                         std::vector<Card>& tricks_taken) {

    bool received = false;

    do {
        poll_fds[0].revents = 0;
        poll_fds[1].revents = 0;

        // Client can wait indefinitely:
        int poll_status = poll(poll_fds, 2, -1); 
        check_poll_error(poll_status);

        if (poll_status > 0) {
            // Message from server:
            if (poll_fds[0].revents & POLLIN) {

                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("server closed the connection\n");
                } else {
                    // Try parsing TAKEN/WRONG:
                    logs.add(from, to, Clock::now(), buffer);
                    int trick_number;
                    std::vector<Card> cards_taken;
                    char taken_by;
                    // TAKEN:
                    if (parse_taken(buffer, &trick_number, cards_taken, &taken_by, trick_one) == GOOD) {
                        if (verbose) verbose_taken(trick_number, taken_by, cards_taken);
                        // Save taken trick:
                        if (taken_by == my_position) {
                            for (Card card : cards_taken) {
                                tricks_taken.push_back(card);
                            }
                        }
                        received = true;
                        *accepted = true;
                        hand.remove_cards_in_taken(cards_taken);
                        break;
                    }
                    // WRONG:
                    else if (parse_wrong(buffer, &trick_number) == GOOD) {
                        if (verbose) verbose_wrong(trick_number);
                        std::cerr << "received wrong (trick: " << trick_number << "), sending card again\n";
                        received = true;
                        break;
                    }
                    else {
                        // Message can't be parsed, waiting:
                        std::cerr << "parsing taken/wrong failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                handle_user_activity(poll_fds, hand, tricks_taken, verbose);
            }
            else {
                check_poll_flags(poll_fds);
            }
        }

    } while (!received);
}

// Receives SCORE and TOTAL from server.
void recv_score_and_total(struct pollfd* poll_fds, int* scores, int* total_scores,
                          Logs& logs, std::string from, std::string to, bool verbose,
                          std::vector<Card>& tricks_taken, Hand& hand) {

    bool received = false;

    do {
        poll_fds[0].revents = 0;
        poll_fds[1].revents = 0;

        // Client can wait indefinitely:
        int poll_status = poll(poll_fds, 2, -1); 
        check_poll_error(poll_status);

        if (poll_status > 0) {
            // Message from server:
            if (poll_fds[0].revents & POLLIN) {

                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("server closed the connection\n");
                } else {
                    logs.add(from, to, Clock::now(), buffer);
                    // SCORE + TOTAL:
                    if (parse_score(buffer, scores) == GOOD) {
                        if (verbose) verbose_score(scores);
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        logs.add(from, to, Clock::now(), buffer);
                        if (parse_total(buffer, total_scores) == GOOD) {
                            if (verbose) verbose_total(total_scores);
                            received = true;
                            break;
                        } else {
                            std::cerr << "error parsing total\n";
                        }
                    }
                    // TOTAL + SCORE:
                    else if (parse_total(buffer, total_scores) == GOOD) {
                        if (verbose) verbose_total(total_scores);
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        logs.add(from, to, Clock::now(), buffer);
                        if (parse_score(buffer, scores) == GOOD) {
                            if (verbose) verbose_score(scores);
                            received = true;
                            break;
                        } else {
                            std::cerr << "error parsing score\n";
                        }
                    }
                    else {
                        // Message can't be parsed, waiting:
                        std::cerr << "parsing score/total failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                handle_user_activity(poll_fds, hand, tricks_taken, verbose);
            }
            else {
                check_poll_flags(poll_fds);
            }
        }
        
    } while (!received);
}


bool recv_deal_wrapper(struct pollfd* poll_fds, Hand& hand, std::vector<Card> tricks_taken, Logs& logs,
                       int* round_type, char* starting_player, bool verbose,
                       std::string server_ip_and_port, std::string my_ip_and_port) {

    hand.cards.clear();
    try {
        recv_deal(poll_fds, round_type, starting_player, hand, logs, server_ip_and_port, my_ip_and_port, verbose, tricks_taken);
        return true;
    } catch (const std::exception& e) {
        if (strcmp(e.what(), "finished") == 0) {
            // Game finished.
            if (!verbose) {
                logs.write_to_stdout();
            }
            return false;
        } else {
            throw std::runtime_error(e.what());
        }
    }
}

// -------------------------------------- Game ------------------------------------------

// Manages player in game.
void play_game(struct pollfd* poll_fds, Hand& hand, Logs& logs, std::vector<Card> tricks_taken,
               int first_trick, int s_round_type, char first_suit, char s_starting_player,
               std::string my_ip_and_port, std::string server_ip_and_port,
               bool verbose, char my_position) {

    int round_type = s_round_type;              // Type of a round (1-7).
    char starting_player = s_starting_player;   // Place of a player that is starting the round.
    int round_number = 0;                       // Round number from the perspective of client.
    bool first = true;                          // Boolean to indicate that we are at the first trick.

    while (true) {
        // Round begins, receive DEAL:
        if (round_number != 0) {
            bool in_game = recv_deal_wrapper(poll_fds, hand, tricks_taken, logs, &round_type,
                                &starting_player, verbose, server_ip_and_port, my_ip_and_port);
            if (!in_game) {
                break;
            }
        }

        bool early_finish = false;              // Boolean to indicate that the round has finished early.
        int scores[5];                          // Array to store round scores of players.
        int total_scores[5];                    // Array to store total scores of players.
        
        // Play 13 (or less) tricks:
        for (int l = first_trick; l <= TRICKS_IN_ROUND; l++) {
            
            bool accepted = false;
            char suit = 'X';

            if (first) {
                suit = first_suit;
                first = false;
            } else {
                recv_trick_or_score(poll_fds, &suit, (l == 1), &early_finish, scores, total_scores,
                            hand, logs, server_ip_and_port, my_ip_and_port, verbose, tricks_taken);
            }
            
            if (!early_finish) {

                // Try sending TRICK message in a loop:
                do {
                    if (verbose) {
                        send_trick_user(poll_fds, hand, logs, tricks_taken, server_ip_and_port,
                                        my_ip_and_port, (l == 1), l);
                    } else {
                        send_trick(poll_fds, hand, l, suit, logs, my_ip_and_port, server_ip_and_port);
                    }
                    recv_trick_response(poll_fds, &accepted, hand, (l == 1), logs, server_ip_and_port,
                                        my_ip_and_port, verbose, my_position, tricks_taken);
                } while (!accepted);
            
            } else {
                break;
            }
        }
        
        if (!early_finish) {
            recv_score_and_total(poll_fds, scores, total_scores, logs, server_ip_and_port,
                                my_ip_and_port, verbose, tricks_taken, hand);
        }

        round_number++;
        first_trick = 1;                        // After using first_trick set it to a default value.
        tricks_taken.clear();                   // After each round clear the list of taken tricks.
    }
}

// --------------------------------------- Main -----------------------------------------

int main(int argc, char** argv) {

    // Input data:
    std::string host, port_s;
    char place;
    bool ipv4 = false;
    bool ipv6 = false;
    bool bot = false;

    // Runtime data:
    std::string server_ip_and_port;
    std::string my_ip_and_port;
    int socket_fd;
    struct pollfd poll_fds[2];

    // First round:
    int round_type;
    char starting_player;
    Hand hand;
    std::vector<Card> tricks_taken;

    // State:
    bool connected = false;

    // Logs:
    Logs logs;

    try {
        // Client initialization:
        parse_arguments(argc, argv, &host, &port_s, &place, &ipv4, &ipv6, &bot);
        connect_to_server(port_s, host, ipv4, ipv6, &socket_fd, &connected, &server_ip_and_port);
        my_ip_and_port = get_client_ip_and_port(socket_fd);
        initialize_descriptors(poll_fds, socket_fd);
        send_iam(socket_fd, place, logs, my_ip_and_port, server_ip_and_port);
        
        // Determine if we are accepted to join the game:
        int first_trick = 1;
        char first_suit = 'X';
        if (recv_busy_or_deal(poll_fds, &round_type, &starting_player, hand, &first_trick, &first_suit, logs, server_ip_and_port, my_ip_and_port, !bot, place, tricks_taken)) {
        
            play_game(poll_fds, hand, logs, tricks_taken, first_trick, round_type, first_suit, starting_player, my_ip_and_port, server_ip_and_port, !bot, place);

        } else {
            disconnect_from_server(&connected, socket_fd);
            if (bot) {
                logs.write_to_stdout();
            }
            return ERROR;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        disconnect_from_server(&connected, socket_fd);
        if (bot) {
            logs.write_to_stdout();
        }
        return ERROR;
    }
    
    disconnect_from_server(&connected, socket_fd);
    return GOOD;
}
