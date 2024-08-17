#include <iostream>
#include <stdexcept>
#include <string>
#include <cstring>
#include <limits>
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <regex>
#include <set>
#include <limits.h>
#include <netdb.h>
#include <stddef.h>
#include <stdlib.h>
#include <signal.h>

#include <climits>
#include <cstdlib>
#include <cstdint>

#include "common.h"
#include "kierki-common.h"

#define GOOD 0
#define ERROR 1

#define HAND 13

// ---------------------- Declarations -----------------------

struct Card {
    std::string value;
    char suit;

    Card(std::string v, char s) : value(v), suit(s) {}
    
    bool operator==(const Card& other) const {
        return value == other.value && suit == other.suit;
    }

    bool operator<(const Card& other) const {
        return (value < other.value) || (value == other.value && suit < other.suit);
    }
};

struct Hand {
    std::vector<Card> cards;

    void add_card(const Card& card) {
        cards.push_back(card);
    }

    void remove_card(const std::string& value, char suit) {
        auto it = std::find(cards.begin(), cards.end(), Card(value, suit));
        if (it != cards.end()) {
            cards.erase(it);
        }
    }
};

struct Round {
    int round_type;
    char starting_player;
    Hand hands[4];

    Round(int type, char starter) : round_type(type), starting_player(starter) {}
};

struct Game {
    std::vector<Round> rounds;

    void add_round(const Round& round) {
        rounds.push_back(round);
    }
};

// -------------------------- Functions for structs --------------------------

// Card parser.
Card parse_card(const std::string& hand_str, size_t& pos, bool* fmt_ok) {
    std::string value = "";
    char suit = 'X';
    bool value_ok = false;
    bool suit_ok = false;

    if (hand_str[pos] == '1' && hand_str[pos + 1] == '0') {
        value = "10";
        value_ok = true;
        pos += 2;
    } else {
        value = hand_str[pos];
        if ((hand_str[pos] >= '2' && hand_str[pos] <= '9') ||
            hand_str[pos] == 'J' || hand_str[pos] == 'Q' ||
            hand_str[pos] == 'K' || hand_str[pos] == 'A') {
            value_ok = true;
            pos += 1;
        } else {
            value_ok = false;
        }
    }

    if (pos < hand_str.size()) {
        suit = hand_str[pos];
        if (suit == 'C' || suit == 'D' || suit == 'H' || suit == 'S') {
            suit_ok = true;
            pos += 1;
        } else {
            suit_ok = false;
        }
    } else {
        suit_ok = false;
        std::cerr << "Invalid card string\n";
    }

    *fmt_ok = (value_ok && suit_ok);
    return Card(value, suit);
}

// Hand parser.
// Doesn't need 13 cards and correctly parses every correct string.
int parse_card_set(const std::string& hand_str, std::vector<Card>& card_vector) {
    size_t pos = 0;
    while (pos < hand_str.size()) {
        bool fmt_ok;
        Card card = parse_card(hand_str, pos, &fmt_ok);
        if (fmt_ok) {
            card_vector.push_back(card);
        } else {
            return ERROR;
        }
    }
    return GOOD;
}

// -------------------------- Initialization -------------------------

// Sets variables describing input options.
int set_input_variables(int argc, char** argv, std::string* host, std::string* port, 
                        char* place, bool* ipv4, bool* ipv6, bool* robot) {
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
                *robot = true;
                break;
            default:
                return ERROR;
        }
    }
    return GOOD;
}

// Parses command line arguments.
void parse_arguments(int argc, char** argv, std::string* host, std::string* port, 
                     char* place, bool* ipv4, bool* ipv6, bool* robot)
{
    if (set_input_variables(argc, argv, host, port, place, ipv4, ipv6, robot) == ERROR ||
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
                        bool ipv4, bool ipv6, bool robot)
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

    if (robot) {
        std::cout << "Robot\n";
    } else {
        std::cout << "Player\n";
    }
}

// Converts port number from string to uint16_t.
// COMMON
uint16_t read_port(std::string port_s) {
    char* endptr;
    unsigned long port_ul = std::strtoul(port_s.c_str(), &endptr, 10);

    if ((port_ul == ULONG_MAX && errno == ERANGE) || 
        *endptr != '\0' ||
        port_ul == 0 ||
        port_ul > UINT16_MAX
    ) {
        throw std::invalid_argument(port_s + " is not a valid port number");
    }

    return static_cast<uint16_t>(port_ul);
}

/*
struct sockaddr_in6 get_server_address(std::string host, uint16_t port) {

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* address_result;
    int errcode = getaddrinfo(host.c_str(), nullptr, &hints, &address_result);
    if (errcode != 0) {
        throw std::runtime_error("getaddrinfo " + std::string(gai_strerror(errcode)));
    }

    struct sockaddr_in6 server_address;
    memset(&server_address, 0, sizeof(struct sockaddr_in6));
    server_address.sin6_family = AF_INET6;
    server_address.sin6_addr = ((struct sockaddr_in6*) (address_result->ai_addr))->sin6_addr;
    server_address.sin6_port = htons(port);

    freeaddrinfo(address_result);

    return server_address;
}
*/

std::string prepend_ipv6_mapped_prefix(const std::string& ip_address) {
    // Check if the address already starts with "::ffff:"
    if (ip_address.rfind("::ffff:", 0) == 0) {
        return ip_address; // Prefix already present
    }
    if (ip_address == "localhost") {
        return ip_address;
    }

    // Prepend the "::ffff:" prefix
    return "::ffff:" + ip_address;
}

// Translates host and port info to server's address.
struct sockaddr_storage get_server_address(const std::string& host, uint16_t port, bool ipv4, bool ipv6) {
    std::string m_host = prepend_ipv6_mapped_prefix(host);
    struct addrinfo hints, *address_result, *p;
    struct sockaddr_storage server_address;
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

    int errcode = getaddrinfo(m_host.c_str(), nullptr, &hints, &address_result);
    if (errcode != 0) {
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(errcode)));
    }

    // Find the first valid address
    for (p = address_result; p != nullptr; p = p->ai_next) {
        if (p->ai_family == hints.ai_family || hints.ai_family == AF_UNSPEC) {
            memcpy(&server_address, p->ai_addr, p->ai_addrlen);
            break;
        }
    }

    freeaddrinfo(address_result);

    if (p == nullptr) {
        throw std::runtime_error("No valid address found");
    }

    // Set the port
    if (server_address.ss_family == AF_INET) {
        ((struct sockaddr_in*)&server_address)->sin_port = htons(port);
    } else if (server_address.ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&server_address)->sin6_port = htons(port);
    }

    return server_address;
}


// Creates a socket.
void create_socket(int* socket_fd, int family) {
    *socket_fd = socket(family, SOCK_STREAM, 0);
    if (*socket_fd < 0) {
        throw std::runtime_error("socket");
    }
}

/*
// Determines size of sockaddr structure based on IP protocol's version.
// *Handles closing the socket manually*
socklen_t determine_addr_size(int socket_fd, struct sockaddr_storage* server_address) {
    socklen_t addr_size;
    if (server_address->ss_family == AF_INET) {
        addr_size = sizeof(struct sockaddr_in);
    } else if (server_address->ss_family == AF_INET6) {
        addr_size = sizeof(struct sockaddr_in6);
    } else {
        close(socket_fd);
        throw std::runtime_error("unknown address family");
    }
    return addr_size;
}
*/

/*
// Creates the connection:
// *Handles closing the socket manually*
void create_connection(bool* connected, int socket_fd, struct sockaddr_in6* server_address) {

    if (connect(socket_fd, reinterpret_cast<struct sockaddr*>(server_address),
        sizeof(*server_address)) < 0) {
        close(socket_fd);
        throw std::runtime_error("connection failed");
    }
    *connected = true;
}
*/

// Creates the connection:
// *Handles closing the socket manually*
void create_connection(bool* connected, int socket_fd, struct sockaddr_storage* server_address) {
    socklen_t addr_len = (server_address->ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    if (connect(socket_fd, reinterpret_cast<struct sockaddr*>(server_address), addr_len) < 0) {
        close(socket_fd);
        throw std::runtime_error("connection failed");
    }
    *connected = true;
}


// Connects client to server.
void connect_to_server(std::string port_s, uint16_t* port, std::string host, bool ipv4,
                       bool ipv6, struct sockaddr_storage* server_address, int* socket_fd,
                       bool* connected, int* family) {

    *port = read_port(port_s);
    *server_address = get_server_address(host, *port, ipv4, ipv6); //change
    *family = ipv4 ? AF_INET : (ipv6 ? AF_INET6 : AF_UNSPEC);

    signal(SIGPIPE, SIG_IGN);

    create_socket(socket_fd, *family);
    // socklen_t addr_size = determine_addr_size(*socket_fd, server_address);
    create_connection(connected, *socket_fd, server_address);

    // assert(*connected == true);

    /*
    // Set timeouts for the server socket:
    struct timeval to = {.tv_sec = MAX_WAIT, .tv_usec = 0};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof to);
    */
}

// Disconnects client from server.
// TODO: Special function with manual error handling
void disconnect_from_server(bool* connected, int socket_fd) {
    if (*connected) {
        close(socket_fd);
        std::cout << "Disconnected from server\n";
        *connected = false;
    }   
}

// Message sending

// Sends IAM<place> message to the server.
void send_iam(char place, int socket_fd) {
    char buffer[] = "IAMN\r\n"; 
    buffer[3] = place;
    ssize_t written_bytes = writen(socket_fd, buffer, 6);
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (iam)");
    }
}

// ------------------------------ Parsers ---------------------------------

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

void test_parse_busy() {
    std::vector<char> busy_places;
    // Correct:
    assert(parse_busy("BUSYN\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYS\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYNES\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYNWES\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYWE\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    // Wrong:
    assert(parse_busy("BUSY\r\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUS", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSY\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSYNESENSE\r\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSYWXD\r\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSYN\r", busy_places) == 1);
}

/*
// Parser for a message of type: DEAL<round type><starting player><card list>\r\n.
int parse_deal(const std::string& message, int* round_type, 
               char* starting_player, Hand& hand) {

    std::regex pattern(R"(DEAL([1-7])([NESW])((2|3|4|5|6|7|8|9|10|J|Q|K|A)(C|D|H|S)){13}\r\n)");
    std::smatch match;

    hand.cards.clear();

    if (std::regex_match(message, match, pattern)) {
        for (int i = 0; i < match.size(); i++) {
            std::cout << "match[" << i << "]: " << match[i] << "\n";
        }
        *round_type = std::stoi(match[1].str());
        *starting_player = match[2].str()[0];
        // Process the matched cards
        std::string card_list = match[3].str();
        size_t pos = 0;
        while (pos < card_list.length()) {
            std::string value;
            if (card_list[pos] == '1' && card_list[pos + 1] == '0') {
                value = "10";
                pos += 2;
            } else {
                value = card_list.substr(pos, 1);
                pos += 1;
            }
            char suit = card_list[pos];
            pos += 1;

            hand.add_card(Card(value, suit));
        }
        return GOOD;
    } else {
        return ERROR;
    }
}
*/

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

void test_parse_deal() {
    int round_type;
    char starting_player;
    Hand hand;
    // CORRECT:
    assert(parse_deal("DEAL3W2D3D4D5D6D7D8D9D10DJDQDKDAD\r\n", &round_type, &starting_player, hand) == 0);
    std::cout << "Round Type: " << round_type << std::endl;
    std::cout << "Starting Player: " << starting_player << std::endl;
    std::cout << "Hand Cards: ";
    for (const auto& card : hand.cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << std::endl;
    assert(parse_deal("DEAL1N2C2S5H4S6D10D8H7SKCAHASJCQD\r\n", &round_type, &starting_player, hand) == 0);
    std::cout << "Round Type: " << round_type << std::endl;
    std::cout << "Starting Player: " << starting_player << std::endl;
    std::cout << "Hand Cards: ";
    for (const auto& card : hand.cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << std::endl;
    assert(parse_deal("DEAL7SJCQDKHAS2D3C4S5H6H7H8S9C10D\r\n", &round_type, &starting_player, hand) == 0);
    std::cout << "Round Type: " << round_type << std::endl;
    std::cout << "Starting Player: " << starting_player << std::endl;
    std::cout << "Hand Cards: ";
    for (const auto& card : hand.cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << std::endl;
    // WRONG:
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8H10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8M9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8H5C9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("aDEAL3N2C3D4H5S6C7D8H9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8H9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
}

// Parser for a message of type: TRICK<trick number><card list>\r\n.
int parse_trick(const std::string& message, int* trick_number, std::vector<Card>& on_table) {
    
    std::regex pattern(R"(TRICK([1-9]|1[0-3])(.*)\r\n)");
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

            if (on_table.size() >= 0 && on_table.size() <= 3 && card_set.size() == on_table.size()) {
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

void test_parse_trick() {
    // Correct:
    int trick_number;
    std::vector<Card> on_table;
    assert(parse_trick("TRICK15H3H4H\r\n", &trick_number, on_table) == 0);
    assert(parse_trick("TRICK1\r\n", &trick_number, on_table) == 0);
    assert(parse_trick("TRICK12H\r\n", &trick_number, on_table) == 0);
    assert(parse_trick("TRICK12H3H\r\n", &trick_number, on_table) == 0);
    assert(parse_trick("TRICK\r\n", &trick_number, on_table) == 1);
    // Wrong:
    assert(parse_trick("aTRICK5KS\r\n", &trick_number, on_table) == 1);
    assert(parse_trick("TRICK0KS\r\n", &trick_number, on_table) == 1);
    assert(parse_trick("TRICKS\r\n", &trick_number, on_table) == 1);
    assert(parse_trick("TRICK500S\r\n", &trick_number, on_table) == 1);
    assert(parse_trick("TRICK59M\r\n", &trick_number, on_table) == 1);
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

void test_parse_wrong() {
    // Correct:
    int trick_number;
    assert(parse_wrong("WRONG1\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG2\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG3\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG4\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG10\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG12\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG13\r\n", &trick_number) == 0);
    // Wrong:
    assert(parse_wrong("WRONG0\r\n", &trick_number) == 1);
    assert(parse_wrong("WRON\r\n", &trick_number) == 1);
    assert(parse_wrong("aWRONG12\r\n", &trick_number) == 1);
    assert(parse_wrong("WRONG14\r\n", &trick_number) == 1);
}

// To write: TAKEN, SCORE, TOTAL


int main(int argc, char** argv) {

    // Input data:
    std::string host, port_s;
    char place;
    bool ipv4 = false;
    bool ipv6 = false;
    bool robot = false;

    // Runtime data:
    uint16_t port;
    int family;
    //struct sockaddr_in6 server_address;
    struct sockaddr_storage server_address;
    int socket_fd;

    // State:
    bool connected = false;

    /*
    try {
        // Client initialization:
        parse_arguments(argc, argv, &host, &port_s, &place, &ipv4, &ipv6, &robot);
        print_options_info(host, port_s, place, ipv4, ipv6, robot); // TEST
        connect_to_server(port_s, &port, host, ipv4, ipv6, &server_address,
                          &socket_fd, &connected, &family);
        send_iam(place, socket_fd);
        // Game:


        // tutaj można odebrać albo BUSY albo DEAL

        while (true) {

        }

        // pętla serwera

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        disconnect_from_server(&connected, socket_fd);
        return ERROR;
    }
    */

    // Test parserów:
    try {
        test_parse_wrong();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        // disconnect_from_server(&connected, socket_fd);
        return ERROR;
    }

    //disconnect_from_server(&connected, socket_fd);
    return GOOD;
}

/*
Approach:

int main() {
    try {
        connect_to_server();
        
        first_function();
        second_function();
        // [...]
        last_function();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        disconnect_from_server();
        return 1;
    }

    disconnect_from_server(); // Close the connection if everything went well
    return EXIT_SUCCESS;
}
*/
