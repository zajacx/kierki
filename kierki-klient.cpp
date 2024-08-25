#include <iostream>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fstream>
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

#define GOOD 0
#define ERROR 1

#define HAND 13
#define TRICKS_IN_ROUND 13

#define BUFFER_SIZE 500
#define TIMEOUT 500
#define READING_LIMIT 200

// --------------------------- Declarations & Data Structures ---------------------------

static std::map<char, int> map_place = {
    {'N', 1},
    {'E', 2},
    {'S', 3},
    {'W', 4}
};

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


// ------------------------------- Functions for structs --------------------------------

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


// ------------------------------------- Parsers ----------------------------------------

int read_to_newline(int descriptor, std::string* result) {
    
    char buf;
    std::string buffer;
    ssize_t last_read_size;

    int count = 0;
    while (count < READING_LIMIT) {
        ssize_t read_byte = readn(descriptor, &buf, 1, &last_read_size);
        if (read_byte < 0) {
            return (int) read_byte;
        } else if (read_byte == 0) {
            break;
        } else if (read_byte == 1) {
            count++;
            buffer += buf;
            if (buffer.size() >= 2 && buffer.substr(buffer.size() - 2) == "\r\n") {
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

int user_read_to_newline(int descriptor, std::string* result) {
    
    char buf;
    std::string buffer;
    ssize_t last_read_size;

    int count = 0;
    while (count < READING_LIMIT) {
        ssize_t read_byte = readn(descriptor, &buf, 1, &last_read_size);
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

// Parser for a message of type: BUSY<place list>\r\n.
int parse_busy(const std::string& message, std::vector<char>& busy_places) {

    std::regex pattern(R"(BUSY([NESW]{1,4})\r\n)");
    std::smatch match;
    
    std::cout << "parsing busy...\n"; // test

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
        std::cout << "parse_taken: trick one\n";
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
        std::cerr << "not match\n";
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

// Checks poll status and throws an exception in case of an error.
// COMMON
void check_poll_error(int poll_status) {
    if (poll_status < 0) {
        if (errno == EINTR) {
            throw std::runtime_error("interrupted system call");
        }
        else {
            throw std::runtime_error("poll");
        }
    }
}


// -------------------------------- Sending messages ------------------------------------

// Sends IAM<place> message to the server.
void send_iam(int socket_fd, char place) {

    std::string message = "IAM";

    message += std::string(1, place);

    message += "\r\n";

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes < 0) {
        throw std::runtime_error("writen (iam)");
    } else if (written_bytes == 0) {
        throw std::runtime_error("empty writen");
    }
}

// Sends TRICK<trick number><card> message to the server.
void send_trick(int socket_fd, struct pollfd* poll_fds, Hand& hand, int trick_number, char required_suit) {

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

    hand.remove_card(value, suit);

    message += value;
    message += std::string(1, suit);

    message += "\r\n";

    std::cout << "sent TRICK" << trick_number << value << suit << "\n";

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (trick)");
    }

}


// ------------------------------- Receiving messages -----------------------------------

// TODO: edgecases (polerr, pollhup, ...) in all receivers

// Receives first message from the server to determine if server accepted a request.
bool recv_busy_or_deal(int socket_fd, struct pollfd* poll_fds, int* round_type, char* starting_player,
                       Hand& hand, int* first_trick, bool* got_trick_in_initialization) {

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

                ssize_t last_read_size;
                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    // błąd, rozłącz klienta
                    std::cerr << "couldn't receive the message, disconnecting\n";
                    break;
                } else if (received_bytes == 0) {
                    // serwer zamknął połączenie, zamknij klienta
                    std::cerr << "server closed the connection\n";
                    break;
                } else {
                    // coś odebrano - próbujemy parsować BUSY albo DEAL
                    std::vector<char> busy_places;
                    if (parse_deal(buffer, round_type, starting_player, hand) == GOOD) {
                        // tutaj serwer może rzucać komunikatami TAKEN, bo możemy
                        // podłączać się do aktualnej rozgrywki, więc czytamy do
                        // skutku - jeśli się nie uda sparsować TAKEN, to próbujemy parsować TRICK

                        // tutaj odbieramy też ewentualne lewy (TAKENy), które rozegrał nasz poprzednik - zaczynamy
                        // rozgrywkę od lewy która wynika z otrzymanych wiadomości

                        // 1. odbierz w pętli wszystkie komunikaty TAKEN
                        // hand.cards.remove(znajdź naszą kartę w komunikacie TAKEN)
                        // 2. jeśli otrzymasz TRICK to wyjdź i ustaw received = true i numer lewy na ten otrzymany
                        // *first_trick = sparsowany z wiadomości od serwera;
                        // *got_trick_in_initialization = true;
                        // 3. zapisz numer lewy na zmiennej którą przekażesz do kolejnej funkcji
                        // 4. ewentualnie ustaw coś boolowskiego (chociaż może nie trzeba, bo gracz liczy sobie rundy)

                        // na razie implementujemy tylko grę od początku do końca
                        std::cout << "received deal, starting game\n";
                        received = true;
                        break;
                    }
                    else if (parse_busy(buffer, busy_places) == GOOD) {
                        std::cerr << "received busy, disconnecting; busy places: ";
                        for (char place : busy_places) {
                            std::cerr << place << " ";
                        }
                        std::cerr << "\n";
                        break;
                    }
                    else {
                        // nie wiadomo co przyszło, czekamy dalej;
                        std::cerr << "parsing busy/deal failed, waiting for another message\n";
                    }
                }
            }
            // Data from user:
            if (poll_fds[1].revents & POLLIN) {
                std::string buffer = ""; 
                int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
                std::cerr << "wait for the game to start!\n";
            }
        }
        else {
            std::cout << "timeout...\n";
        }
    } while (!received);

    return received;
}


void recv_deal(int socket_fd, struct pollfd* poll_fds, int* round_type, char* starting_player, Hand& hand) {

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

                ssize_t last_read_size;
                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("finished");
                } else {
                    // coś odebrano - próbujemy parsować DEAL
                    if (parse_deal(buffer, round_type, starting_player, hand) == GOOD) {
                        std::cout << "received deal\n";
                        received = true;
                        break;
                    }
                    else {
                        // nie wiadomo co przyszło, czekamy dalej;
                        std::cerr << "parsing deal failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                std::string buffer = ""; 
                int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
                std::cerr << "waiting for deal\n";
            }
        }
        else {
            std::cout << "timeout...\n";
        }
    } while (!received);
}


void recv_trick_or_score(int socket_fd, struct pollfd* poll_fds, char* suit, bool trick_one,  bool* early_finish,
                         int* scores, int* total_scores) {

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

                ssize_t last_read_size;
                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("server closed the connection\n");
                } else {
                    int trick_number;
                    std::vector<Card> on_table;

                    // TRICK:
                    if (parse_trick(buffer, &trick_number, on_table, trick_one) == GOOD) {
                        std::cout << "received trick\n";
                        if (on_table.size() != 0) {
                            *suit = on_table[0].suit;
                        }
                        received = true;
                        break;
                    }
                    // SCORE + TOTAL:
                    else if (parse_score(buffer, scores) == GOOD) {
                        std::cout << "received score - early round ending\n";
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        if (parse_total(buffer, total_scores) == GOOD) {
                            std::cout << "received total - early round ending\n";
                            received = true;
                            *early_finish = true;
                            break;
                        } else {
                            std::cerr << "error parsing early total\n";
                        }
                    }
                    // TOTAL + SCORE:
                    else if (parse_total(buffer, total_scores) == GOOD) {
                        std::cout << "received total\n";
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        if (parse_score(buffer, scores) == GOOD) {
                            std::cout << "received score\n";
                            received = true;
                            *early_finish = true;
                            break;
                        } else {
                            std::cerr << "error parsing early score\n";
                        }
                    }
                    else {
                        // nie wiadomo co przyszło, czekamy dalej;
                        std::cerr << "parsing trick failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                std::string buffer = ""; 
                int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
                std::cerr << "waiting for trick\n";
            }
        }
        else {
            std::cout << "timeout...\n";
        }
    } while (!received);
}


void recv_trick_response(int socket_fd, struct pollfd* poll_fds, bool* accepted, bool trick_one) {

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

                ssize_t last_read_size;
                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("server closed the connection\n");
                } else {
                    // coś odebrano - próbujemy parsować TAKEN lub WRONG
                    int trick_number;
                    std::vector<Card> cards_taken;  // TODO: określić czy wypychać te parametry na zewnątrz
                    char taken_by;
                    // TAKEN:
                    if (parse_taken(buffer, &trick_number, cards_taken, &taken_by, trick_one) == GOOD) {
                        std::cout << "trick " << trick_number << " taken by " << taken_by << "\n";
                        received = true;
                        *accepted = true;
                        break;
                    }
                    // WRONG:
                    else if (parse_wrong(buffer, &trick_number) == GOOD) {
                        std::cerr << "received wrong (trick: " << trick_number << "), sending card again\n";
                        received = true;
                        break;
                    }
                    else {
                        // nie wiadomo co przyszło, czekamy dalej;
                        std::cerr << "parsing taken/wrong failed, trying to send TRICK again\n";
                        break;
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                std::string buffer = ""; 
                int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
                std::cerr << "waiting for taken or wrong\n";
            }
        }
        else {
            std::cout << "timeout...\n";
        }
    } while (!received);
}

// Receives SCORE and TOTAL from server.
void recv_score_and_total(int socket_fd, struct pollfd* poll_fds, int* scores, int* total_scores) {

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

                ssize_t last_read_size;
                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("server closed the connection\n");
                } else {
                    // SCORE + TOTAL:
                    if (parse_score(buffer, scores) == GOOD) {
                        std::cout << "received score\n";
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        if (parse_total(buffer, total_scores) == GOOD) {
                            std::cout << "received total\n";
                            received = true;
                            break;
                        } else {
                            std::cerr << "error parsing total\n";
                        }
                    }
                    // TOTAL + SCORE:
                    else if (parse_total(buffer, total_scores) == GOOD) {
                        std::cout << "received total\n";
                        received_bytes = read_to_newline(poll_fds[0].fd, &buffer);
                        if (parse_score(buffer, scores) == GOOD) {
                            std::cout << "received score\n";
                            received = true;
                            break;
                        } else {
                            std::cerr << "error parsing score\n";
                        }
                    }
                    else {
                        // nie wiadomo co przyszło, czekamy dalej;
                        std::cerr << "parsing score/total failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                std::string buffer = ""; 
                int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
                std::cerr << "waiting for score\n";
            }
        }
        else {
            std::cout << "timeout...\n";
        }
    } while (!received);
}


// Receives TOTAL from server.
void recv_total(int socket_fd, struct pollfd* poll_fds, int* total_scores) {

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

                ssize_t last_read_size;
                std::string buffer = "";
                                                
                int received_bytes = read_to_newline(poll_fds[0].fd, &buffer);

                if (received_bytes < 0) {
                    throw std::runtime_error("couldn't receive the message, disconnecting\n");
                } else if (received_bytes == 0) {
                    throw std::runtime_error("server closed the connection\n");
                } else {
                    // coś odebrano - próbujemy parsować TOTAL
                    int total[5];
                    if (parse_total(buffer, total) == GOOD) {
                        std::cout << "received score\n";
                        for (int i = 1; i <= 4; i++) {
                            std::cout << "score " << i << ": " << total[i] << "\n";
                        }
                        received = true;
                        break;
                    }
                    else {
                        // nie wiadomo co przyszło, czekamy dalej;
                        std::cerr << "parsing total failed, waiting for another message\n";
                    }
                }
            }
            // Message from user:
            if (poll_fds[1].revents & POLLIN) {
                std::string buffer = ""; 
                int received_bytes = user_read_to_newline(poll_fds[1].fd, &buffer);
                std::cerr << "waiting for total\n";
            }
        }
        else {
            std::cout << "timeout...\n";
        }
    } while (!received);
}


// -------------------------------------- Game ------------------------------------------

// Manages player in game.
void play_game(int socket_fd, struct pollfd* poll_fds, int s_round_type, char s_starting_player, Hand& hand,
               int first_trick, bool got_trick_in_initialization) {

    int round_type = s_round_type;
    char starting_player = s_starting_player;
    
    int round_number = 0;

    while (true) {
        // początek rozdania, odbierz DEAL:
        
        // tutaj może się przydać first_trick jeśli wchodzimy w środek gry
        // int first_trick = 1;

        if (round_number != 0) {
            hand.cards.clear();
            try {
                recv_deal(socket_fd, poll_fds, &round_type, &starting_player, hand);
            } catch (const std::exception& e) {
                std::cout << "error format: " << e.what() << "\n";
                if (strcmp(e.what(), "finished") == 0) {
                    std::cout << "game finished, writing raport:\n";
                    break;
                } else {
                    throw std::runtime_error("error in recv_deal");
                }
            }
        }

        bool early_finish = false;
        int scores[5];
        int total_scores[5];
        
        for (int l = first_trick; l <= TRICKS_IN_ROUND; l++) {
            
            first_trick = 1; // After using first_trick set it to a default value.
            bool accepted = false;
            char suit = 'X';
            if (!got_trick_in_initialization) {
                recv_trick_or_score(socket_fd, poll_fds, &suit, (l == 1), &early_finish, scores, total_scores);
            }

            got_trick_in_initialization = false;
            
            if (!early_finish) {

                do {
                    sleep(1); // test
                    // Try sending TRICK:
                    send_trick(socket_fd, poll_fds, hand, l, suit);
                    recv_trick_response(socket_fd, poll_fds, &accepted, (l == 1)); 
                } while (!accepted);
            
            } else {
                break;
            }
        }
        if (!early_finish) {
            recv_score_and_total(socket_fd, poll_fds, scores, total_scores);
            //recv_score(socket_fd, poll_fds, scores);
            //recv_total(socket_fd, poll_fds, total_scores);
        }
        round_number++;
        // można też wypisać scores i total_scores, przyda się w kliencie manualnym
    }
}

// Initializes descriptors' array to use in poll().
void initialize_descriptors(struct pollfd* poll_fds, int socket_fd) {
    poll_fds[0].fd = socket_fd;
    poll_fds[0].events = POLLIN;
    poll_fds[1].fd = STDIN_FILENO;
    poll_fds[1].events = POLLIN;
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
    uint16_t port;
    int family;
    //struct sockaddr_in6 server_address;
    struct sockaddr_storage server_address;
    int socket_fd;
    struct pollfd poll_fds[2];

    // First round:
    int round_type;
    char starting_player;
    Hand hand;

    // State:
    bool connected = false;

    try {
        // Client initialization:
        parse_arguments(argc, argv, &host, &port_s, &place, &ipv4, &ipv6, &bot);
        print_options_info(host, port_s, place, ipv4, ipv6, bot); // TEST
        connect_to_server(port_s, &port, host, ipv4, ipv6, &server_address,
                          &socket_fd, &connected, &family);
        initialize_descriptors(poll_fds, socket_fd);
        std::cout << "sending IAM" << place << "\n";
        send_iam(socket_fd, place);
        
        // Determine if we are accepted to join the game:
        int first_trick = 1;
        bool got_trick_in_initialization = false;
        if (recv_busy_or_deal(socket_fd, poll_fds, &round_type, &starting_player, hand, &first_trick, &got_trick_in_initialization)) {
            std::cout << "received deal, round parameters\n";
            std::cout << "round type: " << round_type << "\n";
            std::cout << "starting player: " << starting_player << "\n";
            std::cout << "cards in hand: ";
            for (Card card : hand.cards) {
                std::cout << card.value << card.suit << " ";
            }
            std::cout << "\n";
            play_game(socket_fd, poll_fds, round_type, starting_player, hand, first_trick, got_trick_in_initialization);
        } else {
            std::cout << "received busy, disconnecting\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        disconnect_from_server(&connected, socket_fd);
        return ERROR;
    }
    
    /*
    // Test parserów:
    try {
        test_parse_score();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        // disconnect_from_server(&connected, socket_fd);
        return ERROR;
    }
    */

    disconnect_from_server(&connected, socket_fd);
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
