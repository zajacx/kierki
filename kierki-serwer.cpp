#include <iostream>
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

#define GOOD 0
#define ERROR 1

#define QUEUE_LENGTH 4
#define EMPTY_PORT 0
#define PLAYERS 4
#define POLL_SIZE 5
#define BUFFER_SIZE 250
#define READING_LIMIT 200 // has to be less than BUFFER_SIZE
#define TIMEOUT 500

#define ROUND_TYPES 7
#define TRICKS_IN_ROUND 13

#define PENALTY_7_OR_13 10
#define PENALTY_KH 18

#define DEFAULT_PORT 0

#define N 1
#define E 2
#define S 3
#define W 4
/*
#define INPUT 5
#define OUTPUT 6
*/

// --------------------------- Declarations & Data Structures ---------------------------

// Buffer to use in writen, each buffer for readn is local.
// static char buffer[BUFFER_SIZE];

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

struct ClientInfo {
    int fd;
    uint16_t port;
    std::string ip_and_port;
    TimePoint connection_time;
    int chosen_position;
    int round_points;
    int total_points;
};

static std::map<char, int> map_place = {
    {'N', 1},
    {'E', 2},
    {'S', 3},
    {'W', 4}
};

static std::map<int, char> map_int_to_place_name = {
    {1, 'N'},
    {2, 'E'},
    {3, 'S'},
    {4, 'W'}
};
 
static std::map<std::string, int> map_value = {
    {"2", 2},
    {"3", 3},
    {"4", 4},
    {"5", 5},
    {"6", 6},
    {"7", 7},
    {"8", 8},
    {"9", 9},
    {"10", 10},
    {"J", 11},
    {"Q", 12},
    {"K", 13},
    {"A", 14},
};

struct RoundPoints {
    std::map<std::string, int> value_points;
    std::map<char, int> suit_points;
};

/*
ROUND TYPES:
1. 1 point for a whole trick,
2. 1 point for each heart,
3. 5 points for each queen,
4. 2 points for each king/jack,
5. 18 points for a KH card, 
6. 10 points for taking 7th/13th trick,
7. points for everything mentioned above.
*/
static RoundPoints round_points[ROUND_TYPES + 1] = {
    {},
    // 1.
    {
        {},
        {}
    },
    // 2.
    {
        {},
        { {'H', 1} }
    },
    // 3.
    {
        { {"Q", 5} },
        {}
    },
    // 4.
    {
        { {"J", 2}, {"K", 2} },
        {}
    },
    // 5.
    {
        {},
        {}
    },
    // 6.
    {
        {},
        {}
    },
    // 7.
    {
        { {"Q", 5}, {"J", 2}, {"K", 2} },
        { {'H', 1} }
    }
};

static int points_in_total[ROUND_TYPES + 1] = {0, 13, 13, 20, 16, 18, 20, 100};

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

    std::string to_string() {
        return value + std::string(1, suit);
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

    bool contains(const std::string& value, char suit) {
        auto it = std::find(cards.begin(), cards.end(), Card(value, suit));
        return it != cards.end();
    }
};

struct Round {
    int round_type;
    char starting_player;
    std::string card_strings[5];
    Hand hands[5];

    Round(int type, char starter) : round_type(type), starting_player(starter) {}
};

struct Game {
    std::vector<Round> rounds;

    void add_round(const Round& round) {
        rounds.push_back(round);
    }
};

// COMMON
struct Logs {
    std::vector<std::string> logs;

    void add(std::string from, std::string to, TimePoint time_point, std::string log_message) {

        auto system_time_point = std::chrono::system_clock::now() + (time_point - Clock::now());
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(system_time_point.time_since_epoch()) % 1000;
        std::time_t time_t = std::chrono::system_clock::to_time_t(system_time_point);
        std::tm tm = *std::gmtime(&time_t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") 
            << '.' << std::setw(3) << std::setfill('0') << ms.count();

        std::string formatted_time = oss.str();

        std::string log_entry = "[" + from + "," + to + "," + formatted_time + "] " + log_message;

        logs.push_back(log_entry);
    }

    void write_to_stdout() {
        for (std::string log : logs) {
            std::cout << log;
        }
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

// Game description parser.
Game parse_game_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    Game game;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        int round_type = line[0] - '0';
        char starting_player = line[1];

        Round round(round_type, starting_player);

        for (int i = 1; i < 5; i++) {
            std::getline(file, line);
            round.card_strings[i] = line;
            parse_card_set(line, round.hands[i].cards);
        }

        game.add_round(round);
    }

    file.close();
    return game;
}


// ----------------------------------- Initialization -----------------------------------

// Sets variables describing input options.
int set_input_variables(int argc, char** argv, std::string* port,
                        std::string* filename, int* timeout) {
    int opt;
    while ((opt = getopt(argc, argv, "p:f:t:")) != -1) {
        switch (opt) {
            case 'p':
                *port = optarg;
                break;
            case 'f':
                *filename = optarg;
                break;
            case 't':
                *timeout = 1000 * std::stoi(optarg);
                break;
            default:
                return ERROR;
        }
    }
    return GOOD;
}

// Parses command line arguments.
void parse_arguments(int argc, char** argv, std::string* port,
                    std::string* filename, int* timeout)
{
    if (set_input_variables(argc, argv, port, filename, timeout) == ERROR ||
        (*filename).empty()
    ) {
        throw std::runtime_error(
            "Usage: kierki-serwer -f <file> [-p <port>] [-t <timeout>]\n"
        );
    }
    else if (*timeout <= 0) {
        throw std::runtime_error(
            "Timeout must be a positive integer.\n"
        );
    }
}

// [TEST FUNCTION] Prints initial settings info.
void print_options_info(std::string port_s, std::string filename, int timeout)
{
    std::cout << "Selected program options:\n";
    std::cout << "Port (-p): " << port_s << "\n";
    std::cout << "File (-f): " << filename << "\n";
    std::cout << "Timeout (-t): " << timeout << "\n";
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

// Creates a socket.
void create_socket(int* socket_fd) {
    *socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (*socket_fd < 0) {
        throw std::runtime_error("socket");
    }
    // OPTIONAL THINGS:
    // Allow dual-stack socket to accept both IPv4 and IPv6:
    int opt = 0;
    if (setsockopt(*socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&opt, sizeof(opt)) < 0) {
        // Manually handle closing the socket:
        close(*socket_fd);
        throw std::runtime_error("setsockopt1");
    }
    /*
    // Allow the socket to be reused:
    opt = 1;
    if (setsockopt(*socket_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt))) {
        // Manually handle closing the socket:
        close(*socket_fd);
        throw std::runtime_error("setsockopt2");
    }
    */
}

// Binds socket to a particular address.
void bind_socket_to_address(int socket_fd, uint16_t port, struct sockaddr_in6* server_address) {
    (*server_address).sin6_family = AF_INET6; // check if it works with IPv4
    (*server_address).sin6_addr = in6addr_any;
    (*server_address).sin6_port = htons(port);

    if (bind(socket_fd, (struct sockaddr*)server_address, sizeof(*server_address)) < 0) {
        close(socket_fd);
        throw std::runtime_error("bind");
    }
}

// Gets server's IP address and assigned port number.
void get_server_ip(int socket_fd, uint16_t* port, std::string* ip_and_port) {
    struct sockaddr_storage server_address;
    socklen_t len = sizeof(server_address);
    
    if (getsockname(socket_fd, (struct sockaddr*)&server_address, &len) < 0) {
        close(socket_fd);
        throw std::runtime_error("getsockname helper function");
    }

    char address[INET6_ADDRSTRLEN];
    
    if (server_address.ss_family == AF_INET) {
        struct sockaddr_in* s = (struct sockaddr_in*)&server_address;
        if (inet_ntop(AF_INET, &s->sin_addr, address, INET6_ADDRSTRLEN) == NULL) {
            close(socket_fd);
            throw std::runtime_error("inner inet_ntop 1");
        }
    }
    else if (server_address.ss_family == AF_INET6) {
        struct sockaddr_in6* s = (struct sockaddr_in6*)&server_address;
        if (inet_ntop(AF_INET6, &s->sin6_addr, address, INET6_ADDRSTRLEN) == NULL) {
            close(socket_fd);
            throw std::runtime_error("inner inet_ntop 2");
        }
    }
    else {
        close(socket_fd);
        throw std::runtime_error("unknown address family in server");
    }

    std::string ip_address = address;
    *port = ntohs(((struct sockaddr_in6*)&server_address)->sin6_port);
    std::string port_s = std::to_string(*port);
    *ip_and_port = ip_address + ":" + port_s;
}

// Switches a socket to the listening mode.
void switch_to_listening(int socket_fd) {
    if (listen(socket_fd, QUEUE_LENGTH) < 0) {
        close(socket_fd);
        throw std::runtime_error("listen");
    }
}

// Initializes main socket.
void initialize_main_socket(int* socket_fd, std::string port_s, uint16_t* port,
                            struct sockaddr_in6* server_address, std::string* ip_and_port) {
    *port = (port_s == "0") ? 0 : read_port(port_s);
    // std::cout << "Port: " << *port << "\n";
    create_socket(socket_fd);
    bind_socket_to_address(*socket_fd, *port, server_address);
    switch_to_listening(*socket_fd);
    
    get_server_ip(*socket_fd, port, ip_and_port);
    // test, to remove:
    std::cout << "IP and port: " << *ip_and_port << "\n";
    std::cout << "listening on port: " << *port << "\n";
}


// ------------------------------------- Connection -------------------------------------

// Initializes descriptors' array (of size 9) to use in poll().
void initialize_descriptors(struct pollfd* poll_fds, int socket_fd) {
    for (int i = 0; i < 9; i++) {
        poll_fds[i].fd = -1;
        poll_fds[i].events = POLLIN;
        poll_fds[i].revents = 0;
    }
    poll_fds[0].fd = socket_fd;
}

// Clears i-th descriptor in poll array.
void clear_descriptor(struct pollfd* poll_fds, int i) {
    poll_fds[i].fd = -1;
    poll_fds[i].events = POLLIN;
    poll_fds[i].revents = 0;
}

// Initializes an array (of size 9) with clients data.
void initialize_clients_info(struct ClientInfo* clients) {
    for (int i = 0; i < 9; i++) {
        clients[i].fd = -1;
        clients[i].port = 0;
        clients[i].ip_and_port = "";
        clients[i].connection_time = TimePoint();
        clients[i].chosen_position = 0;
        clients[i].round_points = 0;
        clients[i].total_points = 0;
    }
}

// Clears i-th client's info in clients data array.
void clear_client_info(struct ClientInfo* clients, int i) {
    clients[i].fd = -1;
    clients[i].port = 0;
    clients[i].ip_and_port = "";
    clients[i].connection_time = TimePoint();
    clients[i].chosen_position = 0;
    clients[i].round_points = 0;
    clients[i].total_points = 0;
}

// Initializes an array for the info about occupied places.
void initialize_is_occupied(bool* is_place_occupied) {
    for (int i = 0; i <= PLAYERS; i++) {
        is_place_occupied[i] = false;
    }
}

// Writes true/false to an array that indicates occupation of places.
// is_place_occupied = { _ _ _ _ _ }
//                         N E S W
void get_occupied_places(struct ClientInfo* clients, bool* is_place_occupied) {
    for (int i = 1; i <= PLAYERS; i++) {
        int pos = clients[i].chosen_position;
        is_place_occupied[pos] = (pos != 0) ? true : false;
    }
}

// Gets client's IP address and assigned port number.
void get_client_ip(int client_fd, uint16_t* port, std::string* ip_and_port) {
    struct sockaddr_storage client_address;
    socklen_t len = sizeof(client_address);

    if (getpeername(client_fd, (struct sockaddr*)&client_address, &len) < 0) {
        close(client_fd);
        throw std::runtime_error("getpeername helper function");
    }

    char address[INET6_ADDRSTRLEN];

    if (client_address.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&client_address;
        if (inet_ntop(AF_INET, &s->sin_addr, address, INET6_ADDRSTRLEN) == NULL) {
            close(client_fd);
            throw std::runtime_error("inner inet_ntop 1");
        }
        // test:
        //std::cout << "Client connected from IPv4: " << address << "\n";
    }
    else if (client_address.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_address;
        if (inet_ntop(AF_INET6, &s->sin6_addr, address, INET6_ADDRSTRLEN) == NULL) {
            close(client_fd);
            throw std::runtime_error("inner inet_ntop 2");
        }
        // test:
        //std::cout << "Client connected from IPv6: " << address << "\n"; // test
    }
    else {
        close(client_fd);
        throw std::runtime_error("unknown address family in server");
    }

    std::string ip_address = address;
    *port = ntohs(((struct sockaddr_in6*)&client_address)->sin6_port);
    std::string port_s = std::to_string(*port);
    *ip_and_port = ip_address + ":" + port_s;
}

// Accepts connection from client and puts it in clients array.
void accept_client(struct pollfd* poll_fds, struct ClientInfo* clients) {
    
    struct sockaddr_storage client_address;
    socklen_t len;
    
    int client_fd = accept(poll_fds[0].fd, (struct sockaddr*)&client_address, &len);
    if (client_fd < 0) {
        throw std::runtime_error("accept");
    }

    uint16_t client_port;
    std::string client_ip_and_port;
    get_client_ip(client_fd, &client_port, &client_ip_and_port);

    // Find a place in descriptors array:
    int id = 1;
    while (id <= PLAYERS) {
        if (poll_fds[id].fd == -1) {
            poll_fds[id].fd = client_fd;
            poll_fds[id].events = POLLIN;
            poll_fds[id].revents = 0;
            std::cout << "received new connection (id: " << id << "): " << client_ip_and_port << "\n";
            break;
        }
        id++;
    }

    // Save all important data:
    clients[id].fd = client_fd;
    clients[id].port = client_port;
    clients[id].ip_and_port = client_ip_and_port;
    clients[id].connection_time = Clock::now();
    clients[id].chosen_position = 0;
}

// Disconnects client occupying i-th position in descriptors' array.
void disconnect_client(struct pollfd* poll_fds, struct ClientInfo* clients,
                       int* active_clients, int* ready, int i) {
    close(poll_fds[i].fd);
    (*active_clients)--;
    if (clients[i].chosen_position != 0) (*ready)--;
    clear_descriptor(poll_fds, i);
    clear_client_info(clients, i);
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

// Calculate the remaining time for each client and set poll's timeout.
void calculate_remaining_time(struct pollfd* poll_fds, struct ClientInfo* clients, 
                              int timeout, int* poll_timeout, int* active_clients, int* ready) {
    int min_timeout = TIMEOUT;
    TimePoint now = Clock::now();

    for (int i = 1; i < POLL_SIZE; i++) {
        
        if (poll_fds[i].fd != -1 && clients[i].chosen_position == 0) {
            // Client hasn't sent IAM, so calculate time left:
            auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(now - clients[i].connection_time).count();
            int time_left = timeout - elapsed_time;
            std::cout << "time left for client " << i << ": " << time_left << "\n";

            if (time_left <= 0) {
                disconnect_client(poll_fds, clients, active_clients, ready, i);
                std::cerr << "Time exceeded: ending connection (id: " << i << ")\n";
            }
            else if (time_left > 0 && time_left < min_timeout) {
                min_timeout = time_left;
            }
        }
    }

    *poll_timeout = min_timeout;
}


// --------------------------------- Receiving messages ---------------------------------

// Reads from given descriptor until it finds "\r\n" sequence.
// Writes read sequence to an external buffer ext_buffer
// Returns number of read bytes or -1 in case of error.
// COMMON
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


// -------------------------------- Parsing messages ------------------------------------
// |       All parsers return 0 if a message is parsed correctly, 1 if it's not.        |
// --------------------------------------------------------------------------------------

// Parser for a message of type: IAM<place>\r\n.
int parse_iam(const std::string& message, char* result, Logs& logs, std::string from, std::string to) {

    std::regex pattern(R"(IAM([NESW])\r\n)");
    std::smatch match;

    logs.add(from, to, Clock::now(), message);

    if (std::regex_match(message, match, pattern)) {
        *result = match[1].str()[0];
        return GOOD;
    } else {
        return ERROR;
    }
}

// Parser for a message of type: TRICK<trick number><card>\r\n.
int parse_trick(const std::string& message, int trick_number,
                std::string* value, char* suit, Logs& logs, std::string from, std::string to) {
    
    std::regex pattern(R"(TRICK([1-9]|1[0-3])(10|[2-9]|[JQKA])([CDHS])\r\n)");
    std::smatch match;

    logs.add(from, to, Clock::now(), message);

    if (std::regex_match(message, match, pattern)) {
        if (std::stoi(match[1].str()) == trick_number) {
            *value = match[2].str();
            *suit = match[3].str()[0];
            return GOOD;
        } else {
            std::cerr << "Wrong trick number in parse_trick\n";
            return 2;
        }
    } else {
        return ERROR;
    }
}


// ------------------------------------ Test prints -------------------------------------

// TEST: Prints whole poll_fds array.
void print_poll_fds(struct pollfd* poll_fds) {
    std::cout << "POLL_FDS\n\t0\t1\t2\t3\t4\n";
    std::cout << "fd:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << poll_fds[i].fd << "\t";
    }
    std::cout << "\n";
    std::cout << "ev:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << poll_fds[i].events << "\t";
    }
    std::cout << "\n";
    std::cout << "rev:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << poll_fds[i].revents << "\t";
    }
    std::cout << "\n";
}

// TEST: Prints whole clients array.
void print_clients(struct ClientInfo* clients) {
    std::cout << "CLIENTS\n\t0\t1\t2\t3\t4\n";
    std::cout << "fd:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << clients[i].fd << "\t";
    }
    std::cout << "\n";
    std::cout << "port:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << clients[i].port << "\t";
    }
    std::cout << "\n";
    std::cout << "pos:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << clients[i].chosen_position << "\t";
    }
    std::cout << "\n";
    std::cout << "scr:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << clients[i].round_points << "\t";
    }
    std::cout << "\n";
    std::cout << "tot:\t";
    for (int i = 0; i < POLL_SIZE; i++) {
        std::cout << clients[i].total_points << "\t";
    }
    std::cout << "\n";
}


// ---------------------------------- Sending messages ----------------------------------

// Sends BUSY<place list> message to the client.
void send_busy(int socket_fd, bool* is_place_occupied, Logs& logs, std::string from, std::string to) {
    
    std::string message = "BUSY";
    
    if (is_place_occupied[N]) message += std::string(1, 'N');
    if (is_place_occupied[E]) message += std::string(1, 'E');
    if (is_place_occupied[S]) message += std::string(1, 'S');
    if (is_place_occupied[W]) message += std::string(1, 'W');
    
    message += "\r\n";
    
    std::cout << "sending " << message << "to client\n";
    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (busy)");
    }

    logs.add(from, to, Clock::now(), message);
}

// Sends DEAL<round type><starting player><card list> message to the client.
void send_deal(int socket_fd, int round_type, char starting_player, std::string card_string,
               std::string* deal_msg, Logs& logs, std::string from, std::string to) {

    std::string message = "DEAL";

    message += std::string(1, ('0' + round_type));
    message += std::string(1, starting_player);
    message += card_string;

    message += "\r\n";
    *deal_msg = message;

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (deal)");
    }

    logs.add(from, to, Clock::now(), message);
}

// Sends TRICK<trick number><card list> message to the client.
void send_trick(int socket_fd, int trick_number, std::vector<Card>& cards_on_table,
                Logs& logs, std::string from, std::string to) {

    std::string message = "TRICK";

    message += std::to_string(trick_number);
    for (Card card : cards_on_table) {
        message += card.to_string();
    }

    message += "\r\n";

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (trick)");
    }

    logs.add(from, to, Clock::now(), message);
}

// Sends WRONG<trick number> message to the client.
void send_wrong(int socket_fd, int trick_number, Logs& logs, std::string from, std::string to) {

    std::string message = "WRONG";

    message += std::to_string(trick_number);

    message += "\r\n";

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (wrong)");
    }

    logs.add(from, to, Clock::now(), message);
}

// Sends TAKEN<trick number><card list><trick winner> message to the client.
void send_taken(int socket_fd, int trick_number, std::vector<Card>& cards_on_table, int winner,
                std::string* msg, Logs& logs, std::string from, std::string to) {

    std::string message = "TAKEN";

    message += std::to_string(trick_number);
    for (Card card : cards_on_table) {
        message += card.to_string();
    }
    message += std::string(1, map_int_to_place_name[winner]);

    message += "\r\n";
    *msg = message;

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (taken)");
    }

    logs.add(from, to, Clock::now(), message);
}

// Sends SCORE<player><points>...<player><points> message to the client.
void send_score(int socket_fd, struct ClientInfo* clients,
                Logs& logs, std::string from, std::string to) {

    std::string message = "SCORE";

    for (int i = 1; i <= 4; i++) {
        message += std::string(1, map_int_to_place_name[i]);
        message += std::to_string(clients[i].round_points);
    }

    message += "\r\n";

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (score)");
    }

    logs.add(from, to, Clock::now(), message);
}

// Sends TOTAL<player><points>...<player><points> message to the client.
void send_total(int socket_fd, struct ClientInfo* clients,
                Logs& logs, std::string from, std::string to) {

    std::string message = "TOTAL";

    for (int i = 1; i <= 4; i++) {
        message += std::string(1, map_int_to_place_name[i]);
        message += std::to_string(clients[i].total_points);
    }

    message += "\r\n";

    ssize_t written_bytes = writen(socket_fd, message.c_str(), message.length());
    if (written_bytes <= 0) {
        throw std::runtime_error("writen (total)");
    }

    logs.add(from, to, Clock::now(), message);
}


// ------------------------------- Broadcasting messages --------------------------------

// Calls send_deal() for each player.
void broadcast_deal(struct ClientInfo* clients, int round_type, char starting_player, std::string* card_strings,
                    std::vector<std::string>& deals_sent, Logs& logs, std::string from) {
    for (int i = 1; i <= 4; i++) {
        std::string message;
        send_deal(clients[i].fd, round_type, starting_player, card_strings[i], &message, logs, from, clients[i].ip_and_port);
        deals_sent.push_back(message);
    }
    
}

// Calls send_taken() for each player.
void broadcast_taken(struct ClientInfo* clients, int trick_number, std::vector<Card> cards_on_table, int winner,
                     std::vector<std::string>& takens_sent, Logs& logs, std::string from) {
    std::string message;
    for (int i = 1; i <= 4; i++) {
        send_taken(clients[i].fd, trick_number, cards_on_table, winner, &message, logs, from, clients[i].ip_and_port);
    }
    takens_sent.push_back(message);
}

// Calls send_score() for each player.
void broadcast_score(struct ClientInfo* clients, Logs& logs, std::string from) {
    for (int i = 1; i <= 4; i++) {
        send_score(clients[i].fd, clients, logs, from, clients[i].ip_and_port);
    }
}

// Calls send_total() for each player.
void broadcast_total(struct ClientInfo* clients, Logs& logs, std::string from) {
    for (int i = 1; i <= 4; i++) {
        send_total(clients[i].fd, clients, logs, from, clients[i].ip_and_port);
    }
}


// ---------------------------------- Event handlers ------------------------------------

// Handles an event (client's connection request) on main descriptor.
void handle_new_client_request(int* active_clients, struct pollfd* poll_fds, struct ClientInfo* clients,
                               Logs& logs, std::string from) {
    if (*active_clients < PLAYERS) {
        accept_client(poll_fds, clients);
        (*active_clients)++;
        std::cout << "Client " << *active_clients << " accepted\n"; // test
    } else {
        struct sockaddr_storage client_address;
        socklen_t len;
        int temp_fd = accept(poll_fds[0].fd, (struct sockaddr*)&client_address, &len);
        if (temp_fd < 0) {
            std::cerr << "Couldn't accept client\n";
        }
        uint16_t client_port;
        std::string client_ip_and_port;
        get_client_ip(temp_fd, &client_port, &client_ip_and_port);
        
        bool oc[] = {true, true, true, true, true};
        std::cerr << "new connection rejected because there is no empty place\n";
        send_busy(temp_fd, oc, logs, from, client_ip_and_port);
        close(temp_fd);
    }
}

// Handles an event (new message) on given (i-th) descriptor.
void handle_pollin(struct pollfd* poll_fds, int i, struct ClientInfo* clients,
                   int* active_clients, int* ready, bool* is_place_occupied, Logs& logs, std::string from) {
    
    ssize_t last_read_size;
    std::string buffer = "";
                    
    int received_bytes = read_to_newline(poll_fds[i].fd, &buffer);

    if (received_bytes < 0) {
        disconnect_client(poll_fds, clients, active_clients, ready, i);
        std::cerr << "readn failed: ending connection (id: " << i << ")\n";
    } else if (received_bytes == 0) {
        disconnect_client(poll_fds, clients, active_clients, ready, i);
        std::cerr << "empty readn: ending connection (id: " << i << ")\n";
    } else {
        std::cout << "received " << received_bytes << " bytes within connection (id: " << i << ")\n";
        std::cout << "parsing message: " << buffer << "\n";
        char place;
        if (parse_iam(buffer, &place, logs, clients[i].ip_and_port, from) == 0) {
            std::cout << "received IAM" << place << "\n";
            get_occupied_places(clients, is_place_occupied);
            int p = map_place[place];
            if (!is_place_occupied[p]) {
                clients[i].chosen_position = p;
                (*ready)++;
            } else {
                send_busy(poll_fds[i].fd, is_place_occupied, logs, from, clients[i].ip_and_port);
                disconnect_client(poll_fds, clients, active_clients, ready, i);
                std::cerr << "place busy: ending connection (id: " << i << ")\n";
            }

        } else {
            close(poll_fds[i].fd);
            (*active_clients)--;
            clear_descriptor(poll_fds, i);
            clear_client_info(clients, i);
            std::cerr << "Wrong message from client (id: " << i << "), disconnected\n";
        }
    }
}


// ------------------------------ First part: connection --------------------------------

// Create connections with all players.
void connect_with_players(struct pollfd* ready_poll_fds, struct ClientInfo* ready_clients, 
                          int timeout, int socket_fd, Logs& logs, std::string from) {

    struct pollfd poll_fds[9];
    struct ClientInfo clients[9];
    bool is_place_occupied[POLL_SIZE];

    initialize_descriptors(poll_fds, socket_fd);
    initialize_clients_info(clients);
    initialize_is_occupied(is_place_occupied);

    // After establishing all four connections, poll_fds and clients
    // will be rewritten to ready_poll_fds and ready_clients.

    int poll_timeout = TIMEOUT;
    int active_clients = 0;
    int ready = 0;

    do {
        for (int i = 0; i < 9; i++) {
            poll_fds[i].revents = 0;
        }

        int poll_status = poll(poll_fds, 9, poll_timeout);
        check_poll_error(poll_status);

        if (poll_status > 0) {
            // New connection: new client is accepted.
            if (poll_fds[0].revents & POLLIN) {

                handle_new_client_request(&active_clients, poll_fds, clients, logs, from);
                std::cout << "active_clients after connection: " << active_clients << "\n";

            }
            // Serve connected clients - receive IAM or reject message/connection.
            for (int i = 1; i <= PLAYERS; i++) {
                
                // POLLIN <=> received a message.
                if (poll_fds[i].fd != -1 && (poll_fds[i].revents & POLLIN)) {

                    handle_pollin(poll_fds, i, clients, &active_clients, &ready, is_place_occupied, logs, from);
                    
                }
                // POLLHUP <=> client disconnected by server - in case of some weird behaviour.
                else if (poll_fds[i].fd != -1 && (poll_fds[i].revents & POLLHUP)) {
                    disconnect_client(poll_fds, clients, &active_clients, &ready, i);
                    std::cerr << "client " << i << " disconnected - waiting to reconnect\n";
                }
                // POLLERR <=> client's error.
                else if (poll_fds[i].fd != -1 && (poll_fds[i].revents & POLLERR)) {
                    disconnect_client(poll_fds, clients, &active_clients, &ready, i);
                    std::cerr << "client " << i << " got an error - disconnected\n";
                }
                // POLLNVAL <=> wrong descriptor.
                else if (poll_fds[i].fd != -1 && (poll_fds[i].revents & POLLNVAL)) {
                    disconnect_client(poll_fds, clients, &active_clients, &ready, i);
                    std::cerr << "error in poll_fds array: descriptor " << i << "is wrong\n";
                }
            }
        } 
        else {
            std::cout << "timeout...\n";
        }

        calculate_remaining_time(poll_fds, clients, timeout, &poll_timeout, &active_clients, &ready);

    } while (ready < PLAYERS);

    for (int i = 1; i <= PLAYERS; i++) {
        int p = clients[i].chosen_position;
        ready_poll_fds[p].fd = poll_fds[i].fd;
        ready_clients[p].fd = clients[i].fd;
        ready_clients[p].port = clients[i].port;
        ready_clients[p].ip_and_port = clients[i].ip_and_port;
        ready_clients[p].connection_time = clients[i].connection_time;
        ready_clients[p].chosen_position = clients[i].chosen_position;
    }

    // test
    print_poll_fds(ready_poll_fds);
    print_clients(ready_clients);
    // test

    std::cout << "Connections established, game is starting...\n";
}




// --------------------------------- Second part: game ----------------------------------

/*
struct ClientInfo {
    int fd;
    uint16_t port;
    std::string ip_and_port;
    TimePoint connection_time;
    int chosen_position;
    int round_points;
    int total_points;
};
*/

// Accepts connection from client and puts it in clients array.
void accept_client_in_game(struct pollfd* poll_fds, struct ClientInfo* clients) {
    
    struct sockaddr_storage client_address;
    socklen_t len;
    
    int client_fd = accept(poll_fds[0].fd, (struct sockaddr*)&client_address, &len);
    if (client_fd < 0) {
        throw std::runtime_error("accept");
    }

    uint16_t client_port;
    std::string client_ip_and_port;
    get_client_ip(client_fd, &client_port, &client_ip_and_port);

    // Find a place in descriptors array:
    int id = 5;
    while (id < 9) {
        if (poll_fds[id].fd == -1) {
            poll_fds[id].fd = client_fd;
            poll_fds[id].events = POLLIN;
            poll_fds[id].revents = 0;
            std::cout << "received new connection (id: " << id << "): " << client_ip_and_port << "\n";
            break;
        }
        id++;
    }

    // Save all important data:
    clients[id].fd = client_fd;
    clients[id].port = client_port;
    clients[id].ip_and_port = client_ip_and_port;
    clients[id].connection_time = Clock::now();
    clients[id].chosen_position = 0;
}


/*
DEBUG:
std::cout << "Poll descriptors array:\n";
for (int i = 0; i < POLL_SIZE; i++) {
    std::cout << "fd=" << poll_fds[i].fd << " events=" << poll_fds[i].events << " revents=" << poll_fds[i].revents << "\n";
}
*/

// Usage of clear_descriptor() remains unchanged.

// Clears i-th client's info in clients data array during the game.
void clear_client_info_in_game(struct ClientInfo* clients, int i) {
    clients[i].fd = -1;
    clients[i].port = 0;
    clients[i].ip_and_port = "";
    clients[i].connection_time = TimePoint();
    clients[i].chosen_position = 0;
    // New player inherits all the remaining data.
}

// Disconnects client occupying i-th position in descriptors' array.
void disconnect_client_in_game(struct pollfd* poll_fds, struct ClientInfo* clients,
                               int* active_clients, int i) {
    close(poll_fds[i].fd);
    (*active_clients)--;
    clear_descriptor(poll_fds, i);
    clear_client_info_in_game(clients, i);
}

// Handles an event (client's connection request) on main descriptor.
void handle_new_client_request_in_game(int active_clients, struct pollfd* poll_fds,
                                       struct ClientInfo* clients, Logs& logs, std::string from) {
    if (active_clients < PLAYERS) {
        accept_client_in_game(poll_fds, clients);
        std::cout << "Client accepted\n"; // test
    } else {
        struct sockaddr_storage client_address;
        socklen_t len;
        int temp_fd = accept(poll_fds[0].fd, (struct sockaddr*)&client_address, &len);
        if (temp_fd < 0) {
            std::cerr << "Couldn't accept client\n";
        }
        uint16_t client_port;
        std::string client_ip_and_port;
        get_client_ip(temp_fd, &client_port, &client_ip_and_port);
        
        bool oc[] = {true, true, true, true, true};
        std::cerr << "new connection rejected because there is no empty place\n";
        send_busy(temp_fd, oc, logs, from, client_ip_and_port);
        close(temp_fd);
    }
}

// Manages the game.
void game_manager(Game game, struct pollfd* poll_fds, struct ClientInfo* clients, int timeout,
                  Logs& logs, std::string from) {

    int active_clients = PLAYERS;

    for (Round round : game.rounds) {

        int player = map_place[round.starting_player];      // A player that starts the round.
        int type = round.round_type;                        // Round type (1-7).
        int points_left = points_in_total[type];            // Points to distribute among players.
        struct RoundPoints points = round_points[type];     // Rules of distributing points.
        std::vector<std::string> takens_sent;               // Vector of all sent TAKEN messages.
        std::vector<std::string> deals_sent;                // Vector of all sent DEAL messages.
        
        // Start the round:
        broadcast_deal(clients, type, round.starting_player, round.card_strings, deals_sent, logs, from);
        std::cout << "sent deal to each client\n";
        sleep(2); // test

        // 13 TRICKS:
        for (int l = 1; l <= TRICKS_IN_ROUND; l++) {        // l - trick number.

            std::vector<Card> cards_on_table;               // Cards received from players (0-3).

            int biggest_value = 0;
            int winner = player;
            char starter_suit;
        
            // 4 PLAYERS:
            for (int i = 1; i <= PLAYERS; i++) {            // i - dummy counter.

                int poll_timeout = TIMEOUT;
                bool received = false;
                bool trick_to_send = true;
                TimePoint last_send_time;

                do {
                    // Send TRICK for the first time or after timeout.
                    if (trick_to_send) {
                        send_trick(clients[player].fd, l, cards_on_table, logs, from, clients[player].ip_and_port);
                        last_send_time = Clock::now();
                        trick_to_send = false;
                    }

                    // Reset revents in poll_fds:
                    for (int k = 0; k < 9; k++) {
                        poll_fds[k].revents = 0;
                    }

                    // Poll:
                    int poll_status = poll(poll_fds, 9, poll_timeout);
                    check_poll_error(poll_status);

                    if (poll_status > 0) {
                        // New connection request:
                        if (poll_fds[0].revents & POLLIN) {

                            handle_new_client_request_in_game(active_clients, poll_fds, clients, logs, from);

                        }
                        // Serve connected clients - receive IAM or reject message/connection.
                        for (int j = 1; j <= PLAYERS; j++) { // j - kolejny dummy licznik, do przeiterowania się po poll_fds
                            
                            // POLLIN <=> received a message.
                            if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLIN)) {

                                ssize_t last_read_size;
                                std::string buffer = "";
                                                
                                int received_bytes = read_to_newline(poll_fds[j].fd, &buffer);

                                if (received_bytes < 0) {
                                    // Error in readn, disconnecting:
                                    std::cerr << "Error in readn from player " << map_int_to_place_name[j] << ". Waiting for a new player...\n";
                                    disconnect_client_in_game(poll_fds, clients, &active_clients, j);
                                } else if (received_bytes == 0) {
                                    // Player has disconnected:
                                    std::cerr << "Player " << map_int_to_place_name[j] << " has left - waiting for a player...\n";
                                    disconnect_client_in_game(poll_fds, clients, &active_clients, j);
                                } else {
                                    // Coś odebrano - przetwarzamy wiadomość (wiadomość od dobrego gracza lub nie)
                                    std::cout << "received " << received_bytes << " bytes within connection (id: " << j << ")\n";

                                    if (active_clients == PLAYERS) {

                                        std::cout << "parsing message: " << buffer << "\n";

                                        if (player == j) {
                                            // Dobry gracz - próbujemy parsować
                                            std::string value;
                                            char suit;
                                            int errcode = parse_trick(buffer, l, &value, &suit, logs, clients[j].ip_and_port, from);
                                            if (errcode == GOOD) {
                                                // Numer lewy się zgadza, sprawdzamy czy karta jest na ręce:
                                                if (round.hands[j].contains(value, suit)) {
                                                    // Jeśli gracz zaczyna lewę, to przyjmujemy:
                                                    if (i == 1) {
                                                        // Zapisz kartę
                                                        starter_suit = suit; 
                                                        biggest_value = map_value[value];

                                                        cards_on_table.push_back(Card(value, suit));
                                                        round.hands[j].remove_card(value, suit);
                                                        
                                                        // ACCEPT: Cyclic incrementation, 0 is ommited to fit indices in clients' array:
                                                        player = (player == 4) ? 1 : (player + 1);
                                                        received = true;
                                                    }
                                                    // Jeśli nie zaczyna, to sprawdzamy, czy ruch spełnia obowiązek dokładania karty do koloru:
                                                    else if (i != 1 && suit == starter_suit) { // do starter_suit odwołujemy się tylko jeśli jest zainicjowana
                                                        
                                                        // Jeśli spełnia, to akceptujemy kartę
                                                        cards_on_table.push_back(Card(value, suit));
                                                        round.hands[j].remove_card(value, suit);
                                                        
                                                        if (map_value[value] > biggest_value && suit == starter_suit) {
                                                            biggest_value = map_value[value];
                                                            winner = player;
                                                        }

                                                        // ACCEPT: Cyclic incrementation, 0 is ommited to fit indices in clients' array:
                                                        player = (player == 4) ? 1 : (player + 1);
                                                        received = true;
                                                    } 
                                                    // Jeśli nie spełnia, to sprawdzamy, czy faktycznie gracz nie ma żadnej karty w żądanym kolorze:
                                                    else if (i != 1 && suit != starter_suit) {
                                                        bool poverty = true;
                                                        for (Card card : round.hands[player].cards) {
                                                            if (card.suit == starter_suit) {
                                                                poverty = false;
                                                                break;
                                                            }
                                                        }
                                                        if (poverty) {
                                                            // Jeśli faktycznie ma biedę, to dorzucamy kartę na stół
                                                            cards_on_table.push_back(Card(value, suit));
                                                            round.hands[j].remove_card(value, suit);
                                                            // ...ale nie uwzględniamy jej w punktacji.

                                                            // Cyclic incrementation, 0 is ommited to fit indices in clients' array:
                                                            player = (player == 4) ? 1 : (player + 1);
                                                            received = true;
                                                        } else {
                                                            // Jeśli nas okłamał, to wysyłamy wrong
                                                            send_wrong(poll_fds[j].fd, l, logs, from, clients[j].ip_and_port);
                                                        }
                                                    }
                                                } else {
                                                    // Karty nie ma na ręce, wysyłamy wrong
                                                    std::cerr << "Player doesn't have this card\n";
                                                    send_wrong(poll_fds[j].fd, l, logs, from, clients[j].ip_and_port);
                                                }
                                            } else if (errcode == 2) {
                                                // Wiadomość się parsuje, ale numer lewy jest zły - WRONG
                                                std::cerr << "Incorrect trick number\n";
                                                send_wrong(poll_fds[j].fd, l, logs, from, clients[j].ip_and_port);
                                            } else {
                                                // Wiadomość się nie parsuje
                                                std::cerr << "Incorrect message from player " << map_int_to_place_name[j] << " disconnected\n";
                                                disconnect_client_in_game(poll_fds, clients, &active_clients, j);
                                            }
                                        } else {
                                            // Zły gracz wysyła wiadomość nieproszony - sprawdzamy czy wysłał TRICK
                                            std::string value;
                                            char suit;
                                            int errcode = parse_trick(buffer, l, &value, &suit, logs, clients[j].ip_and_port, from);
                                            if (errcode == GOOD || errcode == 2) {
                                                // Parsuje się, odsyłamy WRONG
                                                std::cerr << "TRICK received from incorrect player\n";
                                                send_wrong(poll_fds[j].fd, l, logs, from, clients[j].ip_and_port);
                                            } else {
                                                // Nie parsuje się - błędny komunikat
                                                std::cerr << "Unexpected message from player " << map_int_to_place_name[j] << " disconnected\n";
                                                disconnect_client_in_game(poll_fds, clients, &active_clients, j);
                                            }
                                        }
                                    } 
                                    // If active_players < 4, then check if somebody sent IAM:
                                    else {
                                        std::cerr << "Message ignored - game suspended\n";
                                        
                                    }
                                }
                            }
                            // POLLHUP <=> client disconnected by server - in case of some weird behaviour.
                            else if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLHUP)) {
                                std::cerr << "POLLHUP in descriptor of player " << map_int_to_place_name[j] << " disconnected\n";
                                disconnect_client_in_game(poll_fds, clients, &active_clients, j);
                            }
                            // POLLERR <=> client's error.
                            else if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLERR)) {
                                std::cerr << "POLLERR in descriptor of player " << map_int_to_place_name[j] << " disconnected\n";
                                disconnect_client_in_game(poll_fds, clients, &active_clients, j);
                            }
                            // POLLNVAL <=> wrong descriptor.
                            else if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLNVAL)) {
                                std::cerr << "POLLNVAL in descriptor of player " << map_int_to_place_name[j] << " disconnected\n";
                                disconnect_client_in_game(poll_fds, clients, &active_clients, j);
                            }
                        }

                        // Tutaj iterujemy się po wszystkich dodatkowych deskryptorach na których czekają kandydaci
                        for (int j = 5; j < 9; j++) {

                            // POLLIN <=> received a message.
                            if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLIN)) {

                                ssize_t last_read_size;
                                std::string buffer = "";
                                                
                                int received_bytes = read_to_newline(poll_fds[j].fd, &buffer);

                                int dummy1 = 0;
                                int dummy2 = 0;

                                if (received_bytes < 0) {
                                    // Error
                                    disconnect_client(poll_fds, clients, &dummy1, &dummy2, j);
                                    std::cerr << "error in readn while waiting for iam\n";

                                } else if (received_bytes == 0) {
                                    // Client disconnected
                                    disconnect_client(poll_fds, clients, &dummy1, &dummy2, j);
                                    std::cerr << "client trying to join left unexpectedly\n";

                                } else {
                                    // Coś odebrano - próbujemy parsować IAM
                                    std::cout << "received " << received_bytes << " bytes within connection (id: " << j << ")\n";
                                    std::cout << "parsing message: " << buffer << "\n";
                                    char place;
                                    if (parse_iam(buffer, &place, logs, clients[j].ip_and_port, from) == GOOD) {
                                        std::cout << "received IAM" << place << "\n";
                                        bool is_place_occupied[5];
                                        is_place_occupied[0] = false;
                                        for (int m = 1; m <= PLAYERS; m++) {
                                            is_place_occupied[m] = (clients[m].chosen_position == 0) ? false : true;
                                        }
                                        int p = map_place[place];
                                        if (!is_place_occupied[p]) {
                                            poll_fds[p].fd = poll_fds[j].fd; 
                                            clients[p].fd = poll_fds[j].fd;
                                            clients[p].port = clients[j].port;
                                            clients[p].ip_and_port = clients[j].ip_and_port;
                                            clients[p].connection_time = Clock::now();
                                            clients[p].chosen_position = p; // dla pewności
                                            active_clients++;
                                            clear_client_info(clients, j);
                                            clear_descriptor(poll_fds, j);
                                            // tutaj wysyłamy wszystkie komunikaty żeby ktoś mógł wrócić do gry
                                            // DEAL w tym rozdaniu (dla tego gracza):
                                            std::string deal_msg = deals_sent[p - 1];
                                            ssize_t written_bytes = writen(poll_fds[p].fd, deal_msg.c_str(), deal_msg.length());
                                            if (written_bytes <= 0) {
                                                throw std::runtime_error("writen (deal for new player)");
                                            }
                                            logs.add(from, clients[p].ip_and_port, Clock::now(), deal_msg);
                                            // wszystkie komunikaty TAKEN:
                                            for (std::string msg : takens_sent) {
                                                written_bytes = writen(poll_fds[p].fd, msg.c_str(), msg.length());
                                                if (written_bytes <= 0) {
                                                    throw std::runtime_error("writen (taken for new player)");
                                                }
                                                logs.add(from, clients[p].ip_and_port, Clock::now(), msg);
                                            }

                                        } else {
                                            std::cerr << "new client tried to occupy a busy place\n";
                                            send_busy(poll_fds[j].fd, is_place_occupied, logs, from, clients[j].ip_and_port);
                                            disconnect_client(poll_fds, clients, &dummy1, &dummy2, j);
                                            std::cerr << "place busy: ending connection (id: " << j << ")\n";
                                        }
                                    } else {
                                        close(poll_fds[j].fd);
                                        clear_descriptor(poll_fds, j);
                                        clear_client_info(clients, j);
                                        std::cerr << "Wrong message from client (id: " << j << "), disconnected\n";
                                    }
                                    
                                }
                            }
                            // POLLHUP <=> client disconnected by server - in case of some weird behaviour.
                            else if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLHUP)) {
                                int dummy1, dummy2;
                                disconnect_client(poll_fds, clients, &dummy1, &dummy2, j);
                                std::cerr << "POLLHUP in client " << j << "while waiting for IAM - disconnected\n";
                            }
                            // POLLERR <=> client's error.
                            else if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLERR)) {
                                int dummy1, dummy2;
                                disconnect_client(poll_fds, clients, &dummy1, &dummy2, j);
                                std::cerr << "POLLERR in client " << j << "while waiting for IAM - disconnected\n";
                            }
                            // POLLNVAL <=> wrong descriptor.
                            else if (poll_fds[j].fd != -1 && (poll_fds[j].revents & POLLNVAL)) {
                                int dummy1, dummy2;
                                disconnect_client(poll_fds, clients, &dummy1, &dummy2, j);
                                std::cerr << "POLLNVAL in client " << j << "while waiting for IAM - disconnected\n";
                            }
                        }
                    } 
                    else {
                        std::cout << "timeout...\n";
                    }

                    // Jeśli gra trwa, to policz czas, który pozostał graczowi na przesłanie TRICKa:
                    if (active_clients == PLAYERS) {
                        poll_timeout = TIMEOUT;
                        auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - last_send_time).count();
                        int time_left = timeout - elapsed_time;
                        std::cout << "time left for client " << player << ": " << time_left << "\n";

                        if (time_left <= 0) {
                            trick_to_send = true;
                        }
                        else if (time_left > 0 && time_left < poll_timeout) {
                            poll_timeout = time_left;
                        }
                    }
                    // W przeciwnym przypadku policz czas, który pozostał łączącym się graczom na przesłanie IAM:
                    else {
                        int min_timeout = TIMEOUT;
                        TimePoint now = Clock::now();

                        for (int k = 5; k < 9; k++) {
                            
                            if (poll_fds[k].fd != -1 && clients[k].chosen_position == 0) {
                                // Client hasn't sent IAM, so calculate time left:
                                auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(now - clients[k].connection_time).count();
                                int time_left = timeout - elapsed_time;
                                std::cout << "time left for client " << k << ": " << time_left << "\n";

                                if (time_left <= 0) {
                                    int dummy1 = 0;
                                    int dummy2 = 0;
                                    disconnect_client(poll_fds, clients, &dummy1, &dummy2, k); // we don't modify any state variables
                                    std::cerr << "Time exceeded: ending connection (id: " << k << ")\n";
                                }
                                else if (time_left > 0 && time_left < min_timeout) {
                                    min_timeout = time_left;
                                }
                            }
                        }

                        poll_timeout = min_timeout;
                    }    

                } while (!received);
                
            }

            broadcast_taken(clients, l, cards_on_table, winner, takens_sent, logs, from);

            // Przyznaj punkty:
            if (type == 1 || type == 7) {
                clients[winner].round_points++;
                clients[winner].total_points++;
                points_left--;
            }
            if ((type == 6 || type == 7) && (l == 7 || l == 13)) {
                clients[winner].round_points += PENALTY_7_OR_13;
                clients[winner].total_points += PENALTY_7_OR_13;
                points_left -= PENALTY_7_OR_13;
            }

            for (Card card : cards_on_table) {
                std::string value = card.value;
                char suit = card.suit;
                int score = points.value_points[value] + points.suit_points[suit];
                clients[winner].round_points += score;
                clients[winner].total_points += score;
                points_left -= score;
                if ((type == 5 || type == 7) && value == "K" && suit == 'H') {
                    clients[winner].round_points += PENALTY_KH;
                    clients[winner].total_points += PENALTY_KH;
                    points_left -= PENALTY_KH;
                }
            }

            // Jeśli wszystkie punkty są już rozdysponowane, to kończymy rozdanie:
            if (points_left == 0) {
                break;
            }

            // Gracz biorący lewę wychodzi jako pierwszy w następnej lewie:
            player = winner;
        }

        print_poll_fds(poll_fds);
        print_clients(clients);

        // Po rozdaniu wysyłamy SCORE i TOTAL:
        broadcast_score(clients, logs, from);
        broadcast_total(clients, logs, from);
        

        // Czyścimy punktację z minionego rozdania, zachowujemy generalną:
        for (int i = 1; i <= PLAYERS; i++) {
            clients[i].round_points = 0;
        }

    }

}


// ---------------------------------------- Main ----------------------------------------

int main(int argc, char** argv) {

    // Input data:
    std::string port_s = "0";
    std::string filename; 
    int timeout = 5000;

    // Runtime data:
    struct sockaddr_in6 server_address;
    std::string ip_and_port;
    int socket_fd;
    uint16_t port;

    // Data structures:
    // Arrays of struct pollfd / struct ClientInfo are size 9:
    // { _ | _ _ _ _ | _ _ _ _ }
    // main  in game  reconnecting

    struct pollfd poll_fds[9];
    struct ClientInfo clients[9];

    Game game;

    // Logs:
    Logs logs;
    
    try {
        parse_arguments(argc, argv, &port_s, &filename, &timeout);
        print_options_info(port_s, filename, timeout); // test
        game = parse_game_file(filename);
        initialize_main_socket(&socket_fd, port_s, &port, &server_address, &ip_and_port);
        initialize_descriptors(poll_fds, socket_fd);
        initialize_clients_info(clients);
        connect_with_players(poll_fds, clients, timeout, socket_fd, logs, ip_and_port);
        game_manager(game, poll_fds, clients, timeout, logs, ip_and_port);
        logs.write_to_stdout();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        // close_server();
        return ERROR;
    }

    /*
    
    TEST PARSERA PLIKU:
    try {
        parse_arguments(argc, argv, &port_s, &filename, &timeout);
        print_options_info(port_s, filename, timeout);
        Game game = parse_game_file(filename);

        // Przykładowe wyświetlenie wczytanych danych
        for (const auto& round : game.rounds) {
            std::cout << "Round type: " << round.round_type << ", Starting player: " << round.starting_player << "\n";
            const char players[] = {'N', 'E', 'S', 'W'};
            for (int i = 0; i < 4; ++i) {
                std::cout << "Player " << players[i] << " cards: ";
                for (const auto& card : round.hands[i].cards) {
                    std::cout << card.value << card.suit << " ";
                }
                std::cout << "\n";
            }
            std::cout << "--------------------------------\n";
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
    

    // TESTY PARSERÓW/LOGÓW/CZEGOKOLWIEKCOJESTPOTRZEBNE:
    try {
        parse_arguments(argc, argv, &port_s, &filename, &timeout);
        print_options_info(port_s, filename, timeout); // test
        game = parse_game_file(filename);
        initialize_main_socket(&socket_fd, port_s, &port, &server_address, &ip_and_port);
        initialize_descriptors(poll_fds, socket_fd);
        initialize_clients_info(clients);
        connect_with_players(poll_fds, clients, timeout, socket_fd);
        logs.add(ip_and_port, clients[1].ip_and_port, Clock::now(), "IAMN\r\n");
        logs.add(clients[1].ip_and_port, ip_and_port, Clock::now(), "aceptN\r\n");
        logs.add(ip_and_port, clients[2].ip_and_port, Clock::now(), "IAME\r\n");
        logs.add(clients[2].ip_and_port, ip_and_port, Clock::now(), "aceptE\r\n");
        logs.add(ip_and_port, clients[3].ip_and_port, Clock::now(), "IAMS\r\n");
        logs.add(clients[3].ip_and_port, ip_and_port, Clock::now(), "aceptS\r\n");
        logs.add(ip_and_port, clients[4].ip_and_port, Clock::now(), "IAMW\r\n");
        logs.add(clients[4].ip_and_port, ip_and_port, Clock::now(), "aceptW\r\n");
        logs.write_to_stdout();
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
*/
    
    // close_server(); TODO!!
    return GOOD;
}