#include <iostream>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
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
#define CONNECTIONS 4
#define POLL_SIZE 5
#define BUFFER_SIZE 250
#define READING_LIMIT 200 // has to be less than BUFFER_SIZE
#define TIMEOUT 500


#define DEFAULT_PORT 0

#define N 1
#define E 2
#define S 3
#define W 4
/*
#define INPUT 5
#define OUTPUT 6
*/

// ---------------------- Declarations & Data Structures ----------------------

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

struct ClientInfo {
    int fd;
    uint16_t port;
    std::string ip_and_port;
    TimePoint connection_time;
    int chosen_position;
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

        for (int i = 0; i < 4; ++i) {
            std::getline(file, line);
            parse_card_set(line, round.hands[i].cards);
        }

        game.add_round(round);
    }

    file.close();
    return game;
}

// ------------------------------ Initialization ------------------------------

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

// ------------------------------- Connection -------------------------------

// Initializes file descriptors' array (of size POLL_SIZE) to use in poll().
void initialize_descriptors(struct pollfd* poll_fds, int socket_fd) {
    for (int i = 0; i < POLL_SIZE; i++) {
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

// Initializes an array (of size POLL_SIZE) with clients data.
void initialize_clients_info(struct ClientInfo* clients) {
    for (int i = 0; i < POLL_SIZE; i++) {
        clients[i].fd = -1;
        clients[i].port = 0;
        clients[i].ip_and_port = "";
        clients[i].connection_time = TimePoint();
        clients[i].chosen_position = 0;
    }
}

// Clears i-th client's info in clients data array.
void clear_client_info(struct ClientInfo* clients, int i) {
    clients[i].fd = -1;
    clients[i].port = 0;
    clients[i].ip_and_port = "";
    clients[i].connection_time = TimePoint();
    clients[i].chosen_position = 0;
}

// Initializes an array for the info about occupied places.
void initialize_is_occupied(bool* is_place_occupied) {
    for (int i = 0; i < POLL_SIZE; i++) {
        is_place_occupied[i] = false;
    }
}

// Writes true/false to an array that indicates occupation of places.
// is_place_occupied = { _ _ _ _ _ }
//                         N E S W
void get_occupied_places(struct ClientInfo* clients, bool* is_place_occupied) {
    for (int i = 1; i < POLL_SIZE; i++) {
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
    while (id <= CONNECTIONS) {
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

// ---------------------------------- Utils ----------------------------------

int map_place(char place) {
    switch (place) {
        case 'N':
            return 1;
        case 'E':
            return 2;
        case 'S':
            return 3;
        case 'W':
            return 4;
    }
    return 0;
}

// ---------------------------- Sending messages ----------------------------

// functions of type: send_<message>()



// --------------------------- Receiving messages ---------------------------

// functions of type: recv_<message>()

// Reads from given descriptor until it finds "\r\n" sequence.
// Writes read sequence to an external buffer ext_buffer
// Returns number of read bytes or -1 in case of error.
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


// ---------------------------- Parsing messages -------------------------------
// |   All parsers return 0 if a message is parsed correctly, 1 if it's not.   |
// -----------------------------------------------------------------------------

/*
int parse_iam(const std::string& message, char* result) {
    // Length:
    if (message.length() != 6) {
        std::cerr << "Error: Incorrect message length." << std::endl;
        return ERROR;
    }
    // "IAM"
    if (message.substr(0, 3) != "IAM") {
        std::cerr << "Error: Message does not start with 'IAM'." << std::endl;
        return ERROR;
    }

    char place = message[3];
    // 'N', 'E', 'S', or 'W'
    if (place != 'N' && place != 'E' && place != 'S' && place != 'W') {
        std::cerr << "Error: Invalid place character." << std::endl;
        return ERROR;
    }

    // Check if the message ends with "\r\n"
    if (message.substr(4, 2) != "\r\n") {
        std::cerr << "Error: Message does not end with '\\r\\n'." << std::endl;
        return ERROR;
    }

    // If all checks pass, return the place character
    *result = place;
    return GOOD;
}
*/

// Parser for a message of type: IAM<place>\r\n.
int parse_iam(const std::string& message, char* result) {

    std::regex pattern(R"(IAM([NESW])\r\n)");
    std::smatch match;

    if (std::regex_match(message, match, pattern)) {
        *result = match[1].str()[0];
        return GOOD;
    } else {
        return ERROR;
    }
}

// Parser for a message of type: TRICK<trick number><card>\r\n.
int parse_trick(const std::string& message, int* trick_number,
                std::string* value, char* suit) {
    
    std::regex pattern(R"(TRICK([1-9]|1[0-3])(10|[2-9]|[JQKA])([CDHS])\r\n)");
    std::smatch match;

    if (std::regex_match(message, match, pattern)) {
        *trick_number = std::stoi(match[1].str());
        *value = match[2].str();
        *suit = match[3].str()[0];
        return GOOD;
    } else {
        return ERROR;
    }
}

void test_parse_trick() {
    // Correct:
    int trick_number;
    std::string value;
    char suit;
    assert(parse_trick("TRICK15H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 1);
    assert(value == "5");
    assert(suit == 'H');
    assert(parse_trick("TRICK125H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 12);
    assert(value == "5");
    assert(suit == 'H');
    assert(parse_trick("TRICK110H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 1);
    assert(value == "10");
    assert(suit == 'H');
    assert(parse_trick("TRICK1310H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 13);
    assert(value == "10");
    assert(suit == 'H');
    assert(parse_trick("TRICK5KS\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 5);
    assert(value == "K");
    assert(suit == 'S');
    // Wrong:
    assert(parse_trick("aTRICK5KS\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICK0KS\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICKS\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICK500S\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICK59M\r\n", &trick_number, &value, &suit) == 1);
}


// -------------------------------- Test prints --------------------------------

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
}

/**
 * CONNECTION
 * - struct pollfd* ready_poll_fds is a pointer to an array of sorted clients data
 *   (according to their place choice) - filled by this function at the end.
 * - struct ClientInfo* ready_clients is similar but for other data.
 * - int timeout is a constant value given as an argument when starting the server.
 * - int socket_fd is a descriptor of the server.
 */

// Create connections with all players.
void connect_with_players(struct pollfd* ready_poll_fds, struct ClientInfo* ready_clients, 
                          int timeout, int socket_fd) {

    struct pollfd poll_fds[POLL_SIZE];
    struct ClientInfo clients[POLL_SIZE];
    bool is_place_occupied[POLL_SIZE];

    initialize_descriptors(poll_fds, socket_fd);
    initialize_clients_info(clients);
    initialize_is_occupied(is_place_occupied);

    // After establishing all four connections, poll_fds and clients
    // will be rewritten to ready_poll_fds and ready_clients.

    int poll_timeout = TIMEOUT;
    int active_clients = 0;
    int ready = 0;

    //static char buffer[BUFFER_SIZE];
    std::string buffer;

    do {
        for (int i = 0; i < POLL_SIZE; i++) {
            poll_fds[i].revents = 0;
        }

        int poll_status = poll(poll_fds, POLL_SIZE, poll_timeout);
        check_poll_error(poll_status);

        /*
        DEBUG:
        std::cout << "Poll descriptors array:\n";
        for (int i = 0; i < POLL_SIZE; i++) {
            std::cout << "fd=" << poll_fds[i].fd << " events=" << poll_fds[i].events << " revents=" << poll_fds[i].revents << "\n";
        }
        */

        if (poll_status > 0) {
            // New connection: new client is accepted.
            if (poll_fds[0].revents & POLLIN) {
                if (active_clients < CONNECTIONS) {
                    accept_client(poll_fds, clients);
                    active_clients++;
                    std::cout << "Client " << active_clients << " accepted\n"; 
                } else {
                    std::cerr << "Maximum clients reached, connection rejected\n";
                }
            }
            // Serve connected clients - receive IAM or reject message/connection.
            for (int i = 1; i <= CONNECTIONS; i++) {
                
                // POLLIN <=> received a message.
                if (poll_fds[i].fd != -1 && (poll_fds[i].revents & POLLIN)) {

                    ssize_t last_read_size;
                    buffer = "";
                    
                    // ssize_t received_bytes = readn(poll_fds[i].fd, buffer, IAM_SIZE, &last_read_size);
                    int received_bytes = read_to_newline(poll_fds[i].fd, &buffer);

                    if (received_bytes < 0) {
                        disconnect_client(poll_fds, clients, &active_clients, &ready, i);
                        std::cerr << "readn failed: ending connection (id: " << i << ")\n";
                    } else if (received_bytes == 0) {
                        disconnect_client(poll_fds, clients, &active_clients, &ready, i);
                        std::cerr << "empty readn: ending connection (id: " << i << ")\n";
                    } else {
                        std::cout << "received " << received_bytes << " bytes within connection (id: " << i << ")\n";
                        std::cout << "parsing message: " << buffer << "\n";
                        char place;
                        if (parse_iam(buffer, &place) == 0) {
                            std::cout << "received IAM" << place << "\n";
                            get_occupied_places(clients, is_place_occupied);
                            int p = map_place(place);
                            if (!is_place_occupied[p]) {
                                clients[i].chosen_position = p;
                                ready++;
                            } else {
                                // tutaj wysyłamy BUSY<listazajetychmiejsc>
                            }

                            
                        } else {
                            // czy to jest na pewno to samo?
                            close(poll_fds[i].fd);
                            active_clients--;
                            // if (clients[i].chosen_position != 0) ready--;
                            clear_descriptor(poll_fds, i);
                            clear_client_info(clients, i);
                            std::cerr << "Wrong message from client (id: " << i << "), disconnected\n";
                        }
                    }
                }
                // POLLHUP <=> client disconnected.
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

    } while (ready < CONNECTIONS);

    for (int i = 1; i <= CONNECTIONS; i++) {
        int p = clients[i].chosen_position;
        ready_poll_fds[p].fd = poll_fds[i].fd;
        ready_clients[p].fd = clients[i].fd;
        ready_clients[p].port = clients[i].port;
        ready_clients[p].ip_and_port = clients[i].ip_and_port;
        ready_clients[p].connection_time = clients[i].connection_time;
        ready_clients[p].chosen_position = clients[i].chosen_position;
    }

    print_poll_fds(ready_poll_fds);
    print_clients(ready_clients);

    std::cout << "Connections established, game is starting...\n";
}

// ---------------------------------- Main ----------------------------------

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

    struct pollfd poll_fds[POLL_SIZE];
    struct ClientInfo clients[POLL_SIZE]; // clients[0] is empty.
    
    static char buffer[BUFFER_SIZE];

    // State:
    size_t active_clients = 0;

    /*
    try {
        parse_arguments(argc, argv, &port_s, &filename, &timeout);
        print_options_info(port_s, filename, timeout);
        initialize_main_socket(&socket_fd, port_s, &port, &server_address, &ip_and_port);
        initialize_descriptors(poll_fds, socket_fd);
        initialize_clients_info(clients);
        connect_with_players(poll_fds, clients, timeout, socket_fd);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        // close_server();
        return ERROR;
    }
    */

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
    */

   // TESTY PARSERÓW:
   try {
        test_parse_trick();
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }

    // close_server();
    return GOOD;
}