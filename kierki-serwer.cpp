#include <iostream>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
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
#define BUFFER_SIZE 100
#define TIMEOUT 5000

#define DEFAULT_PORT 0

#define N 1
#define E 2
#define S 3
#define W 4
/*
#define INPUT 5
#define OUTPUT 6
*/

#define IAM_SIZE 6

// ------------------------------- Declarations -------------------------------

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

struct ClientInfo {
    int fd;
    uint16_t port;
    std::string ip_and_port;
    TimePoint connection_time;
    int chosen_position;
};

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
void calculate_remaining_time(struct ClientInfo* clients, int timeout,
                              struct pollfd* poll_fds, int* active_clients) {

    TimePoint now = Clock::now();

    for (int i = 1; i <= CONNECTIONS; i++) {
        if (poll_fds[i].fd != -1 && clients[i].chosen_position == 0) {

            auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(now - clients[i].connection_time).count();
            int time_left = timeout - elapsed_time;

            if (time_left <= 0) {
                // siodmy raz to samo
                close(poll_fds[i].fd);
                clear_descriptor(poll_fds, i);
                clear_client_info(clients, i);
                (*active_clients)--;
                std::cerr << "Time exceeded: ending connection (id: " << i << ")\n";
            }
            /*
            // ewentualnie mozna sprobowac czy dziala ten ulepszony algorytm liczenia timeoutu
            else if (time_left < *poll_timeout && time_left > 0) {
                *poll_timeout = time_left;
            }
            */
        }
    }
}

// ------------------------------ Message parsers ------------------------------

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

int iam_parser(const std::string& message, char* result) {
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

/*
Pomysł:
Tworzymy tablicę structów z danymi czasowymi kolejnych klientów i na bieżąco ją aktualizujemy.
Między acceptem a ustaleniem połączenia pamiętamy wszystko w zmiennych lokalnych i czekamy
na komunikat IAM. Jeśli on nie dotrze, nie musimy zmieniać żadnych złożonych struktur danych.

Gdy klient w odpowiednim czasie prześle komunikat IAM, przepisujemy jego deskryptor i dane
czasowe do nowych struktur. Gra będzie prowadzona na innym pollu, gdzie z każdym graczem będzie
związana nazwa (można zrobić structa na nazwę <N/E/S/W>, deskryptor i dane czasowe). Następnie
czekamy na wszystkich graczy. Obsługujemy też rozłączenia się klientów, jeśli to zrobią
po przesłaniu IAM.

Poniżej wersja robocza, wymaga dopracowania.
Ten poll zajmuje się przyjmowaniem połączeń, ewentualny syf od przyłączonych klientów olewa.
Kolejny poll będzie przeprowadzać grę, wtedy zerowy deskryptor w tablicy będzie tylko do
olewania i ewentualnego czekania na podłączenie się nowego gracza.
*/

/*
TODO: zebrać zamykanie połączenia w jedną funkcję, przemyśleć obsługę 
*/

// Create connections with all players.
void connect_with_players(struct pollfd* ready_poll_fds, struct ClientInfo* ready_clients, 
                          int timeout, int socket_fd) {

    struct pollfd poll_fds[POLL_SIZE];
    struct ClientInfo clients[POLL_SIZE];

    initialize_descriptors(poll_fds, socket_fd);
    initialize_clients_info(clients);

    // After establishing all four connections, poll_fds and clients
    // will be rewritten to ready_poll_fds and ready_clients.

    int active_clients = 0;
    int ready = 0;

    static char buffer[BUFFER_SIZE];
    
    do {
        for (int i = 0; i < POLL_SIZE; i++) {
            poll_fds[i].revents = 0;
        }

        int poll_status = poll(poll_fds, POLL_SIZE, TIMEOUT);
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
                    memset(buffer, 0, BUFFER_SIZE);
                    
                    ssize_t received_bytes = readn(poll_fds[i].fd, buffer, (size_t) IAM_SIZE, &last_read_size);
                    
                    // TODO: uprościć te ify
                    if (received_bytes < 0) {
                        // zamykanie klienta: ta sama sekwencja krokow
                        close(poll_fds[i].fd);
                        active_clients--;
                        if (clients[i].chosen_position != 0) ready--;
                        clear_descriptor(poll_fds, i);
                        clear_client_info(clients, i);
                        std::cerr << "readn failed: ending connection (id: " << i << ")\n";
                    } else if (received_bytes == 0) {
                        // drugi raz to samo
                        close(poll_fds[i].fd);
                        active_clients--;
                        if (clients[i].chosen_position != 0) ready--;
                        clear_descriptor(poll_fds, i);
                        clear_client_info(clients, i);
                        std::cerr << "empty readn: ending connection (id: " << i << ")\n";
                    } else {
                        std::cout << "received " << received_bytes << " bytes within connection (id: " << i << ")\n";
                        std::cout << "parsing message: " << buffer << "\n";
                        char place;
                        if (iam_parser(buffer, &place) == 0) {
                            std::cout << "received IAM" << place << "\n";
                            clients[i].chosen_position = map_place(place);
                            ready++;
                        } else {
                            // trzeci raz to samo
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
                    // czwarty raz to samo
                    close(poll_fds[i].fd);
                    active_clients--;
                    if (clients[i].chosen_position != 0) ready--;
                    clear_descriptor(poll_fds, i);
                    clear_client_info(clients, i);
                    std::cerr << "client " << i << " disconnected - waiting to reconnect\n";
                }
                // POLLERR <=> client's error.
                else if (poll_fds[i].fd != -1 && (poll_fds[i].revents & POLLERR)) {
                    // piąty raz to samo
                    close(poll_fds[i].fd);
                    active_clients--;
                    if (clients[i].chosen_position != 0) ready--;
                    clear_descriptor(poll_fds, i);
                    clear_client_info(clients, i);
                    std::cerr << "client " << i << " got an error - disconnected\n";
                }
                // POLLNVAL <=> wrong descriptor.
                else if (poll_fds[i].fd != -1 && (poll_fds[i].revents & POLLNVAL)) {
                    // szósty raz to samo
                    close(poll_fds[i].fd);
                    active_clients--;
                    if (clients[i].chosen_position != 0) ready--;
                    clear_descriptor(poll_fds, i);
                    clear_client_info(clients, i);
                    std::cerr << "error in poll_fds array: descriptor " << i << "is wrong\n";
                }
            }
        } 
        else {
            std::cout << "timeout...\n";
        }

        calculate_remaining_time(clients, timeout, poll_fds, &active_clients);

    } while (ready < CONNECTIONS);

    std::cout << "Connections established, game is starting...\n";

    std::cout << "Clients:\n";
    for (int i = 1; i <= CONNECTIONS; i++) {
        int p = clients[i].chosen_position;
        ready_poll_fds[p].fd = poll_fds[i].fd;
        ready_clients[p].fd = clients[i].fd;
        ready_clients[p].port = clients[i].port;
        ready_clients[p].ip_and_port = clients[i].ip_and_port;
        ready_clients[p].connection_time = clients[i].connection_time;
        ready_clients[p].chosen_position = clients[i].chosen_position;
    }

    for (int i = 1; i <= CONNECTIONS; i++) {
        std::cout << "PLACE: " << i << "\n\tfd=" << ready_clients[i].fd << "\n\tip_and_port=" << ready_clients[i].ip_and_port << "\n\tchosen_pos=" << ready_clients[i].chosen_position << "\n";
    }

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

    try {
        parse_arguments(argc, argv, &port_s, &filename, &timeout);
        print_options_info(port_s, filename, timeout);
        // install_signal_handler(SIGINT, catch_int, SA_RESTART);
        initialize_main_socket(&socket_fd, port_s, &port, &server_address, &ip_and_port);
        initialize_descriptors(poll_fds, socket_fd);
        initialize_clients_info(clients);
        connect_with_players(poll_fds, clients, timeout, socket_fd);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        // close_server();
        return ERROR;
    }

    // close_server();
    return GOOD;
}