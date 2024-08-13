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
#include <errno.h>
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
// Translates host and port info to server's address.
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

    
    try {
        parse_arguments(argc, argv, &host, &port_s, &place, &ipv4, &ipv6, &robot);
        print_options_info(host, port_s, place, ipv4, ipv6, robot); // TEST
        connect_to_server(port_s, &port, host, ipv4, ipv6, &server_address,
                          &socket_fd, &connected, &family);

        
        char buffer[] = "IAMN\r\n"; 
        buffer[3] = place;
        ssize_t written_bytes = write(socket_fd, buffer, 6);

        // tutaj można odebrać albo BUSY albo DEAL

        while (true) {

        }

        // pętla serwera

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        disconnect_from_server(&connected, socket_fd);
        return ERROR;
    }

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
