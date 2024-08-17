#include <unistd.h>

#include "kierki-common.h"

// Following two functions come from Stevens' "UNIX Network Programming" book.

// Read n bytes from a descriptor. Use in place of read() when fd is a stream socket.
ssize_t readn(int fd, void *vptr, size_t n, ssize_t *last_read_size) {
    ssize_t nleft, nread;
    char *ptr;

    ptr = (char*) vptr;
    nleft = n;
    while (nleft > 0) {
        if ((nread = read(fd, ptr, nleft)) < 0)
            return nread;     // When error, return < 0.
        else if (nread == 0)
            break;            // EOF

        *last_read_size = nread;
        nleft -= nread;
        ptr += nread;
    }
    return n - nleft;         // return >= 0
}

// Write n bytes to a descriptor.
ssize_t writen(int fd, const void *vptr, size_t n){
    ssize_t nleft, nwritten;
    const char *ptr;

    ptr = (char*) vptr;
    nleft = n;
    while (nleft > 0) {
        if ((nwritten = write(fd, ptr, nleft)) <= 0)
            return nwritten;  // error

        nleft -= nwritten;
        ptr += nwritten;
    }
    return n;
}

// TRASH:

/*
// prefix:
std::string str = "Hello, World!";
std::string prefix = str.substr(0, 5); // "Hello"

// suffix:
std::string str = "Hello, World!";
std::string suffix = str.substr(str.length() - 6, 6); // "World!"

// infix:
std::string str = "Hello, World!";
std::string middle = str.substr(7, 5); // "World"

// rest of the string starting from given position:
std::string str = "Hello, World!";
std::string rest = str.substr(7); // "World!"
*/

/*
// Parser for a message of type: TRICK<1...13><card>.
int parse_trick(const std::string& message) {
    // Length:
    if (message.length() < 10 || message.length() > 12) {
        std::cerr << "Error: Incorrect message length" << std::endl;
        return ERROR;
    }
    // "TRICK"
    if (message.substr(0, 5) != "TRICK") {
        std::cerr << "Error: Message does not start with 'TRICK'" << std::endl;
        return ERROR;
    }
    // Check if the message ends with "\r\n"
    if (message.substr(message.length() - 2, 2) != "\r\n") {
        std::cerr << "Error: Message does not end with '\\r\\n'" << std::endl;
        return ERROR;
    }
    char suit = message[message.length() - 3];
    if (suit != 'C' || suit != 'D' || suit != 'H' || suit != 'S') {
        std::cerr << "Error: Incorrect card suit" << std::endl;
        return ERROR;
    }

    std::string value = "";
    bool ten = false;
    char v = message[message.length() - 4];
    if (v == 'J' || v == 'Q' || v == 'K' || v == 'A') {
        value += v;
    }
    else if (v >= '2' && v <= '9') {
        value += v;
    }
    else if (v == '0') { // 10
        if (message[message.length() - 5] == '1') {
            value = "10";
            ten = true;
        } else {
            std::cerr << "Error: Incorrect card value" << std::endl;
            return ERROR;
        }
    }
    else {
        std::cerr << "Error: Incorrect card value" << std::endl;
        return ERROR;
    }

    int first_char = message.length() - 6;
    int second_char = message.length() - 5;
    if (ten) {
        first_char--;
        second_char--;
    }
    // first char can be 'K' - this means 

}
*/