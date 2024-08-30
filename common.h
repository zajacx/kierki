//
// Created by tomek on 20.05.24.
//

#ifndef KIERKI_COMMON_H
#define KIERKI_COMMON_H

#define READING_LIMIT 200

ssize_t	readn(int fd, void *vptr, size_t n);
ssize_t	writen(int fd, const void *vptr, size_t n);
uint16_t read_port(std::string port_s);
int read_to_newline(int descriptor, std::string* result);

#endif //KIERKI_COMMON_H
