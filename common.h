//
// Created by tomek on 20.05.24.
//

#ifndef KIERKI_COMMON_H
#define KIERKI_COMMON_H

ssize_t	readn(int fd, void *vptr, size_t n, ssize_t *last_read_size);
ssize_t	writen(int fd, const void *vptr, size_t n);

#endif //KIERKI_COMMON_H
