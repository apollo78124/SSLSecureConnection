#ifndef V1_COPY_H
#define V1_COPY_H


#include <stddef.h>
#include <openssl/ssl.h>


void copy(SSL *from_fd, SSL *to_fd, size_t count);


#endif //V1_COPY_H
